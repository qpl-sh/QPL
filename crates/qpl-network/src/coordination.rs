// SPDX-License-Identifier: MIT OR Apache-2.0

//! Coordination state machine for multi-operator operations.
//!
//! Manages the lifecycle of a coordination round: collecting partial responses
//! from multiple operators until a threshold is reached or timeout occurs.
//!
//! Includes bounded-state safeguards (F-3) so a single misbehaving operator
//! cannot exhaust memory by opening unbounded coordination rounds: per-operator
//! and global concurrent-round caps, plus opportunistic cleanup of finished
//! rounds.

use crate::errors::NetworkError;
use crate::types::*;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use thiserror::Error;

/// Default maximum number of concurrent rounds a single operator may
/// coordinate at once.
pub const DEFAULT_MAX_PER_OPERATOR_ROUNDS: u32 = 1024;

/// Default maximum number of concurrent rounds across the whole manager.
pub const DEFAULT_MAX_GLOBAL_ROUNDS: u32 = 65_536;

/// Soft size threshold above which `start_round` will eagerly trigger a
/// cleanup pass before insertion.
pub const DEFAULT_CLEANUP_SOFT_THRESHOLD: usize = 2_048;

/// Maximum interval between automatic cleanups, regardless of map size.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 5;

/// Maximum age (in seconds) of a finished round before it becomes eligible
/// for eviction during cleanup.
pub const DEFAULT_ROUND_MAX_AGE_SECS: u64 = 300; // 5 minutes

/// Errors specific to coordination-state management (F-3 bounded state).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// The given operator already has the maximum number of concurrent
    /// coordination rounds in flight.
    #[error("operator {0} has reached the per-operator concurrent-round cap")]
    TooManyConcurrentRounds(OperatorId),

    /// The manager has reached the global cap on concurrent coordination
    /// rounds across all operators.
    #[error("global concurrent-round cap reached")]
    TooManyConcurrentRoundsGlobal,
}

/// A partial response from an operator during a coordination round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResponse {
    /// The operator that produced this response.
    pub operator_id: OperatorId,
    /// The shard index (for signing) or vote (for verification).
    pub shard_index: u8,
    /// The actual partial data (partial signature bytes, verification vote, etc.).
    pub payload: Vec<u8>,
    /// Timestamp when this partial was received.
    pub received_at: DateTime<Utc>,
}

/// Status of a coordination round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoundStatus {
    /// Waiting for partial responses.
    Collecting,
    /// Threshold reached — ready to finalize.
    ThresholdReached,
    /// Round completed successfully.
    Completed,
    /// Round timed out before threshold was reached.
    TimedOut,
    /// Round failed for another reason.
    Failed,
}

/// A coordination round tracks the collection of partial responses for a
/// threshold operation (e.g., threshold signing, proof verification quorum).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationRound {
    /// The request this round is fulfilling.
    pub request_id: RequestId,
    /// The operator coordinating this round.
    pub coordinator_id: OperatorId,
    /// Required number of responses to reach threshold.
    pub threshold: u8,
    /// Total operators invited to participate.
    pub total_invited: u8,
    /// Collected partial responses.
    pub partials: HashMap<OperatorId, PartialResponse>,
    /// Current status.
    pub status: RoundStatus,
    /// When this round was started.
    pub started_at: DateTime<Utc>,
    /// Deadline for collecting responses.
    pub deadline: DateTime<Utc>,
}

impl CoordinationRound {
    /// Creates a new coordination round.
    pub fn new(
        request_id: RequestId,
        coordinator_id: OperatorId,
        threshold: u8,
        total_invited: u8,
        timeout_secs: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            request_id,
            coordinator_id,
            threshold,
            total_invited,
            partials: HashMap::new(),
            status: RoundStatus::Collecting,
            started_at: now,
            deadline: now + Duration::seconds(timeout_secs as i64),
        }
    }

    /// Adds a partial response from an operator. Returns the new round status.
    pub fn add_partial(&mut self, response: PartialResponse) -> Result<RoundStatus, NetworkError> {
        if self.status == RoundStatus::Completed || self.status == RoundStatus::Failed {
            return Err(NetworkError::RequestAlreadyCompleted(self.request_id.clone()));
        }

        if self.is_expired() {
            self.status = RoundStatus::TimedOut;
            return Err(NetworkError::CoordinationTimeout(self.request_id.clone()));
        }

        self.partials.insert(response.operator_id.clone(), response);

        if self.partials.len() >= self.threshold as usize {
            self.status = RoundStatus::ThresholdReached;
        }

        Ok(self.status)
    }

    /// Marks the round as completed after successful finalization.
    pub fn complete(&mut self) {
        self.status = RoundStatus::Completed;
    }

    /// Marks the round as failed.
    pub fn fail(&mut self) {
        self.status = RoundStatus::Failed;
    }

    /// Returns true if the deadline has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.deadline
    }

    /// Returns true if the threshold has been reached.
    pub fn threshold_reached(&self) -> bool {
        self.partials.len() >= self.threshold as usize
    }

    /// Returns all collected partial payloads in shard_index order.
    pub fn ordered_payloads(&self) -> Vec<&PartialResponse> {
        let mut responses: Vec<&PartialResponse> = self.partials.values().collect();
        responses.sort_by_key(|r| r.shard_index);
        responses
    }

    /// Returns the number of responses still needed.
    pub fn remaining_needed(&self) -> u8 {
        let collected = self.partials.len() as u8;
        self.threshold.saturating_sub(collected)
    }
}

/// Manages multiple active coordination rounds with bounded memory.
#[derive(Debug)]
pub struct CoordinationManager {
    rounds: HashMap<RequestId, CoordinationRound>,
    /// Active-round count per coordinator operator. Decremented during
    /// cleanup as rounds are evicted.
    per_operator_counts: HashMap<OperatorId, u32>,
    /// Maximum number of concurrent rounds permitted for any single operator.
    pub max_per_operator_rounds: u32,
    /// Maximum number of concurrent rounds permitted across all operators.
    pub max_global_rounds: u32,
    /// `start_round` triggers cleanup when `rounds.len() >` this threshold.
    pub cleanup_soft_threshold: usize,
    /// `start_round` triggers cleanup when more than this many seconds have
    /// elapsed since the last cleanup pass.
    pub cleanup_interval_secs: u64,
    /// Maximum age (in seconds) of a finished round before cleanup may evict it.
    pub round_max_age_secs: u64,
    /// Wall-clock instant of the most recent cleanup pass.
    last_cleanup: Instant,
}

impl Default for CoordinationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CoordinationManager {
    /// Creates a manager with default caps and cleanup tuning.
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
            per_operator_counts: HashMap::new(),
            max_per_operator_rounds: DEFAULT_MAX_PER_OPERATOR_ROUNDS,
            max_global_rounds: DEFAULT_MAX_GLOBAL_ROUNDS,
            cleanup_soft_threshold: DEFAULT_CLEANUP_SOFT_THRESHOLD,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            round_max_age_secs: DEFAULT_ROUND_MAX_AGE_SECS,
            last_cleanup: Instant::now(),
        }
    }

    /// Number of currently-tracked rounds (any status). Mostly diagnostic.
    pub fn total_rounds(&self) -> usize {
        self.rounds.len()
    }

    /// Number of active rounds (i.e. coordinator slots in use) for `op`.
    pub fn rounds_for(&self, op: &OperatorId) -> u32 {
        self.per_operator_counts.get(op).copied().unwrap_or(0)
    }

    /// Starts a new coordination round.
    ///
    /// Enforces both per-operator and global concurrent-round caps and runs
    /// an opportunistic cleanup pass when the rounds map is large or the
    /// last cleanup is stale (F-3).
    pub fn start_round(
        &mut self,
        request_id: RequestId,
        coordinator_id: OperatorId,
        threshold: u8,
        total_invited: u8,
        timeout_secs: u64,
    ) -> Result<&CoordinationRound, CoordinationError> {
        // Opportunistic cleanup BEFORE cap checks so that long-finished rounds
        // do not spuriously block a new one.
        if self.rounds.len() > self.cleanup_soft_threshold
            || self.last_cleanup.elapsed()
                >= std::time::Duration::from_secs(self.cleanup_interval_secs)
        {
            self.cleanup_old_rounds(self.round_max_age_secs);
            self.last_cleanup = Instant::now();
        }

        // Global cap.
        if self.rounds.len() >= self.max_global_rounds as usize {
            return Err(CoordinationError::TooManyConcurrentRoundsGlobal);
        }
        // Per-operator cap.
        let current_for_op = self
            .per_operator_counts
            .get(&coordinator_id)
            .copied()
            .unwrap_or(0);
        if current_for_op >= self.max_per_operator_rounds {
            return Err(CoordinationError::TooManyConcurrentRounds(coordinator_id));
        }

        let round = CoordinationRound::new(
            request_id.clone(),
            coordinator_id.clone(),
            threshold,
            total_invited,
            timeout_secs,
        );
        // Only bump the per-operator counter if we actually inserted a fresh
        // round (a duplicate request_id would replace an existing entry — in
        // that rare case we leave the counter untouched).
        if !self.rounds.contains_key(&request_id) {
            *self.per_operator_counts.entry(coordinator_id).or_insert(0) += 1;
        }
        self.rounds.insert(request_id.clone(), round);
        Ok(self.rounds.get(&request_id).unwrap())
    }

    /// Adds a partial response to an existing round.
    pub fn add_partial(
        &mut self,
        request_id: &RequestId,
        response: PartialResponse,
    ) -> Result<RoundStatus, NetworkError> {
        let round = self
            .rounds
            .get_mut(request_id)
            .ok_or_else(|| NetworkError::CoordinationTimeout(request_id.clone()))?;
        round.add_partial(response)
    }

    /// Gets a round by request ID.
    pub fn get_round(&self, request_id: &RequestId) -> Option<&CoordinationRound> {
        self.rounds.get(request_id)
    }

    /// Gets a mutable round by request ID.
    pub fn get_round_mut(&mut self, request_id: &RequestId) -> Option<&mut CoordinationRound> {
        self.rounds.get_mut(request_id)
    }

    /// Removes finished rounds older than `max_age_secs` and decrements the
    /// owning operators' active-round counters accordingly.
    pub fn cleanup_old_rounds(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now() - Duration::seconds(max_age_secs as i64);
        let mut evicted_coordinators: Vec<OperatorId> = Vec::new();
        self.rounds.retain(|_, round| {
            let finished = matches!(
                round.status,
                RoundStatus::Completed | RoundStatus::TimedOut | RoundStatus::Failed
            );
            let too_old = round.started_at <= cutoff;
            // Evict only if the round is finished AND old enough, OR if it's
            // simply old enough (which catches stuck-Collecting rounds whose
            // deadline has long since passed).
            let evict = too_old && (finished || round.is_expired());
            if evict {
                evicted_coordinators.push(round.coordinator_id.clone());
            }
            !evict
        });
        for op in evicted_coordinators {
            if let Some(count) = self.per_operator_counts.get_mut(&op) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_operator_counts.remove(&op);
                }
            }
        }
    }

    /// Returns the number of active rounds.
    pub fn active_count(&self) -> usize {
        self.rounds
            .values()
            .filter(|r| r.status == RoundStatus::Collecting)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_operator_id(seed: u8) -> OperatorId {
        OperatorId::from_public_key(&[seed; 32])
    }

    #[test]
    fn test_coordination_round_lifecycle() {
        let mut round = CoordinationRound::new(
            RequestId::new(),
            test_operator_id(0),
            3,  // threshold
            5,  // total invited
            30, // 30s timeout
        );

        assert_eq!(round.status, RoundStatus::Collecting);
        assert_eq!(round.remaining_needed(), 3);

        // Add 2 partials — still collecting
        round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(1),
                shard_index: 1,
                payload: vec![0xAA; 32],
                received_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(round.status, RoundStatus::Collecting);
        assert_eq!(round.remaining_needed(), 2);

        round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(2),
                shard_index: 2,
                payload: vec![0xBB; 32],
                received_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(round.status, RoundStatus::Collecting);

        // Third partial — threshold reached
        let status = round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(3),
                shard_index: 3,
                payload: vec![0xCC; 32],
                received_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(status, RoundStatus::ThresholdReached);
        assert!(round.threshold_reached());
        assert_eq!(round.remaining_needed(), 0);
    }

    #[test]
    fn test_ordered_payloads() {
        let mut round = CoordinationRound::new(
            RequestId::new(),
            test_operator_id(0),
            3,
            5,
            30,
        );

        // Add in non-sequential order
        round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(3),
                shard_index: 3,
                payload: vec![0xCC],
                received_at: Utc::now(),
            })
            .unwrap();
        round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(1),
                shard_index: 1,
                payload: vec![0xAA],
                received_at: Utc::now(),
            })
            .unwrap();
        round
            .add_partial(PartialResponse {
                operator_id: test_operator_id(2),
                shard_index: 2,
                payload: vec![0xBB],
                received_at: Utc::now(),
            })
            .unwrap();

        let ordered = round.ordered_payloads();
        assert_eq!(ordered[0].shard_index, 1);
        assert_eq!(ordered[1].shard_index, 2);
        assert_eq!(ordered[2].shard_index, 3);
    }

    #[test]
    fn test_coordination_manager() {
        let mut mgr = CoordinationManager::new();
        let req_id = RequestId::new();

        mgr.start_round(req_id.clone(), test_operator_id(0), 2, 3, 30)
            .unwrap();
        assert_eq!(mgr.active_count(), 1);

        let status = mgr
            .add_partial(
                &req_id,
                PartialResponse {
                    operator_id: test_operator_id(1),
                    shard_index: 1,
                    payload: vec![0xAA],
                    received_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(status, RoundStatus::Collecting);

        let status = mgr
            .add_partial(
                &req_id,
                PartialResponse {
                    operator_id: test_operator_id(2),
                    shard_index: 2,
                    payload: vec![0xBB],
                    received_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(status, RoundStatus::ThresholdReached);
    }

    // ---------- F-3 acceptance tests ----------

    /// (a) Per-operator concurrent-round cap is enforced.
    #[test]
    fn test_per_operator_concurrent_round_cap_is_enforced() {
        let mut mgr = CoordinationManager::new();
        mgr.max_per_operator_rounds = 3; // tighten for the test
        mgr.max_global_rounds = 100;
        let coord = test_operator_id(42);

        for _ in 0..3 {
            mgr.start_round(RequestId::new(), coord.clone(), 2, 3, 30)
                .expect("first three rounds should succeed");
        }

        let err = mgr
            .start_round(RequestId::new(), coord.clone(), 2, 3, 30)
            .unwrap_err();
        match err {
            CoordinationError::TooManyConcurrentRounds(op) => assert_eq!(op, coord),
            other => panic!("expected per-operator cap error, got {other:?}"),
        }

        // A different operator is unaffected by the per-operator cap.
        let other = test_operator_id(7);
        mgr.start_round(RequestId::new(), other, 2, 3, 30)
            .expect("different operator should not hit per-operator cap");
    }

    /// Global cap is enforced regardless of which operator is coordinating.
    #[test]
    fn test_global_concurrent_round_cap_is_enforced() {
        let mut mgr = CoordinationManager::new();
        mgr.max_per_operator_rounds = 1024;
        mgr.max_global_rounds = 2;

        mgr.start_round(RequestId::new(), test_operator_id(1), 2, 3, 30)
            .unwrap();
        mgr.start_round(RequestId::new(), test_operator_id(2), 2, 3, 30)
            .unwrap();

        let err = mgr
            .start_round(RequestId::new(), test_operator_id(3), 2, 3, 30)
            .unwrap_err();
        assert!(matches!(err, CoordinationError::TooManyConcurrentRoundsGlobal));
    }

    /// (b) Cleanup is triggered automatically once the soft-threshold is
    /// crossed. We force the threshold low and verify `last_cleanup` advances
    /// when `start_round` is called.
    #[test]
    fn test_cleanup_triggered_after_soft_threshold() {
        let mut mgr = CoordinationManager::new();
        mgr.cleanup_soft_threshold = 1;
        mgr.cleanup_interval_secs = 3600; // disable time-based trigger
        mgr.round_max_age_secs = 0; // anything old is fair game

        // Insert two old, finished rounds.
        for seed in 0..2u8 {
            let rid = RequestId::new();
            let coord = test_operator_id(seed);
            mgr.start_round(rid.clone(), coord, 2, 3, 30).unwrap();
            // Backdate and mark completed so cleanup_old_rounds will evict.
            let r = mgr.get_round_mut(&rid).unwrap();
            r.started_at = Utc::now() - Duration::seconds(10);
            r.complete();
        }
        assert_eq!(mgr.total_rounds(), 2);

        // The next start_round call sees rounds.len() (=2) > threshold (=1)
        // and invokes cleanup synchronously.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let pre = mgr.last_cleanup;
        mgr.start_round(RequestId::new(), test_operator_id(99), 2, 3, 30)
            .unwrap();
        assert!(mgr.last_cleanup > pre, "cleanup did not run");
        // The two old finished rounds were evicted; only the new one remains.
        assert_eq!(mgr.total_rounds(), 1);
    }

    /// (c) Old finished/expired round entries are evicted by cleanup_old_rounds
    /// and the per-operator counter is decremented accordingly.
    #[test]
    fn test_cleanup_evicts_old_rounds_and_decrements_counts() {
        let mut mgr = CoordinationManager::new();
        let coord = test_operator_id(1);

        let r1 = RequestId::new();
        let r2 = RequestId::new();
        mgr.start_round(r1.clone(), coord.clone(), 2, 3, 30).unwrap();
        mgr.start_round(r2.clone(), coord.clone(), 2, 3, 30).unwrap();
        assert_eq!(mgr.rounds_for(&coord), 2);

        // Backdate r1 and mark completed so it is eligible for eviction.
        {
            let r = mgr.get_round_mut(&r1).unwrap();
            r.started_at = Utc::now() - Duration::seconds(600);
            r.complete();
        }

        mgr.cleanup_old_rounds(60);

        assert!(mgr.get_round(&r1).is_none(), "old round was not evicted");
        assert!(mgr.get_round(&r2).is_some(), "fresh round was incorrectly evicted");
        assert_eq!(
            mgr.rounds_for(&coord),
            1,
            "per-operator counter was not decremented on eviction"
        );
    }

    /// Time-based cleanup trigger fires even when the map size is small.
    #[test]
    fn test_cleanup_triggered_by_time() {
        let mut mgr = CoordinationManager::new();
        mgr.cleanup_soft_threshold = 1024;
        mgr.cleanup_interval_secs = 0; // any elapsed time triggers cleanup

        std::thread::sleep(std::time::Duration::from_millis(5));
        let pre = mgr.last_cleanup;
        mgr.start_round(RequestId::new(), test_operator_id(1), 2, 3, 30)
            .unwrap();
        assert!(mgr.last_cleanup > pre);
    }
}
