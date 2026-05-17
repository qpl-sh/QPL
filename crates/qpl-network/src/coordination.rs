// SPDX-License-Identifier: MIT OR Apache-2.0

//! Coordination state machine for multi-operator operations.
//!
//! Manages the lifecycle of a coordination round: collecting partial responses
//! from multiple operators until a threshold is reached or timeout occurs.

use crate::errors::NetworkError;
use crate::types::*;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        if collected >= self.threshold {
            0
        } else {
            self.threshold - collected
        }
    }
}

/// Manages multiple active coordination rounds.
#[derive(Debug, Default)]
pub struct CoordinationManager {
    rounds: HashMap<RequestId, CoordinationRound>,
}

impl CoordinationManager {
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }

    /// Starts a new coordination round.
    pub fn start_round(
        &mut self,
        request_id: RequestId,
        coordinator_id: OperatorId,
        threshold: u8,
        total_invited: u8,
        timeout_secs: u64,
    ) -> &CoordinationRound {
        let round = CoordinationRound::new(
            request_id.clone(),
            coordinator_id,
            threshold,
            total_invited,
            timeout_secs,
        );
        self.rounds.insert(request_id.clone(), round);
        self.rounds.get(&request_id).unwrap()
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

    /// Removes completed/expired rounds older than the given age.
    pub fn cleanup_old_rounds(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now() - Duration::seconds(max_age_secs as i64);
        self.rounds.retain(|_, round| {
            round.started_at > cutoff
                || (round.status != RoundStatus::Completed && round.status != RoundStatus::TimedOut)
        });
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
        OperatorId::from_public_key(&vec![seed; 32])
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

        mgr.start_round(req_id.clone(), test_operator_id(0), 2, 3, 30);
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
}
