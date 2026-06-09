// SPDX-License-Identifier: MIT OR Apache-2.0

//! Request routing — selects operators for service requests.
//!
//! Uses consistent hashing for coordinator selection and load-aware scoring
//! for optimal operator assignment. Assembles quorum groups for threshold
//! operations (signing, proving verification).

use crate::errors::NetworkError;
use crate::operator::OperatorRecord;
use crate::types::*;
use sha2::{Digest, Sha256};

/// Routes requests to appropriate operators in the network.
pub struct RequestRouter;

impl RequestRouter {
    /// Selects a coordinator for a request using consistent hashing.
    ///
    /// The coordinator is the active operator whose ID hash is closest
    /// to the request ID hash. If that operator is unavailable, the next
    /// in the ring is selected.
    pub fn select_coordinator<'a>(
        request_id: &RequestId,
        operators: &'a [&'a OperatorRecord],
    ) -> Result<&'a OperatorRecord, NetworkError> {
        if operators.is_empty() {
            return Err(NetworkError::InsufficientOperators {
                service: ServiceType::Signing,
                needed: 1,
                available: 0,
            });
        }

        let request_hash = Self::hash_for_ring(request_id.0.as_bytes());

        // Find the operator whose hash is closest (consistent hashing). On a
        // distance tie, pick the lexicographically-smallest operator id so
        // the result is deterministic across all honest replicas (F-2).
        let mut best: Option<&OperatorRecord> = None;
        let mut best_distance = u64::MAX;

        for op in operators {
            let op_hash = Self::hash_for_ring(&op.id.0);
            let distance = Self::ring_distance(request_hash, op_hash);
            if Self::is_better_candidate(best, best_distance, op, distance) {
                best_distance = distance;
                best = Some(op);
            }
        }

        best.ok_or(NetworkError::InsufficientOperators {
            service: ServiceType::Signing,
            needed: 1,
            available: 0,
        })
    }

    /// Returns `true` if `(candidate, candidate_distance)` should replace the
    /// current best `(current, current_distance)` in coordinator selection.
    ///
    /// Tie-break rule: when distances are equal, the operator with the
    /// lexicographically-smaller `OperatorId` wins. This makes selection
    /// deterministic across honest nodes regardless of iteration order.
    fn is_better_candidate(
        current: Option<&OperatorRecord>,
        current_distance: u64,
        candidate: &OperatorRecord,
        candidate_distance: u64,
    ) -> bool {
        match current {
            None => true,
            Some(curr) => {
                candidate_distance < current_distance
                    || (candidate_distance == current_distance && candidate.id < curr.id)
            }
        }
    }

    /// Selects a quorum of operators for a threshold operation.
    ///
    /// Picks operators sorted by: (1) lowest load factor, (2) fewest active
    /// requests. Ensures all selected operators support the required service.
    pub fn select_quorum<'a>(
        service: ServiceType,
        quorum: &QuorumRequirement,
        operators: &'a [&'a OperatorRecord],
    ) -> Result<Vec<&'a OperatorRecord>, NetworkError> {
        let mut eligible: Vec<&OperatorRecord> = operators
            .iter()
            .filter(|op| op.capabilities.supports(service) && op.status == OperatorStatus::Active)
            .copied()
            .collect();

        if eligible.len() < quorum.threshold as usize {
            return Err(NetworkError::InsufficientOperators {
                service,
                needed: quorum.threshold,
                available: eligible.len() as u8,
            });
        }

        // Sort by load (ascending) — prefer less-loaded operators
        eligible.sort_by(|a, b| {
            a.load_factor
                .partial_cmp(&b.load_factor)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.active_requests.cmp(&b.active_requests))
        });

        Ok(eligible.into_iter().take(quorum.threshold as usize).collect())
    }

    /// Selects a single operator for non-threshold operations.
    /// Picks the least-loaded active operator with the required capability.
    pub fn select_single<'a>(
        service: ServiceType,
        operators: &'a [&'a OperatorRecord],
    ) -> Result<&'a OperatorRecord, NetworkError> {
        operators
            .iter()
            .filter(|op| op.capabilities.supports(service) && op.status == OperatorStatus::Active)
            .min_by(|a, b| {
                a.load_factor
                    .partial_cmp(&b.load_factor)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()
            .ok_or(NetworkError::InsufficientOperators {
                service,
                needed: 1,
                available: 0,
            })
    }

    /// Produces a u64 hash for consistent hash ring placement.
    fn hash_for_ring(data: &[u8]) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        u64::from_le_bytes(hash[..8].try_into().unwrap())
    }

    /// Calculates distance on a ring (wrapping).
    fn ring_distance(a: u64, b: u64) -> u64 {
        if b >= a {
            b - a
        } else {
            (u64::MAX - a) + b + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::OperatorRecord;
    use chrono::Utc;

    fn make_operator(seed: u8, services: Vec<ServiceType>, load: f32) -> OperatorRecord {
        OperatorRecord {
            id: OperatorId::from_public_key(&vec![seed; 1952]),
            public_key: vec![seed; 1952],
            endpoint: format!("localhost:900{}", seed),
            capabilities: OperatorCapabilities::new(services),
            status: OperatorStatus::Active,
            stake: StakeInfo {
                amount: 10_000_000_000,
                program_id: [0u8; 32],
                staked_at: Utc::now(),
                stake_tx_signature: vec![0u8; 64],
            },
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            missed_heartbeats: 0,
            load_factor: load,
            active_requests: 0,
        }
    }

    #[test]
    fn test_select_coordinator_deterministic() {
        let op1 = make_operator(1, vec![ServiceType::Signing], 0.0);
        let op2 = make_operator(2, vec![ServiceType::Signing], 0.0);
        let op3 = make_operator(3, vec![ServiceType::Signing], 0.0);
        let operators: Vec<&OperatorRecord> = vec![&op1, &op2, &op3];

        let request_id = RequestId::new();

        // Same request_id always picks the same coordinator
        let coord1 = RequestRouter::select_coordinator(&request_id, &operators).unwrap();
        let coord2 = RequestRouter::select_coordinator(&request_id, &operators).unwrap();
        assert_eq!(coord1.id, coord2.id);
    }

    #[test]
    fn test_select_quorum_prefers_low_load() {
        let op1 = make_operator(1, vec![ServiceType::Signing], 0.9);
        let op2 = make_operator(2, vec![ServiceType::Signing], 0.1);
        let op3 = make_operator(3, vec![ServiceType::Signing], 0.5);
        let operators: Vec<&OperatorRecord> = vec![&op1, &op2, &op3];

        let quorum = QuorumRequirement { threshold: 2, total: 3 };
        let selected =
            RequestRouter::select_quorum(ServiceType::Signing, &quorum, &operators).unwrap();

        assert_eq!(selected.len(), 2);
        // Should pick the two least-loaded: op2 (0.1) and op3 (0.5)
        assert_eq!(selected[0].id, op2.id);
        assert_eq!(selected[1].id, op3.id);
    }

    #[test]
    fn test_select_quorum_insufficient_operators() {
        let op1 = make_operator(1, vec![ServiceType::Signing], 0.0);
        let operators: Vec<&OperatorRecord> = vec![&op1];

        let quorum = QuorumRequirement { threshold: 3, total: 5 };
        let result = RequestRouter::select_quorum(ServiceType::Signing, &quorum, &operators);

        assert!(matches!(result, Err(NetworkError::InsufficientOperators { .. })));
    }

    #[test]
    fn test_select_single_least_loaded() {
        let op1 = make_operator(1, vec![ServiceType::Proving], 0.8);
        let op2 = make_operator(2, vec![ServiceType::Proving], 0.2);
        let operators: Vec<&OperatorRecord> = vec![&op1, &op2];

        let selected = RequestRouter::select_single(ServiceType::Proving, &operators).unwrap();
        assert_eq!(selected.id, op2.id);
    }

    /// F-2 regression: when two operators share an identical ring distance,
    /// `select_coordinator` must deterministically prefer the
    /// lexicographically-smaller operator id, regardless of input ordering.
    /// We exercise the tie-break logic directly via `is_better_candidate`
    /// (engineering a SHA-256 collision is infeasible) and assert it picks
    /// the smaller id on ties and is order-independent.
    #[test]
    fn test_select_coordinator_deterministic_tie_break() {
        // Two operators with engineered equal distances: we feed identical
        // distances into the tie-break helper and check it always picks the
        // smaller id no matter the call order.
        let mut low = make_operator(1, vec![ServiceType::Signing], 0.0);
        let mut high = make_operator(2, vec![ServiceType::Signing], 0.0);
        // Force ids to known relative ordering: low.id < high.id.
        low.id = OperatorId([0x01; 32]);
        high.id = OperatorId([0x02; 32]);
        assert!(low.id < high.id);

        let same_distance = 42u64;

        // Order A: high first, then low — low must win.
        let mut best: Option<&OperatorRecord> = None;
        let mut best_d = u64::MAX;
        for (op, d) in [(&high, same_distance), (&low, same_distance)] {
            if RequestRouter::is_better_candidate(best, best_d, op, d) {
                best = Some(op);
                best_d = d;
            }
        }
        assert_eq!(best.unwrap().id, low.id);

        // Order B: low first, then high — low must still win.
        let mut best: Option<&OperatorRecord> = None;
        let mut best_d = u64::MAX;
        for (op, d) in [(&low, same_distance), (&high, same_distance)] {
            if RequestRouter::is_better_candidate(best, best_d, op, d) {
                best = Some(op);
                best_d = d;
            }
        }
        assert_eq!(best.unwrap().id, low.id);

        // Strictly smaller distance still beats id ordering.
        assert!(RequestRouter::is_better_candidate(
            Some(&low),
            same_distance,
            &high,
            same_distance - 1,
        ));
        // Strictly larger distance never wins, even with smaller id.
        assert!(!RequestRouter::is_better_candidate(
            Some(&high),
            same_distance,
            &low,
            same_distance + 1,
        ));
    }
}
