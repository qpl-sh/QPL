// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator registry and management.
//!
//! Tracks all known operators, their capabilities, status, and liveness.
//! Provides capability-based queries for routing decisions.

use crate::errors::NetworkError;
use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full operator record in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRecord {
    pub id: OperatorId,
    pub public_key: Vec<u8>,
    pub endpoint: String,
    pub capabilities: OperatorCapabilities,
    pub status: OperatorStatus,
    pub stake: StakeInfo,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub missed_heartbeats: u8,
    /// Current load factor (0.0 = idle, 1.0 = at capacity).
    pub load_factor: f32,
    /// Number of active in-flight requests.
    pub active_requests: u32,
}

/// In-memory operator registry.
#[derive(Debug, Default)]
pub struct OperatorRegistry {
    operators: HashMap<OperatorId, OperatorRecord>,
    config: NetworkConfig,
}

impl OperatorRegistry {
    pub fn new(config: NetworkConfig) -> Self {
        Self {
            operators: HashMap::new(),
            config,
        }
    }

    /// Registers a new operator. Returns error if already registered or stake insufficient.
    pub fn register(
        &mut self,
        id: OperatorId,
        public_key: Vec<u8>,
        endpoint: String,
        capabilities: OperatorCapabilities,
        stake: StakeInfo,
    ) -> Result<(), NetworkError> {
        if self.operators.contains_key(&id) {
            return Err(NetworkError::OperatorAlreadyRegistered(id));
        }

        if stake.amount < self.config.min_stake {
            return Err(NetworkError::InsufficientStake {
                min_required: self.config.min_stake,
                provided: stake.amount,
            });
        }

        let now = Utc::now();
        let record = OperatorRecord {
            id: id.clone(),
            public_key,
            endpoint,
            capabilities,
            status: OperatorStatus::Joining,
            stake,
            registered_at: now,
            last_heartbeat: now,
            missed_heartbeats: 0,
            load_factor: 0.0,
            active_requests: 0,
        };

        self.operators.insert(id, record);
        Ok(())
    }

    /// Activates a joining operator after successful handshake.
    pub fn activate(&mut self, id: &OperatorId) -> Result<(), NetworkError> {
        let record = self
            .operators
            .get_mut(id)
            .ok_or_else(|| NetworkError::OperatorNotFound(id.clone()))?;

        if record.status != OperatorStatus::Joining {
            return Err(NetworkError::InvalidStatusTransition {
                from: record.status,
                to: OperatorStatus::Active,
            });
        }

        record.status = OperatorStatus::Active;
        Ok(())
    }

    /// Records a heartbeat from an operator.
    pub fn record_heartbeat(
        &mut self,
        id: &OperatorId,
        load_factor: f32,
        active_requests: u32,
    ) -> Result<(), NetworkError> {
        let record = self
            .operators
            .get_mut(id)
            .ok_or_else(|| NetworkError::OperatorNotFound(id.clone()))?;

        record.last_heartbeat = Utc::now();
        record.missed_heartbeats = 0;
        record.load_factor = load_factor;
        record.active_requests = active_requests;
        Ok(())
    }

    /// Marks an operator as having missed a heartbeat. Suspends after threshold.
    pub fn record_missed_heartbeat(&mut self, id: &OperatorId) -> Result<(), NetworkError> {
        let max_missed = self.config.max_missed_heartbeats;
        let record = self
            .operators
            .get_mut(id)
            .ok_or_else(|| NetworkError::OperatorNotFound(id.clone()))?;

        record.missed_heartbeats += 1;
        if record.missed_heartbeats >= max_missed && record.status == OperatorStatus::Active {
            record.status = OperatorStatus::Suspended;
        }
        Ok(())
    }

    /// Begins draining an operator (preparing for exit).
    pub fn begin_drain(&mut self, id: &OperatorId) -> Result<(), NetworkError> {
        let record = self
            .operators
            .get_mut(id)
            .ok_or_else(|| NetworkError::OperatorNotFound(id.clone()))?;

        if record.status != OperatorStatus::Active {
            return Err(NetworkError::InvalidStatusTransition {
                from: record.status,
                to: OperatorStatus::Draining,
            });
        }

        record.status = OperatorStatus::Draining;
        Ok(())
    }

    /// Returns all active operators that support a given service.
    pub fn operators_for_service(&self, service: ServiceType) -> Vec<&OperatorRecord> {
        self.operators
            .values()
            .filter(|op| op.status == OperatorStatus::Active && op.capabilities.supports(service))
            .collect()
    }

    /// Returns the number of active operators for a service.
    pub fn active_count_for_service(&self, service: ServiceType) -> usize {
        self.operators_for_service(service).len()
    }

    /// Returns an operator record by ID.
    pub fn get(&self, id: &OperatorId) -> Option<&OperatorRecord> {
        self.operators.get(id)
    }

    /// Returns all registered operators.
    pub fn all_operators(&self) -> Vec<&OperatorRecord> {
        self.operators.values().collect()
    }

    /// Returns count of all operators.
    pub fn total_count(&self) -> usize {
        self.operators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_stake() -> StakeInfo {
        StakeInfo {
            amount: 10_000_000_000, // ~10 SOL in lamports
            program_id: [0u8; 32],
            staked_at: Utc::now(),
            stake_tx_signature: vec![0u8; 64],
        }
    }

    fn test_operator_id(seed: u8) -> OperatorId {
        OperatorId::from_public_key(&vec![seed; 1952])
    }

    #[test]
    fn test_register_and_activate() {
        let mut registry = OperatorRegistry::new(NetworkConfig::default());
        let id = test_operator_id(1);

        registry
            .register(
                id.clone(),
                vec![1u8; 1952],
                "localhost:9000".to_string(),
                OperatorCapabilities::new([ServiceType::Signing, ServiceType::Proving]),
                test_stake(),
            )
            .unwrap();

        assert_eq!(registry.get(&id).unwrap().status, OperatorStatus::Joining);

        registry.activate(&id).unwrap();
        assert_eq!(registry.get(&id).unwrap().status, OperatorStatus::Active);
    }

    #[test]
    fn test_insufficient_stake_rejected() {
        let mut registry = OperatorRegistry::new(NetworkConfig::default());
        let id = test_operator_id(1);

        let low_stake = StakeInfo {
            amount: 100, // Way below minimum
            ..test_stake()
        };

        let result = registry.register(
            id,
            vec![1u8; 1952],
            "localhost:9000".to_string(),
            OperatorCapabilities::new([ServiceType::Signing]),
            low_stake,
        );

        assert!(matches!(result, Err(NetworkError::InsufficientStake { .. })));
    }

    #[test]
    fn test_operators_for_service() {
        let mut registry = OperatorRegistry::new(NetworkConfig::default());

        // Register 3 operators with different capabilities
        for i in 1..=3 {
            let id = test_operator_id(i);
            let services = match i {
                1 => vec![ServiceType::Signing, ServiceType::Proving],
                2 => vec![ServiceType::Signing, ServiceType::Settlement],
                3 => vec![ServiceType::Proving, ServiceType::Yield],
                _ => unreachable!(),
            };
            registry
                .register(
                    id.clone(),
                    vec![i; 1952],
                    format!("localhost:900{}", i),
                    OperatorCapabilities::new(services),
                    test_stake(),
                )
                .unwrap();
            registry.activate(&id).unwrap();
        }

        assert_eq!(registry.operators_for_service(ServiceType::Signing).len(), 2);
        assert_eq!(registry.operators_for_service(ServiceType::Proving).len(), 2);
        assert_eq!(registry.operators_for_service(ServiceType::Settlement).len(), 1);
        assert_eq!(registry.operators_for_service(ServiceType::Yield).len(), 1);
        assert_eq!(registry.operators_for_service(ServiceType::Rwa).len(), 0);
    }

    #[test]
    fn test_heartbeat_suspension() {
        let mut registry = OperatorRegistry::new(NetworkConfig::default());
        let id = test_operator_id(1);

        registry
            .register(
                id.clone(),
                vec![1u8; 1952],
                "localhost:9000".to_string(),
                OperatorCapabilities::new([ServiceType::Signing]),
                test_stake(),
            )
            .unwrap();
        registry.activate(&id).unwrap();

        // Miss 3 heartbeats → suspended
        registry.record_missed_heartbeat(&id).unwrap();
        registry.record_missed_heartbeat(&id).unwrap();
        assert_eq!(registry.get(&id).unwrap().status, OperatorStatus::Active);

        registry.record_missed_heartbeat(&id).unwrap();
        assert_eq!(registry.get(&id).unwrap().status, OperatorStatus::Suspended);
    }
}
