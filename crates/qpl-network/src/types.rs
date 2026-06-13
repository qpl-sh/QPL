// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core network types for the QPL operator network.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use uuid::Uuid;

/// Unique identifier for an operator node, derived from its ML-DSA public key.
///
/// `PartialOrd` / `Ord` are derived so that operator IDs can be compared
/// lexicographically — used as a deterministic tie-breaker in coordinator
/// selection (see [`crate::routing::RequestRouter::select_coordinator`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperatorId(pub [u8; 32]);

impl OperatorId {
    /// Derives an OperatorId from an ML-DSA public key by SHA-256 hashing.
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        OperatorId(id)
    }

    /// Returns the hex-encoded operator ID.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for OperatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.to_hex()[..16])
    }
}

/// Unique identifier for a service request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub fn new() -> Self {
        RequestId(Uuid::new_v4())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Types of services an operator can provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ServiceType {
    /// PQC-MPC threshold signing (ML-DSA)
    Signing = 1,
    /// STARK proof generation and verification
    Proving = 2,
    /// Programmable settlement workflows (escrow, DvP, PvP)
    Settlement = 3,
    /// Yield token accrual and distribution
    Yield = 4,
    /// Real-world asset tokenization and lifecycle
    Rwa = 5,
}

impl ServiceType {
    /// Returns all available service types.
    pub fn all() -> &'static [ServiceType] {
        &[
            ServiceType::Signing,
            ServiceType::Proving,
            ServiceType::Settlement,
            ServiceType::Yield,
            ServiceType::Rwa,
        ]
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceType::Signing => write!(f, "signing"),
            ServiceType::Proving => write!(f, "proving"),
            ServiceType::Settlement => write!(f, "settlement"),
            ServiceType::Yield => write!(f, "yield"),
            ServiceType::Rwa => write!(f, "rwa"),
        }
    }
}

/// Set of capabilities an operator advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCapabilities {
    pub services: HashSet<ServiceType>,
}

impl OperatorCapabilities {
    pub fn new(services: impl IntoIterator<Item = ServiceType>) -> Self {
        Self {
            services: services.into_iter().collect(),
        }
    }

    /// Returns true if this operator supports the given service.
    pub fn supports(&self, service: ServiceType) -> bool {
        self.services.contains(&service)
    }

    /// Returns a bitmask representation of capabilities.
    pub fn as_bitmask(&self) -> u32 {
        self.services
            .iter()
            .fold(0u32, |mask, s| mask | (1 << (*s as u8)))
    }

    /// Constructs capabilities from a bitmask.
    pub fn from_bitmask(mask: u32) -> Self {
        let mut services = HashSet::new();
        for s in ServiceType::all() {
            if mask & (1 << (*s as u8)) != 0 {
                services.insert(*s);
            }
        }
        Self { services }
    }
}

/// Status of an operator in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorStatus {
    /// Operator has staked but not yet completed handshake.
    Joining,
    /// Operator is active and serving requests.
    Active,
    /// Operator is completing in-flight requests before exit.
    Draining,
    /// Operator has been suspended (missed heartbeats or slashed).
    Suspended,
    /// Operator has fully exited the network.
    Exited,
}

/// On-chain staking information for an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    /// Amount staked (in lamports).
    pub amount: u128,
    /// Solana program ID of the QPL Staking program (32 bytes).
    pub program_id: [u8; 32],
    /// Timestamp when stake was deposited.
    pub staked_at: DateTime<Utc>,
    /// Transaction signature of the stake transaction (proof, 64 bytes).
    pub stake_tx_signature: Vec<u8>,
}

/// Urgency level for a service request — affects fee multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Urgency {
    /// Standard processing (1.0x fee).
    Standard,
    /// Fast processing (1.5x fee).
    Fast,
    /// Instant processing (2.0x fee).
    Instant,
}

impl Urgency {
    pub fn multiplier(&self) -> f64 {
        match self {
            Urgency::Standard => 1.0,
            Urgency::Fast => 1.5,
            Urgency::Instant => 2.0,
        }
    }

    /// Integer percentage multiplier for deterministic fee calculation.
    /// Standard = 100, Fast = 150, Instant = 200.
    pub fn multiplier_pct(&self) -> u64 {
        match self {
            Urgency::Standard => 100,
            Urgency::Fast => 150,
            Urgency::Instant => 200,
        }
    }
}

/// Network-wide configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Minimum stake required to join (in USDC base units, 6 decimals).
    pub min_stake: u128,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
    /// Number of missed heartbeats before auto-suspend.
    pub max_missed_heartbeats: u8,
    /// Unbonding period in seconds (default 7 days).
    pub unbond_period_secs: u64,
    /// Minimum operators required per service type.
    pub min_operators_per_service: u8,
    /// Fee quote expiry in seconds.
    pub fee_quote_expiry_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            min_stake: 10_000_000_000, // 10,000 USDC (6 decimals)
            heartbeat_interval_secs: 30,
            max_missed_heartbeats: 3,
            unbond_period_secs: 7 * 24 * 3600, // 7 days
            min_operators_per_service: 3,
            fee_quote_expiry_secs: 60,
        }
    }
}

/// Quorum configuration for threshold operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumRequirement {
    /// Minimum number of operators that must participate.
    pub threshold: u8,
    /// Total number of operators holding shards/state.
    pub total: u8,
}

impl Default for QuorumRequirement {
    fn default() -> Self {
        Self::three_of_five()
    }
}

impl QuorumRequirement {
    pub fn three_of_five() -> Self {
        Self {
            threshold: 3,
            total: 5,
        }
    }

    pub fn two_of_three() -> Self {
        Self {
            threshold: 2,
            total: 3,
        }
    }

    pub fn five_of_seven() -> Self {
        Self {
            threshold: 5,
            total: 7,
        }
    }
}

/// Proof that a fee has been paid on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeePaymentProof {
    /// Solana transaction signature (64 bytes).
    pub tx_signature: Vec<u8>,
    /// The fee quote ID this payment references.
    pub fee_quote_id: Uuid,
    /// Slot number where payment was confirmed.
    pub slot: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_id_from_public_key() {
        let key = vec![1u8; 1952]; // ML-DSA-65 public key size
        let id = OperatorId::from_public_key(&key);
        assert_eq!(id.0.len(), 32);

        // Same key produces same ID
        let id2 = OperatorId::from_public_key(&key);
        assert_eq!(id, id2);

        // Different key produces different ID
        let key2 = vec![2u8; 1952];
        let id3 = OperatorId::from_public_key(&key2);
        assert_ne!(id, id3);
    }

    #[test]
    fn test_capabilities_bitmask_roundtrip() {
        let caps = OperatorCapabilities::new([ServiceType::Signing, ServiceType::Proving]);
        let mask = caps.as_bitmask();
        let caps2 = OperatorCapabilities::from_bitmask(mask);
        assert_eq!(caps, caps2);
    }

    #[test]
    fn test_capabilities_supports() {
        let caps = OperatorCapabilities::new([ServiceType::Signing, ServiceType::Settlement]);
        assert!(caps.supports(ServiceType::Signing));
        assert!(caps.supports(ServiceType::Settlement));
        assert!(!caps.supports(ServiceType::Proving));
        assert!(!caps.supports(ServiceType::Yield));
    }

    #[test]
    fn test_quorum_presets() {
        let q = QuorumRequirement::three_of_five();
        assert_eq!(q.threshold, 3);
        assert_eq!(q.total, 5);
    }

    #[test]
    fn test_urgency_multiplier() {
        assert_eq!(Urgency::Standard.multiplier(), 1.0);
        assert_eq!(Urgency::Fast.multiplier(), 1.5);
        assert_eq!(Urgency::Instant.multiplier(), 2.0);
    }

    #[test]
    fn test_request_id_unique() {
        let id1 = RequestId::new();
        let id2 = RequestId::new();
        assert_ne!(id1, id2);
    }
}
