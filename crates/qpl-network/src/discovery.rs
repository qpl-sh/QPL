// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer discovery and bootstrap configuration.
//!
//! Defines how operators find each other and join the network.

use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Information about a known peer in the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Operator identity.
    pub operator_id: OperatorId,
    /// ML-DSA public key for verifying messages from this peer.
    pub public_key: Vec<u8>,
    /// gRPC endpoint (host:port).
    pub endpoint: String,
    /// Capabilities this peer advertises.
    pub capabilities: OperatorCapabilities,
    /// When we last heard from this peer.
    pub last_seen: DateTime<Utc>,
    /// Whether this peer is currently reachable.
    pub reachable: bool,
}

/// Bootstrap configuration for joining the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Initial peers to connect to when joining the network.
    /// At least one must be reachable for initial discovery.
    pub bootstrap_peers: Vec<String>,
    /// On-chain registry contract address to discover operators.
    pub registry_contract: Option<RegistryContract>,
    /// Maximum number of peers to maintain connections to.
    pub max_peers: usize,
    /// Minimum number of connected peers to consider the node healthy.
    pub min_peers: usize,
}

/// On-chain registry reference for operator discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryContract {
    /// Chain ID where the registry lives.
    pub chain_id: u64,
    /// Contract address.
    pub address: [u8; 20],
    /// RPC endpoint for reading state.
    pub rpc_url: String,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            bootstrap_peers: Vec::new(),
            registry_contract: None,
            max_peers: 50,
            min_peers: 3,
        }
    }
}

/// Announcement message broadcast when an operator joins or updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorAnnouncement {
    /// The announcing operator.
    pub operator_id: OperatorId,
    /// Their public key for verification.
    pub public_key: Vec<u8>,
    /// Their gRPC endpoint.
    pub endpoint: String,
    /// Capabilities offered.
    pub capabilities: OperatorCapabilities,
    /// Proof of stake (tx hash).
    pub stake_proof: [u8; 32],
    /// Protocol version.
    pub version: String,
    /// Timestamp of announcement.
    pub timestamp: DateTime<Utc>,
    /// ML-DSA signature over the announcement payload.
    pub signature: Vec<u8>,
}

/// Heartbeat message sent periodically to peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub operator_id: OperatorId,
    pub timestamp: DateTime<Utc>,
    /// Current load (0.0 to 1.0).
    pub load_factor: f32,
    /// Number of active requests being processed.
    pub active_requests: u32,
    /// Sequence number for ordering.
    pub sequence: u64,
}

/// Response to a heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAck {
    pub operator_id: OperatorId,
    pub timestamp: DateTime<Utc>,
    pub sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config_defaults() {
        let config = BootstrapConfig::default();
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.min_peers, 3);
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn test_peer_info_creation() {
        let peer = PeerInfo {
            operator_id: OperatorId::from_public_key(&[1u8; 32]),
            public_key: vec![1u8; 1952],
            endpoint: "localhost:9000".to_string(),
            capabilities: OperatorCapabilities::new([ServiceType::Signing]),
            last_seen: Utc::now(),
            reachable: true,
        };
        assert!(peer.reachable);
        assert!(peer.capabilities.supports(ServiceType::Signing));
    }
}
