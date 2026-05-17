// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node configuration — loaded from TOML file.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Full node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Human-readable node name.
    pub name: String,
    /// gRPC listen address (e.g., "0.0.0.0:9000").
    pub listen_addr: String,
    /// Path to operator identity (keypair) file.
    pub identity_path: String,
    /// Bootstrap peer addresses for discovery.
    pub bootstrap_peers: Vec<String>,
    /// Services this operator provides.
    pub services: ServicesConfig,
    /// Fee configuration.
    pub fees: FeeConfig,
    /// Chain configuration for fee collection.
    pub chain: ChainConfig,
}

/// Which services this operator is willing to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesConfig {
    pub signing: bool,
    pub proving: bool,
    pub settlement: bool,
    pub yield_ops: bool,
    pub rwa: bool,
}

/// Fee-related settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Minimum fee this operator will accept (USD micro-units).
    pub min_fee_micro_usd: u64,
    /// Fee multiplier for urgency.
    pub urgency_multiplier: f64,
}

/// On-chain configuration for fee verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain ID where fees are collected.
    pub chain_id: u64,
    /// RPC endpoint for fee verification.
    pub rpc_url: String,
    /// QPL Fee Router contract address.
    pub fee_router_address: String,
    /// QPL Staking contract address.
    pub staking_address: String,
}

impl NodeConfig {
    /// Load config from a TOML file, or return defaults if not found.
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if Path::new(path).exists() {
            let contents = std::fs::read_to_string(path)?;
            let config: Self = toml::from_str(&contents)?;
            Ok(config)
        } else {
            tracing::warn!("Config file '{}' not found, using defaults", path);
            Ok(Self::default())
        }
    }

    /// Generate a default config file and write to disk.
    pub fn write_default(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config = Self::default();
        let toml_str = toml::to_string_pretty(&config)?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: "qpl-operator-1".to_string(),
            listen_addr: "0.0.0.0:9000".to_string(),
            identity_path: "./operator-identity.json".to_string(),
            bootstrap_peers: vec![
                "http://localhost:9010".to_string(),
                "http://localhost:9020".to_string(),
            ],
            services: ServicesConfig {
                signing: true,
                proving: true,
                settlement: true,
                yield_ops: true,
                rwa: true,
            },
            fees: FeeConfig {
                min_fee_micro_usd: 500,
                urgency_multiplier: 1.5,
            },
            chain: ChainConfig {
                chain_id: 31337,
                rpc_url: "http://localhost:8545".to_string(),
                fee_router_address: "0x0000000000000000000000000000000000000000".to_string(),
                staking_address: "0x0000000000000000000000000000000000000000".to_string(),
            },
        }
    }
}
