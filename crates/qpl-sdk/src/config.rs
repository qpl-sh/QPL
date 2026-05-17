// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK configuration.

use std::time::Duration;

/// Configuration for the QPL SDK client.
#[derive(Debug, Clone)]
pub struct SdkConfig {
    /// Bootstrap node endpoints to connect to.
    pub bootstrap_nodes: Vec<String>,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Maximum retries per request.
    pub max_retries: u32,
    /// Maximum fee willing to pay per operation (USD micro-units).
    pub max_fee_micro_usd: u64,
    /// Chain ID for fee payments.
    pub fee_chain_id: u64,
    /// RPC endpoint for fee payment chain.
    pub fee_chain_rpc: String,
}

impl SdkConfig {
    /// Configuration for local testnet (Docker compose).
    pub fn testnet() -> Self {
        Self {
            bootstrap_nodes: vec![
                "http://localhost:9000".to_string(),
                "http://localhost:9010".to_string(),
                "http://localhost:9020".to_string(),
            ],
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            max_fee_micro_usd: 1_000_000, // $1 max per operation
            fee_chain_id: 31337,           // Anvil default
            fee_chain_rpc: "http://localhost:8545".to_string(),
        }
    }

    /// Configuration for mainnet.
    pub fn mainnet(bootstrap_nodes: Vec<String>, fee_chain_rpc: String) -> Self {
        Self {
            bootstrap_nodes,
            request_timeout: Duration::from_secs(60),
            max_retries: 5,
            max_fee_micro_usd: 500_000, // $0.50 max per operation
            fee_chain_id: 1,            // Ethereum mainnet
            fee_chain_rpc,
        }
    }
}
