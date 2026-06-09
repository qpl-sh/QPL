// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node configuration — loaded from TOML file.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Full node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Human-readable node name.
    pub name: String,
    /// JSON-RPC listen address (e.g., "0.0.0.0:9000").
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
    /// TLS configuration (D-1 CRITICAL remediation).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Per-operator rate-limit configuration (D-3 HIGH remediation).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Pre-authorized operators that may issue authenticated requests
    /// (D-2 HIGH remediation).
    ///
    /// Map of `operator_id` (hex SHA-256 of ML-DSA-65 public key) →
    /// hex-encoded ML-DSA-65 public key bytes.
    ///
    /// TODO(QPL-AUTH-2): replace with on-chain registry lookup against
    /// the QPL Registry program once the Solana RPC client is wired up.
    #[serde(default)]
    pub authorized_operators: HashMap<String, String>,
}

/// Which services this operator is willing to perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesConfig {
    pub signing: bool,
    pub proving: bool,
}

/// Fee-related settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    /// Minimum fee this operator will accept (USD micro-units).
    pub min_fee_micro_usd: u64,
    /// Fee multiplier for urgency.
    pub urgency_multiplier: f64,
}

/// Solana on-chain configuration for fee verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Solana cluster RPC endpoint.
    pub rpc_url: String,
    /// QPL Fee Router program ID (base58).
    pub fee_router_program_id: String,
    /// QPL Staking program ID (base58).
    pub staking_program_id: String,
    /// QPL Registry program ID (base58).
    pub registry_program_id: String,
}

/// TLS / mTLS configuration.
///
/// When `enabled` is `true` (the default) the server performs a rustls
/// handshake on every accepted TCP stream. When `client_ca_path` is set,
/// the server additionally requires client certificates signed by that
/// CA bundle (mTLS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether TLS is required. Defaults to `true`.
    /// Setting this to `false` enables a plaintext fallback for local
    /// development; the server logs a prominent WARN at startup in that
    /// case. NEVER use `enabled = false` in production.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to PEM-encoded server certificate chain.
    #[serde(default)]
    pub cert_path: PathBuf,
    /// Path to PEM-encoded server private key (PKCS#8 or RSA).
    #[serde(default)]
    pub key_path: PathBuf,
    /// Optional PEM-encoded client CA bundle. When `Some`, mTLS is
    /// enforced — clients must present a certificate signed by this CA.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: PathBuf::from("/qpl/tls/server.crt"),
            key_path: PathBuf::from("/qpl/tls/server.key"),
            client_ca_path: None,
        }
    }
}

/// Per-operator token-bucket rate-limit settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Tokens added per second (steady-state allowed RPS).
    pub refill_per_sec: u32,
    /// Maximum bucket size (peak burst tolerance).
    pub burst_capacity: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            refill_per_sec: 100,
            burst_capacity: 500,
        }
    }
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
    #[allow(dead_code)]
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
            },
            fees: FeeConfig {
                min_fee_micro_usd: 500,
                urgency_multiplier: 1.5,
            },
            chain: ChainConfig {
                rpc_url: "http://localhost:8899".to_string(),
                fee_router_program_id: "11111111111111111111111111111111".to_string(),
                staking_program_id: "11111111111111111111111111111111".to_string(),
                registry_program_id: "11111111111111111111111111111111".to_string(),
            },
            tls: TlsConfig::default(),
            rate_limit: RateLimitConfig::default(),
            authorized_operators: HashMap::new(),
        }
    }
}
