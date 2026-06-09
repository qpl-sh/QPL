// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node state — shared mutable state for the operator node.

use crate::config::NodeConfig;
use crate::identity::OperatorIdentity;
use crate::rate_limit::RateLimiter;
use qpl_network::coordination::CoordinationManager;
use qpl_network::fees::FeeCalculator;
use qpl_network::operator::OperatorRegistry;
use qpl_network::NetworkConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Subset of state needed for authentication checks. Cloned cheaply
/// (`Arc` internally) and shared into [`crate::auth::verify_auth`] so
/// that auth has no transitive dependency on tokio runtime types.
#[derive(Clone, Debug)]
pub struct AuthState {
    authorized_operators: Arc<HashMap<String, String>>,
}

impl AuthState {
    pub fn new(authorized_operators: HashMap<String, String>) -> Self {
        Self {
            authorized_operators: Arc::new(authorized_operators),
        }
    }

    /// Look up the hex-encoded ML-DSA-65 public key for an operator,
    /// or `None` if the operator is not in the static authorization
    /// table.
    ///
    /// TODO(QPL-AUTH-2): also consult the on-chain QPL Registry program
    /// before failing — this hook will become an `async` lookup once
    /// the Solana RPC client is wired in.
    pub fn authorized_pubkey_hex(&self, operator_id: &str) -> Option<String> {
        self.authorized_operators.get(operator_id).cloned()
    }

    #[cfg(test)]
    pub fn test_with_operator(operator_id: &str, pubkey: &[u8]) -> Self {
        let mut m = HashMap::new();
        m.insert(operator_id.to_string(), hex::encode(pubkey));
        Self::new(m)
    }
}

/// Shared node state accessible from all service handlers.
#[derive(Clone)]
#[allow(dead_code)]
pub struct NodeState {
    pub identity: OperatorIdentity,
    pub config: NodeConfig,
    pub registry: Arc<RwLock<OperatorRegistry>>,
    pub coordinator: Arc<RwLock<CoordinationManager>>,
    pub fee_calculator: Arc<FeeCalculator>,
    pub metrics: Arc<Metrics>,
    /// Per-operator token-bucket rate limiter (D-3).
    pub rate_limiter: RateLimiter,
    /// Authorization state used by the per-request auth check (D-2).
    pub auth: AuthState,
}

/// Simple in-memory metrics counters.
#[allow(dead_code)]
pub struct Metrics {
    pub requests_total: std::sync::atomic::AtomicU64,
    pub requests_success: std::sync::atomic::AtomicU64,
    pub requests_failed: std::sync::atomic::AtomicU64,
    pub active_rounds: std::sync::atomic::AtomicU64,
    pub fees_collected_micro_usd: std::sync::atomic::AtomicU64,
    /// Number of requests that were rejected by the rate limiter.
    pub rate_limited_total: std::sync::atomic::AtomicU64,
    /// Number of requests that failed the auth envelope check.
    pub auth_failures_total: std::sync::atomic::AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: std::sync::atomic::AtomicU64::new(0),
            requests_success: std::sync::atomic::AtomicU64::new(0),
            requests_failed: std::sync::atomic::AtomicU64::new(0),
            active_rounds: std::sync::atomic::AtomicU64::new(0),
            fees_collected_micro_usd: std::sync::atomic::AtomicU64::new(0),
            rate_limited_total: std::sync::atomic::AtomicU64::new(0),
            auth_failures_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_request(&self) {
        self.requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.requests_success
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.requests_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_fee(&self, micro_usd: u64) {
        self.fees_collected_micro_usd
            .fetch_add(micro_usd, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self) {
        self.auth_failures_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl NodeState {
    pub fn new(identity: OperatorIdentity, config: NodeConfig) -> Self {
        let rate_limiter = RateLimiter::new(
            config.rate_limit.refill_per_sec,
            config.rate_limit.burst_capacity,
        );
        let auth = AuthState::new(config.authorized_operators.clone());
        Self {
            identity,
            config,
            registry: Arc::new(RwLock::new(OperatorRegistry::new(NetworkConfig::default()))),
            coordinator: Arc::new(RwLock::new(CoordinationManager::new())),
            fee_calculator: Arc::new(FeeCalculator::default()),
            metrics: Arc::new(Metrics::new()),
            rate_limiter,
            auth,
        }
    }
}
