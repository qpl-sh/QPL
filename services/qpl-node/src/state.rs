// SPDX-License-Identifier: MIT OR Apache-2.0

//! Node state — shared mutable state for the operator node.

use crate::config::NodeConfig;
use crate::identity::OperatorIdentity;
use qpl_network::coordination::CoordinationManager;
use qpl_network::fees::FeeCalculator;
use qpl_network::operator::OperatorRegistry;
use qpl_network::NetworkConfig;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared node state accessible from all service handlers.
#[derive(Clone)]
pub struct NodeState {
    pub identity: OperatorIdentity,
    pub config: NodeConfig,
    pub registry: Arc<RwLock<OperatorRegistry>>,
    pub coordinator: Arc<RwLock<CoordinationManager>>,
    pub fee_calculator: Arc<FeeCalculator>,
    pub metrics: Arc<Metrics>,
}

/// Simple in-memory metrics counters.
pub struct Metrics {
    pub requests_total: std::sync::atomic::AtomicU64,
    pub requests_success: std::sync::atomic::AtomicU64,
    pub requests_failed: std::sync::atomic::AtomicU64,
    pub active_rounds: std::sync::atomic::AtomicU64,
    pub fees_collected_micro_usd: std::sync::atomic::AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: std::sync::atomic::AtomicU64::new(0),
            requests_success: std::sync::atomic::AtomicU64::new(0),
            requests_failed: std::sync::atomic::AtomicU64::new(0),
            active_rounds: std::sync::atomic::AtomicU64::new(0),
            fees_collected_micro_usd: std::sync::atomic::AtomicU64::new(0),
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
}

impl NodeState {
    pub fn new(identity: OperatorIdentity, config: NodeConfig) -> Self {
        Self {
            identity,
            config,
            registry: Arc::new(RwLock::new(OperatorRegistry::new(NetworkConfig::default()))),
            coordinator: Arc::new(RwLock::new(CoordinationManager::new())),
            fee_calculator: Arc::new(FeeCalculator::default()),
            metrics: Arc::new(Metrics::new()),
        }
    }
}
