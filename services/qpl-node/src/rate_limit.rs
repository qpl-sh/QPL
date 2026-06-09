// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-operator token-bucket rate limiter (D-3 HIGH remediation).
//!
//! Each authenticated operator gets an in-process [`TokenBucket`] keyed
//! by `operator_id`. A bucket starts full at `burst_capacity` and
//! refills at `refill_per_sec` tokens per second up to capacity. Each
//! authenticated request consumes one token; if no token is available,
//! the request is rejected with [`crate::errors::ErrorCode::RateLimitExceeded`].
//!
//! The map of buckets uses [`dashmap::DashMap`] for lock-free per-key
//! access on the hot path. Buckets are created lazily on first contact
//! and never evicted (operator population is bounded by the staking
//! registry; if that grows large, add a TTL-based eviction sweep).

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

/// Configuration snapshot for a bucket.
#[derive(Debug, Clone, Copy)]
pub struct BucketParams {
    pub refill_per_sec: f64,
    pub burst_capacity: f64,
}

/// A single operator's token bucket.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    params: BucketParams,
}

impl TokenBucket {
    pub fn new(params: BucketParams) -> Self {
        Self {
            tokens: params.burst_capacity,
            last_refill: Instant::now(),
            params,
        }
    }

    /// Refill the bucket up to capacity based on time elapsed since
    /// the last refill, then attempt to deduct one token.
    pub fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.params.refill_per_sec)
            .min(self.params.burst_capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn remaining(&self) -> f64 {
        self.tokens
    }
}

/// Thread-safe map of `operator_id → TokenBucket`.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    buckets: Arc<DashMap<String, TokenBucket>>,
    params: BucketParams,
}

impl RateLimiter {
    pub fn new(refill_per_sec: u32, burst_capacity: u32) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            params: BucketParams {
                refill_per_sec: refill_per_sec as f64,
                burst_capacity: burst_capacity as f64,
            },
        }
    }

    /// Attempt to consume one token from the bucket for `operator_id`.
    /// Creates the bucket lazily on first contact.
    pub fn check(&self, operator_id: &str) -> bool {
        let now = Instant::now();
        let mut entry = self
            .buckets
            .entry(operator_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.params));
        entry.try_consume(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn burst_then_reject() {
        let rl = RateLimiter::new(10, 3);
        assert!(rl.check("op-A"));
        assert!(rl.check("op-A"));
        assert!(rl.check("op-A"));
        // 4th call within the same instant must be rejected.
        assert!(!rl.check("op-A"));
    }

    #[test]
    fn refill_after_wait() {
        let rl = RateLimiter::new(100, 1); // 100 tokens/s, burst 1
        assert!(rl.check("op-B"));
        assert!(!rl.check("op-B"));
        sleep(Duration::from_millis(50));
        // After 50ms at 100/s we should have ~5 tokens, capped at 1.
        assert!(rl.check("op-B"));
    }

    #[test]
    fn buckets_are_per_operator() {
        let rl = RateLimiter::new(1, 1);
        assert!(rl.check("op-X"));
        assert!(rl.check("op-Y"));
        assert!(!rl.check("op-X"));
        assert!(!rl.check("op-Y"));
    }
}
