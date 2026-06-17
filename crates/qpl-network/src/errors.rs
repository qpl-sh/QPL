// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network error types.

use crate::types::{OperatorId, RequestId, ServiceType};
use thiserror::Error;

/// Errors that can occur in QPL network operations.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("operator not found: {0}")]
    OperatorNotFound(OperatorId),

    #[error("operator already registered: {0}")]
    OperatorAlreadyRegistered(OperatorId),

    #[error("insufficient operators for service {service}: need {needed}, have {available}")]
    InsufficientOperators {
        service: ServiceType,
        needed: u8,
        available: u8,
    },

    #[error("operator does not support service: {0}")]
    UnsupportedService(ServiceType),

    #[error("invalid stake: minimum {min_required}, provided {provided}")]
    InsufficientStake { min_required: u128, provided: u128 },

    #[error("operator not active: {0}")]
    OperatorNotActive(OperatorId),

    #[error("fee quote expired: {0}")]
    FeeQuoteExpired(String),

    #[error("fee payment verification failed: {0}")]
    FeeVerificationFailed(String),

    #[error("coordination timeout for request {0}")]
    CoordinationTimeout(RequestId),

    #[error("insufficient partial responses: need {needed}, got {received}")]
    InsufficientPartials { needed: u8, received: u8 },

    #[error("request already completed: {0}")]
    RequestAlreadyCompleted(RequestId),

    #[error("invalid operator status transition: cannot move from {from:?} to {to:?}")]
    InvalidStatusTransition {
        from: crate::types::OperatorStatus,
        to: crate::types::OperatorStatus,
    },

    #[error("peer connection failed: {0}")]
    PeerConnectionFailed(String),

    #[error("no bootstrap peers configured")]
    NoBootstrapPeers,

    #[error("heartbeat timeout for operator {0}")]
    HeartbeatTimeout(OperatorId),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("cryptographic error: {0}")]
    CryptoError(String),

    /// A message with a (sender, sequence) pair already observed was received
    /// (potential replay attack). Carries the sender and the offending sequence
    /// number.
    #[error("replay detected: sender {0}, sequence {1} already observed")]
    ReplayDetected(OperatorId, u64),

    /// The message's `timestamp_nanos` field is outside the allowed clock-skew
    /// window relative to the receiver's current wall clock.
    #[error(
        "timestamp out of window: now={now_nanos} msg={msg_nanos} \
         max_past_nanos={max_skew_past_nanos} max_future_nanos={max_skew_future_nanos}"
    )]
    TimestampOutOfWindow {
        now_nanos: u64,
        msg_nanos: u64,
        max_skew_past_nanos: u64,
        max_skew_future_nanos: u64,
    },

    /// A message arrived with a sequence number that did not strictly exceed
    /// the previously observed high-water mark for the same sender.
    #[error("non-monotonic sequence from {sender}: got {got}, must be > {expected_gt}")]
    NonMonotonicSequence {
        sender: OperatorId,
        expected_gt: u64,
        got: u64,
    },

    #[error("arithmetic overflow in fee calculation: {0}")]
    ArithmeticOverflow(String),
}
