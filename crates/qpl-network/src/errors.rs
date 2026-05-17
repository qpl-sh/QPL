// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network error types.

use thiserror::Error;
use crate::types::{OperatorId, RequestId, ServiceType};

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
}
