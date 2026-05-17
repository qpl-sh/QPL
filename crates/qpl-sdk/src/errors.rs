// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK error types.

use thiserror::Error;

/// Errors that can occur when using the QPL SDK.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("no operators available for service: {0}")]
    NoOperatorsAvailable(String),

    #[error("request timeout after {0}ms")]
    Timeout(u64),

    #[error("fee exceeds maximum: estimated {estimated} > max {max}")]
    FeeExceedsMax { estimated: u64, max: u64 },

    #[error("fee payment failed: {0}")]
    FeePaymentFailed(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("proving failed: {0}")]
    ProvingFailed(String),

    #[error("operator returned error: {0}")]
    OperatorError(String),

    #[error("all retries exhausted")]
    RetriesExhausted,

    #[error("gRPC transport error: {0}")]
    TransportError(String),
}
