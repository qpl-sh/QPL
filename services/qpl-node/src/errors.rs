// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sanitized JSON-RPC error envelope (D-6 MEDIUM remediation).
//!
//! The server logs the **detailed** error chain via `tracing::error!`
//! server-side — including stack-traces, parse positions, key handles,
//! and HSM error codes — but the **client only ever sees** a stable,
//! generic mapping. This prevents leaking internal implementation
//! details (cert paths, file system layout, HSM error chains, parse
//! positions, etc.) to a potentially-malicious peer.

use serde::Serialize;

/// Sanitized JSON-RPC error code mapping.
///
/// These codes follow the spirit of JSON-RPC 2.0 reserved/server codes
/// while leaving a clear stable contract for clients.
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    /// -32600 Invalid request envelope (malformed JSON, missing fields).
    InvalidRequest,
    /// -32601 Method not found (unknown RPC method name).
    MethodNotFound,
    /// -32602 Invalid params (failed deserialization of params).
    InvalidParams,
    /// -32603 Internal error (handler panicked / unexpected I/O).
    InternalError,
    /// -32001 Authentication failed (signature/timestamp/operator check).
    AuthenticationFailed,
    /// -32002 Rate limit exceeded for this operator.
    RateLimitExceeded,
}

impl ErrorCode {
    pub fn code(self) -> i32 {
        match self {
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::AuthenticationFailed => -32001,
            Self::RateLimitExceeded => -32002,
        }
    }

    /// Stable client-facing message. NEVER includes internal detail.
    pub fn public_message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid request",
            Self::MethodNotFound => "method not found",
            Self::InvalidParams => "invalid params",
            Self::InternalError => "internal error",
            Self::AuthenticationFailed => "authentication failed",
            Self::RateLimitExceeded => "rate limit exceeded",
        }
    }
}

/// JSON-RPC error body that gets serialized to the wire.
#[derive(Debug, Clone, Serialize)]
pub struct WireError {
    pub code: i32,
    pub message: &'static str,
}

impl WireError {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code: code.code(),
            message: code.public_message(),
        }
    }
}

/// Build a sanitized JSON-RPC error response string.
///
/// `internal_detail` is logged at `error!` level server-side but is
/// **not** placed on the wire.
pub fn sanitized_error_response(
    code: ErrorCode,
    internal_detail: impl std::fmt::Display,
) -> String {
    tracing::error!(
        code = code.code(),
        public_message = code.public_message(),
        detail = %internal_detail,
        "rpc error"
    );
    let body = serde_json::json!({ "error": WireError::new(code) });
    body.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_error_does_not_leak_detail() {
        let internal = "secret_key_path=/etc/qpl/keys/op-1.pem parse_error_at_byte=42";
        let s = sanitized_error_response(ErrorCode::InvalidParams, internal);
        assert!(!s.contains("secret_key_path"));
        assert!(!s.contains("parse_error_at_byte"));
        assert!(s.contains("invalid params"));
        assert!(s.contains("-32602"));
    }

    #[test]
    fn auth_error_uses_minus_32001() {
        let s = sanitized_error_response(ErrorCode::AuthenticationFailed, "stale timestamp 60s");
        assert!(s.contains("-32001"));
        assert!(s.contains("authentication failed"));
        assert!(!s.contains("stale"));
    }

    #[test]
    fn rate_limit_error_uses_minus_32002() {
        let s = sanitized_error_response(ErrorCode::RateLimitExceeded, "bucket=-2.5");
        assert!(s.contains("-32002"));
        assert!(s.contains("rate limit exceeded"));
        assert!(!s.contains("bucket"));
    }
}
