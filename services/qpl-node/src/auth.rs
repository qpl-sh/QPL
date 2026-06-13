// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-request operator authentication (D-2 HIGH remediation).
//!
//! Every JSON-RPC request — except the unauthenticated `health`
//! liveness probe — must carry an `auth` envelope:
//!
//! ```json
//! {
//!   "auth": {
//!     "operator_id":      "<32-byte hex SHA-256 of ML-DSA-65 pubkey>",
//!     "timestamp_nanos":  17791099698180000000,
//!     "signature":        "<hex of ML-DSA-65 signature>"
//!   },
//!   "request": { "method": "...", "params": {...} }
//! }
//! ```
//!
//! The signature is computed over the canonical pre-image:
//!
//! ```text
//! method || "\n" || canonical_json(params) || "\n" || timestamp_nanos
//! ```
//!
//! where `canonical_json` is the canonical (key-sorted, no-whitespace)
//! `serde_json::Value` rendering. This pre-image is recomputed
//! server-side from the parsed envelope before verification.
//!
//! ## Why an outer envelope (option (b)) was chosen
//!
//! The existing dispatcher in [`crate::server`] consumes a
//! [`serde_json::Value`] for `params` and then deserializes per-handler.
//! Wrapping the inner JSON-RPC body in `{auth, request}` keeps the
//! handler signatures **completely unchanged** — we strip the outer
//! envelope in the dispatcher, run the auth check, and pass the inner
//! `request` object to exactly the same code path as before. Option (a)
//! (top-level fields on every request) would have required every
//! handler's own `serde::Deserialize` to ignore three foreign fields,
//! which is more invasive.

use crate::errors::ErrorCode;
use crate::state::AuthState;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum age of an `auth_timestamp_nanos` (clock-skew window into
/// the past). Requests older than this are rejected as stale.
pub const MAX_TIMESTAMP_AGE_NANOS: u128 = 30 * 1_000_000_000;
/// Maximum lead time of an `auth_timestamp_nanos` (clock-skew window
/// into the future). Requests further ahead are rejected as suspicious.
pub const MAX_TIMESTAMP_FUTURE_NANOS: u128 = 5 * 1_000_000_000;

/// Outer authenticated JSON-RPC envelope.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthEnvelope {
    pub auth: AuthHeader,
    pub request: serde_json::Value,
}

/// Authentication header.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthHeader {
    /// Hex-encoded SHA-256 of the operator's ML-DSA-65 public key.
    pub operator_id: String,
    /// Wall-clock timestamp at which the client signed the request.
    pub timestamp_nanos: u64,
    /// Hex-encoded ML-DSA-65 detached signature.
    pub signature: String,
}

/// Outcome of an authentication attempt. Detailed reasons are kept
/// inside this enum for **server-side logging only**; clients only
/// ever see `ErrorCode::AuthenticationFailed`.
#[derive(Debug)]
pub enum AuthFailure {
    UnknownOperator,
    StaleTimestamp { age_nanos: u128 },
    FutureTimestamp { ahead_nanos: u128 },
    BadOperatorIdHex,
    BadSignatureHex,
    BadPublicKey,
    SignatureRejected,
    CanonicalEncodingFailed,
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownOperator => write!(f, "unknown operator id"),
            Self::StaleTimestamp { age_nanos } => {
                write!(f, "stale timestamp ({} ns old)", age_nanos)
            }
            Self::FutureTimestamp { ahead_nanos } => {
                write!(f, "future timestamp ({} ns ahead)", ahead_nanos)
            }
            Self::BadOperatorIdHex => write!(f, "operator_id is not valid hex"),
            Self::BadSignatureHex => write!(f, "signature is not valid hex"),
            Self::BadPublicKey => write!(f, "configured public key failed to parse"),
            Self::SignatureRejected => write!(f, "ML-DSA verify returned false"),
            Self::CanonicalEncodingFailed => write!(f, "canonical pre-image encoding failed"),
        }
    }
}

/// Compute the canonical signing pre-image for a request.
///
/// The format is `method || "\n" || canonical_json(params) || "\n" || timestamp_nanos`
/// and matches what the client signed.
pub fn canonical_preimage(
    method: &str,
    params: &serde_json::Value,
    timestamp_nanos: u64,
) -> Result<Vec<u8>, AuthFailure> {
    let canonical = canonical_json(params).map_err(|_| AuthFailure::CanonicalEncodingFailed)?;
    let mut buf = Vec::with_capacity(method.len() + canonical.len() + 32);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(canonical.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(timestamp_nanos.to_string().as_bytes());
    Ok(buf)
}

/// Render a `serde_json::Value` in canonical form: object keys sorted
/// lexicographically, no whitespace, JSON numbers preserved as-is.
fn canonical_json(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    let canonical = sort_keys(value.clone());
    serde_json::to_string(&canonical)
}

fn sort_keys(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                sorted.insert(k, sort_keys(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_keys).collect()),
        other => other,
    }
}

/// Verify an authentication envelope. Returns `Ok(operator_id)` on
/// success or a detailed [`AuthFailure`] on failure (logged
/// server-side; clients only see [`ErrorCode::AuthenticationFailed`]).
pub fn verify_auth(
    handle: &AuthState,
    auth: &AuthHeader,
    method: &str,
    params: &serde_json::Value,
) -> Result<String, AuthFailure> {
    // Step 1: clock-skew window.
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let req_nanos = auth.timestamp_nanos as u128;
    if req_nanos + MAX_TIMESTAMP_AGE_NANOS < now_nanos {
        return Err(AuthFailure::StaleTimestamp {
            age_nanos: now_nanos.saturating_sub(req_nanos),
        });
    }
    if req_nanos > now_nanos + MAX_TIMESTAMP_FUTURE_NANOS {
        return Err(AuthFailure::FutureTimestamp {
            ahead_nanos: req_nanos - now_nanos,
        });
    }

    // Step 2: known operator?
    let pubkey_hex = handle
        .authorized_pubkey_hex(&auth.operator_id)
        .ok_or(AuthFailure::UnknownOperator)?;
    let pubkey_bytes = hex::decode(&pubkey_hex).map_err(|_| AuthFailure::BadPublicKey)?;

    // Step 3: hex-decode signature.
    let _signature_bytes =
        hex::decode(&auth.signature).map_err(|_| AuthFailure::BadSignatureHex)?;
    // Sanity check operator_id is hex too.
    let _ = hex::decode(&auth.operator_id).map_err(|_| AuthFailure::BadOperatorIdHex)?;

    // Step 4: canonical pre-image.
    let preimage = canonical_preimage(method, params, auth.timestamp_nanos)?;

    // Step 5: ML-DSA-65 verify via qpl-crypto.
    //
    // Production path: require real ML-DSA-65 public key (≥1952 bytes).
    // Debug/test path: allow placeholder 32-byte keys with SHA-256 dev signature.
    // The dev fallback is compiled out in release builds to prevent any
    // possibility of bypassing quantum-secure authentication in production.
    if pubkey_bytes.len() >= 1952 {
        // Real ML-DSA-65 public key — production path.
        let pk = qpl_crypto::ml_dsa::MlDsaPublicKey::from_bytes(&pubkey_bytes)
            .map_err(|_| AuthFailure::BadPublicKey)?;
        let sig_bytes = hex::decode(&auth.signature).map_err(|_| AuthFailure::BadSignatureHex)?;
        let sig = qpl_crypto::ml_dsa::MlDsaSignature::from_bytes(&sig_bytes)
            .map_err(|_| AuthFailure::SignatureRejected)?;
        let ok = qpl_crypto::ml_dsa::verify(&pk, &preimage, &sig)
            .map_err(|_| AuthFailure::SignatureRejected)?;
        if !ok {
            return Err(AuthFailure::SignatureRejected);
        }
    } else {
        // Dev / test path — only available in debug builds.
        #[cfg(any(test, debug_assertions))]
        {
            let sig_bytes =
                hex::decode(&auth.signature).map_err(|_| AuthFailure::BadSignatureHex)?;
            let expected = dev_signature(&pubkey_bytes, &preimage);
            if sig_bytes != expected {
                return Err(AuthFailure::SignatureRejected);
            }
        }
        #[cfg(not(any(test, debug_assertions)))]
        {
            let _ = &preimage; // suppress unused warning
            return Err(AuthFailure::BadPublicKey);
        }
    }

    Ok(auth.operator_id.clone())
}

/// Dev / test signature stub — SHA-256(pubkey || preimage) — used only
/// in debug/test builds when a non-ML-DSA placeholder pubkey is configured.
///
/// **Compiled out in release builds.** Production operators MUST register
/// an ML-DSA-65 public key (≥1952 bytes) in `authorized_operators`.
#[cfg(any(test, debug_assertions))]
pub fn dev_signature(pubkey: &[u8], preimage: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(preimage);
    hasher.finalize().to_vec()
}

/// Map an [`AuthFailure`] to the public [`ErrorCode`]. All variants
/// collapse to the same generic code so attackers cannot distinguish
/// "wrong signature" from "stale timestamp" from "unknown operator".
pub fn failure_to_code(_f: &AuthFailure) -> ErrorCode {
    ErrorCode::AuthenticationFailed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = serde_json::json!({"b": 1, "a": [{"y": 2, "x": 1}]});
        let s = canonical_json(&v).unwrap();
        assert_eq!(s, r#"{"a":[{"x":1,"y":2}],"b":1}"#);
    }

    #[test]
    fn preimage_is_stable() {
        let p1 = canonical_preimage("sign", &serde_json::json!({"a": 1, "b": 2}), 1234).unwrap();
        let p2 = canonical_preimage("sign", &serde_json::json!({"b": 2, "a": 1}), 1234).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn stale_timestamp_rejected() {
        let stale = now_ns().saturating_sub(60 * 1_000_000_000);
        let auth = AuthHeader {
            operator_id: "00".repeat(32),
            timestamp_nanos: stale,
            signature: "00".to_string(),
        };
        let handle = AuthState::test_with_operator(&auth.operator_id, &[0u8; 32]);
        let err = verify_auth(&handle, &auth, "sign", &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AuthFailure::StaleTimestamp { .. }));
    }

    #[test]
    fn future_timestamp_rejected() {
        let ahead = now_ns().saturating_add(60 * 1_000_000_000);
        let auth = AuthHeader {
            operator_id: "00".repeat(32),
            timestamp_nanos: ahead,
            signature: "00".to_string(),
        };
        let handle = AuthState::test_with_operator(&auth.operator_id, &[0u8; 32]);
        let err = verify_auth(&handle, &auth, "sign", &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AuthFailure::FutureTimestamp { .. }));
    }

    #[test]
    fn unknown_operator_rejected() {
        let auth = AuthHeader {
            operator_id: "11".repeat(32),
            timestamp_nanos: now_ns(),
            signature: "00".to_string(),
        };
        let handle = AuthState::test_with_operator(&"22".repeat(32), &[0u8; 32]);
        let err = verify_auth(&handle, &auth, "sign", &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, AuthFailure::UnknownOperator));
    }

    #[test]
    fn bad_signature_rejected() {
        let pk = vec![0xABu8; 32];
        let op = "33".repeat(32);
        let auth = AuthHeader {
            operator_id: op.clone(),
            timestamp_nanos: now_ns(),
            signature: hex::encode([0u8; 32]),
        };
        let handle = AuthState::test_with_operator(&op, &pk);
        let err = verify_auth(&handle, &auth, "sign", &serde_json::json!({"x": 1})).unwrap_err();
        assert!(matches!(err, AuthFailure::SignatureRejected));
    }

    #[test]
    fn good_dev_signature_accepts() {
        let pk = vec![0xCDu8; 32];
        let op = "44".repeat(32);
        let ts = now_ns();
        let preimage = canonical_preimage("sign", &serde_json::json!({"x": 1}), ts).unwrap();
        let sig = dev_signature(&pk, &preimage);
        let auth = AuthHeader {
            operator_id: op.clone(),
            timestamp_nanos: ts,
            signature: hex::encode(&sig),
        };
        let handle = AuthState::test_with_operator(&op, &pk);
        let id = verify_auth(&handle, &auth, "sign", &serde_json::json!({"x": 1})).unwrap();
        assert_eq!(id, op);
    }
}
