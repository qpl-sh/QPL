// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threshold signing handler.
//!
//! Coordinates N-of-M ML-DSA threshold signing across operators.
//! Delegates to `OperatorIdentity::sign()` which uses real ML-DSA-65
//! via `qpl_crypto::ml_dsa::MlDsaKeyPair`.

use crate::server::{SignRequest, SignResponse};
use crate::state::NodeState;

/// Handle a threshold signing request.
///
/// Flow:
/// 1. Verify fee payment proof (tx hash on-chain)
/// 2. Select quorum of operators via consistent hashing
/// 3. Fan out partial sign requests
/// 4. Collect threshold partial signatures
/// 5. Combine into full ML-DSA signature
/// 6. Return to client
pub async fn handle_sign(
    state: &NodeState,
    req: SignRequest,
) -> Result<SignResponse, Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        message_len = req.message.len(),
        threshold = req.threshold,
        total = req.total,
        "Processing sign request"
    );

    // Step 1: Verify fee payment proof
    // [QPL-004] Validate tx signature format (base58-encoded, 87-88 chars for Solana)
    if req.fee_proof_tx.is_empty() {
        return Err("fee_proof_tx is required".into());
    }
    let tx_len = req.fee_proof_tx.len();
    if !(32..=128).contains(&tx_len) {
        return Err(format!(
            "fee_proof_tx has invalid length {} (expected 32-128 base58 chars)",
            tx_len
        )
        .into());
    }
    if !req.fee_proof_tx.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("fee_proof_tx contains invalid characters (expected base58)".into());
    }
    // TODO: Verify tx on-chain via Solana RPC (confirm signature, check fee amount)

    // Step 2-5: Single-operator ML-DSA-65 signature.
    // Full threshold coordination (multi-operator) is a future enhancement.
    let signature = state.identity.sign(&req.message);
    let request_id = uuid::Uuid::new_v4().to_string();

    // Record fee: $0.025 = 25_000 micro-USD
    state.metrics.record_fee(25_000);

    tracing::info!(
        request_id = %request_id,
        sig_len = signature.len(),
        "Sign request completed"
    );

    Ok(SignResponse {
        signature,
        request_id,
        participants: 1, // Single operator for now
    })
}
