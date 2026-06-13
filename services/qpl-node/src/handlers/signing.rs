// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threshold signing handler.
//!
//! Coordinates N-of-M ML-DSA threshold signing across operators.
//! In production: fan out partial sign requests, collect threshold responses,
//! combine into full signature. For now: single-operator local sign.

use crate::server::{SignRequest, SignResponse};
use crate::state::NodeState;
use std::sync::atomic::Ordering;

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

    // Step 1: Verify fee (simplified — check tx hash is non-empty)
    if req.fee_proof_tx.is_empty() {
        return Err("fee_proof_tx is required".into());
    }

    // Step 2-5: In production, coordinate with peer operators.
    // For now: local single-operator signature.
    let signature = state.identity.sign(&req.message);
    let request_id = uuid::Uuid::new_v4().to_string();

    // Record fee collection
    state.metrics.record_fee(1000); // placeholder fee amount
    state
        .metrics
        .fees_collected_micro_usd
        .fetch_add(0, Ordering::Relaxed);

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
