// SPDX-License-Identifier: MIT OR Apache-2.0

//! STARK proving handler.
//!
//! Generates FRI-based STARK proofs for transaction batches.
//! In production: delegates to qpl-stark-rollup for Winterfell-based proving.
//! For now: returns a placeholder proof.

use crate::server::{ProveRequest, ProveResponse};
use crate::state::NodeState;
use sha2::{Digest, Sha256};

/// Handle a STARK proof generation request.
///
/// Flow:
/// 1. Verify fee payment proof
/// 2. Deserialize transactions into AIR trace
/// 3. Generate STARK proof via Winterfell prover
/// 4. Verify proof locally
/// 5. Return proof + public inputs to client
pub async fn handle_prove(
    state: &NodeState,
    req: ProveRequest,
) -> Result<ProveResponse, Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        tx_len = req.transactions.len(),
        security_bits = req.security_bits,
        "Processing prove request"
    );

    // Step 1: Verify fee
    if req.fee_proof_tx.is_empty() {
        return Err("fee_proof_tx is required".into());
    }

    // Step 2-4: In production, delegates to qpl-stark-rollup.
    // Placeholder: return a dummy proof structure.
    let security_bits = if req.security_bits == 0 {
        96
    } else {
        req.security_bits
    };

    // Simulate proof generation (real proof would be KBs)
    let proof = vec![0xDE, 0xAD, 0xBE, 0xEF]; // Placeholder

    let mut hasher = Sha256::new();
    hasher.update(&req.transactions);
    hasher.update(security_bits.to_le_bytes());
    let public_inputs = hasher.finalize().to_vec();

    let request_id = uuid::Uuid::new_v4().to_string();

    // Record fee
    state.metrics.record_fee(5000); // proving is more expensive

    tracing::info!(
        request_id = %request_id,
        proof_len = proof.len(),
        "Prove request completed"
    );

    Ok(ProveResponse {
        proof,
        public_inputs,
        request_id,
    })
}
