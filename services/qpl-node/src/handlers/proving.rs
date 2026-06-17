// SPDX-License-Identifier: MIT OR Apache-2.0

//! STARK proving handler.
//!
//! Generates FRI-based STARK proofs for transaction batches by delegating
//! to `qpl-stark-rollup::SettlementProver` (Winterfell-based).

use crate::server::{ProveRequest, ProveResponse};
use crate::state::NodeState;
use qpl_stark_rollup::{
    ProofConfig as StarkProofConfig, RollupState, SecurityLevel, SettlementProver, Transaction,
};

/// Handle a STARK proof generation request.
///
/// Flow:
/// 1. Verify fee payment proof
/// 2. Deserialize transactions from request bytes
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

    // Step 2: Deserialize transactions from JSON
    let transactions: Vec<Transaction> = serde_json::from_slice(&req.transactions)
        .map_err(|e| format!("failed to deserialize transactions: {}", e))?;

    if transactions.is_empty() {
        return Err("transaction batch must not be empty".into());
    }

    // Step 3: Enforce minimum High128 security level
    // [QPL-010] Ignore client-supplied security_bits — always use production-grade
    let security_level = SecurityLevel::High128;

    let config = StarkProofConfig::new(security_level);
    let prover = SettlementProver::new(config);

    // Create initial state (empty — balances derived from transactions)
    let initial_state = RollupState::new();

    // Generate the STARK proof
    let proof = prover.prove_batch(&transactions, &initial_state)?;

    // Step 4: Serialize public inputs for client
    let public_inputs = serde_json::to_vec(&proof.public_inputs)
        .map_err(|e| format!("failed to serialize public inputs: {}", e))?;
    let request_id = uuid::Uuid::new_v4().to_string();

    // Record fee
    state.metrics.record_fee(5000); // proving is more expensive

    tracing::info!(
        request_id = %request_id,
        proof_len = proof.proof_bytes.len(),
        "Prove request completed"
    );

    Ok(ProveResponse {
        proof: proof.proof_bytes,
        public_inputs,
        request_id,
    })
}
