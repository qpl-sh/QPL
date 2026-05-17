// SPDX-License-Identifier: MIT OR Apache-2.0
//! STARK proof verification for settlement batches.
//!
//! Verifies that a settlement proof is valid against the claimed
//! public inputs, without requiring access to private transaction data.

use thiserror::Error;
use winterfell::{
    crypto::DefaultRandomCoin,
    math::fields::f128::BaseElement,
    verify, AcceptableOptions, Proof, ProofOptions, VerifierError as WinterfellVerifierError,
};

use crate::air::{SettlementAir, SettlementPublicInputs};
use crate::types::{RollupProof, RollupProofWithCommitment};

/// Errors that can occur during proof verification
#[derive(Debug, Error)]
pub enum VerifierError {
    /// Error deserializing the proof
    #[error("Proof deserialization error: {0}")]
    DeserializationError(String),

    /// Winterfell verification error
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid public inputs
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Proof structure is invalid
    #[error("Invalid proof structure: {0}")]
    InvalidProofStructure(String),
}

impl From<WinterfellVerifierError> for VerifierError {
    fn from(e: WinterfellVerifierError) -> Self {
        VerifierError::VerificationFailed(e.to_string())
    }
}

/// Hash function type for verification (must match prover)
type HashFn = winterfell::crypto::hashers::Blake3_256<BaseElement>;
type RandomCoin = DefaultRandomCoin<HashFn>;

/// Minimum acceptable security level for STARK proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 96-bit security (32 queries, 8x blowup). Suitable for testing only.
    Standard96,
    /// 128-bit security (48 queries, 16x blowup). Required for production.
    High128,
}

/// Verify a settlement STARK proof (production-grade: High128 only).
///
/// Only accepts proofs generated with the High128 security level
/// (48 queries, 16x blowup). Standard96 proofs are rejected.
///
/// # Arguments
/// * `proof` - The rollup proof to verify
/// * `pub_inputs` - The settlement public inputs for verification
///
/// # Returns
/// * `Ok(true)` if the proof is valid
/// * `Err(VerifierError)` if verification fails
pub fn verify_proof(
    proof: &RollupProof,
    pub_inputs: &SettlementPublicInputs,
) -> Result<bool, VerifierError> {
    // Deserialize the winterfell proof
    let stark_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    // Only accept High128 security level (S1 hardening)
    let acceptable_options = AcceptableOptions::OptionSet(vec![
        ProofOptions::new(48, 16, 0, winterfell::FieldExtension::None, 8, 31),
    ]);

    // Verify the proof using winterfell's verifier
    verify::<SettlementAir, HashFn, RandomCoin>(stark_proof, pub_inputs.clone(), &acceptable_options)?;

    Ok(true)
}

/// Verify a settlement STARK proof with a configurable minimum security level.
///
/// When `min_level` is `Standard96`, both Standard96 and High128 proofs are
/// accepted. When `min_level` is `High128`, only High128 proofs are accepted.
///
/// # Arguments
/// * `proof` - The rollup proof to verify
/// * `pub_inputs` - The settlement public inputs for verification
/// * `min_level` - The minimum acceptable security level
pub fn verify_proof_with_security_level(
    proof: &RollupProof,
    pub_inputs: &SettlementPublicInputs,
    min_level: SecurityLevel,
) -> Result<bool, VerifierError> {
    let stark_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    let acceptable_options = match min_level {
        SecurityLevel::Standard96 => AcceptableOptions::OptionSet(vec![
            ProofOptions::new(32, 8, 0, winterfell::FieldExtension::None, 8, 31),
            ProofOptions::new(48, 16, 0, winterfell::FieldExtension::None, 8, 31),
        ]),
        SecurityLevel::High128 => AcceptableOptions::OptionSet(vec![
            ProofOptions::new(48, 16, 0, winterfell::FieldExtension::None, 8, 31),
        ]),
    };

    verify::<SettlementAir, HashFn, RandomCoin>(stark_proof, pub_inputs.clone(), &acceptable_options)?;

    Ok(true)
}

/// Verify a settlement STARK proof with commitment binding (S2 hardening).
///
/// Checks that the cryptographic commitment embedded in the proof matches
/// the provided public inputs before performing STARK verification.
/// This prevents public-inputs substitution attacks by a relayer.
///
/// # Arguments
/// * `committed_proof` - Proof with embedded public-inputs hash
/// * `pub_inputs` - The settlement public inputs to verify against
pub fn verify_proof_with_commitment(
    committed_proof: &RollupProofWithCommitment,
    pub_inputs: &SettlementPublicInputs,
) -> Result<bool, VerifierError> {
    // Recompute commitment from the supplied public inputs
    let expected_hash = crate::types::compute_public_inputs_commitment(pub_inputs);
    if expected_hash != committed_proof.public_inputs_hash {
        return Err(VerifierError::InvalidPublicInputs(
            "Public inputs hash does not match the commitment embedded in the proof".to_string(),
        ));
    }

    // Proceed with standard High128-only STARK verification
    let stark_proof = Proof::from_bytes(&committed_proof.proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    let acceptable_options = AcceptableOptions::OptionSet(vec![
        ProofOptions::new(48, 16, 0, winterfell::FieldExtension::None, 8, 31),
    ]);

    verify::<SettlementAir, HashFn, RandomCoin>(stark_proof, pub_inputs.clone(), &acceptable_options)?;

    Ok(true)
}

/// Verify a proof with custom acceptable options
///
/// # Arguments
/// * `proof` - The rollup proof to verify
/// * `pub_inputs` - The settlement public inputs for verification
/// * `acceptable_options` - Custom acceptable proof options
///
/// # Returns
/// * `Ok(true)` if the proof is valid
/// * `Err(VerifierError)` if verification fails
pub fn verify_proof_with_options(
    proof: &RollupProof,
    pub_inputs: &SettlementPublicInputs,
    acceptable_options: &AcceptableOptions,
) -> Result<bool, VerifierError> {
    let stark_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| VerifierError::DeserializationError(e.to_string()))?;

    verify::<SettlementAir, HashFn, RandomCoin>(stark_proof, pub_inputs.clone(), acceptable_options)?;

    Ok(true)
}

/// Quick check if proof bytes appear valid (basic structure check)
///
/// This does NOT verify the proof cryptographically, only checks
/// if the bytes can be parsed as a valid STARK proof structure.
pub fn is_proof_well_formed(proof_bytes: &[u8]) -> bool {
    Proof::from_bytes(proof_bytes).is_ok()
}

/// Get the proof size in bytes
pub fn proof_size(proof: &RollupProof) -> usize {
    proof.proof_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::SettlementProver;
    use crate::trace::build_settlement_trace;
    use crate::types::{AccountBalance, AccountId, RollupState, Transaction};

    fn make_test_transaction(sender_seed: u8, receiver_seed: u8, amount: u64, nonce: u64) -> Transaction {
        // For verifier tests, we use the legacy new() method
        // Verification operates on already-validated transactions
        Transaction::new(
            AccountId::from_bytes([sender_seed; 32]),
            AccountId::from_bytes([receiver_seed; 32]),
            amount,
            nonce,
            1234567890,
            vec![],
        )
    }

    fn make_initial_state(sender_seed: u8, sender_balance: u64) -> RollupState {
        let mut state = RollupState::new();
        let sender_id = AccountId::from_bytes([sender_seed; 32]);
        state.get_or_create_account(&sender_id).balance = sender_balance;
        state.compute_state_root();
        state
    }

    #[test]
    fn test_verify_valid_proof() {
        // Generate a proof using High128 (the new default)
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let proof = prover.prove_batch(&txs, &initial_state).expect("Proof generation should succeed");

        // Get the sender/receiver initial balances for public inputs
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let trace_result = build_settlement_trace(&txs, &sender, &receiver);

        // Create matching public inputs
        let pub_inputs = SettlementPublicInputs::new(
            sender.balance,
            receiver.balance,
            sender.nonce,
            trace_result.final_sender_balance,
            trace_result.final_receiver_balance,
            trace_result.final_nonce,
        );

        // Verify the proof (default verifier now requires High128)
        let result = verify_proof(&proof, &pub_inputs);
        assert!(result.is_ok(), "Verification should succeed: {:?}", result.err());
        assert!(result.unwrap(), "Proof should be valid");
    }

    #[test]
    fn test_verify_invalid_public_inputs() {
        // Generate a proof
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let proof = prover.prove_batch(&txs, &initial_state).expect("Proof generation should succeed");

        // Create WRONG public inputs (different final balances)
        let wrong_pub_inputs = SettlementPublicInputs::new(
            1000, // initial sender
            0,    // initial receiver
            0,    // initial nonce
            500,  // WRONG: final sender should be 900
            500,  // WRONG: final receiver should be 100
            1,    // final nonce
        );

        // Verification should fail
        let result = verify_proof(&proof, &wrong_pub_inputs);
        assert!(result.is_err(), "Verification should fail with wrong public inputs");
    }

    #[test]
    fn test_verify_tampered_proof() {
        // Generate a valid proof
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let mut proof = prover.prove_batch(&txs, &initial_state).expect("Proof generation should succeed");

        // Get correct public inputs
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let trace_result = build_settlement_trace(&txs, &sender, &receiver);

        let pub_inputs = SettlementPublicInputs::new(
            sender.balance,
            receiver.balance,
            sender.nonce,
            trace_result.final_sender_balance,
            trace_result.final_receiver_balance,
            trace_result.final_nonce,
        );

        // Tamper with the proof bytes
        if !proof.proof_bytes.is_empty() {
            let mid = proof.proof_bytes.len() / 2;
            proof.proof_bytes[mid] ^= 0xFF; // Flip some bits
        }

        // Verification should fail
        let result = verify_proof(&proof, &pub_inputs);
        assert!(result.is_err(), "Verification should fail with tampered proof");
    }

    #[test]
    fn test_is_proof_well_formed() {
        // Generate a valid proof
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let proof = prover.prove_batch(&txs, &initial_state).expect("Proof generation should succeed");

        assert!(is_proof_well_formed(&proof.proof_bytes), "Valid proof should be well-formed");

        // Invalid bytes should not be well-formed
        assert!(!is_proof_well_formed(&[0u8; 32]), "Random bytes should not be well-formed");
    }

    #[test]
    fn test_proof_size() {
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let proof = prover.prove_batch(&txs, &initial_state).expect("Proof generation should succeed");

        let size = proof_size(&proof);
        assert!(size > 0, "Proof should have non-zero size");
        // STARK proofs are typically several KB
        assert!(size > 1000, "STARK proof should be at least 1KB");
    }
}
