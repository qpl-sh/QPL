// SPDX-License-Identifier: MIT OR Apache-2.0

//! Red Team Exploit Tests — QPL STARK Rollup Verifier
//!
//! These tests verify that previously-identified attack vectors (S1, S2, S3)
//! are now **mitigated** after security hardening. Each test asserts that
//! the exploit is REJECTED by the hardened code.

#[cfg(test)]
mod red_team_tests {
    use crate::air::SettlementPublicInputs;
    use crate::executor::{NonceRegistry, TransactionValidator};
    use crate::prover::{ProofConfig, SecurityLevel, SettlementProver};
    use crate::trace::build_settlement_trace;
    use crate::types::{AccountBalance, AccountId, RollupState, Transaction};
    use crate::verifier::SecurityLevel as VerifierSecurityLevel;
    use crate::verifier::{
        verify_proof, verify_proof_with_commitment, verify_proof_with_security_level,
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_tx(sender_seed: u8, receiver_seed: u8, amount: u64, nonce: u64) -> Transaction {
        Transaction::new(
            AccountId::from_bytes([sender_seed; 32]),
            AccountId::from_bytes([receiver_seed; 32]),
            amount,
            nonce,
            1_700_000_000, // fixed timestamp
            vec![],        // empty sig — for trace/proof tests (no sig check in prover)
        )
    }

    fn initial_state_with(sender_seed: u8, balance: u64) -> RollupState {
        let mut state = RollupState::new();
        let sender = AccountId::from_bytes([sender_seed; 32]);
        state.get_or_create_account(&sender).balance = balance;
        state.compute_state_root();
        state
    }

    // -----------------------------------------------------------------------
    // S1 — REMEDIATED: Low-Security Proof Rejected by Default Verifier
    //
    // After hardening, the default `verify_proof()` only accepts High128
    // proofs (48 queries, 16× blowup). Standard96 proofs are rejected.
    // The configurable `verify_proof_with_security_level()` allows
    // explicitly opting into Standard96 when appropriate.
    // -----------------------------------------------------------------------

    #[test]
    fn test_s1_low_security_proof_rejected_by_default_verifier() {
        // Generate a proof using the LOWER security level (Standard96)
        let low_config = ProofConfig::new(SecurityLevel::Standard96);
        let low_prover = SettlementProver::new(low_config);

        let initial_state = initial_state_with(1, 1_000);
        let txs = vec![make_tx(1, 2, 100, 0)];

        let proof = low_prover
            .prove_batch(&txs, &initial_state)
            .expect("Standard96 proof generation should succeed");

        // Compute correct public inputs
        let sender = AccountBalance::new(1_000);
        let receiver = AccountBalance::new(0);
        let trace = build_settlement_trace(&txs, &sender, &receiver);

        let pub_inputs = SettlementPublicInputs::new(
            sender.balance,
            receiver.balance,
            sender.nonce,
            trace.final_sender_balance,
            trace.final_receiver_balance,
            trace.final_nonce,
        );

        // REMEDIATION: Default verifier now REJECTS Standard96 proofs
        let result = verify_proof(&proof, &pub_inputs);
        assert!(
            result.is_err(),
            "REMEDIATED: Standard96 proof must be rejected by default verifier"
        );

        // The configurable verifier still accepts it when Standard96 is explicit
        let relaxed = verify_proof_with_security_level(
            &proof,
            &pub_inputs,
            VerifierSecurityLevel::Standard96,
        );
        assert!(
            relaxed.is_ok(),
            "Standard96 proof should be accepted when explicitly allowed: {:?}",
            relaxed.err()
        );

        // High128 proof is accepted by the default verifier
        let high_config = ProofConfig::new(SecurityLevel::High128);
        let high_prover = SettlementProver::new(high_config);

        let high_proof = high_prover
            .prove_batch(&txs, &initial_state)
            .expect("High128 proof generation should succeed");

        let high_result = verify_proof(&high_proof, &pub_inputs);
        assert!(
            high_result.is_ok(),
            "High128 proof should be accepted by default verifier: {:?}",
            high_result.err()
        );
    }

    // -----------------------------------------------------------------------
    // S2 — REMEDIATED: Public Inputs Bound to Proof via Commitment
    //
    // After hardening, `verify_proof_with_commitment()` checks a SHA-256
    // hash binding the proof to the exact public inputs used during proving.
    // Substituting different public inputs is detected and rejected.
    // -----------------------------------------------------------------------

    #[test]
    fn test_s2_public_inputs_commitment_rejects_substitution() {
        let prover = SettlementProver::with_default_config();
        let initial_state = initial_state_with(1, 5_000);
        let txs = vec![make_tx(1, 2, 500, 0)];

        // Generate a committed proof
        let (committed_proof, correct_inputs) = prover
            .prove_batch_with_commitment(&txs, &initial_state)
            .expect("Committed proof generation should succeed");

        // Verify with correct inputs — should pass
        let valid = verify_proof_with_commitment(&committed_proof, &correct_inputs);
        assert!(
            valid.is_ok(),
            "Correct inputs should verify with commitment: {:?}",
            valid.err()
        );

        // ATTACK: Substitute public inputs to claim attacker received more
        let fraudulent_inputs = SettlementPublicInputs::new(
            5_000, // initial sender — same
            0,     // initial receiver — same
            0,     // initial nonce — same
            0,     // FRAUD: claim sender was drained to 0
            5_000, // FRAUD: claim receiver got everything
            1,     // final nonce — same
        );

        // REMEDIATION: Commitment verification rejects the substitution
        let fraud_result = verify_proof_with_commitment(&committed_proof, &fraudulent_inputs);
        assert!(
            fraud_result.is_err(),
            "REMEDIATED: Substituted public inputs must be rejected by commitment check"
        );

        // Verify the error message mentions commitment
        let err_msg = fraud_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("hash does not match"),
            "Error should mention hash mismatch, got: {}",
            err_msg
        );
    }

    // -----------------------------------------------------------------------
    // S3 — REMEDIATED: Nonce Replay Across Independent Batches
    //
    // After hardening, the `NonceRegistry` tracks (account, nonce) pairs
    // globally. Even if a fresh `RollupState` is used for each batch,
    // the registry prevents the same nonce from being accepted twice.
    // -----------------------------------------------------------------------

    #[test]
    fn test_s3_nonce_replay_rejected_by_global_registry() {
        let sender_id = AccountId::from_bytes([0xAA; 32]);
        let receiver_id = AccountId::from_bytes([0xBB; 32]);
        let mut registry = NonceRegistry::new();

        // --- Batch 1: Fresh state, sender has 10,000, transfer 1,000 at nonce 0 ---
        let mut state1 = RollupState::new();
        state1.get_or_create_account(&sender_id).balance = 10_000;
        state1.compute_state_root();

        let batch1_tx = Transaction::new(
            sender_id.clone(),
            receiver_id.clone(),
            1_000,
            0, // nonce = 0
            1_700_000_001,
            vec![],
        );

        // Validate without signature
        let validation1 =
            TransactionValidator::validate_transaction_skip_signature(&batch1_tx, &state1);
        assert!(
            validation1.is_ok(),
            "Batch 1 tx should validate: {:?}",
            validation1.err()
        );

        // Record in global nonce registry
        let record1 = registry.record(&sender_id, batch1_tx.nonce, state1.batch_height);
        assert!(record1.is_ok(), "First nonce recording should succeed");

        // Apply batch 1
        {
            let sender_account = state1.get_or_create_account(&sender_id);
            sender_account.balance = sender_account.balance.saturating_sub(batch1_tx.amount);
            sender_account.nonce += 1;
        }
        {
            let receiver_account = state1.get_or_create_account(&receiver_id);
            receiver_account.balance = receiver_account.balance.saturating_add(batch1_tx.amount);
        }
        state1.compute_state_root();
        state1.batch_height += 1;

        // --- Batch 2: FRESH state — same sender, same nonce 0 ---
        let mut state2 = RollupState::new();
        state2.get_or_create_account(&sender_id).balance = 10_000;
        state2.compute_state_root();

        let batch2_tx = Transaction::new(
            sender_id.clone(),
            receiver_id.clone(),
            1_000,
            0, // REPLAY: nonce 0 again
            1_700_000_002,
            vec![],
        );

        // Local state validation passes (fresh state doesn't know about batch 1)
        let validation2 =
            TransactionValidator::validate_transaction_skip_signature(&batch2_tx, &state2);
        assert!(
            validation2.is_ok(),
            "Local validation passes on fresh state — this is expected"
        );

        // REMEDIATION: Global nonce registry REJECTS the replayed nonce
        let record2 = registry.record(&sender_id, batch2_tx.nonce, state2.batch_height);
        assert!(
            record2.is_err(),
            "REMEDIATED: Global nonce registry must reject replayed nonce 0"
        );

        let err_msg = record2.unwrap_err().to_string();
        assert!(
            err_msg.contains("already used"),
            "Error should mention nonce already used, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_s3_nonce_registry_cleanup() {
        let sender_id = AccountId::from_bytes([0xCC; 32]);
        let mut registry = NonceRegistry::new();

        // Record nonces at various batch heights
        registry.record(&sender_id, 0, 0).unwrap();
        registry.record(&sender_id, 1, 1).unwrap();
        registry.record(&sender_id, 2, 5).unwrap();
        assert_eq!(registry.len(), 3);

        // Cleanup with retention of 3 batches from height 5
        // cutoff = 5 - 3 = 2; entries at height 0 and 1 are evicted
        registry.cleanup(5, 3);
        assert_eq!(registry.len(), 1);

        // Nonce 0 at height 0 was evicted — can be re-used (in new context)
        let re_record = registry.record(&sender_id, 0, 6);
        assert!(
            re_record.is_ok(),
            "Evicted nonce should be recordable again"
        );
    }
}
