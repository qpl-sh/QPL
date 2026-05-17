// SPDX-License-Identifier: MIT OR Apache-2.0
//! STARK proof generation pipeline for settlement batches.
//!
//! Uses winterfell's FRI-based prover to generate proofs that
//! a batch of settlement transactions was executed correctly.

use thiserror::Error;
use winterfell::{
    crypto::DefaultRandomCoin,
    math::fields::f128::BaseElement,
    matrix::ColMatrix,
    DefaultConstraintEvaluator, DefaultTraceLde, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{SettlementAir, SettlementPublicInputs, TRACE_WIDTH};
use crate::trace::{build_settlement_trace, TraceResult};
use crate::types::{AccountBalance, RollupProof, RollupProofWithCommitment, RollupPublicInputs, RollupState, Transaction};

/// Security level for STARK proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum SecurityLevel {
    /// 96-bit security (faster, suitable for testing)
    #[default]
    Standard96,
    /// 128-bit security (production-grade)
    High128,
}


/// Configuration for the STARK prover
#[derive(Debug, Clone)]
pub struct ProofConfig {
    /// Security level
    pub security_level: SecurityLevel,
    /// Number of FRI queries
    pub num_queries: usize,
    /// Blowup factor for LDE
    pub blowup_factor: usize,
    /// FRI folding factor
    pub fri_folding_factor: usize,
}

impl ProofConfig {
    /// Create a new proof configuration
    pub fn new(security_level: SecurityLevel) -> Self {
        match security_level {
            SecurityLevel::Standard96 => Self {
                security_level,
                num_queries: 32,
                blowup_factor: 8,
                fri_folding_factor: 8,
            },
            SecurityLevel::High128 => Self {
                security_level,
                num_queries: 48,
                blowup_factor: 16,
                fri_folding_factor: 8,
            },
        }
    }

    /// Convert to winterfell ProofOptions
    pub fn to_proof_options(&self) -> ProofOptions {
        ProofOptions::new(
            self.num_queries,
            self.blowup_factor,
            0, // grinding_factor
            winterfell::FieldExtension::None,
            self.fri_folding_factor,
            31, // fri_max_remainder_degree
        )
    }
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self::new(SecurityLevel::High128)
    }
}

/// Errors that can occur during proof generation
#[derive(Debug, Error)]
pub enum ProverError {
    /// Error building the execution trace
    #[error("Trace building error: {0}")]
    TraceBuildError(String),

    /// Error during proof generation
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Empty transaction batch
    #[error("Empty transaction batch")]
    EmptyBatch,
}

/// STARK prover for settlement batches
pub struct SettlementProver {
    config: ProofConfig,
    options: ProofOptions,
}

impl SettlementProver {
    /// Create a new settlement prover with the given configuration
    pub fn new(config: ProofConfig) -> Self {
        let options = config.to_proof_options();
        Self { config, options }
    }

    /// Create a prover with default configuration
    pub fn with_default_config() -> Self {
        Self::new(ProofConfig::default())
    }

    /// Get the default proof configuration
    pub fn default_config() -> ProofConfig {
        ProofConfig::default()
    }

    /// Get the current configuration
    pub fn config(&self) -> &ProofConfig {
        &self.config
    }

    /// Prove a batch of settlement transactions
    ///
    /// # Arguments
    /// * `transactions` - The transactions to prove (must not be empty)
    /// * `initial_state` - The rollup state before transactions
    ///
    /// # Returns
    /// * `Ok(RollupProof)` - The generated STARK proof
    /// * `Err(ProverError)` - If proof generation fails
    ///
    /// # Errors
    /// Returns `ProverError::EmptyBatch` if the transaction list is empty.
    /// STARK proofs require non-trivial execution traces.
    pub fn prove_batch(
        &self,
        transactions: &[Transaction],
        initial_state: &RollupState,
    ) -> Result<RollupProof, ProverError> {
        // Empty batches cannot be proved - STARK requires non-trivial trace
        if transactions.is_empty() {
            return Err(ProverError::EmptyBatch);
        }

        // Get initial balances from first transaction's sender/receiver
        let sender_id = &transactions[0].sender;
        let receiver_id = &transactions[0].receiver;

        let sender_initial = initial_state
            .get_account(sender_id)
            .cloned()
            .unwrap_or_else(|| AccountBalance::new(0));
        let receiver_initial = initial_state
            .get_account(receiver_id)
            .cloned()
            .unwrap_or_else(|| AccountBalance::new(0));

        // Build execution trace
        let trace_result = build_settlement_trace(transactions, &sender_initial, &receiver_initial);

        // Create public inputs for the AIR
        let pub_inputs = SettlementPublicInputs::new(
            sender_initial.balance,
            receiver_initial.balance,
            sender_initial.nonce,
            trace_result.final_sender_balance,
            trace_result.final_receiver_balance,
            trace_result.final_nonce,
        );

        // Create the trace table
        let trace = self.create_trace_table(&trace_result)?;

        // Create the prover wrapper and generate proof
        let prover_wrapper = SettlementProverWrapper::new(self.options.clone(), pub_inputs.clone());

        let proof = prover_wrapper
            .prove(trace)
            .map_err(|e| ProverError::ProofGenerationError(e.to_string()))?;

        // Serialize the proof
        let proof_bytes = proof.to_bytes();

        // Create rollup public inputs for verification context
        let mut final_state = initial_state.clone();
        final_state.compute_state_root();

        let rollup_pub_inputs = RollupPublicInputs::new(
            initial_state.state_root,
            final_state.state_root,
            transactions.len() as u64,
            initial_state.batch_height + 1,
        );

        Ok(RollupProof::new(proof_bytes, rollup_pub_inputs))
    }

    /// Prove a batch of settlement transactions and return a committed proof.
    ///
    /// Identical to [`prove_batch`] but returns a [`RollupProofWithCommitment`]
    /// that binds the proof to the public inputs via a SHA-256 hash.
    pub fn prove_batch_with_commitment(
        &self,
        transactions: &[Transaction],
        initial_state: &RollupState,
    ) -> Result<(RollupProofWithCommitment, SettlementPublicInputs), ProverError> {
        if transactions.is_empty() {
            return Err(ProverError::EmptyBatch);
        }

        let sender_id = &transactions[0].sender;
        let receiver_id = &transactions[0].receiver;

        let sender_initial = initial_state
            .get_account(sender_id)
            .cloned()
            .unwrap_or_else(|| AccountBalance::new(0));
        let receiver_initial = initial_state
            .get_account(receiver_id)
            .cloned()
            .unwrap_or_else(|| AccountBalance::new(0));

        let trace_result = build_settlement_trace(transactions, &sender_initial, &receiver_initial);

        let pub_inputs = SettlementPublicInputs::new(
            sender_initial.balance,
            receiver_initial.balance,
            sender_initial.nonce,
            trace_result.final_sender_balance,
            trace_result.final_receiver_balance,
            trace_result.final_nonce,
        );

        let trace = self.create_trace_table(&trace_result)?;
        let prover_wrapper = SettlementProverWrapper::new(self.options.clone(), pub_inputs.clone());

        let proof = prover_wrapper
            .prove(trace)
            .map_err(|e| ProverError::ProofGenerationError(e.to_string()))?;

        let proof_bytes = proof.to_bytes();

        // Compute commitment binding the proof to these specific public inputs
        let public_inputs_hash = crate::types::compute_public_inputs_commitment(&pub_inputs);

        Ok((
            RollupProofWithCommitment::new(proof_bytes, public_inputs_hash),
            pub_inputs,
        ))
    }

    /// Create a TraceTable from the trace result
    fn create_trace_table(&self, trace_result: &TraceResult) -> Result<TraceTable<BaseElement>, ProverError> {
        // Verify we have the right number of columns
        if trace_result.trace_columns.len() != TRACE_WIDTH {
            return Err(ProverError::TraceBuildError(format!(
                "Expected {} columns, got {}",
                TRACE_WIDTH,
                trace_result.trace_columns.len()
            )));
        }

        // Create trace table from columns
        let trace = TraceTable::init(trace_result.trace_columns.clone());

        Ok(trace)
    }
}

/// Internal prover wrapper that implements winterfell's Prover trait
struct SettlementProverWrapper {
    options: ProofOptions,
    pub_inputs: SettlementPublicInputs,
}

impl SettlementProverWrapper {
    fn new(options: ProofOptions, pub_inputs: SettlementPublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for SettlementProverWrapper {
    type BaseField = BaseElement;
    type Air = SettlementAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = winterfell::crypto::hashers::Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: winterfell::math::FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: winterfell::math::FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SettlementPublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: winterfell::math::FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: winterfell::math::FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AccountId;

    fn make_test_transaction(sender_seed: u8, receiver_seed: u8, amount: u64, nonce: u64) -> Transaction {
        // For prover tests, we use the legacy new() method
        // Proof generation operates on already-validated transactions
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
    fn test_proof_config_security_levels() {
        let standard = ProofConfig::new(SecurityLevel::Standard96);
        assert_eq!(standard.num_queries, 32);
        assert_eq!(standard.blowup_factor, 8);

        let high = ProofConfig::new(SecurityLevel::High128);
        assert_eq!(high.num_queries, 48);
        assert_eq!(high.blowup_factor, 16);
    }

    #[test]
    fn test_proof_config_to_options() {
        let config = ProofConfig::new(SecurityLevel::Standard96);
        let options = config.to_proof_options();
        assert!(options.num_queries() > 0);
    }

    #[test]
    fn test_prover_creation() {
        let prover = SettlementProver::with_default_config();
        assert_eq!(prover.config().security_level, SecurityLevel::High128);
    }

    #[test]
    fn test_prove_single_transaction() {
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![make_test_transaction(1, 2, 100, 0)];

        let result = prover.prove_batch(&txs, &initial_state);
        assert!(result.is_ok(), "Proof generation should succeed: {:?}", result.err());

        let proof = result.unwrap();
        assert!(!proof.proof_bytes.is_empty(), "Proof bytes should not be empty");
        assert_eq!(proof.public_inputs.transaction_count, 1);
    }

    #[test]
    fn test_prove_empty_batch() {
        let prover = SettlementProver::with_default_config();
        let initial_state = RollupState::new();
        let txs: Vec<Transaction> = vec![];

        // Empty batches should return an error
        let result = prover.prove_batch(&txs, &initial_state);
        assert!(result.is_err(), "Empty batch should fail");
        assert!(matches!(result.unwrap_err(), ProverError::EmptyBatch));
    }

    #[test]
    fn test_prove_multiple_transactions() {
        let prover = SettlementProver::with_default_config();
        let initial_state = make_initial_state(1, 1000);
        let txs = vec![
            make_test_transaction(1, 2, 100, 0),
            make_test_transaction(1, 2, 150, 1),
            make_test_transaction(1, 2, 50, 2),
        ];

        let result = prover.prove_batch(&txs, &initial_state);
        assert!(result.is_ok(), "Multiple tx proof should succeed: {:?}", result.err());

        let proof = result.unwrap();
        assert_eq!(proof.public_inputs.transaction_count, 3);
    }
}
