// SPDX-License-Identifier: MIT OR Apache-2.0
//! # QPL STARK Rollup
//!
//! Native FRI-based zk-STARK rollup for QPL (Quantum Proof Layer).
//! Implements quantum-secure settlement with Private Validium mode.
//!
//! ## Architecture
//!
//! This crate provides a complete Layer-2 rollup solution using FRI-based
//! zk-STARKs (via winterfell). Key design principles:
//!
//! - **No trusted setup**: All proofs are hash-based using FRI commitments
//! - **No SNARKs**: Uses only FRI (Fast Reed-Solomon Interactive Oracle Proofs)
//! - **Private Validium**: Sensitive bank data stays off-chain; only proofs posted on-chain
//! - **Quantum-secure**: Integrates with qpl-crypto's ML-DSA signatures
//! - **Transaction privacy**: Hash commitments protect individual transaction details
//!
//! ## Modules
//!
//! - [`types`] - Core domain types (Transaction, RollupState, AccountBalance, etc.)
//! - [`air`] - AIR (Algebraic Intermediate Representation) constraints for settlement
//! - [`trace`] - Execution trace builder for transaction batches
//! - [`prover`] - STARK proof generation pipeline
//! - [`verifier`] - Proof verification
//! - [`executor`] - Transaction execution and state machine
//! - [`validium`] - Private Validium off-chain data management
//! - [`crypto`] - ML-DSA integration and hash commitments

pub mod air;
pub mod crypto;
pub mod executor;
pub mod prover;
pub mod security;
pub mod trace;
pub mod types;
pub mod validium;
pub mod verifier;

#[cfg(test)]
mod red_team_tests;

// Re-export core types at crate root
pub use executor::{
    CdaEngineHook, ExecutionError, NoOpCdaHook, NonceRegistry, StateExecutor,
    StateExecutorWithHooks, TransactionValidator,
};
pub use prover::{ProofConfig, ProverError, SecurityLevel, SettlementProver};
pub use security::GasEstimates;
pub use types::{
    compute_public_inputs_commitment, AccountBalance, AccountId, BatchResult, RollupProof,
    RollupProofWithCommitment, RollupPublicInputs, RollupState, Transaction,
};
pub use validium::{
    create_commitment, InMemoryValidiumStore, ValidiumCommitment, ValidiumData, ValidiumError,
    ValidiumStore,
};
pub use verifier::SecurityLevel as VerifierSecurityLevel;
pub use verifier::{
    is_proof_well_formed, proof_size, verify_proof, verify_proof_with_commitment,
    verify_proof_with_options, verify_proof_with_security_level, VerifierError,
};
