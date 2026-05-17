// SPDX-License-Identifier: MIT OR Apache-2.0
//! # QPL STARK Rollup
//!
//! Native FRI-based zk-STARK rollup for Ligare (QPL).
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

pub mod types;
pub mod air;
pub mod trace;
pub mod prover;
pub mod verifier;
pub mod executor;
pub mod validium;
pub mod crypto;
pub mod security;

#[cfg(test)]
mod red_team_tests;

// Re-export core types at crate root
pub use types::{Transaction, RollupState, AccountBalance, RollupProof, RollupProofWithCommitment, RollupPublicInputs, BatchResult, AccountId, compute_public_inputs_commitment};
pub use validium::{ValidiumCommitment, ValidiumData, ValidiumStore, InMemoryValidiumStore, ValidiumError, create_commitment};
pub use prover::{SettlementProver, ProofConfig, ProverError, SecurityLevel};
pub use verifier::{verify_proof, verify_proof_with_options, verify_proof_with_security_level, verify_proof_with_commitment, VerifierError, is_proof_well_formed, proof_size};
pub use verifier::SecurityLevel as VerifierSecurityLevel;
pub use executor::{StateExecutor, TransactionValidator, ExecutionError, CdaEngineHook, NoOpCdaHook, StateExecutorWithHooks, NonceRegistry};
pub use security::GasEstimates;
