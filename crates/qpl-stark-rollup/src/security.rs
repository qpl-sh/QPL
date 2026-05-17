// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Security Properties and Formal Verification Notes
//!
//! This module documents the security guarantees, threat model, and
//! formal properties of the QPL STARK Rollup.
//!
//! ## Proof System Security
//!
//! ### FRI Soundness
//!
//! The soundness error of our STARK proof system is bounded by approximately
//! `2^{-SECURITY_LEVEL_BITS}`. For the standard configuration (96-bit security),
//! this means the probability that a malicious prover can generate a valid proof
//! for an invalid statement is at most `2^{-96}`.
//!
//! The FRI (Fast Reed-Solomon Interactive Oracle Proofs of Proximity) protocol
//! ensures that any polynomial committed in the proof is actually low-degree.
//! This is the foundation of STARK proof security.
//!
//! ### Constraint Degrees and Blowup Factor
//!
//! Our AIR (Algebraic Intermediate Representation) uses constraints of degree 2:
//! - Balance transitions: `next_sender_bal - sender_bal + amount * valid = 0`
//! - Validity binary check: `valid * (1 - valid) = 0`
//!
//! The blowup factor (8x for standard, 16x for high security) determines the
//! ratio between the trace length and the evaluation domain. Higher blowup
//! factors provide better security but increase proof size.
//!
//! ### No Trusted Setup
//!
//! Unlike SNARK-based systems (Groth16, PLONK with trusted setup), our STARK
//! proofs require **no trusted setup ceremony**. All randomness is derived
//! from public parameters and Fiat-Shamir heuristics applied to the transcript.
//!
//! This eliminates the "toxic waste" problem and makes the system more suitable
//! for decentralized and high-security applications.
//!
//! ### Hash Function Security
//!
//! We use Blake3-256 as our cryptographic hash function for:
//! - Merkle tree commitments
//! - Fiat-Shamir challenges
//! - FRI layer commitments
//!
//! Blake3 provides 128-bit collision resistance and is significantly faster
//! than SHA-256 while maintaining comparable security guarantees.
//!
//! ### Field Extension Strategy
//!
//! The proof system operates over the 128-bit prime field `F_p` where
//! `p = 2^128 - 45 * 2^40 + 1`. This field provides:
//! - Efficient arithmetic on 64-bit platforms
//! - Sufficient security margin for cryptographic operations
//! - Smooth multiplicative group order for FFT-based polynomial operations
//!
//! ## Quantum Resistance
//!
//! ### Why STARKs are Quantum-Secure
//!
//! STARK proofs are believed to be quantum-secure because:
//!
//! 1. **Hash-based security**: The security relies on collision resistance of
//!    cryptographic hash functions. Grover's algorithm provides only a quadratic
//!    speedup for hash collision finding, so a 256-bit hash still provides
//!    128-bit security against quantum adversaries.
//!
//! 2. **No algebraic assumptions**: Unlike SNARKs which rely on elliptic curve
//!    discrete logarithm or pairing assumptions (broken by Shor's algorithm),
//!    STARKs rely only on hash functions and coding theory.
//!
//! 3. **Information-theoretic soundness**: The core FRI protocol has
//!    unconditional soundness (not relying on computational assumptions).
//!
//! ### ML-DSA Integration
//!
//! For transaction signatures, we integrate with ML-DSA (Module-Lattice
//! Digital Signature Algorithm, FIPS 204), providing:
//! - Post-quantum secure signatures
//! - Standardized by NIST for post-quantum cryptography
//! - Compatible with our STARK proof system
//!
//! ### Comparison with SNARK Approaches
//!
//! | Property | STARK (this system) | SNARK (Groth16/PLONK) |
//! |----------|--------------------|-----------------------|
//! | Quantum-secure | Yes | No (vulnerable to Shor) |
//! | Trusted setup | No | Yes (for some schemes) |
//! | Proof size | ~50-200 KB | ~200-500 bytes |
//! | Verification time | ~2-10 ms | ~1-5 ms |
//! | Prover time | Higher | Lower |
//!
//! ## Privacy Model (Private Validium)
//!
//! ### Off-Chain Data
//!
//! The following data remains off-chain (not posted to L1):
//! - Individual transaction details (sender, receiver, amount)
//! - Account balances and nonces
//! - Transaction signatures
//! - Historical transaction logs
//!
//! ### On-Chain Data
//!
//! The following data is posted on-chain:
//! - STARK proofs (proving correct execution)
//! - State root commitments (SHA-256 Merkle root)
//! - Batch metadata (height, transaction count)
//! - ValidiumCommitment (hash of off-chain data)
//!
//! ### Data Availability Assumptions
//!
//! In Private Validium mode, data availability is provided by:
//! - Designated node operators (banks, financial institutions)
//! - Data availability committees (DACs)
//! - Redundant storage across multiple parties
//!
//! If data becomes unavailable, users can still verify proof validity but
//! cannot reconstruct the full state. This is an acceptable trade-off for
//! financial institutions prioritizing privacy over trustless DA.
//!
//! ### Commitment Scheme Security
//!
//! State commitments use SHA-256 Merkle trees providing:
//! - **Binding**: Computationally infeasible to find two different states
//!   that produce the same commitment (collision resistance)
//! - **Hiding**: The commitment reveals nothing about the underlying state
//!   (preimage resistance)
//!
//! ## Threat Model
//!
//! ### Malicious Prover
//!
//! A malicious prover **cannot**:
//! - Generate a valid proof for an invalid state transition
//! - Steal funds by forging balance increases
//! - Replay old transactions (nonce protection)
//! - Create money from nothing (balance conservation constraints)
//!
//! The STARK proof system ensures that any accepted proof corresponds to
//! a valid execution trace satisfying all AIR constraints.
//!
//! ### Data Withholding
//!
//! In Validium mode, data availability relies on node operators:
//! - Operators could theoretically withhold transaction data
//! - Users must trust the data availability committee
//! - For high-trust environments (banks), this is acceptable
//! - For trustless operation, use ZK-Rollup mode (all data on-chain)
//!
//! ### Front-Running
//!
//! Transaction ordering is determined by the batch builder:
//! - The batch builder could theoretically reorder transactions
//! - This is mitigated by trusted batch builders (in permissioned settings)
//! - Future versions may implement encrypted mempools
//!
//! ### State Corruption
//!
//! State integrity is protected by:
//! - Merkle commitment scheme (any change detected via root mismatch)
//! - STARK proofs (only valid transitions accepted)
//! - Nonce sequencing (prevents replay attacks)

/// Security level achieved by the STARK proof system.
///
/// Standard configuration provides 96-bit security, meaning the probability
/// of a soundness error is approximately 2^{-96}.
pub const SECURITY_LEVEL_BITS: u32 = 96;

/// High security level configuration.
///
/// Provides 128-bit security for production deployments requiring
/// maximum security guarantees.
pub const HIGH_SECURITY_LEVEL_BITS: u32 = 128;

/// Maximum trace length supported by the prover.
///
/// This corresponds to 1 million execution steps (2^20).
/// Larger batches must be split across multiple proofs.
pub const MAX_TRACE_LENGTH: usize = 1 << 20;

/// Minimum trace length (must be power of 2 for FRI).
pub const MIN_TRACE_LENGTH: usize = 8;

/// Number of FRI queries for standard security.
pub const STANDARD_FRI_QUERIES: usize = 32;

/// Number of FRI queries for high security.
pub const HIGH_FRI_QUERIES: usize = 48;

/// Blowup factor for standard security LDE.
pub const STANDARD_BLOWUP_FACTOR: usize = 8;

/// Blowup factor for high security LDE.
pub const HIGH_BLOWUP_FACTOR: usize = 16;

/// Field modulus for the prime field F_p.
///
/// p = 2^128 - 45 * 2^40 + 1
/// This is a 128-bit prime with efficient arithmetic properties.
pub const FIELD_MODULUS_DESCRIPTION: &str = "2^128 - 45 * 2^40 + 1";

/// Hash function used for commitments and Fiat-Shamir.
pub const HASH_FUNCTION: &str = "Blake3-256";

/// Collision resistance of the hash function (bits).
pub const HASH_COLLISION_RESISTANCE_BITS: u32 = 128;

/// Estimated gas costs for on-chain proof verification.
///
/// These estimates are based on theoretical analysis of STARK verification
/// on Ethereum-compatible chains. Actual costs may vary based on:
/// - Proof size
/// - Number of FRI queries
/// - EVM implementation details
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasEstimates {
    /// Base verification cost (calldata + computation).
    ///
    /// This includes:
    /// - Calldata cost for proof bytes (~16 gas per byte)
    /// - Hash computations for Fiat-Shamir challenges
    /// - FRI verification computations
    pub base_verification: u64,

    /// Per-transaction overhead (amortized).
    ///
    /// Additional gas per transaction in the batch.
    /// This is minimal since proof size is roughly constant
    /// regardless of batch size.
    pub per_transaction: u64,

    /// State root update cost.
    ///
    /// Cost to update the on-chain state root storage slot.
    /// This is primarily the SSTORE opcode cost.
    pub state_root_update: u64,
}

impl GasEstimates {
    /// Create standard gas estimates for typical STARK verification.
    ///
    /// These estimates assume:
    /// - ~50KB proof size
    /// - Standard security level (96-bit)
    /// - Ethereum mainnet gas costs
    pub fn standard() -> Self {
        Self {
            base_verification: 350_000,  // ~350K gas for STARK verification
            per_transaction: 500,         // ~500 gas per tx amortized
            state_root_update: 20_000,    // ~20K gas for storage update
        }
    }

    /// Create gas estimates for high-security configuration.
    ///
    /// Higher security level requires more FRI queries and larger proofs.
    pub fn high_security() -> Self {
        Self {
            base_verification: 500_000,  // ~500K gas for high-security verification
            per_transaction: 600,         // ~600 gas per tx amortized
            state_root_update: 20_000,    // Same storage cost
        }
    }

    /// Create custom gas estimates.
    pub fn custom(base_verification: u64, per_transaction: u64, state_root_update: u64) -> Self {
        Self {
            base_verification,
            per_transaction,
            state_root_update,
        }
    }

    /// Estimate total gas cost for verifying a batch.
    ///
    /// # Arguments
    /// * `num_transactions` - Number of transactions in the batch
    ///
    /// # Returns
    /// Estimated total gas cost for on-chain verification.
    ///
    /// # Example
    /// ```
    /// use qpl_stark_rollup::security::GasEstimates;
    ///
    /// let estimates = GasEstimates::standard();
    /// let cost = estimates.estimate_batch_cost(100);
    /// assert!(cost > 350_000); // Base + per-tx + storage
    /// ```
    pub fn estimate_batch_cost(&self, num_transactions: usize) -> u64 {
        self.base_verification
            + (self.per_transaction * num_transactions as u64)
            + self.state_root_update
    }

    /// Estimate gas cost per transaction (for amortization analysis).
    ///
    /// # Arguments
    /// * `num_transactions` - Number of transactions in the batch
    ///
    /// # Returns
    /// Average gas cost per transaction.
    pub fn cost_per_transaction(&self, num_transactions: usize) -> u64 {
        if num_transactions == 0 {
            return 0;
        }
        self.estimate_batch_cost(num_transactions) / num_transactions as u64
    }
}

impl Default for GasEstimates {
    fn default() -> Self {
        Self::standard()
    }
}

/// Performance targets for the STARK rollup system.
///
/// These are aspirational targets based on typical hardware (modern 8-core CPU).
/// Actual performance depends on hardware, batch composition, and configuration.
pub mod performance_targets {
    /// Target proof generation time for 100-transaction batch.
    pub const PROOF_GENERATION_100TX_SECS: u64 = 10;

    /// Target proof verification time.
    pub const PROOF_VERIFICATION_MS: u64 = 5;

    /// Target maximum proof size in bytes.
    pub const MAX_PROOF_SIZE_BYTES: usize = 100_000;

    /// Target state transition execution time per transaction.
    pub const EXECUTION_PER_TX_US: u64 = 1000;
}

/// Security parameter documentation.
pub mod security_params {
    /// FRI folding factor (layers reduced per round).
    pub const FRI_FOLDING_FACTOR: usize = 8;

    /// Maximum degree of FRI remainder polynomial.
    pub const FRI_MAX_REMAINDER_DEGREE: usize = 31;

    /// Number of trace columns in the AIR.
    pub const TRACE_WIDTH: usize = 5;

    /// Maximum constraint degree in the AIR.
    pub const MAX_CONSTRAINT_DEGREE: usize = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_estimate_calculation() {
        let estimates = GasEstimates::standard();

        // Base cost for 0 transactions
        let cost_0 = estimates.estimate_batch_cost(0);
        assert_eq!(cost_0, 350_000 + 0 + 20_000);

        // Cost for 100 transactions
        let cost_100 = estimates.estimate_batch_cost(100);
        assert_eq!(cost_100, 350_000 + (500 * 100) + 20_000);
        assert_eq!(cost_100, 420_000);

        // Cost for 1000 transactions
        let cost_1000 = estimates.estimate_batch_cost(1000);
        assert_eq!(cost_1000, 350_000 + (500 * 1000) + 20_000);
        assert_eq!(cost_1000, 870_000);
    }

    #[test]
    fn test_gas_estimate_per_transaction() {
        let estimates = GasEstimates::standard();

        // More transactions = lower per-tx cost (amortization)
        let per_tx_10 = estimates.cost_per_transaction(10);
        let per_tx_100 = estimates.cost_per_transaction(100);
        let per_tx_1000 = estimates.cost_per_transaction(1000);

        assert!(per_tx_10 > per_tx_100);
        assert!(per_tx_100 > per_tx_1000);
    }

    #[test]
    fn test_gas_estimate_zero_transactions() {
        let estimates = GasEstimates::standard();
        assert_eq!(estimates.cost_per_transaction(0), 0);
    }

    #[test]
    fn test_security_constants() {
        // Verify constants are reasonable values
        assert!(SECURITY_LEVEL_BITS >= 80);
        assert!(SECURITY_LEVEL_BITS <= 256);

        assert!(HIGH_SECURITY_LEVEL_BITS > SECURITY_LEVEL_BITS);

        assert!(MAX_TRACE_LENGTH.is_power_of_two());
        assert!(MIN_TRACE_LENGTH.is_power_of_two());
        assert!(MAX_TRACE_LENGTH > MIN_TRACE_LENGTH);

        assert!(STANDARD_FRI_QUERIES > 0);
        assert!(HIGH_FRI_QUERIES > STANDARD_FRI_QUERIES);

        assert!(STANDARD_BLOWUP_FACTOR.is_power_of_two());
        assert!(HIGH_BLOWUP_FACTOR.is_power_of_two());
        assert!(HIGH_BLOWUP_FACTOR > STANDARD_BLOWUP_FACTOR);
    }

    #[test]
    fn test_high_security_estimates() {
        let standard = GasEstimates::standard();
        let high = GasEstimates::high_security();

        // High security should cost more
        assert!(high.base_verification > standard.base_verification);

        let cost_std = standard.estimate_batch_cost(100);
        let cost_high = high.estimate_batch_cost(100);
        assert!(cost_high > cost_std);
    }

    #[test]
    fn test_custom_estimates() {
        let custom = GasEstimates::custom(100_000, 200, 15_000);

        assert_eq!(custom.base_verification, 100_000);
        assert_eq!(custom.per_transaction, 200);
        assert_eq!(custom.state_root_update, 15_000);

        let cost = custom.estimate_batch_cost(50);
        assert_eq!(cost, 100_000 + (200 * 50) + 15_000);
    }

    #[test]
    fn test_default_estimates() {
        let default_est = GasEstimates::default();
        let standard = GasEstimates::standard();

        assert_eq!(default_est.base_verification, standard.base_verification);
        assert_eq!(default_est.per_transaction, standard.per_transaction);
        assert_eq!(default_est.state_root_update, standard.state_root_update);
    }

    #[test]
    fn test_performance_targets() {
        use performance_targets::*;

        // Verify targets are reasonable
        assert!(PROOF_GENERATION_100TX_SECS <= 60); // Under 1 minute
        assert!(PROOF_VERIFICATION_MS <= 100); // Under 100ms
        assert!(MAX_PROOF_SIZE_BYTES <= 1_000_000); // Under 1MB
        assert!(EXECUTION_PER_TX_US <= 10_000); // Under 10ms per tx
    }

    #[test]
    fn test_security_params() {
        use security_params::*;

        assert!(FRI_FOLDING_FACTOR.is_power_of_two());
        assert!(FRI_MAX_REMAINDER_DEGREE > 0);
        assert!(TRACE_WIDTH > 0);
        assert!(MAX_CONSTRAINT_DEGREE >= 1);
    }
}
