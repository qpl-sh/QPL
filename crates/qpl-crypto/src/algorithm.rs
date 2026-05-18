// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Algorithmic Agility
//!
//! This module provides the cryptographic agility layer that allows QPL operators
//! to choose signing algorithms based on the capabilities of their HSM hardware.
//!
//! ## The Problem It Solves
//!
//! As of 2026, no commercial HSM ships native FIPS 204 (ML-DSA) or FIPS 203 (ML-KEM)
//! firmware. If QPL only supported ML-DSA, the signing shard would have to be
//! unwrapped from the HSM into process memory to perform signatures, breaking the
//! HSM hardware boundary on every signing operation.
//!
//! ## The Solution
//!
//! Algorithmic agility lets each operator advertise the algorithms its HSM can
//! perform **natively** (without the key ever leaving the HSM) and lets clients
//! select the strongest available option for the threat model:
//!
//! | Algorithm   | HSM-Native (2026) | Quantum-Safe | Use Case                          |
//! |-------------|-------------------|--------------|-----------------------------------|
//! | Ed25519     | Yes               | No           | Production GTM today              |
//! | ECDSA-P256  | Yes (FIPS 186-4)  | No           | Compliance (FIPS 140-3)           |
//! | ML-DSA-65   | No (software)     | Yes          | Future-proofing / migration       |
//!
//! ## Migration Path
//!
//! 1. **Day 1 (GTM)**: Operators run Ed25519 or ECDSA-P256 keys with the signing
//!    key never leaving the HSM. The threshold property (t-of-n shards across
//!    independent operators) provides multi-party security.
//! 2. **Migration**: When HSM vendors ship FIPS 204 firmware, operators rotate
//!    to ML-DSA-65 keys without changing any application code.
//! 3. **STARK Layer**: The settlement layer uses post-quantum FRI/hash-based
//!    proofs from day one, so settlement integrity is quantum-safe regardless
//!    of which signing algorithm individual operators run.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A signing algorithm supported by the QPL agility layer.
///
/// Operators advertise which algorithms their HSM can run natively; clients
/// select among them based on policy (e.g., "must be HSM-native" or
/// "must be post-quantum").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032 EdDSA over Curve25519).
    /// HSM-native on virtually all modern HSMs. Classical security only.
    Ed25519,
    /// ECDSA over NIST P-256 (FIPS 186-4).
    /// HSM-native on FIPS 140-3 certified hardware. Classical security only.
    EcdsaP256,
    /// ML-DSA-65 (FIPS 204, Dilithium3).
    /// Software-only as of 2026; will become HSM-native when vendors ship FIPS 204
    /// firmware. Post-quantum secure.
    MlDsa65,
}

impl SignatureAlgorithm {
    /// Returns true if this algorithm provides post-quantum security.
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, SignatureAlgorithm::MlDsa65)
    }

    /// Returns true if commercial HSM firmware natively supports this algorithm,
    /// meaning the secret key never has to leave the HSM boundary to sign.
    pub fn is_hsm_native(&self) -> bool {
        matches!(
            self,
            SignatureAlgorithm::Ed25519 | SignatureAlgorithm::EcdsaP256
        )
    }

    /// Returns the canonical signature size in bytes for this algorithm.
    pub fn signature_size(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519 => 64,
            SignatureAlgorithm::EcdsaP256 => 64, // r || s, 32 bytes each
            SignatureAlgorithm::MlDsa65 => crate::ml_dsa::SIGNATURE_LENGTH,
        }
    }

    /// Returns the canonical public-key size in bytes for this algorithm.
    pub fn public_key_size(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519 => 32,
            SignatureAlgorithm::EcdsaP256 => 33, // SEC1 compressed
            SignatureAlgorithm::MlDsa65 => crate::ml_dsa::PUBLIC_KEY_LENGTH,
        }
    }

    /// String identifier suitable for protocol negotiation.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256 => "ecdsa-p256",
            SignatureAlgorithm::MlDsa65 => "ml-dsa-65",
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A signature tagged with its algorithm.
///
/// This is the canonical wire format for QPL agile signatures. Verifiers
/// dispatch on `algorithm` to pick the right verification routine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgileSignature {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl AgileSignature {
    /// Constructs a new agile signature, validating the byte length matches
    /// the algorithm's expected signature size.
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Result<Self, AgilityError> {
        if bytes.len() != algorithm.signature_size() {
            return Err(AgilityError::InvalidSignatureLength {
                expected: algorithm.signature_size(),
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }
}

/// A public key tagged with its algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgilePublicKey {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl AgilePublicKey {
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Result<Self, AgilityError> {
        if bytes.len() != algorithm.public_key_size() {
            return Err(AgilityError::InvalidPublicKeyLength {
                expected: algorithm.public_key_size(),
                got: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }
}

/// Errors specific to the agility layer.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AgilityError {
    #[error("Algorithm {0} is not supported by this provider")]
    AlgorithmNotSupported(SignatureAlgorithm),

    #[error("Invalid signature length: expected {expected} bytes, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },

    #[error("Invalid public key length: expected {expected} bytes, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },

    #[error("Algorithm mismatch: key is {key_alg}, signature is {sig_alg}")]
    AlgorithmMismatch {
        key_alg: SignatureAlgorithm,
        sig_alg: SignatureAlgorithm,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_quantum_classification() {
        assert!(SignatureAlgorithm::MlDsa65.is_post_quantum());
        assert!(!SignatureAlgorithm::Ed25519.is_post_quantum());
        assert!(!SignatureAlgorithm::EcdsaP256.is_post_quantum());
    }

    #[test]
    fn test_hsm_native_classification() {
        // 2026 reality: only classical algorithms are HSM-native
        assert!(SignatureAlgorithm::Ed25519.is_hsm_native());
        assert!(SignatureAlgorithm::EcdsaP256.is_hsm_native());
        assert!(!SignatureAlgorithm::MlDsa65.is_hsm_native());
    }

    #[test]
    fn test_signature_sizes() {
        assert_eq!(SignatureAlgorithm::Ed25519.signature_size(), 64);
        assert_eq!(SignatureAlgorithm::EcdsaP256.signature_size(), 64);
        assert_eq!(
            SignatureAlgorithm::MlDsa65.signature_size(),
            crate::ml_dsa::SIGNATURE_LENGTH
        );
    }

    #[test]
    fn test_agile_signature_length_validation() {
        let ok = AgileSignature::new(SignatureAlgorithm::Ed25519, vec![0u8; 64]);
        assert!(ok.is_ok());

        let bad = AgileSignature::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]);
        assert!(matches!(
            bad,
            Err(AgilityError::InvalidSignatureLength { .. })
        ));
    }

    #[test]
    fn test_agile_public_key_length_validation() {
        let ok = AgilePublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 32]);
        assert!(ok.is_ok());

        let bad = AgilePublicKey::new(SignatureAlgorithm::Ed25519, vec![0u8; 64]);
        assert!(matches!(
            bad,
            Err(AgilityError::InvalidPublicKeyLength { .. })
        ));
    }

    #[test]
    fn test_string_identifiers() {
        assert_eq!(SignatureAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(SignatureAlgorithm::EcdsaP256.as_str(), "ecdsa-p256");
        assert_eq!(SignatureAlgorithm::MlDsa65.as_str(), "ml-dsa-65");
    }

    #[test]
    fn test_serde_roundtrip() {
        let algo = SignatureAlgorithm::Ed25519;
        let json = serde_json::to_string(&algo).unwrap();
        let back: SignatureAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(algo, back);
    }
}
