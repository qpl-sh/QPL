// SPDX-License-Identifier: MIT OR Apache-2.0
//! # QPL Crypto
//!
//! Unified post-quantum cryptography library for QPL (Quantum Proof Layer).
//! Implements NIST-standardized PQC primitives as a reusable, blockchain-agnostic library.
//!
//! ## Modules
//! - [`ml_dsa`] - ML-DSA-65 (FIPS 204) digital signatures using Dilithium3
//! - [`ml_kem`] - ML-KEM-1024 (FIPS 203) key encapsulation using Kyber1024
//! - [`algorithm`] - Algorithmic agility layer (Ed25519, ECDSA-P256, ML-DSA-65)
//! - [`hsm`] - Hardware Security Module abstraction layer
//! - [`vectors`] - Wycheproof-style test vector framework
//!
//! ## Security Properties
//! - All cryptographic operations use constant-time implementations
//! - Secret keys are zeroized on drop to prevent memory leakage
//! - Side-channel resistant through pqcrypto reference implementations
//! - HSM abstraction for production-grade key management
//! - Algorithmic agility lets operators select HSM-native algorithms today and
//!   migrate to ML-DSA when HSM firmware ships FIPS 204 support

pub mod algorithm;
pub mod hsm;
pub mod ml_dsa;
pub mod ml_kem;
pub mod vectors;

// Re-export core types at crate root for convenience
pub use algorithm::{AgilePublicKey, AgileSignature, AgilityError, SignatureAlgorithm};
#[cfg(feature = "cloudhsm")]
pub use hsm::Pkcs11HsmProvider;
pub use hsm::{HsmError, HsmProvider, KeyHandle, KeyType, SoftHsmProvider};
pub use ml_dsa::{MlDsaError, MlDsaKeyPair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use ml_kem::{
    MlKemCiphertext, MlKemError, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, SharedSecret,
};
