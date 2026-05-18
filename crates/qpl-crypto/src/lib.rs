// SPDX-License-Identifier: MIT OR Apache-2.0
//! # QPL Crypto
//!
//! Unified post-quantum cryptography library for Ligare (QPL).
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

pub mod ml_dsa;
pub mod ml_kem;
pub mod algorithm;
pub mod hsm;
pub mod vectors;

// Re-export core types at crate root for convenience
pub use ml_dsa::{MlDsaKeyPair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaError};
pub use ml_kem::{MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, SharedSecret, MlKemError};
pub use algorithm::{AgilePublicKey, AgileSignature, AgilityError, SignatureAlgorithm};
pub use hsm::{HsmProvider, SoftHsmProvider, KeyHandle, KeyType, HsmError};
#[cfg(feature = "cloudhsm")]
pub use hsm::Pkcs11HsmProvider;
