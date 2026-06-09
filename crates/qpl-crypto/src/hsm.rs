// SPDX-License-Identifier: MIT OR Apache-2.0
//! # PQC HSM Abstraction Layer
//!
//! This module provides a hardware security module (HSM) abstraction layer for
//! cryptographic operations in QPL, with **algorithmic agility** so that
//! operators can choose the strongest algorithm their HSM supports natively.
//!
//! ## Architecture
//!
//! The module defines an [`HsmProvider`] trait that abstracts HSM operations for:
//! - **Ed25519** (RFC 8032): HSM-native on virtually all production HSMs today
//! - **ECDSA-P256** (FIPS 186-4): HSM-native on FIPS 140-3 certified HSMs
//! - **ML-DSA (FIPS 204)**: Module-Lattice digital signatures (post-quantum)
//! - **ML-KEM (FIPS 203)**: Module-Lattice key encapsulation (post-quantum)
//!
//! ## Algorithmic Agility — Why It Matters
//!
//! As of 2026, no commercial HSM ships native FIPS 204 (ML-DSA) firmware.
//! Without agility, signing with ML-DSA would require unwrapping the shard
//! into process memory, breaking the HSM hardware boundary.
//!
//! With agility, each operator advertises which algorithms its HSM supports
//! natively. Production operators today select **Ed25519** or **ECDSA-P256**,
//! where the signing key genuinely never leaves the HSM. When HSM vendors ship
//! FIPS 204 firmware, operators rotate to ML-DSA-65 — no application code changes.
//!
//! See [`crate::algorithm`] for the agility types.
//!
//! ## Threshold + HSM Security Model
//!
//! In QPL's threshold signing architecture, the full private key **never exists**
//! in any single location. Each operator holds only a signing shard (produced via
//! DKG/Shamir secret sharing). The HSM stores and protects this shard — not a
//! complete private key.
//!
//! This means the security boundary has two independent layers:
//!
//! 1. **Threshold property** — Even if an attacker compromises one operator's
//!    shard entirely, they cannot produce a valid signature without obtaining
//!    t-of-n shards from separate operators on different infrastructure.
//! 2. **HSM boundary** — When the operator runs an HSM-native algorithm
//!    (Ed25519 or ECDSA-P256), the shard never leaves the HSM at all. When
//!    running ML-DSA in software-fallback mode, the shard is AES-256 wrapped
//!    at rest and zeroized after each use.
//!
//! The STARK rollup settlement layer uses post-quantum FRI/hash-based proofs
//! independently of the operator signing algorithm, so settlement integrity is
//! quantum-safe regardless of which signing algorithm operators run.
//!
//! ## Providers
//!
//! - [`SoftHsmProvider`]: Software-based implementation for development and testing.
//!   **WARNING**: This does NOT provide real HSM security guarantees and should
//!   only be used in development/testing environments.
//!
//! - [`Pkcs11HsmProvider`]: PKCS#11-based provider for AWS CloudHSM, SoftHSM2, etc.
//!   For Ed25519 and ECDSA-P256, all crypto operations are performed inside the
//!   HSM (key never leaves). For ML-DSA, uses the hybrid wrapping-key pattern
//!   until firmware adds native FIPS 204 mechanisms.
//!   (feature-gated behind `cloudhsm`)
//! - [`ThalesHsmProvider`]: Placeholder for Thales Luna HSM integration (not yet implemented)
//!
//! ## Example
//!
//! ```rust,no_run
//! use qpl_crypto::hsm::{HsmProvider, SoftHsmProvider};
//! use qpl_crypto::algorithm::SignatureAlgorithm;
//!
//! #[tokio::main]
//! async fn main() {
//!     let hsm = SoftHsmProvider::new();
//!
//!     // Pick HSM-native algorithm for production GTM today
//!     let handle = hsm
//!         .generate_signing_keypair(SignatureAlgorithm::Ed25519)
//!         .await
//!         .expect("keygen failed");
//!
//!     let message = b"Hello, agile world!";
//!     let signature = hsm.sign_agile(&handle, message).await.expect("sign failed");
//!     let valid = hsm.verify_agile(&handle, message, &signature).await.expect("verify failed");
//!     assert!(valid);
//! }
//! ```

use async_trait::async_trait;
// FIPS 204 ML-DSA-65 backed by `pqcrypto-mldsa`. The legacy `pqcrypto-dilithium`
// crate (RUSTSEC-2024-0380) is no longer used; the module path `mldsa65` is the
// successor to `dilithium3` and produces byte-identical key/signature material.
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-exports from ml_dsa for convenience
pub use crate::ml_dsa::{
    MlDsaError, MlDsaKeyPair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    PUBLIC_KEY_LENGTH as ML_DSA_PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH as ML_DSA_SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH as ML_DSA_SIGNATURE_LENGTH,
};

// Re-exports from ml_kem for convenience
pub use crate::ml_kem::{
    MlKemCiphertext, MlKemError, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey, SharedSecret,
    CIPHERTEXT_BYTES as ML_KEM_CIPHERTEXT_BYTES,
    PUBLIC_KEY_BYTES as ML_KEM_PUBLIC_KEY_BYTES,
    SECRET_KEY_BYTES as ML_KEM_SECRET_KEY_BYTES,
    SHARED_SECRET_BYTES as ML_KEM_SHARED_SECRET_BYTES,
};

/// Errors that can occur during HSM operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HsmError {
    /// Error during key generation.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Error during signing operation.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Error during signature verification.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Error during key encapsulation.
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    /// Error during key decapsulation.
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    /// The requested key was not found in the HSM.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Error from the underlying HSM provider.
    #[error("Provider error: {0}")]
    ProviderError(String),
}

/// The type of cryptographic key stored in the HSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// ML-DSA (Module-Lattice Digital Signature Algorithm) key for signing
    MlDsa,
    /// ML-KEM (Module-Lattice Key Encapsulation Mechanism) key for key exchange
    MlKem,
    /// Ed25519 (RFC 8032) signing key — HSM-native on most production HSMs
    Ed25519,
    /// ECDSA-P256 (FIPS 186-4) signing key — HSM-native on FIPS 140-3 hardware
    EcdsaP256,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::MlDsa => write!(f, "ML-DSA"),
            KeyType::MlKem => write!(f, "ML-KEM"),
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::EcdsaP256 => write!(f, "ECDSA-P256"),
        }
    }
}

impl KeyType {
    /// Returns the matching [`crate::algorithm::SignatureAlgorithm`], if this
    /// key type represents a signing algorithm.
    pub fn as_signature_algorithm(&self) -> Option<crate::algorithm::SignatureAlgorithm> {
        use crate::algorithm::SignatureAlgorithm;
        match self {
            KeyType::MlDsa => Some(SignatureAlgorithm::MlDsa65),
            KeyType::Ed25519 => Some(SignatureAlgorithm::Ed25519),
            KeyType::EcdsaP256 => Some(SignatureAlgorithm::EcdsaP256),
            KeyType::MlKem => None,
        }
    }
}

impl From<crate::algorithm::SignatureAlgorithm> for KeyType {
    fn from(algo: crate::algorithm::SignatureAlgorithm) -> Self {
        use crate::algorithm::SignatureAlgorithm;
        match algo {
            SignatureAlgorithm::MlDsa65 => KeyType::MlDsa,
            SignatureAlgorithm::Ed25519 => KeyType::Ed25519,
            SignatureAlgorithm::EcdsaP256 => KeyType::EcdsaP256,
        }
    }
}

/// A handle to a key stored in the HSM.
///
/// Key handles are opaque identifiers that reference keys stored within the HSM.
/// They do not contain the actual key material and can be safely logged or transmitted.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle {
    /// Unique identifier for the key
    id: String,
    /// The type of key (ML-DSA or ML-KEM)
    key_type: KeyType,
}

impl KeyHandle {
    /// Creates a new key handle.
    pub fn new(id: String, key_type: KeyType) -> Self {
        Self { id, key_type }
    }

    /// Returns the unique identifier for this key.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the type of key this handle references.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyHandle")
            .field("id", &self.id)
            .field("key_type", &self.key_type)
            .finish()
    }
}

/// Trait defining HSM operations for post-quantum cryptography.
///
/// Implementations of this trait provide secure key storage and cryptographic
/// operations for ML-DSA (digital signatures) and ML-KEM (key encapsulation).
///
/// # Security Considerations
///
/// - Keys are referenced by handles, not raw bytes
/// - All operations are performed within the HSM boundary
/// - Secret keys never leave the HSM in production implementations
#[async_trait]
pub trait HsmProvider: Send + Sync {
    /// Generates an ML-DSA keypair and returns a handle to the stored key.
    ///
    /// The keypair is generated within the HSM and stored securely.
    /// Only a handle to the key is returned.
    async fn generate_ml_dsa_keypair(&self) -> Result<KeyHandle, HsmError>;

    /// Signs a message using the ML-DSA key referenced by the handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to an ML-DSA key
    /// * `message` - The message to sign
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::KeyNotFound`] if the handle doesn't reference a valid key.
    /// Returns [`HsmError::SigningFailed`] if the key type is not ML-DSA or signing fails.
    async fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<crate::ml_dsa::MlDsaSignature, HsmError>;

    /// Verifies a signature using the ML-DSA key referenced by the handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to an ML-DSA key
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the signature is valid
    /// * `Ok(false)` if the signature is invalid
    /// * `Err(...)` if verification could not be performed
    async fn verify(
        &self,
        handle: &KeyHandle,
        message: &[u8],
        signature: &crate::ml_dsa::MlDsaSignature,
    ) -> Result<bool, HsmError>;

    /// Generates an ML-KEM keypair and returns a handle to the stored key.
    ///
    /// The keypair is generated within the HSM and stored securely.
    /// Only a handle to the key is returned.
    async fn generate_ml_kem_keypair(&self) -> Result<KeyHandle, HsmError>;

    /// Encapsulates a shared secret using the ML-KEM public key referenced by the handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to an ML-KEM key
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret). The ciphertext should be sent to
    /// the owner of the corresponding secret key.
    async fn encapsulate(
        &self,
        handle: &KeyHandle,
    ) -> Result<(crate::ml_kem::MlKemCiphertext, crate::ml_kem::SharedSecret), HsmError>;

    /// Decapsulates a ciphertext using the ML-KEM secret key referenced by the handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to an ML-KEM key
    /// * `ciphertext` - The ciphertext to decapsulate
    ///
    /// # Returns
    ///
    /// The shared secret that was encapsulated.
    async fn decapsulate(
        &self,
        handle: &KeyHandle,
        ciphertext: &crate::ml_kem::MlKemCiphertext,
    ) -> Result<crate::ml_kem::SharedSecret, HsmError>;

    /// Deletes a key from the HSM.
    ///
    /// # Arguments
    ///
    /// * `handle` - Handle to the key to delete
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::KeyNotFound`] if the handle doesn't reference a valid key.
    async fn delete_key(&self, handle: &KeyHandle) -> Result<(), HsmError>;

    // ──────────────────────────────────────────────────────────────────────
    // Algorithmic Agility API
    // ──────────────────────────────────────────────────────────────────────
    //
    // Algorithm-agnostic surface used by the QPL operator network. Default
    // implementations dispatch to ML-DSA only; providers supporting classical
    // algorithms (Ed25519, ECDSA-P256) MUST override these methods.

    /// Returns the list of signing algorithms this provider supports.
    fn supported_signing_algorithms(&self) -> Vec<crate::algorithm::SignatureAlgorithm> {
        vec![crate::algorithm::SignatureAlgorithm::MlDsa65]
    }

    /// Generates a signing keypair for the requested algorithm.
    async fn generate_signing_keypair(
        &self,
        algorithm: crate::algorithm::SignatureAlgorithm,
    ) -> Result<KeyHandle, HsmError> {
        use crate::algorithm::SignatureAlgorithm;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => self.generate_ml_dsa_keypair().await,
            other => Err(HsmError::ProviderError(format!(
                "Algorithm {} is not supported by this HSM provider",
                other
            ))),
        }
    }

    /// Signs a message and returns an algorithm-tagged signature.
    async fn sign_agile(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<crate::algorithm::AgileSignature, HsmError> {
        use crate::algorithm::{AgileSignature, SignatureAlgorithm};
        match handle.key_type() {
            KeyType::MlDsa => {
                let sig = self.sign(handle, message).await?;
                AgileSignature::new(SignatureAlgorithm::MlDsa65, sig.as_bytes().to_vec())
                    .map_err(|e| HsmError::SigningFailed(e.to_string()))
            }
            other => Err(HsmError::SigningFailed(format!(
                "Key type {} not supported by this provider's agile sign API",
                other
            ))),
        }
    }

    /// Verifies an agile signature.
    async fn verify_agile(
        &self,
        handle: &KeyHandle,
        message: &[u8],
        signature: &crate::algorithm::AgileSignature,
    ) -> Result<bool, HsmError> {
        use crate::algorithm::SignatureAlgorithm;
        let key_alg = handle.key_type().as_signature_algorithm().ok_or_else(|| {
            HsmError::VerificationFailed(format!("Key {} is not a signing key", handle.id()))
        })?;
        if key_alg != signature.algorithm {
            return Err(HsmError::VerificationFailed(format!(
                "Algorithm mismatch: key is {}, signature is {}",
                key_alg, signature.algorithm
            )));
        }
        match signature.algorithm {
            SignatureAlgorithm::MlDsa65 => {
                let ml_sig = crate::ml_dsa::MlDsaSignature::from_bytes(&signature.bytes)
                    .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
                self.verify(handle, message, &ml_sig).await
            }
            other => Err(HsmError::VerificationFailed(format!(
                "Algorithm {} not supported by this provider's agile verify API",
                other
            ))),
        }
    }

    /// Exports the public key portion of a signing key.
    async fn export_public_key(
        &self,
        _handle: &KeyHandle,
    ) -> Result<crate::algorithm::AgilePublicKey, HsmError> {
        Err(HsmError::ProviderError(
            "Public key export not implemented for this provider".to_string(),
        ))
    }
}

/// Internal storage for ML-DSA keypair bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredMlDsaKey {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

/// Internal storage for ML-KEM keypair bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredMlKemKey {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

/// Internal storage for an Ed25519 keypair (RFC 8032).
#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredEd25519Key {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
}

/// Internal storage for an ECDSA-P256 keypair (FIPS 186-4).
#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredEcdsaP256Key {
    /// SEC1 compressed public key (33 bytes)
    public_key_bytes: Vec<u8>,
    /// Big-endian scalar (32 bytes)
    secret_key_bytes: Vec<u8>,
}

/// Internal enum to hold different key types.
enum StoredKey {
    MlDsa(StoredMlDsaKey),
    MlKem(StoredMlKemKey),
    Ed25519(StoredEd25519Key),
    EcdsaP256(StoredEcdsaP256Key),
}

/// Software-based HSM provider for development and testing.
///
/// # WARNING
///
/// This implementation stores keys in memory and does **NOT** provide real HSM
/// security guarantees. It should only be used for:
///
/// - Development and testing
/// - Integration testing before HSM hardware is available
/// - Demonstrating the HSM abstraction API
///
/// For production use, implement [`HsmProvider`] using a real HSM via PKCS#11.
pub struct SoftHsmProvider {
    /// Key storage: maps key IDs to stored keys
    keys: RwLock<HashMap<String, StoredKey>>,
    /// Counter for generating unique key IDs
    key_counter: AtomicU64,
}

impl SoftHsmProvider {
    /// Creates a new software HSM provider.
    ///
    /// # Example
    ///
    /// ```rust
    /// use qpl_crypto::hsm::SoftHsmProvider;
    ///
    /// let hsm = SoftHsmProvider::new();
    /// ```
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            key_counter: AtomicU64::new(0),
        }
    }

    /// Generates a unique key ID.
    fn generate_key_id(&self) -> String {
        let counter = self.key_counter.fetch_add(1, Ordering::SeqCst);
        format!("soft-hsm-key-{:016x}", counter)
    }
}

impl Default for SoftHsmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SoftHsmProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_count = self.keys.read().map(|k| k.len()).unwrap_or(0);
        f.debug_struct("SoftHsmProvider")
            .field("key_count", &key_count)
            .finish()
    }
}

#[async_trait]
impl HsmProvider for SoftHsmProvider {
    async fn generate_ml_dsa_keypair(&self) -> Result<KeyHandle, HsmError> {
        // Generate the keypair using ML-DSA-65 (FIPS 204) directly
        let (pk, sk) = mldsa65::keypair();

        // Store the key bytes
        let stored_key = StoredMlDsaKey {
            public_key_bytes: pk.as_bytes().to_vec(),
            secret_key_bytes: sk.as_bytes().to_vec(),
        };

        let key_id = self.generate_key_id();
        let handle = KeyHandle::new(key_id.clone(), KeyType::MlDsa);

        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;
            keys.insert(key_id, StoredKey::MlDsa(stored_key));
        }

        Ok(handle)
    }

    async fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<crate::ml_dsa::MlDsaSignature, HsmError> {
        if handle.key_type() != KeyType::MlDsa {
            return Err(HsmError::SigningFailed(format!(
                "Key {} is not an ML-DSA key",
                handle.id()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;

        let stored_key = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        match stored_key {
            StoredKey::MlDsa(key) => {
                // Sign using ML-DSA-65 (FIPS 204) directly
                let sk = mldsa65::SecretKey::from_bytes(&key.secret_key_bytes).map_err(|e| {
                    HsmError::SigningFailed(format!("Failed to parse secret key: {:?}", e))
                })?;

                let sig = mldsa65::detached_sign(message, &sk);

                crate::ml_dsa::MlDsaSignature::from_bytes(sig.as_bytes())
                    .map_err(|e| HsmError::SigningFailed(format!("Invalid signature: {}", e)))
            }
            StoredKey::MlKem(_) => Err(HsmError::SigningFailed(format!(
                "Key {} is an ML-KEM key, not ML-DSA",
                handle.id()
            ))),
            StoredKey::Ed25519(_) | StoredKey::EcdsaP256(_) => Err(HsmError::SigningFailed(format!(
                "Key {} is a classical signing key — use sign_agile() instead of sign() for non-ML-DSA algorithms",
                handle.id()
            ))),
        }
    }

    async fn verify(
        &self,
        handle: &KeyHandle,
        message: &[u8],
        signature: &crate::ml_dsa::MlDsaSignature,
    ) -> Result<bool, HsmError> {
        if handle.key_type() != KeyType::MlDsa {
            return Err(HsmError::VerificationFailed(format!(
                "Key {} is not an ML-DSA key",
                handle.id()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;

        let stored_key = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        match stored_key {
            StoredKey::MlDsa(key) => {
                let public_key = crate::ml_dsa::MlDsaPublicKey::from_bytes(&key.public_key_bytes)
                    .map_err(|e| {
                        HsmError::VerificationFailed(format!("Invalid public key: {}", e))
                    })?;

                crate::ml_dsa::verify(&public_key, message, signature)
                    .map_err(|e| HsmError::VerificationFailed(format!("Verification error: {}", e)))
            }
            StoredKey::MlKem(_) => Err(HsmError::VerificationFailed(format!(
                "Key {} is an ML-KEM key, not ML-DSA",
                handle.id()
            ))),
            StoredKey::Ed25519(_) | StoredKey::EcdsaP256(_) => Err(HsmError::VerificationFailed(format!(
                "Key {} is a classical signing key — use verify_agile() instead of verify() for non-ML-DSA algorithms",
                handle.id()
            ))),
        }
    }

    async fn generate_ml_kem_keypair(&self) -> Result<KeyHandle, HsmError> {
        // Generate the keypair using ml_kem
        let keypair = crate::ml_kem::generate_keypair().map_err(|e| {
            HsmError::KeyGenerationFailed(format!("ML-KEM key generation failed: {}", e))
        })?;

        // Store the key bytes
        let stored_key = StoredMlKemKey {
            public_key_bytes: keypair.public_key.as_bytes().to_vec(),
            secret_key_bytes: keypair.secret_key.as_bytes().to_vec(),
        };

        let key_id = self.generate_key_id();
        let handle = KeyHandle::new(key_id.clone(), KeyType::MlKem);

        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;
            keys.insert(key_id, StoredKey::MlKem(stored_key));
        }

        Ok(handle)
    }

    async fn encapsulate(
        &self,
        handle: &KeyHandle,
    ) -> Result<(crate::ml_kem::MlKemCiphertext, crate::ml_kem::SharedSecret), HsmError> {
        if handle.key_type() != KeyType::MlKem {
            return Err(HsmError::EncapsulationFailed(format!(
                "Key {} is not an ML-KEM key",
                handle.id()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;

        let stored_key = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        match stored_key {
            StoredKey::MlKem(key) => {
                let public_key = crate::ml_kem::MlKemPublicKey::from_bytes(&key.public_key_bytes)
                    .map_err(|e| {
                        HsmError::EncapsulationFailed(format!("Invalid public key: {}", e))
                    })?;

                crate::ml_kem::encapsulate(&public_key)
                    .map_err(|e| HsmError::EncapsulationFailed(format!("Encapsulation error: {}", e)))
            }
            StoredKey::MlDsa(_) => Err(HsmError::EncapsulationFailed(format!(
                "Key {} is an ML-DSA key, not ML-KEM",
                handle.id()
            ))),
            StoredKey::Ed25519(_) | StoredKey::EcdsaP256(_) => Err(HsmError::EncapsulationFailed(format!(
                "Key {} is a classical signing key, not an ML-KEM key",
                handle.id()
            ))),
        }
    }

    async fn decapsulate(
        &self,
        handle: &KeyHandle,
        ciphertext: &crate::ml_kem::MlKemCiphertext,
    ) -> Result<crate::ml_kem::SharedSecret, HsmError> {
        if handle.key_type() != KeyType::MlKem {
            return Err(HsmError::DecapsulationFailed(format!(
                "Key {} is not an ML-KEM key",
                handle.id()
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;

        let stored_key = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        match stored_key {
            StoredKey::MlKem(key) => {
                let secret_key = crate::ml_kem::MlKemSecretKey::from_bytes(&key.secret_key_bytes)
                    .map_err(|e| {
                        HsmError::DecapsulationFailed(format!("Invalid secret key: {}", e))
                    })?;

                crate::ml_kem::decapsulate(ciphertext, &secret_key).map_err(|e| {
                    HsmError::DecapsulationFailed(format!("Decapsulation error: {}", e))
                })
            }
            StoredKey::MlDsa(_) => Err(HsmError::DecapsulationFailed(format!(
                "Key {} is an ML-DSA key, not ML-KEM",
                handle.id()
            ))),
            StoredKey::Ed25519(_) | StoredKey::EcdsaP256(_) => Err(HsmError::DecapsulationFailed(format!(
                "Key {} is a classical signing key, not an ML-KEM key",
                handle.id()
            ))),
        }
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<(), HsmError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;

        keys.remove(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        Ok(())
    }

    // ─── Agile (algorithm-agnostic) API ────────────────────────────────────

    fn supported_signing_algorithms(&self) -> Vec<crate::algorithm::SignatureAlgorithm> {
        use crate::algorithm::SignatureAlgorithm;
        vec![
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::EcdsaP256,
            SignatureAlgorithm::MlDsa65,
        ]
    }

    async fn generate_signing_keypair(
        &self,
        algorithm: crate::algorithm::SignatureAlgorithm,
    ) -> Result<KeyHandle, HsmError> {
        use crate::algorithm::SignatureAlgorithm;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => self.generate_ml_dsa_keypair().await,
            SignatureAlgorithm::Ed25519 => {
                use ed25519_dalek::SigningKey;
                use rand_core::OsRng;
                let signing_key = SigningKey::generate(&mut OsRng);
                let verifying_key = signing_key.verifying_key();
                let stored = StoredEd25519Key {
                    public_key_bytes: verifying_key.to_bytes().to_vec(),
                    secret_key_bytes: signing_key.to_bytes().to_vec(),
                };
                let key_id = self.generate_key_id();
                let handle = KeyHandle::new(key_id.clone(), KeyType::Ed25519);
                {
                    let mut keys = self.keys.write().map_err(|_| {
                        HsmError::ProviderError("Lock poisoned".to_string())
                    })?;
                    keys.insert(key_id, StoredKey::Ed25519(stored));
                }
                Ok(handle)
            }
            SignatureAlgorithm::EcdsaP256 => {
                use p256::ecdsa::SigningKey;
                // NOTE: `to_encoded_point` is an inherent method on `VerifyingKey`
                // in p256 0.13 / ecdsa 0.16 — no trait import is needed.
                use rand_core::OsRng;
                let signing_key = SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();
                let pk_compressed = verifying_key
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec();
                let sk_bytes = signing_key.to_bytes().to_vec();
                let stored = StoredEcdsaP256Key {
                    public_key_bytes: pk_compressed,
                    secret_key_bytes: sk_bytes,
                };
                let key_id = self.generate_key_id();
                let handle = KeyHandle::new(key_id.clone(), KeyType::EcdsaP256);
                {
                    let mut keys = self.keys.write().map_err(|_| {
                        HsmError::ProviderError("Lock poisoned".to_string())
                    })?;
                    keys.insert(key_id, StoredKey::EcdsaP256(stored));
                }
                Ok(handle)
            }
        }
    }

    async fn sign_agile(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<crate::algorithm::AgileSignature, HsmError> {
        use crate::algorithm::{AgileSignature, SignatureAlgorithm};
        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;
        let stored = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
        match stored {
            StoredKey::MlDsa(key) => {
                let sk = mldsa65::SecretKey::from_bytes(&key.secret_key_bytes)
                    .map_err(|e| HsmError::SigningFailed(format!("{:?}", e)))?;
                let sig = mldsa65::detached_sign(message, &sk);
                AgileSignature::new(SignatureAlgorithm::MlDsa65, sig.as_bytes().to_vec())
                    .map_err(|e| HsmError::SigningFailed(e.to_string()))
            }
            StoredKey::Ed25519(key) => {
                use ed25519_dalek::{Signer, SigningKey};
                let sk_arr: [u8; 32] = key.secret_key_bytes.as_slice().try_into().map_err(|_| {
                    HsmError::SigningFailed("Ed25519 secret key wrong length".to_string())
                })?;
                let signing_key = SigningKey::from_bytes(&sk_arr);
                let sig = signing_key.sign(message);
                AgileSignature::new(SignatureAlgorithm::Ed25519, sig.to_bytes().to_vec())
                    .map_err(|e| HsmError::SigningFailed(e.to_string()))
            }
            StoredKey::EcdsaP256(key) => {
                use p256::ecdsa::{signature::Signer, Signature, SigningKey};
                let signing_key = SigningKey::from_slice(&key.secret_key_bytes).map_err(|e| {
                    HsmError::SigningFailed(format!("Invalid ECDSA-P256 secret: {}", e))
                })?;
                let sig: Signature = signing_key.sign(message);
                // p256 returns r||s big-endian, 64 bytes
                AgileSignature::new(SignatureAlgorithm::EcdsaP256, sig.to_bytes().to_vec())
                    .map_err(|e| HsmError::SigningFailed(e.to_string()))
            }
            StoredKey::MlKem(_) => Err(HsmError::SigningFailed(format!(
                "Key {} is an ML-KEM key, not a signing key",
                handle.id()
            ))),
        }
    }

    async fn verify_agile(
        &self,
        handle: &KeyHandle,
        message: &[u8],
        signature: &crate::algorithm::AgileSignature,
    ) -> Result<bool, HsmError> {
        use crate::algorithm::SignatureAlgorithm;
        let key_alg = handle.key_type().as_signature_algorithm().ok_or_else(|| {
            HsmError::VerificationFailed(format!("Key {} is not a signing key", handle.id()))
        })?;
        if key_alg != signature.algorithm {
            return Err(HsmError::VerificationFailed(format!(
                "Algorithm mismatch: key is {}, signature is {}",
                key_alg, signature.algorithm
            )));
        }

        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;
        let stored = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;

        match (stored, signature.algorithm) {
            (StoredKey::MlDsa(key), SignatureAlgorithm::MlDsa65) => {
                let pk = crate::ml_dsa::MlDsaPublicKey::from_bytes(&key.public_key_bytes)
                    .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
                let sig = crate::ml_dsa::MlDsaSignature::from_bytes(&signature.bytes)
                    .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
                crate::ml_dsa::verify(&pk, message, &sig)
                    .map_err(|e| HsmError::VerificationFailed(e.to_string()))
            }
            (StoredKey::Ed25519(key), SignatureAlgorithm::Ed25519) => {
                use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey};
                let pk_arr: [u8; 32] =
                    key.public_key_bytes.as_slice().try_into().map_err(|_| {
                        HsmError::VerificationFailed("Ed25519 public key wrong length".to_string())
                    })?;
                let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                    HsmError::VerificationFailed(format!("Invalid Ed25519 public key: {}", e))
                })?;
                let sig_arr: [u8; 64] =
                    signature.bytes.as_slice().try_into().map_err(|_| {
                        HsmError::VerificationFailed("Ed25519 signature wrong length".to_string())
                    })?;
                let sig = EdSignature::from_bytes(&sig_arr);
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            (StoredKey::EcdsaP256(key), SignatureAlgorithm::EcdsaP256) => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let verifying_key =
                    VerifyingKey::from_sec1_bytes(&key.public_key_bytes).map_err(|e| {
                        HsmError::VerificationFailed(format!("Invalid P-256 public key: {}", e))
                    })?;
                let sig = Signature::from_slice(&signature.bytes).map_err(|e| {
                    HsmError::VerificationFailed(format!("Invalid P-256 signature: {}", e))
                })?;
                Ok(verifying_key.verify(message, &sig).is_ok())
            }
            _ => Err(HsmError::VerificationFailed(
                "Stored key/algorithm mismatch (corrupted state)".to_string(),
            )),
        }
    }

    async fn export_public_key(
        &self,
        handle: &KeyHandle,
    ) -> Result<crate::algorithm::AgilePublicKey, HsmError> {
        use crate::algorithm::{AgilePublicKey, SignatureAlgorithm};
        let keys = self
            .keys
            .read()
            .map_err(|_| HsmError::ProviderError("Lock poisoned".to_string()))?;
        let stored = keys
            .get(handle.id())
            .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
        match stored {
            StoredKey::MlDsa(key) => {
                AgilePublicKey::new(SignatureAlgorithm::MlDsa65, key.public_key_bytes.clone())
                    .map_err(|e| HsmError::ProviderError(e.to_string()))
            }
            StoredKey::Ed25519(key) => {
                AgilePublicKey::new(SignatureAlgorithm::Ed25519, key.public_key_bytes.clone())
                    .map_err(|e| HsmError::ProviderError(e.to_string()))
            }
            StoredKey::EcdsaP256(key) => AgilePublicKey::new(
                SignatureAlgorithm::EcdsaP256,
                key.public_key_bytes.clone(),
            )
            .map_err(|e| HsmError::ProviderError(e.to_string())),
            StoredKey::MlKem(_) => Err(HsmError::ProviderError(format!(
                "Key {} is an ML-KEM key — not a signing key",
                handle.id()
            ))),
        }
    }
}

// ============================================================================
// PKCS#11 HSM Provider (feature-gated: cloudhsm)
// ============================================================================

#[cfg(feature = "cloudhsm")]
mod pkcs11_provider {
    use super::*;
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{
        Attribute, AttributeType, KeyType as Pkcs11KeyType, ObjectClass, ObjectHandle,
    };
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
    use std::sync::Mutex;
    use uuid::Uuid;

    /// DER-encoded ASN.1 OID for the Ed25519 curve (`1.3.101.112`).
    /// Used as the `CKA_EC_PARAMS` attribute when generating an Edwards keypair.
    const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

    /// DER-encoded ASN.1 OID for the secp256r1 / NIST P-256 curve
    /// (`1.2.840.10045.3.1.7`). Used as the `CKA_EC_PARAMS` attribute when
    /// generating an ECDSA-P256 keypair.
    const P256_OID_DER: &[u8] = &[
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    ];

    /// Wrapper to make Session Send-safe.
    ///
    /// # Safety
    ///
    /// PKCS#11 sessions initialized with CKF_OS_LOCKING_OK support concurrent
    /// access from multiple threads when properly serialized. The Mutex in
    /// Pkcs11HsmProvider ensures exclusive access to the session.
    struct SendSession(cryptoki::session::Session);
    unsafe impl Send for SendSession {}

    /// Entry tracking PKCS#11 objects for a stored key.
    struct Pkcs11KeyEntry {
        /// For ML-DSA: `CKO_DATA` object storing public key bytes (plaintext).
        /// For Ed25519/ECDSA-P256: the actual `CKO_PUBLIC_KEY` object handle.
        public_object: ObjectHandle,
        /// For ML-DSA: `CKO_DATA` object storing wrapped (AES-CBC-PAD encrypted) private key bytes.
        /// For Ed25519/ECDSA-P256: the actual `CKO_PRIVATE_KEY` object handle.
        /// In the latter case the key material NEVER leaves the HSM — we hold
        /// only the opaque object handle.
        private_object: ObjectHandle,
        /// The type of cryptographic key
        key_type: KeyType,
        /// Cached public-key bytes for HSM-native signing keys
        /// (Ed25519 raw 32 bytes, ECDSA-P256 SEC1 compressed 33 bytes).
        /// `None` for ML-DSA / ML-KEM where public material is fetched from
        /// the on-token `CKO_DATA` object on demand.
        cached_public_bytes: Option<Vec<u8>>,
    }

    /// PKCS#11-based HSM provider for production key management.
    ///
    /// Uses PKCS#11 bindings via the `cryptoki` crate to interface with hardware
    /// security modules (HSMs) such as AWS CloudHSM, Thales Luna, or SoftHSM2.
    ///
    /// # Threshold Shard Protection
    ///
    /// In QPL's threshold signing model, this provider stores a single operator's
    /// **signing shard** — not a full private key. Even in the worst case (complete
    /// node compromise), an attacker obtains only 1-of-t shards and cannot produce
    /// a valid signature without compromising the threshold number of independent
    /// operators.
    ///
    /// ## Security Layers
    ///
    /// - **At rest**: Shards AES-256-CBC encrypted with an HSM-resident wrapping key
    /// - **In transit**: Shard material never crosses network boundaries
    /// - **In use**: Decrypted only within process memory, zeroized immediately after
    ///   producing a partial signature
    /// - **Session isolation**: PKCS#11 session mutex prevents concurrent shard exposure
    /// - **Threshold property**: Even full shard extraction from one node is insufficient
    ///   to reconstruct the signing key
    ///
    /// ## Hybrid Architecture
    ///
    /// Since PKCS#11 firmware doesn't yet natively support ML-DSA-65 or ML-KEM-1024,
    /// this provider uses a hybrid approach:
    ///
    /// - **Shard storage**: Signing shards are encrypted with an AES-256 master wrapping
    ///   key (generated inside the HSM) and stored as `CKO_DATA` objects.
    /// - **Crypto operations**: PQC partial signing, verification, encapsulation, and
    ///   decapsulation are performed in software using the `pqcrypto` crate.
    /// - **Shard protection**: Key material is encrypted at rest in the HSM
    ///   and zeroized immediately after use in software memory.
    ///
    /// When HSM firmware adds native ML-DSA/ML-KEM mechanisms, the implementation
    /// can be swapped without changing the `HsmProvider` interface.
    pub struct Pkcs11HsmProvider {
        /// PKCS#11 library context (must stay alive for session validity)
        _pkcs11: Pkcs11,
        /// Active R/W session with the HSM (Mutex for thread-safe access)
        session: Mutex<SendSession>,
        /// Master AES-256 wrapping key handle in the HSM
        wrapping_key: ObjectHandle,
        /// Mapping from KeyHandle IDs to PKCS#11 object handles
        key_map: RwLock<HashMap<String, Pkcs11KeyEntry>>,
        /// Counter for generating unique key IDs
        key_counter: AtomicU64,
    }

    impl Pkcs11HsmProvider {
        /// Creates a new PKCS#11 HSM provider.
        ///
        /// # Arguments
        ///
        /// * `library_path` - Path to the PKCS#11 shared library (e.g. `libsofthsm2.so`)
        /// * `slot_index` - Zero-based index into the list of slots with tokens
        /// * `pin` - User PIN for HSM authentication
        ///
        /// # Errors
        ///
        /// Returns `HsmError::ProviderError` if the library cannot be loaded,
        /// the slot doesn't exist, authentication fails, or the master wrapping
        /// key cannot be created.
        pub fn new(library_path: &str, slot_index: usize, pin: &str) -> Result<Self, HsmError> {
            // Load PKCS#11 library
            let pkcs11 = Pkcs11::new(library_path).map_err(|e| {
                HsmError::ProviderError(format!("Failed to load PKCS#11 library '{}': {:?}", library_path, e))
            })?;

            // Initialize with OS-level thread locking
            pkcs11.initialize(CInitializeArgs::OsThreads).map_err(|e| {
                HsmError::ProviderError(format!("Failed to initialize PKCS#11: {:?}", e))
            })?;

            // Get slots with initialized tokens
            let slots = pkcs11.get_slots_with_token().map_err(|e| {
                HsmError::ProviderError(format!("Failed to enumerate HSM slots: {:?}", e))
            })?;

            let slot = *slots.get(slot_index).ok_or_else(|| {
                HsmError::ProviderError(format!(
                    "Slot index {} out of range (available slots: {})",
                    slot_index,
                    slots.len()
                ))
            })?;

            // Open a read/write session
            let session = pkcs11.open_rw_session(slot).map_err(|e| {
                HsmError::ProviderError(format!("Failed to open R/W session: {:?}", e))
            })?;

            // Authenticate as normal user
            session
                .login(UserType::User, Some(&AuthPin::new(pin.to_string())))
                .map_err(|e| {
                    HsmError::ProviderError(format!("HSM authentication failed: {:?}", e))
                })?;

            // Find or create the master AES-256 wrapping key
            let wrapping_key = Self::find_or_create_wrapping_key(&session)?;

            Ok(Self {
                _pkcs11: pkcs11,
                session: Mutex::new(SendSession(session)),
                wrapping_key,
                key_map: RwLock::new(HashMap::new()),
                key_counter: AtomicU64::new(0),
            })
        }

        /// Finds an existing master wrapping key or generates a new one.
        ///
        /// Searches for a `CKO_SECRET_KEY` with label `QPL_MASTER_WRAP_KEY`.
        /// If none is found, generates a new AES-256 key with that label.
        fn find_or_create_wrapping_key(
            session: &cryptoki::session::Session,
        ) -> Result<ObjectHandle, HsmError> {
            let label = b"QPL_MASTER_WRAP_KEY".to_vec();

            // Search for an existing wrapping key
            let search_template = vec![
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(Pkcs11KeyType::AES),
                Attribute::Label(label.clone()),
            ];

            let objects = session.find_objects(&search_template).map_err(|e| {
                HsmError::ProviderError(format!("Failed to search for wrapping key: {:?}", e))
            })?;

            if let Some(&handle) = objects.first() {
                return Ok(handle);
            }

            // Generate a new AES-256 master wrapping key
            let gen_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Label(label),
                Attribute::ValueLen(32.into()),
            ];

            session
                .generate_key(&Mechanism::AesKeyGen, &gen_template)
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to generate master wrapping key: {:?}", e))
                })
        }

        /// Generates a unique key ID.
        fn generate_key_id(&self) -> String {
            let counter = self.key_counter.fetch_add(1, Ordering::SeqCst);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("pkcs11-{:016x}-{:016x}", counter, timestamp)
        }

        /// Encrypts key material using the master wrapping key (AES-CBC-PAD).
        ///
        /// Returns `[IV (16 bytes) || ciphertext]`.
        fn wrap_key_material(&self, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;

            // Generate a random 16-byte IV inside the HSM
            let iv_vec = session_guard.0.generate_random_vec(16).map_err(|e| {
                HsmError::ProviderError(format!("Failed to generate IV: {:?}", e))
            })?;
            let iv: [u8; 16] = iv_vec.try_into().map_err(|_| {
                HsmError::ProviderError("IV generation returned unexpected length".to_string())
            })?;

            let ciphertext = session_guard
                .0
                .encrypt(&Mechanism::AesCbcPad(iv), self.wrapping_key, plaintext)
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to encrypt key material: {:?}", e))
                })?;

            // Prepend IV to ciphertext
            let mut result = Vec::with_capacity(16 + ciphertext.len());
            result.extend_from_slice(&iv);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }

        /// Decrypts wrapped key material using the master wrapping key (AES-CBC-PAD).
        ///
        /// Expects `[IV (16 bytes) || ciphertext]`.
        fn unwrap_key_material(&self, wrapped: &[u8]) -> Result<Vec<u8>, HsmError> {
            // SECURITY WARNING: ML-DSA-65 signing currently unwraps the wrapped private key
            // into host RAM for the duration of one signing operation. This is a transitional
            // posture pending HSM vendor FIPS 204 firmware. Production deployments SHOULD
            // negotiate Ed25519 or ECDSA-P256 (HSM-native, key never leaves the boundary).
            // The threshold property remains the primary security boundary during this window.
            //
            // This helper is the single point through which wrapped ML-DSA shard
            // material crosses the HSM boundary into process memory. The caller
            // MUST zeroize the returned bytes immediately after the cryptographic
            // operation completes (see `sign` and `decapsulate` below).
            if wrapped.len() < 17 {
                return Err(HsmError::ProviderError(
                    "Wrapped key material too short (need at least IV + 1 block)".to_string(),
                ));
            }

            let iv: [u8; 16] = wrapped[..16].try_into().map_err(|_| {
                HsmError::ProviderError("IV extraction failed".to_string())
            })?;

            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;

            session_guard
                .0
                .decrypt(&Mechanism::AesCbcPad(iv), self.wrapping_key, &wrapped[16..])
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to decrypt key material: {:?}", e))
                })
        }

        /// Stores a byte blob as a `CKO_DATA` object in the HSM.
        fn store_data_object(&self, label: &str, data: &[u8]) -> Result<ObjectHandle, HsmError> {
            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Value(data.to_vec()),
            ];

            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;

            session_guard.0.create_object(&template).map_err(|e| {
                HsmError::ProviderError(format!("Failed to create data object '{}': {:?}", label, e))
            })
        }

        /// Retrieves the `CKA_VALUE` of a `CKO_DATA` object from the HSM.
        fn retrieve_data_object(&self, handle: ObjectHandle) -> Result<Vec<u8>, HsmError> {
            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;

            let attrs = session_guard
                .0
                .get_attributes(handle, &[AttributeType::Value])
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to read data object: {:?}", e))
                })?;

            for attr in attrs {
                if let Attribute::Value(val) = attr {
                    return Ok(val);
                }
            }

            Err(HsmError::ProviderError(
                "CKA_VALUE attribute not found on data object".to_string(),
            ))
        }

        /// Decodes an ASN.1 DER `OCTET STRING` (tag `0x04`) and returns the
        /// inner content. PKCS#11 returns `CKA_EC_POINT` wrapped this way.
        fn decode_octet_string(der: &[u8]) -> Result<Vec<u8>, HsmError> {
            if der.len() < 2 || der[0] != 0x04 {
                return Err(HsmError::ProviderError(
                    "CKA_EC_POINT: expected DER OCTET STRING (tag 0x04)".to_string(),
                ));
            }
            let (content_len, header_len) = if der[1] & 0x80 == 0 {
                (der[1] as usize, 2usize)
            } else {
                let nlen = (der[1] & 0x7f) as usize;
                if nlen == 0 || nlen > 4 || der.len() < 2 + nlen {
                    return Err(HsmError::ProviderError(
                        "CKA_EC_POINT: malformed DER length".to_string(),
                    ));
                }
                let mut len = 0usize;
                for &b in &der[2..2 + nlen] {
                    len = (len << 8) | (b as usize);
                }
                (len, 2 + nlen)
            };
            if der.len() < header_len + content_len {
                return Err(HsmError::ProviderError(
                    "CKA_EC_POINT: truncated DER OCTET STRING".to_string(),
                ));
            }
            Ok(der[header_len..header_len + content_len].to_vec())
        }

        /// Reads `CKA_EC_POINT` from a public-key object handle and returns
        /// the raw point bytes (DER OCTET STRING wrapper stripped).
        fn read_ec_point(&self, public_object: ObjectHandle) -> Result<Vec<u8>, HsmError> {
            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;
            let attrs = session_guard
                .0
                .get_attributes(public_object, &[AttributeType::EcPoint])
                .map_err(|e| {
                    HsmError::ProviderError(format!(
                        "Failed to read CKA_EC_POINT: {:?}",
                        e
                    ))
                })?;
            for attr in attrs {
                if let Attribute::EcPoint(der) = attr {
                    return Self::decode_octet_string(&der);
                }
            }
            Err(HsmError::ProviderError(
                "CKA_EC_POINT attribute not found on public-key object".to_string(),
            ))
        }

        /// Generates an Ed25519 keypair INSIDE the HSM via
        /// `C_GenerateKeyPair` with `CKM_EC_EDWARDS_KEY_PAIR_GEN`. The private
        /// key never leaves the HSM (`CKA_EXTRACTABLE = false`,
        /// `CKA_SENSITIVE = true`). The public key is read back via
        /// `CKA_EC_POINT` and cached in memory.
        fn generate_ed25519_keypair_pkcs11(&self) -> Result<KeyHandle, HsmError> {
            let key_id = Uuid::new_v4().to_string();
            let pub_label = format!("QPL_ED25519_PUB_{}", key_id);
            let priv_label = format!("QPL_ED25519_PRIV_{}", key_id);

            let pub_template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(Pkcs11KeyType::EC_EDWARDS),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Verify(true),
                Attribute::Label(pub_label.as_bytes().to_vec()),
                Attribute::EcParams(ED25519_OID_DER.to_vec()),
            ];
            let priv_template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(Pkcs11KeyType::EC_EDWARDS),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(priv_label.as_bytes().to_vec()),
            ];

            let (pub_handle, priv_handle) = {
                let session_guard = self.session.lock().map_err(|_| {
                    HsmError::ProviderError("Session lock poisoned".to_string())
                })?;
                session_guard
                    .0
                    .generate_key_pair(
                        &Mechanism::EccEdwardsKeyPairGen,
                        &pub_template,
                        &priv_template,
                    )
                    .map_err(|e| {
                        HsmError::KeyGenerationFailed(format!(
                            "Ed25519 C_GenerateKeyPair failed: {:?}",
                            e
                        ))
                    })?
            };

            // Read CKA_EC_POINT for the freshly generated public key (raw 32 B for Ed25519).
            let pk_bytes = self.read_ec_point(pub_handle)?;
            if pk_bytes.len() != 32 {
                return Err(HsmError::KeyGenerationFailed(format!(
                    "Ed25519 public key has unexpected length {} (want 32)",
                    pk_bytes.len()
                )));
            }

            {
                let mut map = self.key_map.write().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                map.insert(
                    key_id.clone(),
                    Pkcs11KeyEntry {
                        public_object: pub_handle,
                        private_object: priv_handle,
                        key_type: KeyType::Ed25519,
                        cached_public_bytes: Some(pk_bytes),
                    },
                );
            }

            Ok(KeyHandle::new(key_id, KeyType::Ed25519))
        }

        /// Generates an ECDSA-P256 keypair INSIDE the HSM via
        /// `C_GenerateKeyPair` with `CKM_EC_KEY_PAIR_GEN`. The private key
        /// never leaves the HSM. The public point is read via `CKA_EC_POINT`,
        /// re-encoded in SEC1 compressed form (33 bytes) and cached.
        fn generate_ecdsa_p256_keypair_pkcs11(&self) -> Result<KeyHandle, HsmError> {
            let key_id = Uuid::new_v4().to_string();
            let pub_label = format!("QPL_P256_PUB_{}", key_id);
            let priv_label = format!("QPL_P256_PRIV_{}", key_id);

            let pub_template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(Pkcs11KeyType::EC),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Verify(true),
                Attribute::Label(pub_label.as_bytes().to_vec()),
                Attribute::EcParams(P256_OID_DER.to_vec()),
            ];
            let priv_template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(Pkcs11KeyType::EC),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(priv_label.as_bytes().to_vec()),
            ];

            let (pub_handle, priv_handle) = {
                let session_guard = self.session.lock().map_err(|_| {
                    HsmError::ProviderError("Session lock poisoned".to_string())
                })?;
                session_guard
                    .0
                    .generate_key_pair(
                        &Mechanism::EccKeyPairGen,
                        &pub_template,
                        &priv_template,
                    )
                    .map_err(|e| {
                        HsmError::KeyGenerationFailed(format!(
                            "P-256 C_GenerateKeyPair failed: {:?}",
                            e
                        ))
                    })?
            };

            // Read CKA_EC_POINT and re-encode SEC1 compressed (33 B).
            let raw_point = self.read_ec_point(pub_handle)?;
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw_point).map_err(|e| {
                    HsmError::KeyGenerationFailed(format!(
                        "HSM returned invalid P-256 public point: {}",
                        e
                    ))
                })?;
            let pk_compressed = verifying_key.to_encoded_point(true).as_bytes().to_vec();

            {
                let mut map = self.key_map.write().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                map.insert(
                    key_id.clone(),
                    Pkcs11KeyEntry {
                        public_object: pub_handle,
                        private_object: priv_handle,
                        key_type: KeyType::EcdsaP256,
                        cached_public_bytes: Some(pk_compressed),
                    },
                );
            }

            Ok(KeyHandle::new(key_id, KeyType::EcdsaP256))
        }

        /// Looks up a key entry and returns the requested fields, cloning the
        /// cached public bytes if present. Releases the read lock before
        /// returning so callers can re-acquire other locks.
        fn lookup_entry(&self, id: &str) -> Result<LookupEntry, HsmError> {
            let map = self.key_map.read().map_err(|_| {
                HsmError::ProviderError("Key map lock poisoned".to_string())
            })?;
            let entry = map
                .get(id)
                .ok_or_else(|| HsmError::KeyNotFound(id.to_string()))?;
            Ok(LookupEntry {
                public_object: entry.public_object,
                private_object: entry.private_object,
                key_type: entry.key_type,
                cached_public_bytes: entry.cached_public_bytes.clone(),
            })
        }
    }

    /// Snapshot of fields read out of a `Pkcs11KeyEntry` without holding the
    /// `key_map` lock across the rest of the operation.
    struct LookupEntry {
        public_object: ObjectHandle,
        private_object: ObjectHandle,
        key_type: KeyType,
        cached_public_bytes: Option<Vec<u8>>,
    }

    #[async_trait]
    impl HsmProvider for Pkcs11HsmProvider {
        async fn generate_ml_dsa_keypair(&self) -> Result<KeyHandle, HsmError> {
            // Generate ML-DSA-65 keypair in software
            let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();
            let pk_bytes = pk.as_bytes().to_vec();
            let mut sk_bytes = sk.as_bytes().to_vec();

            let key_id = self.generate_key_id();

            // Store public key as plaintext CKO_DATA
            let pub_label = format!("QPL_DSA_PUB_{}", key_id);
            let pub_handle = self.store_data_object(&pub_label, &pk_bytes)?;

            // Encrypt and store private key
            let wrapped_sk = self.wrap_key_material(&sk_bytes)?;
            sk_bytes.zeroize();

            let priv_label = format!("QPL_DSA_PRIV_{}", key_id);
            let priv_handle = self.store_data_object(&priv_label, &wrapped_sk)?;

            // Register in key map
            {
                let mut map = self.key_map.write().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                map.insert(
                    key_id.clone(),
                    Pkcs11KeyEntry {
                        public_object: pub_handle,
                        private_object: priv_handle,
                        key_type: KeyType::MlDsa,
                        cached_public_bytes: None,
                    },
                );
            }

            Ok(KeyHandle::new(key_id, KeyType::MlDsa))
        }

        async fn sign(
            &self,
            handle: &KeyHandle,
            message: &[u8],
        ) -> Result<crate::ml_dsa::MlDsaSignature, HsmError> {
            if handle.key_type() != KeyType::MlDsa {
                return Err(HsmError::SigningFailed(format!(
                    "Key {} is not an ML-DSA key",
                    handle.id()
                )));
            }

            let priv_object = {
                let map = self.key_map.read().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                let entry = map
                    .get(handle.id())
                    .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
                if entry.key_type != KeyType::MlDsa {
                    return Err(HsmError::SigningFailed(format!(
                        "Key {} is an ML-KEM key, not ML-DSA",
                        handle.id()
                    )));
                }
                entry.private_object
            };

            // Retrieve encrypted private key from HSM and decrypt
            let wrapped = self.retrieve_data_object(priv_object)?;
            let mut sk_bytes = self.unwrap_key_material(&wrapped)?;

            // SECURITY WARNING: ML-DSA-65 signing currently unwraps the wrapped private key
            // into host RAM for the duration of one signing operation. This is a transitional
            // posture pending HSM vendor FIPS 204 firmware. Production deployments SHOULD
            // negotiate Ed25519 or ECDSA-P256 (HSM-native, key never leaves the boundary).
            // The threshold property remains the primary security boundary during this window.
            //
            // The closure below is intentionally short and bracketed by the
            // `sk_bytes.zeroize()` call after `result` so that the unwrapped
            // shard material is wiped from RAM as soon as `detached_sign`
            // returns, regardless of success or failure.
            // Sign in software, then zeroize
            let result = (|| -> Result<crate::ml_dsa::MlDsaSignature, HsmError> {
                let sk = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(&sk_bytes)
                    .map_err(|e| HsmError::SigningFailed(format!("Failed to parse secret key: {:?}", e)))?;

                let sig = pqcrypto_mldsa::mldsa65::detached_sign(message, &sk);

                crate::ml_dsa::MlDsaSignature::from_bytes(sig.as_bytes())
                    .map_err(|e| HsmError::SigningFailed(format!("Invalid signature: {}", e)))
            })();

            sk_bytes.zeroize();
            result
        }

        async fn verify(
            &self,
            handle: &KeyHandle,
            message: &[u8],
            signature: &crate::ml_dsa::MlDsaSignature,
        ) -> Result<bool, HsmError> {
            if handle.key_type() != KeyType::MlDsa {
                return Err(HsmError::VerificationFailed(format!(
                    "Key {} is not an ML-DSA key",
                    handle.id()
                )));
            }

            let pub_object = {
                let map = self.key_map.read().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                let entry = map
                    .get(handle.id())
                    .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
                if entry.key_type != KeyType::MlDsa {
                    return Err(HsmError::VerificationFailed(format!(
                        "Key {} is an ML-KEM key, not ML-DSA",
                        handle.id()
                    )));
                }
                entry.public_object
            };

            // Retrieve public key from HSM (plaintext)
            let pk_bytes = self.retrieve_data_object(pub_object)?;

            let public_key = crate::ml_dsa::MlDsaPublicKey::from_bytes(&pk_bytes).map_err(|e| {
                HsmError::VerificationFailed(format!("Invalid public key: {}", e))
            })?;

            crate::ml_dsa::verify(&public_key, message, signature)
                .map_err(|e| HsmError::VerificationFailed(format!("Verification error: {}", e)))
        }

        async fn generate_ml_kem_keypair(&self) -> Result<KeyHandle, HsmError> {
            // Generate ML-KEM-1024 keypair in software
            let keypair = crate::ml_kem::generate_keypair().map_err(|e| {
                HsmError::KeyGenerationFailed(format!("ML-KEM key generation failed: {}", e))
            })?;

            let pk_bytes = keypair.public_key.as_bytes().to_vec();
            let mut sk_bytes = keypair.secret_key.as_bytes().to_vec();

            let key_id = self.generate_key_id();

            // Store public key as plaintext CKO_DATA
            let pub_label = format!("QPL_KEM_PUB_{}", key_id);
            let pub_handle = self.store_data_object(&pub_label, &pk_bytes)?;

            // Encrypt and store private key
            let wrapped_sk = self.wrap_key_material(&sk_bytes)?;
            sk_bytes.zeroize();

            let priv_label = format!("QPL_KEM_PRIV_{}", key_id);
            let priv_handle = self.store_data_object(&priv_label, &wrapped_sk)?;

            // Register in key map
            {
                let mut map = self.key_map.write().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                map.insert(
                    key_id.clone(),
                    Pkcs11KeyEntry {
                        public_object: pub_handle,
                        private_object: priv_handle,
                        key_type: KeyType::MlKem,
                        cached_public_bytes: None,
                    },
                );
            }

            Ok(KeyHandle::new(key_id, KeyType::MlKem))
        }

        async fn encapsulate(
            &self,
            handle: &KeyHandle,
        ) -> Result<(crate::ml_kem::MlKemCiphertext, crate::ml_kem::SharedSecret), HsmError> {
            if handle.key_type() != KeyType::MlKem {
                return Err(HsmError::EncapsulationFailed(format!(
                    "Key {} is not an ML-KEM key",
                    handle.id()
                )));
            }

            let pub_object = {
                let map = self.key_map.read().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                let entry = map
                    .get(handle.id())
                    .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
                if entry.key_type != KeyType::MlKem {
                    return Err(HsmError::EncapsulationFailed(format!(
                        "Key {} is an ML-DSA key, not ML-KEM",
                        handle.id()
                    )));
                }
                entry.public_object
            };

            let pk_bytes = self.retrieve_data_object(pub_object)?;

            let public_key = crate::ml_kem::MlKemPublicKey::from_bytes(&pk_bytes).map_err(|e| {
                HsmError::EncapsulationFailed(format!("Invalid public key: {}", e))
            })?;

            crate::ml_kem::encapsulate(&public_key)
                .map_err(|e| HsmError::EncapsulationFailed(format!("Encapsulation error: {}", e)))
        }

        async fn decapsulate(
            &self,
            handle: &KeyHandle,
            ciphertext: &crate::ml_kem::MlKemCiphertext,
        ) -> Result<crate::ml_kem::SharedSecret, HsmError> {
            if handle.key_type() != KeyType::MlKem {
                return Err(HsmError::DecapsulationFailed(format!(
                    "Key {} is not an ML-KEM key",
                    handle.id()
                )));
            }

            let priv_object = {
                let map = self.key_map.read().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                let entry = map
                    .get(handle.id())
                    .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?;
                if entry.key_type != KeyType::MlKem {
                    return Err(HsmError::DecapsulationFailed(format!(
                        "Key {} is an ML-DSA key, not ML-KEM",
                        handle.id()
                    )));
                }
                entry.private_object
            };

            // Retrieve encrypted private key and decrypt
            let wrapped = self.retrieve_data_object(priv_object)?;
            let mut sk_bytes = self.unwrap_key_material(&wrapped)?;

            let result = (|| -> Result<crate::ml_kem::SharedSecret, HsmError> {
                let secret_key = crate::ml_kem::MlKemSecretKey::from_bytes(&sk_bytes).map_err(|e| {
                    HsmError::DecapsulationFailed(format!("Invalid secret key: {}", e))
                })?;

                crate::ml_kem::decapsulate(ciphertext, &secret_key)
                    .map_err(|e| HsmError::DecapsulationFailed(format!("Decapsulation error: {}", e)))
            })();

            sk_bytes.zeroize();
            result
        }

        async fn delete_key(&self, handle: &KeyHandle) -> Result<(), HsmError> {
            let entry = {
                let mut map = self.key_map.write().map_err(|_| {
                    HsmError::ProviderError("Key map lock poisoned".to_string())
                })?;
                map.remove(handle.id())
                    .ok_or_else(|| HsmError::KeyNotFound(handle.id().to_string()))?
            };

            let session_guard = self.session.lock().map_err(|_| {
                HsmError::ProviderError("Session lock poisoned".to_string())
            })?;

            // Destroy both the public and private data objects in the HSM
            session_guard
                .0
                .destroy_object(entry.public_object)
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to destroy public key object: {:?}", e))
                })?;

            session_guard
                .0
                .destroy_object(entry.private_object)
                .map_err(|e| {
                    HsmError::ProviderError(format!("Failed to destroy private key object: {:?}", e))
                })?;

            Ok(())
        }

        // ─── Algorithmic Agility API ───────────────────────────────────────
        //
        // Pkcs11HsmProvider exposes Ed25519 and ECDSA-P256 as HSM-native
        // signing algorithms (key never leaves the boundary) in addition to
        // the transitional ML-DSA-65 software-shim path.

        fn supported_signing_algorithms(&self) -> Vec<crate::algorithm::SignatureAlgorithm> {
            use crate::algorithm::SignatureAlgorithm;
            vec![
                SignatureAlgorithm::Ed25519,
                SignatureAlgorithm::EcdsaP256,
                SignatureAlgorithm::MlDsa65,
            ]
        }

        async fn generate_signing_keypair(
            &self,
            algorithm: crate::algorithm::SignatureAlgorithm,
        ) -> Result<KeyHandle, HsmError> {
            use crate::algorithm::SignatureAlgorithm;
            match algorithm {
                SignatureAlgorithm::MlDsa65 => self.generate_ml_dsa_keypair().await,
                SignatureAlgorithm::Ed25519 => self.generate_ed25519_keypair_pkcs11(),
                SignatureAlgorithm::EcdsaP256 => self.generate_ecdsa_p256_keypair_pkcs11(),
            }
        }

        async fn sign_agile(
            &self,
            handle: &KeyHandle,
            message: &[u8],
        ) -> Result<crate::algorithm::AgileSignature, HsmError> {
            use crate::algorithm::{AgileSignature, SignatureAlgorithm};
            let LookupEntry {
                public_object: _,
                private_object: priv_obj,
                key_type: kt,
                cached_public_bytes: _,
            } = self.lookup_entry(handle.id())?;

            // Sanity-check that the handle agrees with the on-token entry.
            if kt != handle.key_type() {
                return Err(HsmError::SigningFailed(format!(
                    "Handle key type {} disagrees with stored entry {}",
                    handle.key_type(),
                    kt
                )));
            }

            match kt {
                KeyType::MlDsa => {
                    // SECURITY WARNING: ML-DSA-65 signing currently unwraps the wrapped private key
                    // into host RAM for the duration of one signing operation. This is a transitional
                    // posture pending HSM vendor FIPS 204 firmware. Production deployments SHOULD
                    // negotiate Ed25519 or ECDSA-P256 (HSM-native, key never leaves the boundary).
                    // The threshold property remains the primary security boundary during this window.
                    let sig = self.sign(handle, message).await?;
                    AgileSignature::new(SignatureAlgorithm::MlDsa65, sig.as_bytes().to_vec())
                        .map_err(|e| HsmError::SigningFailed(e.to_string()))
                }
                KeyType::Ed25519 => {
                    let session_guard = self.session.lock().map_err(|_| {
                        HsmError::ProviderError("Session lock poisoned".to_string())
                    })?;
                    let sig_bytes = session_guard
                        .0
                        .sign(&Mechanism::Eddsa, priv_obj, message)
                        .map_err(|e| {
                            HsmError::SigningFailed(format!(
                                "PKCS#11 Ed25519 C_Sign failed: {:?}",
                                e
                            ))
                        })?;
                    AgileSignature::new(SignatureAlgorithm::Ed25519, sig_bytes)
                        .map_err(|e| HsmError::SigningFailed(e.to_string()))
                }
                KeyType::EcdsaP256 => {
                    let session_guard = self.session.lock().map_err(|_| {
                        HsmError::ProviderError("Session lock poisoned".to_string())
                    })?;
                    // CKM_ECDSA_SHA256 hashes the message inside the HSM and
                    // emits the IEEE P1363 r||s 64-byte signature, matching
                    // the encoding our software verifier expects.
                    let sig_bytes = session_guard
                        .0
                        .sign(&Mechanism::EcdsaSha256, priv_obj, message)
                        .map_err(|e| {
                            HsmError::SigningFailed(format!(
                                "PKCS#11 ECDSA-P256 C_Sign failed: {:?}",
                                e
                            ))
                        })?;
                    AgileSignature::new(SignatureAlgorithm::EcdsaP256, sig_bytes)
                        .map_err(|e| HsmError::SigningFailed(e.to_string()))
                }
                KeyType::MlKem => Err(HsmError::SigningFailed(format!(
                    "Key {} is an ML-KEM key, not a signing key",
                    handle.id()
                ))),
            }
        }

        async fn verify_agile(
            &self,
            handle: &KeyHandle,
            message: &[u8],
            signature: &crate::algorithm::AgileSignature,
        ) -> Result<bool, HsmError> {
            let key_alg = handle.key_type().as_signature_algorithm().ok_or_else(|| {
                HsmError::VerificationFailed(format!(
                    "Key {} is not a signing key",
                    handle.id()
                ))
            })?;
            if key_alg != signature.algorithm {
                return Err(HsmError::VerificationFailed(format!(
                    "Algorithm mismatch: key is {}, signature is {}",
                    key_alg, signature.algorithm
                )));
            }

            let LookupEntry {
                public_object: pub_obj,
                private_object: _,
                key_type: kt,
                cached_public_bytes: cached_pk,
            } = self.lookup_entry(handle.id())?;

            match kt {
                KeyType::MlDsa => {
                    // ML-DSA verification re-uses the existing software path
                    // (public key fetched from on-token CKO_DATA).
                    let ml_sig = crate::ml_dsa::MlDsaSignature::from_bytes(&signature.bytes)
                        .map_err(|e| HsmError::VerificationFailed(e.to_string()))?;
                    self.verify(handle, message, &ml_sig).await
                }
                KeyType::Ed25519 => {
                    use ed25519_dalek::{
                        Signature as EdSignature, Verifier, VerifyingKey,
                    };
                    let pk_bytes = match cached_pk {
                        Some(b) => b,
                        None => self.read_ec_point(pub_obj)?,
                    };
                    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| {
                        HsmError::VerificationFailed(
                            "Ed25519 public key wrong length".to_string(),
                        )
                    })?;
                    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| {
                        HsmError::VerificationFailed(format!(
                            "Invalid Ed25519 public key: {}",
                            e
                        ))
                    })?;
                    let sig_arr: [u8; 64] =
                        signature.bytes.as_slice().try_into().map_err(|_| {
                            HsmError::VerificationFailed(
                                "Ed25519 signature wrong length".to_string(),
                            )
                        })?;
                    let sig = EdSignature::from_bytes(&sig_arr);
                    Ok(verifying_key.verify(message, &sig).is_ok())
                }
                KeyType::EcdsaP256 => {
                    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                    let pk_bytes = match cached_pk {
                        Some(b) => b,
                        None => {
                            // Re-encode SEC1 compressed for downstream consumers.
                            let raw = self.read_ec_point(pub_obj)?;
                            let vk =
                                VerifyingKey::from_sec1_bytes(&raw).map_err(|e| {
                                    HsmError::VerificationFailed(format!(
                                        "Invalid P-256 public key from HSM: {}",
                                        e
                                    ))
                                })?;
                            vk.to_encoded_point(true).as_bytes().to_vec()
                        }
                    };
                    let verifying_key =
                        VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|e| {
                            HsmError::VerificationFailed(format!(
                                "Invalid P-256 public key: {}",
                                e
                            ))
                        })?;
                    let sig = Signature::from_slice(&signature.bytes).map_err(|e| {
                        HsmError::VerificationFailed(format!(
                            "Invalid P-256 signature: {}",
                            e
                        ))
                    })?;
                    Ok(verifying_key.verify(message, &sig).is_ok())
                }
                KeyType::MlKem => Err(HsmError::VerificationFailed(format!(
                    "Key {} is an ML-KEM key, not a signing key",
                    handle.id()
                ))),
            }
        }

        async fn export_public_key(
            &self,
            handle: &KeyHandle,
        ) -> Result<crate::algorithm::AgilePublicKey, HsmError> {
            use crate::algorithm::{AgilePublicKey, SignatureAlgorithm};
            let LookupEntry {
                public_object: pub_obj,
                private_object: _,
                key_type: kt,
                cached_public_bytes: cached_pk,
            } = self.lookup_entry(handle.id())?;
            match kt {
                KeyType::MlDsa => {
                    let pk_bytes = self.retrieve_data_object(pub_obj)?;
                    AgilePublicKey::new(SignatureAlgorithm::MlDsa65, pk_bytes)
                        .map_err(|e| HsmError::ProviderError(e.to_string()))
                }
                KeyType::Ed25519 => {
                    let pk_bytes = match cached_pk {
                        Some(b) => b,
                        None => self.read_ec_point(pub_obj)?,
                    };
                    AgilePublicKey::new(SignatureAlgorithm::Ed25519, pk_bytes)
                        .map_err(|e| HsmError::ProviderError(e.to_string()))
                }
                KeyType::EcdsaP256 => {
                    let pk_bytes = match cached_pk {
                        Some(b) => b,
                        None => {
                            let raw = self.read_ec_point(pub_obj)?;
                            let vk =
                                p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                                    .map_err(|e| {
                                        HsmError::ProviderError(format!(
                                            "Invalid P-256 public key: {}",
                                            e
                                        ))
                                    })?;
                            vk.to_encoded_point(true).as_bytes().to_vec()
                        }
                    };
                    AgilePublicKey::new(SignatureAlgorithm::EcdsaP256, pk_bytes)
                        .map_err(|e| HsmError::ProviderError(e.to_string()))
                }
                KeyType::MlKem => Err(HsmError::ProviderError(format!(
                    "Key {} is an ML-KEM key — not a signing key",
                    handle.id()
                ))),
            }
        }
    }

    impl Drop for Pkcs11HsmProvider {
        fn drop(&mut self) {
            // Attempt graceful logout; ignore errors during teardown
            if let Ok(session_guard) = self.session.lock() {
                let _ = session_guard.0.logout();
            }
        }
    }

    impl fmt::Debug for Pkcs11HsmProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let key_count = self.key_map.read().map(|k| k.len()).unwrap_or(0);
            f.debug_struct("Pkcs11HsmProvider")
                .field("key_count", &key_count)
                .finish()
        }
    }
}

#[cfg(feature = "cloudhsm")]
pub use pkcs11_provider::Pkcs11HsmProvider;

/// Thales Luna HSM provider stub.
///
/// This is a placeholder for the Thales Luna HSM integration. The actual implementation
/// will use the PKCS#11 interface via the `cryptoki` crate.
///
/// # Implementation Plan
///
/// 1. Connect to Luna HSM using PKCS#11
/// 2. Use Luna's PQC firmware modules when available
/// 3. Implement FIPS 140-2/3 compliant key management
/// 4. Support HSM clustering for high availability
pub struct ThalesHsmProvider {
    // TODO: Implement Thales Luna HSM integration via PKCS#11 / cryptoki
    //
    // Fields to add:
    // - pkcs11_context: Pkcs11 context from cryptoki
    // - session: Active session with the HSM
    // - slot_id: The HSM slot being used
    // - partition_label: The HSM partition being used
    _private: (),
}

impl ThalesHsmProvider {
    /// Creates a new Thales Luna HSM provider.
    ///
    /// # Arguments
    ///
    /// * `_slot_id` - The HSM slot ID to use
    /// * `_pin` - The PIN for authentication
    ///
    /// # Errors
    ///
    /// Currently returns `HsmError::ProviderError` as this is a stub implementation.
    /// Use `SoftHsmProvider` for development and testing.
    #[allow(dead_code)]
    pub fn new(_slot_id: u64, _pin: &str) -> Result<Self, HsmError> {
        // TODO: Implement Thales Luna HSM integration via PKCS#11 / cryptoki
        //
        // Steps:
        // 1. Load the Luna PKCS#11 library (libCryptoki2.so or cryptoki.dll)
        // 2. Initialize the PKCS#11 context
        // 3. Find the appropriate slot/partition
        // 4. Open a session with the HSM
        // 5. Authenticate with the HSM (login with partition password)
        // 6. Store session and context for later use
        Err(HsmError::ProviderError(
            "Thales Luna HSM integration not yet implemented. Use SoftHsmProvider for development.".to_string(),
        ))
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_ml_dsa_keypair() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair generation should succeed");

        assert_eq!(handle.key_type(), KeyType::MlDsa);
        assert!(!handle.id().is_empty());
        assert!(handle.id().starts_with("soft-hsm-key-"));
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair generation should succeed");

        let message = b"Hello, quantum-safe world!";
        let signature = hsm
            .sign(&handle, message)
            .await
            .expect("Signing should succeed");

        let is_valid = hsm
            .verify(&handle, message, &signature)
            .await
            .expect("Verification should succeed");

        assert!(is_valid, "Signature should be valid");
    }

    #[tokio::test]
    async fn test_verify_tampered_message() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair generation should succeed");

        let original_message = b"Original message";
        let tampered_message = b"Tampered message";

        let signature = hsm
            .sign(&handle, original_message)
            .await
            .expect("Signing should succeed");

        let is_valid = hsm
            .verify(&handle, tampered_message, &signature)
            .await
            .expect("Verification should succeed");

        assert!(!is_valid, "Signature should be invalid for tampered message");
    }

    #[tokio::test]
    async fn test_verify_wrong_key() {
        let hsm = SoftHsmProvider::new();

        let handle_a = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair A generation should succeed");

        let handle_b = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair B generation should succeed");

        let message = b"Test message";
        let signature = hsm
            .sign(&handle_a, message)
            .await
            .expect("Signing with key A should succeed");

        let is_valid = hsm
            .verify(&handle_b, message, &signature)
            .await
            .expect("Verification with key B should succeed");

        assert!(!is_valid, "Signature should be invalid with wrong key");
    }

    #[tokio::test]
    async fn test_generate_ml_kem_keypair() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair generation should succeed");

        assert_eq!(handle.key_type(), KeyType::MlKem);
        assert!(!handle.id().is_empty());
        assert!(handle.id().starts_with("soft-hsm-key-"));
    }

    #[tokio::test]
    async fn test_encapsulate_decapsulate() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair generation should succeed");

        let (ciphertext, shared_secret_sender) = hsm
            .encapsulate(&handle)
            .await
            .expect("Encapsulation should succeed");

        let shared_secret_receiver = hsm
            .decapsulate(&handle, &ciphertext)
            .await
            .expect("Decapsulation should succeed");

        assert_eq!(
            shared_secret_sender.as_bytes(),
            shared_secret_receiver.as_bytes(),
            "Shared secrets should match"
        );
    }

    #[tokio::test]
    async fn test_decapsulate_wrong_key() {
        let hsm = SoftHsmProvider::new();

        let handle_a = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair A generation should succeed");

        let handle_b = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair B generation should succeed");

        let (ciphertext, shared_secret_a) = hsm
            .encapsulate(&handle_a)
            .await
            .expect("Encapsulation with key A should succeed");

        let shared_secret_b = hsm
            .decapsulate(&handle_b, &ciphertext)
            .await
            .expect("Decapsulation with key B should succeed");

        // ML-KEM is IND-CCA2: wrong key produces different shared secret, not an error
        assert_ne!(
            shared_secret_a.as_bytes(),
            shared_secret_b.as_bytes(),
            "Shared secrets should differ when using wrong key"
        );
    }

    #[tokio::test]
    async fn test_delete_key() {
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair generation should succeed");

        let message = b"Test message";
        let _ = hsm
            .sign(&handle, message)
            .await
            .expect("Signing should succeed before deletion");

        // Delete the key
        hsm.delete_key(&handle)
            .await
            .expect("Key deletion should succeed");

        // Operations with deleted handle should fail with KeyNotFound
        let sign_result = hsm.sign(&handle, message).await;
        assert!(
            matches!(sign_result, Err(HsmError::KeyNotFound(_))),
            "Signing with deleted key should return KeyNotFound, got {:?}",
            sign_result
        );

        // Deleting again should also fail with KeyNotFound
        let delete_result = hsm.delete_key(&handle).await;
        assert!(
            matches!(delete_result, Err(HsmError::KeyNotFound(_))),
            "Deleting already deleted key should return KeyNotFound, got {:?}",
            delete_result
        );
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let hsm = SoftHsmProvider::new();

        // Generate multiple DSA keys
        let dsa_handle_1 = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair 1 generation should succeed");
        let dsa_handle_2 = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair 2 generation should succeed");
        let dsa_handle_3 = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair 3 generation should succeed");

        // Generate multiple KEM keys
        let kem_handle_1 = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair 1 generation should succeed");
        let kem_handle_2 = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair 2 generation should succeed");

        // Verify all keys have unique IDs
        let ids = [
            dsa_handle_1.id(),
            dsa_handle_2.id(),
            dsa_handle_3.id(),
            kem_handle_1.id(),
            kem_handle_2.id(),
        ];
        let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique_ids.len(), "All key IDs should be unique");

        // Verify each key works independently
        let message = b"Test message";

        // Test DSA key 1
        let sig_1 = hsm
            .sign(&dsa_handle_1, message)
            .await
            .expect("Signing with key 1 should succeed");
        assert!(
            hsm.verify(&dsa_handle_1, message, &sig_1)
                .await
                .expect("Verification should succeed"),
            "Key 1 signature should verify with key 1"
        );

        // Test DSA key 2
        let sig_2 = hsm
            .sign(&dsa_handle_2, message)
            .await
            .expect("Signing with key 2 should succeed");
        assert!(
            hsm.verify(&dsa_handle_2, message, &sig_2)
                .await
                .expect("Verification should succeed"),
            "Key 2 signature should verify with key 2"
        );

        // Test KEM key 1
        let (ct_1, ss_1) = hsm
            .encapsulate(&kem_handle_1)
            .await
            .expect("Encapsulation with KEM key 1 should succeed");
        let ss_1_dec = hsm
            .decapsulate(&kem_handle_1, &ct_1)
            .await
            .expect("Decapsulation with KEM key 1 should succeed");
        assert_eq!(
            ss_1.as_bytes(),
            ss_1_dec.as_bytes(),
            "KEM key 1 shared secrets should match"
        );

        // Test KEM key 2
        let (ct_2, ss_2) = hsm
            .encapsulate(&kem_handle_2)
            .await
            .expect("Encapsulation with KEM key 2 should succeed");
        let ss_2_dec = hsm
            .decapsulate(&kem_handle_2, &ct_2)
            .await
            .expect("Decapsulation with KEM key 2 should succeed");
        assert_eq!(
            ss_2.as_bytes(),
            ss_2_dec.as_bytes(),
            "KEM key 2 shared secrets should match"
        );

        // Cross-key verification should fail
        assert!(
            !hsm.verify(&dsa_handle_2, message, &sig_1)
                .await
                .expect("Cross verification should succeed"),
            "Key 1 signature should not verify with key 2"
        );
    }

    #[tokio::test]
    async fn test_key_handle_debug() {
        let handle = KeyHandle::new("test-key-123".to_string(), KeyType::MlDsa);
        let debug_str = format!("{:?}", handle);

        assert!(debug_str.contains("KeyHandle"));
        assert!(debug_str.contains("test-key-123"));
        assert!(debug_str.contains("MlDsa"));
    }

    #[tokio::test]
    async fn test_hsm_error_display() {
        let errors = vec![
            HsmError::KeyGenerationFailed("test".to_string()),
            HsmError::SigningFailed("test".to_string()),
            HsmError::VerificationFailed("test".to_string()),
            HsmError::EncapsulationFailed("test".to_string()),
            HsmError::DecapsulationFailed("test".to_string()),
            HsmError::KeyNotFound("test".to_string()),
            HsmError::ProviderError("test".to_string()),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty(), "Error display should not be empty");
            assert!(
                display.contains("test"),
                "Error display should contain the message"
            );
        }
    }

    #[tokio::test]
    async fn test_wrong_key_type_operations() {
        let hsm = SoftHsmProvider::new();

        // Generate a DSA key
        let dsa_handle = hsm
            .generate_ml_dsa_keypair()
            .await
            .expect("ML-DSA keypair generation should succeed");

        // Generate a KEM key
        let kem_handle = hsm
            .generate_ml_kem_keypair()
            .await
            .expect("ML-KEM keypair generation should succeed");

        // Try to encapsulate with DSA key (should fail)
        let encap_result = hsm.encapsulate(&dsa_handle).await;
        assert!(
            matches!(encap_result, Err(HsmError::EncapsulationFailed(_))),
            "Encapsulation with DSA key should fail, got {:?}",
            encap_result
        );

        // Try to sign with KEM key (should fail)
        let sign_result = hsm.sign(&kem_handle, b"test").await;
        assert!(
            matches!(sign_result, Err(HsmError::SigningFailed(_))),
            "Signing with KEM key should fail, got {:?}",
            sign_result
        );
    }

    // Note: AwsCloudHsmProvider replaced by Pkcs11HsmProvider (feature = "cloudhsm").
    // PKCS#11 integration tests are in tests/hsm_pkcs11_tests.rs.

    #[test]
    fn test_thales_provider_returns_error() {
        let result = ThalesHsmProvider::new(1, "pin");
        assert!(result.is_err());
        match result {
            Err(HsmError::ProviderError(msg)) => {
                assert!(msg.contains("Thales Luna HSM"));
                assert!(msg.contains("not yet implemented"));
            }
            _ => panic!("Expected ProviderError"),
        }
    }

    // ─── Algorithmic Agility Tests ─────────────────────────────────────────

    #[tokio::test]
    async fn test_supported_signing_algorithms() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let algos = hsm.supported_signing_algorithms();
        assert!(algos.contains(&SignatureAlgorithm::Ed25519));
        assert!(algos.contains(&SignatureAlgorithm::EcdsaP256));
        assert!(algos.contains(&SignatureAlgorithm::MlDsa65));
    }

    #[tokio::test]
    async fn test_ed25519_sign_verify_roundtrip() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::Ed25519)
            .await
            .expect("Ed25519 keygen should succeed");
        assert_eq!(handle.key_type(), KeyType::Ed25519);

        let message = b"agile signing works";
        let sig = hsm.sign_agile(&handle, message).await.expect("sign");
        assert_eq!(sig.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(sig.bytes.len(), 64);

        let valid = hsm.verify_agile(&handle, message, &sig).await.expect("verify");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_ed25519_tampered_message_rejected() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::Ed25519)
            .await
            .unwrap();
        let sig = hsm.sign_agile(&handle, b"original").await.unwrap();
        let valid = hsm.verify_agile(&handle, b"tampered", &sig).await.unwrap();
        assert!(!valid, "Tampered message should fail verification");
    }

    #[tokio::test]
    async fn test_ecdsa_p256_sign_verify_roundtrip() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::EcdsaP256)
            .await
            .expect("ECDSA-P256 keygen should succeed");
        assert_eq!(handle.key_type(), KeyType::EcdsaP256);

        let message = b"agile FIPS 186-4 signing";
        let sig = hsm.sign_agile(&handle, message).await.expect("sign");
        assert_eq!(sig.algorithm, SignatureAlgorithm::EcdsaP256);
        assert_eq!(sig.bytes.len(), 64);

        let valid = hsm.verify_agile(&handle, message, &sig).await.expect("verify");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_ecdsa_p256_tampered_message_rejected() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::EcdsaP256)
            .await
            .unwrap();
        let sig = hsm.sign_agile(&handle, b"original").await.unwrap();
        let valid = hsm.verify_agile(&handle, b"tampered", &sig).await.unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_ml_dsa_sign_via_agile_api() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::MlDsa65)
            .await
            .expect("ML-DSA keygen should succeed");
        assert_eq!(handle.key_type(), KeyType::MlDsa);

        let message = b"agile post-quantum signing";
        let sig = hsm.sign_agile(&handle, message).await.expect("sign");
        assert_eq!(sig.algorithm, SignatureAlgorithm::MlDsa65);

        let valid = hsm.verify_agile(&handle, message, &sig).await.expect("verify");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_cross_algorithm_signature_rejected() {
        // An Ed25519 signature must not validate against an ECDSA key, even
        // when raw bytes happen to be the same length.
        use crate::algorithm::{AgileSignature, SignatureAlgorithm};
        let hsm = SoftHsmProvider::new();

        let ed_handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::Ed25519)
            .await
            .unwrap();
        let ec_handle = hsm
            .generate_signing_keypair(SignatureAlgorithm::EcdsaP256)
            .await
            .unwrap();

        let ed_sig = hsm.sign_agile(&ed_handle, b"x").await.unwrap();

        // Reuse Ed25519 bytes but tag as ECDSA — verify should reject due to
        // algorithm mismatch with the ECDSA key.
        let spoof = AgileSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: ed_sig.bytes.clone(),
        };
        let result = hsm.verify_agile(&ec_handle, b"x", &spoof).await;
        assert!(matches!(result, Err(HsmError::VerificationFailed(_))));
    }

    #[tokio::test]
    async fn test_export_public_key() {
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();

        for algo in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::EcdsaP256,
            SignatureAlgorithm::MlDsa65,
        ] {
            let handle = hsm.generate_signing_keypair(algo).await.unwrap();
            let pk = hsm.export_public_key(&handle).await.unwrap();
            assert_eq!(pk.algorithm, algo);
            assert_eq!(pk.bytes.len(), algo.public_key_size());
        }
    }

    #[tokio::test]
    async fn test_ml_kem_handle_rejected_by_export_public_key() {
        let hsm = SoftHsmProvider::new();
        let kem_handle = hsm.generate_ml_kem_keypair().await.unwrap();
        let result = hsm.export_public_key(&kem_handle).await;
        assert!(matches!(result, Err(HsmError::ProviderError(_))));
    }

    #[tokio::test]
    async fn test_signatures_differ_across_keys() {
        // Same algorithm, two keys — same message must yield different sigs
        // (or at least different verification results).
        use crate::algorithm::SignatureAlgorithm;
        let hsm = SoftHsmProvider::new();
        let h1 = hsm
            .generate_signing_keypair(SignatureAlgorithm::Ed25519)
            .await
            .unwrap();
        let h2 = hsm
            .generate_signing_keypair(SignatureAlgorithm::Ed25519)
            .await
            .unwrap();

        let msg = b"same message";
        let s1 = hsm.sign_agile(&h1, msg).await.unwrap();
        let s2 = hsm.sign_agile(&h2, msg).await.unwrap();

        // Must verify under their own keys
        assert!(hsm.verify_agile(&h1, msg, &s1).await.unwrap());
        assert!(hsm.verify_agile(&h2, msg, &s2).await.unwrap());

        // Must NOT verify under the wrong key
        assert!(!hsm.verify_agile(&h1, msg, &s2).await.unwrap());
        assert!(!hsm.verify_agile(&h2, msg, &s1).await.unwrap());
    }
}
