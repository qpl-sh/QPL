// SPDX-License-Identifier: MIT OR Apache-2.0
//! # PQC HSM Abstraction Layer
//!
//! This module provides a hardware security module (HSM) abstraction layer for
//! post-quantum cryptographic operations in Ligare (QPL).
//!
//! ## Architecture
//!
//! The module defines an [`HsmProvider`] trait that abstracts HSM operations for:
//! - **ML-DSA (FIPS 204)**: Digital signatures using Module-Lattice Digital Signature Algorithm
//! - **ML-KEM (FIPS 203)**: Key encapsulation using Module-Lattice Key Encapsulation Mechanism
//!
//! ## Providers
//!
//! - [`SoftHsmProvider`]: Software-based implementation for development and testing.
//!   **WARNING**: This does NOT provide real HSM security guarantees and should
//!   only be used in development/testing environments.
//!
//! - [`Pkcs11HsmProvider`]: PKCS#11-based provider for AWS CloudHSM, SoftHSM2, etc.
//!   (feature-gated behind `cloudhsm`)
//! - [`ThalesHsmProvider`]: Placeholder for Thales Luna HSM integration (not yet implemented)
//!
//! ## Production HSM Integration Plan
//!
//! Production HSM providers will integrate via PKCS#11 / cryptoki:
//!
//! 1. Use the `cryptoki` crate for PKCS#11 bindings
//! 2. Store PQC keys in HSM slots with appropriate access controls
//! 3. Perform all cryptographic operations within the HSM boundary
//! 4. Support key attestation and audit logging
//!
//! ## Example
//!
//! ```rust,no_run
//! use qpl_crypto::hsm::{HsmProvider, SoftHsmProvider, KeyHandle};
//!
//! #[tokio::main]
//! async fn main() {
//!     let hsm = SoftHsmProvider::new();
//!     
//!     // Generate an ML-DSA keypair
//!     let handle = hsm.generate_ml_dsa_keypair().await.expect("keygen failed");
//!     
//!     // Sign a message
//!     let message = b"Hello, quantum-safe world!";
//!     let signature = hsm.sign(&handle, message).await.expect("signing failed");
//!     
//!     // Verify the signature
//!     let valid = hsm.verify(&handle, message, &signature).await.expect("verify failed");
//!     assert!(valid);
//! }
//! ```

use async_trait::async_trait;
use pqcrypto_dilithium::dilithium3;
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
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::MlDsa => write!(f, "ML-DSA"),
            KeyType::MlKem => write!(f, "ML-KEM"),
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

/// Internal enum to hold different key types.
enum StoredKey {
    MlDsa(StoredMlDsaKey),
    MlKem(StoredMlKemKey),
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
        // Generate the keypair using dilithium3 directly
        let (pk, sk) = dilithium3::keypair();

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
                // Sign using dilithium3 directly
                let sk = dilithium3::SecretKey::from_bytes(&key.secret_key_bytes).map_err(|e| {
                    HsmError::SigningFailed(format!("Failed to parse secret key: {:?}", e))
                })?;

                let sig = dilithium3::detached_sign(message, &sk);

                crate::ml_dsa::MlDsaSignature::from_bytes(sig.as_bytes())
                    .map_err(|e| HsmError::SigningFailed(format!("Invalid signature: {}", e)))
            }
            StoredKey::MlKem(_) => Err(HsmError::SigningFailed(format!(
                "Key {} is an ML-KEM key, not ML-DSA",
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
        /// CKO_DATA object storing public key bytes (plaintext)
        public_object: ObjectHandle,
        /// CKO_DATA object storing wrapped (AES-CBC-PAD encrypted) private key bytes
        private_object: ObjectHandle,
        /// The type of cryptographic key
        key_type: KeyType,
    }

    /// PKCS#11-based HSM provider for production key management.
    ///
    /// Uses PKCS#11 bindings via the `cryptoki` crate to interface with hardware
    /// security modules (HSMs) such as AWS CloudHSM, Thales Luna, or SoftHSM2.
    ///
    /// ## Hybrid Architecture
    ///
    /// Since PKCS#11 firmware doesn't yet natively support ML-DSA-65 or ML-KEM-1024,
    /// this provider uses a hybrid approach:
    ///
    /// - **Key storage**: Private keys are encrypted with an AES-256 master wrapping
    ///   key (generated inside the HSM) and stored as `CKO_DATA` objects.
    /// - **Crypto operations**: PQC signing, verification, encapsulation, and
    ///   decapsulation are performed in software using the `pqcrypto` crate.
    /// - **Key protection**: Private key material is encrypted at rest in the HSM
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
    }

    #[async_trait]
    impl HsmProvider for Pkcs11HsmProvider {
        async fn generate_ml_dsa_keypair(&self) -> Result<KeyHandle, HsmError> {
            // Generate ML-DSA-65 keypair in software
            let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
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

            // Sign in software, then zeroize
            let result = (|| -> Result<crate::ml_dsa::MlDsaSignature, HsmError> {
                let sk = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(&sk_bytes)
                    .map_err(|e| HsmError::SigningFailed(format!("Failed to parse secret key: {:?}", e)))?;

                let sig = pqcrypto_dilithium::dilithium3::detached_sign(message, &sk);

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

        // Kyber is IND-CCA2: wrong key produces different shared secret, not an error
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
        let ids = vec![
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
}
