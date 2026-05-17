// SPDX-License-Identifier: MIT OR Apache-2.0
//! # ML-KEM (FIPS 203) Key Encapsulation Mechanism
//!
//! This module implements ML-KEM using Kyber1024 for the highest security level (Level 5).
//! It is part of the Ligare (QPL) post-quantum cryptographic foundation.
//!
//! ## Security Properties
//!
//! - All operations use constant-time implementations from the pqcrypto reference library
//! - Secret keys and shared secrets are automatically zeroized on drop to prevent memory leakage
//! - IND-CCA2 security: decapsulation with wrong key produces a pseudorandom shared secret
//!
//! ## Usage
//!
//! ```rust,no_run
//! use qpl_crypto::ml_kem::{generate_keypair, encapsulate, decapsulate};
//!
//! // Generate a keypair
//! let keypair = generate_keypair().expect("keypair generation failed");
//!
//! // Encapsulate to create a shared secret
//! let (ciphertext, shared_secret_sender) = encapsulate(keypair.public_key())
//!     .expect("encapsulation failed");
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret_receiver = decapsulate(&ciphertext, &keypair.secret_key)
//!     .expect("decapsulation failed");
//!
//! assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
//! ```

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Expected byte length of a Kyber1024 public key.
pub const PUBLIC_KEY_BYTES: usize = 1568;

/// Expected byte length of a Kyber1024 secret key.
pub const SECRET_KEY_BYTES: usize = 3168;

/// Expected byte length of a Kyber1024 ciphertext.
pub const CIPHERTEXT_BYTES: usize = 1568;

/// Expected byte length of a Kyber1024 shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;

/// Errors that can occur during ML-KEM operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MlKemError {
    /// Error during key encapsulation.
    #[error("Encapsulation error: {0}")]
    EncapsulationError(String),

    /// Error during key decapsulation.
    #[error("Decapsulation error: {0}")]
    DecapsulationError(String),

    /// Error during serialization or deserialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Error during key generation.
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

/// ML-KEM public key wrapper.
///
/// Wraps the raw public key bytes from Kyber1024.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemPublicKey {
    bytes: Vec<u8>,
}

impl MlKemPublicKey {
    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constructs a public key from raw bytes.
    ///
    /// Returns an error if the byte length is incorrect.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(MlKemError::SerializationError(format!(
                "Invalid public key length: expected {}, got {}",
                PUBLIC_KEY_BYTES,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl std::fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show hex prefix of the public key (first 16 bytes)
        let hex_prefix: String = self.bytes.iter().take(16).map(|b| format!("{:02x}", b)).collect();
        f.debug_struct("MlKemPublicKey")
            .field("bytes", &format!("{}... ({} bytes)", hex_prefix, self.bytes.len()))
            .finish()
    }
}

/// ML-KEM secret key wrapper.
///
/// Wraps the raw secret key bytes from Kyber1024.
/// The secret key is zeroized on drop to prevent memory leakage.
/// Clone is intentionally not implemented to prevent accidental duplication of secret material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey {
    bytes: Vec<u8>,
}

impl MlKemSecretKey {
    /// Returns the raw bytes of the secret key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constructs a secret key from raw bytes.
    ///
    /// Returns an error if the byte length is incorrect.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(MlKemError::SerializationError(format!(
                "Invalid secret key length: expected {}, got {}",
                SECRET_KEY_BYTES,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl std::fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never show secret key material
        f.debug_struct("MlKemSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// ML-KEM ciphertext wrapper.
///
/// Wraps the ciphertext bytes produced by encapsulation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlKemCiphertext {
    bytes: Vec<u8>,
}

impl MlKemCiphertext {
    /// Returns the raw bytes of the ciphertext.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constructs a ciphertext from raw bytes.
    ///
    /// Returns an error if the byte length is incorrect.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(MlKemError::SerializationError(format!(
                "Invalid ciphertext length: expected {}, got {}",
                CIPHERTEXT_BYTES,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl std::fmt::Debug for MlKemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show hex prefix of the ciphertext (first 16 bytes)
        let hex_prefix: String = self.bytes.iter().take(16).map(|b| format!("{:02x}", b)).collect();
        f.debug_struct("MlKemCiphertext")
            .field("bytes", &format!("{}... ({} bytes)", hex_prefix, self.bytes.len()))
            .finish()
    }
}

/// Shared secret produced by ML-KEM encapsulation/decapsulation.
///
/// The shared secret is zeroized on drop to prevent memory leakage.
/// Clone is intentionally not implemented to prevent accidental duplication of secret material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Returns the raw bytes of the shared secret.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never show shared secret material
        f.debug_struct("SharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing attacks
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        let mut result = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for SharedSecret {}

/// ML-KEM keypair containing both public and secret keys.
pub struct MlKemKeyPair {
    /// The public key, safe to share.
    pub public_key: MlKemPublicKey,
    /// The secret key, must be kept confidential.
    pub secret_key: MlKemSecretKey,
}

impl MlKemKeyPair {
    /// Generates a new ML-KEM keypair using Kyber1024.
    pub fn generate() -> Result<Self, MlKemError> {
        let (pk, sk) = kyber1024::keypair();

        let public_key = MlKemPublicKey {
            bytes: pk.as_bytes().to_vec(),
        };
        let secret_key = MlKemSecretKey {
            bytes: sk.as_bytes().to_vec(),
        };

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.public_key
    }
}

impl std::fmt::Debug for MlKemKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show the public key
        f.debug_struct("MlKemKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Encapsulates a shared secret using the given public key.
///
/// Returns a tuple of (ciphertext, shared_secret). The ciphertext should be sent
/// to the owner of the corresponding secret key, who can then decapsulate it
/// to recover the same shared secret.
pub fn encapsulate(public_key: &MlKemPublicKey) -> Result<(MlKemCiphertext, SharedSecret), MlKemError> {
    let pk = kyber1024::PublicKey::from_bytes(&public_key.bytes).map_err(|e| {
        MlKemError::EncapsulationError(format!("Failed to parse public key: {:?}", e))
    })?;

    let (ss, ct) = kyber1024::encapsulate(&pk);

    let ciphertext = MlKemCiphertext {
        bytes: ct.as_bytes().to_vec(),
    };
    let shared_secret = SharedSecret {
        bytes: ss.as_bytes().to_vec(),
    };

    Ok((ciphertext, shared_secret))
}

/// Decapsulates a ciphertext using the given secret key to recover the shared secret.
///
/// Note: Due to Kyber's IND-CCA2 security, decapsulating with the wrong secret key
/// will produce a pseudorandom shared secret rather than an error. This prevents
/// chosen-ciphertext attacks.
pub fn decapsulate(
    ciphertext: &MlKemCiphertext,
    secret_key: &MlKemSecretKey,
) -> Result<SharedSecret, MlKemError> {
    let ct = kyber1024::Ciphertext::from_bytes(&ciphertext.bytes).map_err(|e| {
        MlKemError::DecapsulationError(format!("Failed to parse ciphertext: {:?}", e))
    })?;

    let sk = kyber1024::SecretKey::from_bytes(&secret_key.bytes).map_err(|e| {
        MlKemError::DecapsulationError(format!("Failed to parse secret key: {:?}", e))
    })?;

    let ss = kyber1024::decapsulate(&ct, &sk);

    Ok(SharedSecret {
        bytes: ss.as_bytes().to_vec(),
    })
}

/// Convenience function to generate a new ML-KEM keypair.
///
/// This is equivalent to `MlKemKeyPair::generate()`.
pub fn generate_keypair() -> Result<MlKemKeyPair, MlKemError> {
    MlKemKeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().expect("keypair generation should succeed");

        // Verify keys are non-empty
        assert!(!keypair.public_key.as_bytes().is_empty());
        assert!(!keypair.secret_key.as_bytes().is_empty());

        // Verify correct lengths
        assert_eq!(keypair.public_key.as_bytes().len(), PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret_key.as_bytes().len(), SECRET_KEY_BYTES);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let keypair = generate_keypair().expect("keypair generation should succeed");

        // Encapsulate with public key
        let (ciphertext, shared_secret_sender) =
            encapsulate(keypair.public_key()).expect("encapsulation should succeed");

        // Verify ciphertext length
        assert_eq!(ciphertext.as_bytes().len(), CIPHERTEXT_BYTES);

        // Verify shared secret length
        assert_eq!(shared_secret_sender.as_bytes().len(), SHARED_SECRET_BYTES);

        // Decapsulate with secret key
        let shared_secret_receiver =
            decapsulate(&ciphertext, &keypair.secret_key).expect("decapsulation should succeed");

        // Shared secrets must match
        assert_eq!(
            shared_secret_sender.as_bytes(),
            shared_secret_receiver.as_bytes()
        );
    }

    #[test]
    fn test_decapsulate_wrong_key() {
        let keypair1 = generate_keypair().expect("keypair1 generation should succeed");
        let keypair2 = generate_keypair().expect("keypair2 generation should succeed");

        // Encapsulate with keypair1's public key
        let (ciphertext, shared_secret_sender) =
            encapsulate(keypair1.public_key()).expect("encapsulation should succeed");

        // Decapsulate with keypair2's secret key (wrong key)
        let shared_secret_wrong =
            decapsulate(&ciphertext, &keypair2.secret_key).expect("decapsulation should succeed");

        // Kyber is IND-CCA2: wrong key produces different shared secret, not an error
        assert_ne!(
            shared_secret_sender.as_bytes(),
            shared_secret_wrong.as_bytes(),
            "Decapsulating with wrong key should produce different shared secret"
        );
    }

    #[test]
    fn test_multiple_encapsulations_differ() {
        let keypair = generate_keypair().expect("keypair generation should succeed");

        // Two encapsulations of the same public key
        let (ciphertext1, shared_secret1) =
            encapsulate(keypair.public_key()).expect("encapsulation 1 should succeed");
        let (ciphertext2, shared_secret2) =
            encapsulate(keypair.public_key()).expect("encapsulation 2 should succeed");

        // Ciphertexts should differ (randomized encapsulation)
        assert_ne!(
            ciphertext1.as_bytes(),
            ciphertext2.as_bytes(),
            "Multiple encapsulations should produce different ciphertexts"
        );

        // Shared secrets should also differ
        assert_ne!(
            shared_secret1.as_bytes(),
            shared_secret2.as_bytes(),
            "Multiple encapsulations should produce different shared secrets"
        );
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let keypair = generate_keypair().expect("keypair generation should succeed");

        let bytes = keypair.public_key.as_bytes();
        let restored =
            MlKemPublicKey::from_bytes(bytes).expect("public key deserialization should succeed");

        assert_eq!(keypair.public_key, restored);
    }

    #[test]
    fn test_secret_key_serialization_roundtrip() {
        let keypair = generate_keypair().expect("keypair generation should succeed");

        // Serialize and deserialize the secret key
        let bytes = keypair.secret_key.as_bytes().to_vec();
        let restored =
            MlKemSecretKey::from_bytes(&bytes).expect("secret key deserialization should succeed");

        // Verify the restored key still works for decapsulation
        let (ciphertext, shared_secret_sender) =
            encapsulate(keypair.public_key()).expect("encapsulation should succeed");

        let shared_secret_receiver =
            decapsulate(&ciphertext, &restored).expect("decapsulation should succeed");

        assert_eq!(
            shared_secret_sender.as_bytes(),
            shared_secret_receiver.as_bytes()
        );
    }

    #[test]
    fn test_ciphertext_serialization_roundtrip() {
        let keypair = generate_keypair().expect("keypair generation should succeed");
        let (ciphertext, _) = encapsulate(keypair.public_key()).expect("encapsulation should succeed");

        let bytes = ciphertext.as_bytes();
        let restored =
            MlKemCiphertext::from_bytes(bytes).expect("ciphertext deserialization should succeed");

        assert_eq!(ciphertext, restored);
    }

    #[test]
    fn test_debug_redacts_secret_key() {
        let keypair = generate_keypair().expect("keypair generation should succeed");
        let debug_str = format!("{:?}", keypair.secret_key);

        assert!(
            debug_str.contains("REDACTED"),
            "Debug output should redact secret key material: {}",
            debug_str
        );
        // Ensure no raw bytes are leaked
        assert!(
            !debug_str.contains("[0x"),
            "Debug output should not contain raw bytes"
        );
    }

    #[test]
    fn test_debug_redacts_shared_secret() {
        let keypair = generate_keypair().expect("keypair generation should succeed");
        let (_, shared_secret) = encapsulate(keypair.public_key()).expect("encapsulation should succeed");
        let debug_str = format!("{:?}", shared_secret);

        assert!(
            debug_str.contains("REDACTED"),
            "Debug output should redact shared secret material: {}",
            debug_str
        );
    }

    #[test]
    fn test_invalid_public_key_length() {
        let invalid_bytes = vec![0u8; 100]; // Wrong length
        let result = MlKemPublicKey::from_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlKemError::SerializationError(_)));
    }

    #[test]
    fn test_invalid_secret_key_length() {
        let invalid_bytes = vec![0u8; 100]; // Wrong length
        let result = MlKemSecretKey::from_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlKemError::SerializationError(_)));
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let invalid_bytes = vec![0u8; 100]; // Wrong length
        let result = MlKemCiphertext::from_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MlKemError::SerializationError(_)));
    }

    #[test]
    fn test_shared_secret_constant_time_eq() {
        let keypair = generate_keypair().expect("keypair generation should succeed");
        let (ciphertext, ss1) = encapsulate(keypair.public_key()).expect("encapsulation should succeed");
        let ss2 = decapsulate(&ciphertext, &keypair.secret_key).expect("decapsulation should succeed");

        // Same shared secrets should be equal
        assert_eq!(ss1, ss2);

        // Different shared secrets should not be equal
        let (_, ss3) = encapsulate(keypair.public_key()).expect("encapsulation should succeed");
        assert_ne!(ss1, ss3);
    }
}
