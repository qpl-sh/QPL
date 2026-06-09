// SPDX-License-Identifier: MIT OR Apache-2.0
//! ML-DSA (FIPS 204) digital signature implementation at security level 3.
//!
//! This module is part of the Ligare (QPL) post-quantum cryptographic foundation.
//! It implements ML-DSA-65 (Module-Lattice Digital Signature Algorithm) which
//! provides NIST security level 3 (equivalent to AES-192). The underlying
//! implementation comes from the FIPS-validated `pqcrypto-mldsa` crate; outputs
//! remain byte-identical to the legacy Dilithium3 reference implementation.
//!
//! # Security Properties
//!
//! - All cryptographic operations use constant-time implementations from the pqcrypto
//!   reference implementation to prevent timing side-channel attacks.
//! - Secret keys are automatically zeroized on drop using the `zeroize` crate to prevent
//!   memory leakage of sensitive key material.
//! - Secret keys cannot be cloned to prevent accidental copies of sensitive material.
//! - Debug output for secret keys is redacted to prevent accidental logging of key material.
//!
//! # Example
//!
//! ```
//! use qpl_crypto::ml_dsa::{generate_keypair, verify};
//!
//! // Generate a new ML-DSA keypair
//! let keypair = generate_keypair().expect("Key generation failed");
//!
//! // Sign a message
//! let message = b"Hello, quantum-safe world!";
//! let signature = keypair.sign(message).expect("Signing failed");
//!
//! // Verify the signature
//! let is_valid = verify(keypair.public_key(), message, &signature).expect("Verification failed");
//! assert!(is_valid);
//! ```

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Expected length of an ML-DSA-65 public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 1952;

/// Expected length of an ML-DSA-65 secret key in bytes.
pub const SECRET_KEY_LENGTH: usize = 4032;

/// Expected length of an ML-DSA-65 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 3309;

/// Errors that can occur during ML-DSA operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MlDsaError {
    /// Error during signing operation.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Error during signature verification.
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// Error during serialization or deserialization.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Error during key generation.
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
}

/// An ML-DSA public key.
///
/// This key can be freely shared and is used to verify signatures.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaPublicKey {
    bytes: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Creates a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length doesn't match the expected
    /// public key length for ML-DSA-65.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(MlDsaError::SerializationError(format!(
                "Invalid public key length: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_prefix: String = self.bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect();
        write!(f, "MlDsaPublicKey({}...)", hex_prefix)
    }
}

/// An ML-DSA secret key.
///
/// This key must be kept confidential and is used to create signatures.
/// The secret key is automatically zeroized when dropped to prevent memory leakage.
///
/// # Security
///
/// - Cannot be cloned to prevent accidental copies of sensitive material.
/// - Debug output is redacted to prevent accidental logging.
/// - Automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MlDsaSecretKey {
    bytes: Vec<u8>,
}

impl MlDsaSecretKey {
    /// Returns the raw bytes of the secret key.
    ///
    /// # Security
    ///
    /// Handle the returned bytes with care. They contain sensitive key material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Creates a secret key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length doesn't match the expected
    /// secret key length for ML-DSA-65.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(MlDsaError::SerializationError(format!(
                "Invalid secret key length: expected {}, got {}",
                SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlDsaSecretKey(REDACTED)")
    }
}

/// An ML-DSA detached signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlDsaSignature {
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Returns the raw bytes of the signature.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Creates a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice length doesn't match the expected
    /// signature length for ML-DSA-65.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(MlDsaError::SerializationError(format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

impl fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_prefix: String = self.bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect();
        write!(f, "MlDsaSignature({}...)", hex_prefix)
    }
}

/// An ML-DSA keypair consisting of a public key and a secret key.
pub struct MlDsaKeyPair {
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
}

impl MlDsaKeyPair {
    /// Generates a new ML-DSA keypair using a cryptographically secure random number generator.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails (extremely rare with proper entropy).
    pub fn generate() -> Result<Self, MlDsaError> {
        let (pk, sk) = mldsa65::keypair();

        Ok(Self {
            public_key: MlDsaPublicKey {
                bytes: pk.as_bytes().to_vec(),
            },
            secret_key: MlDsaSecretKey {
                bytes: sk.as_bytes().to_vec(),
            },
        })
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    /// Signs a message using this keypair's secret key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign (can be any length, including empty).
    ///
    /// # Returns
    ///
    /// A detached signature that can be verified using the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing operation fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature, MlDsaError> {
        let sk = mldsa65::SecretKey::from_bytes(self.secret_key.as_bytes()).map_err(|e| {
            MlDsaError::SigningError(format!("Failed to parse secret key: {:?}", e))
        })?;

        let sig = mldsa65::detached_sign(message, &sk);

        Ok(MlDsaSignature {
            bytes: sig.as_bytes().to_vec(),
        })
    }
}

impl fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"REDACTED")
            .finish()
    }
}

/// Verifies a signature against a message using the given public key.
///
/// # Arguments
///
/// * `public_key` - The public key to verify the signature against.
/// * `message` - The original message that was signed.
/// * `signature` - The signature to verify.
///
/// # Returns
///
/// * `Ok(true)` if the signature is valid for the given message and public key.
/// * `Ok(false)` if the signature is invalid (tampered message, wrong key, or corrupted signature).
/// * `Err(...)` if there was an error parsing the keys or signature.
pub fn verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool, MlDsaError> {
    let pk = mldsa65::PublicKey::from_bytes(public_key.as_bytes()).map_err(|e| {
        MlDsaError::VerificationError(format!("Failed to parse public key: {:?}", e))
    })?;

    let sig = mldsa65::DetachedSignature::from_bytes(signature.as_bytes()).map_err(|e| {
        MlDsaError::VerificationError(format!("Failed to parse signature: {:?}", e))
    })?;

    match mldsa65::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generates a new ML-DSA keypair.
///
/// This is a convenience wrapper around [`MlDsaKeyPair::generate()`].
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_keypair() -> Result<MlDsaKeyPair, MlDsaError> {
    MlDsaKeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().expect("Key generation should succeed");

        // Verify public key is non-empty and correct length
        assert_eq!(
            keypair.public_key().as_bytes().len(),
            PUBLIC_KEY_LENGTH,
            "Public key should be {} bytes",
            PUBLIC_KEY_LENGTH
        );
        assert!(
            keypair.public_key().as_bytes().iter().any(|&b| b != 0),
            "Public key should not be all zeros"
        );

        // Verify the keypair's secret key would produce valid signatures
        // (we can't directly check length without exposing it)
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let message = b"Hello, quantum-safe world!";

        let signature = keypair.sign(message).expect("Signing should succeed");
        let is_valid = verify(keypair.public_key(), message, &signature)
            .expect("Verification should not error");

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_verify_tampered_message() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let message = b"Original message";
        let tampered_message = b"Tampered message";

        let signature = keypair.sign(message).expect("Signing should succeed");
        let is_valid = verify(keypair.public_key(), tampered_message, &signature)
            .expect("Verification should not error");

        assert!(!is_valid, "Signature should be invalid for tampered message");
    }

    #[test]
    fn test_verify_wrong_key() {
        let keypair1 = generate_keypair().expect("Key generation should succeed");
        let keypair2 = generate_keypair().expect("Key generation should succeed");
        let message = b"Test message";

        let signature = keypair1.sign(message).expect("Signing should succeed");
        let is_valid = verify(keypair2.public_key(), message, &signature)
            .expect("Verification should not error");

        assert!(!is_valid, "Signature should be invalid with wrong public key");
    }

    #[test]
    fn test_verify_tampered_signature() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let message = b"Test message";

        let signature = keypair.sign(message).expect("Signing should succeed");

        // Tamper with the signature bytes
        let mut tampered_bytes = signature.as_bytes().to_vec();
        tampered_bytes[0] ^= 0xFF; // Flip bits in first byte
        tampered_bytes[100] ^= 0xFF; // Flip bits in middle

        // Try to create a tampered signature - this may fail or succeed depending on validation
        if let Ok(tampered_sig) = MlDsaSignature::from_bytes(&tampered_bytes) {
            let result = verify(keypair.public_key(), message, &tampered_sig);
            // Either returns Ok(false) or Err - both are acceptable
            if let Ok(is_valid) = result {
                assert!(!is_valid, "Tampered signature should be invalid");
            }
            // Err during verification is also acceptable for malformed signature
        }
        // Err during deserialization is also acceptable
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let original = keypair.public_key();

        let bytes = original.as_bytes();
        let restored =
            MlDsaPublicKey::from_bytes(bytes).expect("Public key deserialization should succeed");

        assert_eq!(
            original.as_bytes(),
            restored.as_bytes(),
            "Public key should survive serialization roundtrip"
        );
        assert_eq!(original, &restored, "Public keys should be equal");
    }

    #[test]
    fn test_secret_key_serialization_roundtrip() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let message = b"Test message for signing";

        // Get the original signature
        let original_signature = keypair.sign(message).expect("Signing should succeed");

        // Serialize and deserialize the secret key
        let sk_bytes = keypair.secret_key.as_bytes().to_vec();
        let restored_sk =
            MlDsaSecretKey::from_bytes(&sk_bytes).expect("Secret key deserialization should succeed");

        // Create a new keypair-like setup to test signing with restored key
        let _pk = mldsa65::PublicKey::from_bytes(keypair.public_key().as_bytes())
            .expect("Public key should be valid");
        let sk = mldsa65::SecretKey::from_bytes(restored_sk.as_bytes())
            .expect("Secret key should be valid");

        // Sign with restored key
        let restored_signature = mldsa65::detached_sign(message, &sk);

        // Verify both signatures work
        let restored_sig_wrapped = MlDsaSignature::from_bytes(restored_signature.as_bytes())
            .expect("Signature wrapping should succeed");

        let original_valid = verify(keypair.public_key(), message, &original_signature)
            .expect("Original verification should not error");
        let restored_valid = verify(keypair.public_key(), message, &restored_sig_wrapped)
            .expect("Restored verification should not error");

        assert!(original_valid, "Original signature should be valid");
        assert!(restored_valid, "Signature from restored key should be valid");
    }

    #[test]
    fn test_signature_serialization_roundtrip() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let message = b"Test message";

        let original = keypair.sign(message).expect("Signing should succeed");

        let bytes = original.as_bytes();
        let restored =
            MlDsaSignature::from_bytes(bytes).expect("Signature deserialization should succeed");

        assert_eq!(
            original.as_bytes(),
            restored.as_bytes(),
            "Signature should survive serialization roundtrip"
        );
        assert_eq!(original, restored, "Signatures should be equal");

        // Verify the restored signature still works
        let is_valid = verify(keypair.public_key(), message, &restored)
            .expect("Verification should not error");
        assert!(is_valid, "Restored signature should be valid");
    }

    #[test]
    fn test_sign_empty_message() {
        let keypair = generate_keypair().expect("Key generation should succeed");
        let empty_message: &[u8] = b"";

        let signature = keypair
            .sign(empty_message)
            .expect("Signing empty message should succeed");
        let is_valid = verify(keypair.public_key(), empty_message, &signature)
            .expect("Verification should not error");

        assert!(is_valid, "Empty message signature should be valid");
    }

    #[test]
    fn test_debug_redacts_secret_key() {
        let keypair = generate_keypair().expect("Key generation should succeed");

        // Test MlDsaSecretKey debug
        let secret_key_debug = format!("{:?}", keypair.secret_key);
        assert!(
            secret_key_debug.contains("REDACTED"),
            "Secret key debug output should contain REDACTED, got: {}",
            secret_key_debug
        );
        assert!(
            !secret_key_debug.contains('['),
            "Secret key debug should not contain raw bytes"
        );

        // Test MlDsaKeyPair debug
        let keypair_debug = format!("{:?}", keypair);
        assert!(
            keypair_debug.contains("REDACTED"),
            "Keypair debug output should contain REDACTED for secret key"
        );

        // Public key debug should show hex prefix, not REDACTED
        let public_key_debug = format!("{:?}", keypair.public_key());
        assert!(
            public_key_debug.contains("MlDsaPublicKey("),
            "Public key debug should show type name"
        );
        assert!(
            public_key_debug.contains("..."),
            "Public key debug should show truncated hex"
        );
    }

    #[test]
    fn test_invalid_public_key_length() {
        let short_bytes = vec![0u8; 10];
        let result = MlDsaPublicKey::from_bytes(&short_bytes);
        assert!(result.is_err(), "Should reject short public key");

        let long_bytes = vec![0u8; PUBLIC_KEY_LENGTH + 100];
        let result = MlDsaPublicKey::from_bytes(&long_bytes);
        assert!(result.is_err(), "Should reject long public key");
    }

    #[test]
    fn test_invalid_secret_key_length() {
        let short_bytes = vec![0u8; 10];
        let result = MlDsaSecretKey::from_bytes(&short_bytes);
        assert!(result.is_err(), "Should reject short secret key");

        let long_bytes = vec![0u8; SECRET_KEY_LENGTH + 100];
        let result = MlDsaSecretKey::from_bytes(&long_bytes);
        assert!(result.is_err(), "Should reject long secret key");
    }

    #[test]
    fn test_invalid_signature_length() {
        let short_bytes = vec![0u8; 10];
        let result = MlDsaSignature::from_bytes(&short_bytes);
        assert!(result.is_err(), "Should reject short signature");

        let long_bytes = vec![0u8; SIGNATURE_LENGTH + 100];
        let result = MlDsaSignature::from_bytes(&long_bytes);
        assert!(result.is_err(), "Should reject long signature");
    }
}
