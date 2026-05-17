// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator identity — ML-DSA keypair management.
//!
//! Each operator has a persistent ML-DSA-65 keypair that serves as their
//! network identity. The OperatorId is SHA-256(public_key).

use sha2::{Digest, Sha256};
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Operator's cryptographic identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorIdentity {
    /// ML-DSA-65 public key bytes (serialized).
    public_key: Vec<u8>,
    /// ML-DSA-65 secret key bytes (serialized). 
    /// In production: stored in HSM or encrypted at rest.
    #[serde(with = "hex_serde")]
    secret_key: Vec<u8>,
}

mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

impl OperatorIdentity {
    /// Generate a new random operator identity.
    ///
    /// Uses randomness for key generation. In production this would call
    /// `qpl_crypto::mldsa::keygen()`. For now we generate a placeholder
    /// keypair to avoid the heavyweight PQC dependency at build time.
    pub fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        // Placeholder: 32 bytes random "public key" and 64 bytes "secret key"
        // Real implementation delegates to qpl-crypto ML-DSA-65 keygen
        let mut public_key = vec![0u8; 32];
        let mut secret_key = vec![0u8; 64];
        
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut public_key);
        rng.fill_bytes(&mut secret_key);

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Load identity from file, or generate a new one if it doesn't exist.
    pub fn load_or_generate(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if Path::new(path).exists() {
            let data = std::fs::read_to_string(path)?;
            let identity: Self = serde_json::from_str(&data)?;
            Ok(identity)
        } else {
            let identity = Self::generate()?;
            let json = serde_json::to_string_pretty(&identity)?;
            // Ensure parent directory exists
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, json)?;
            tracing::info!("Generated new operator identity at: {}", path);
            Ok(identity)
        }
    }

    /// Get the operator ID (SHA-256 of public key).
    pub fn operator_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.public_key);
        hex::encode(hasher.finalize())
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a message with this operator's secret key.
    ///
    /// Placeholder — delegates to qpl-crypto in production.
    pub fn sign(&self, _message: &[u8]) -> Vec<u8> {
        // In production: qpl_crypto::mldsa::sign(&self.secret_key, message)
        let mut sig = vec![0u8; 64];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut sig);
        sig
    }
}
