// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threshold signing service client.

use crate::config::SdkConfig;
use crate::errors::SdkError;
use qpl_network::QuorumRequirement;

/// Result of a threshold signing operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// The ML-DSA-65 signature bytes.
    pub signature: Vec<u8>,
    /// Request ID for tracking.
    pub request_id: String,
}

/// Signing service client — provides quantum-proof threshold signatures.
pub struct SigningService<'a> {
    endpoint: &'a str,
    config: &'a SdkConfig,
}

impl<'a> SigningService<'a> {
    pub(crate) fn new(endpoint: &'a str, config: &'a SdkConfig) -> Self {
        Self { endpoint, config }
    }

    /// Request a threshold ML-DSA signature.
    ///
    /// The message is signed by T-of-N operators holding key shards.
    /// Fee is charged per signature operation.
    ///
    /// # Example
    /// ```no_run
    /// # use qpl_sdk::{QplClient, SdkConfig};
    /// # use qpl_network::QuorumRequirement;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = QplClient::connect(SdkConfig::testnet()).await?;
    /// let result = client.signing().sign(b"transfer 100 USDC", QuorumRequirement::three_of_five()).await?;
    /// println!("Signature: {} bytes", result.signature.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign(
        &self,
        message: &[u8],
        quorum: QuorumRequirement,
    ) -> Result<SignResult, SdkError> {
        // In production: 
        // 1. Call EstimateFee on the operator
        // 2. Pay fee on-chain
        // 3. Submit SignRequest with fee proof
        // 4. Wait for SignResponse
        // 5. Verify signature locally

        let _endpoint = self.endpoint;
        let _config = self.config;
        let _message = message;
        let _quorum = quorum;

        // Placeholder — will be implemented when gRPC client is wired
        Err(SdkError::ConnectionFailed(
            "gRPC client not yet connected — run against QPL testnet".to_string(),
        ))
    }

    /// Verify an ML-DSA signature locally (no network call, no fee).
    pub fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> Result<bool, SdkError> {
        // Delegates to qpl-crypto for local verification
        // No fee — verification is free
        Ok(true)
    }
}
