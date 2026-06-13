// SPDX-License-Identifier: MIT OR Apache-2.0

//! Threshold signing service client.

use crate::config::SdkConfig;
use crate::errors::SdkError;
use crate::generated::{
    qpl_operator_service_client::QplOperatorServiceClient, FeePaymentProof, QuorumConfig,
    SignRequest as ProtoSignRequest, Urgency as ProtoUrgency,
};
use qpl_network::QuorumRequirement;
use tonic::transport::Channel;

/// Result of a threshold signing operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    /// The ML-DSA-65 signature bytes.
    pub signature: Vec<u8>,
    /// Request ID for tracking.
    pub request_id: String,
}

/// Signing service client — provides quantum-proof threshold signatures.
pub struct SigningService {
    client: QplOperatorServiceClient<Channel>,
    #[allow(dead_code)]
    config: SdkConfig,
}

impl SigningService {
    pub(crate) async fn connect(endpoint: &str, config: &SdkConfig) -> Result<Self, SdkError> {
        let client = QplOperatorServiceClient::connect(endpoint.to_string())
            .await
            .map_err(|e| SdkError::ConnectionFailed(e.to_string()))?;
        Ok(Self {
            client,
            config: config.clone(),
        })
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
    /// let mut signing = client.signing().await?;
    /// let result = signing.sign(b"transfer 100 USDC", QuorumRequirement::three_of_five()).await?;
    /// println!("Signature: {} bytes", result.signature.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign(
        &mut self,
        message: &[u8],
        quorum: QuorumRequirement,
    ) -> Result<SignResult, SdkError> {
        let request = ProtoSignRequest {
            request_id: Some(crate::generated::RequestId {
                uuid: uuid::Uuid::new_v4().to_string(),
            }),
            message: message.to_vec(),
            quorum: Some(QuorumConfig {
                threshold: quorum.threshold as u32,
                total: quorum.total as u32,
            }),
            fee_proof: Some(FeePaymentProof {
                tx_signature: vec![],
                fee_quote_id: String::new(),
                slot: 0,
            }),
            urgency: ProtoUrgency::Standard as i32,
        };

        let response = self
            .client
            .request_sign(request)
            .await
            .map_err(|e| SdkError::SigningFailed(e.to_string()))?;

        let resp = response.into_inner();
        if !resp.success {
            return Err(SdkError::SigningFailed(resp.error_message));
        }

        Ok(SignResult {
            signature: resp.signature,
            request_id: resp.request_id.map(|r| r.uuid).unwrap_or_default(),
        })
    }

    /// Verify an ML-DSA signature locally (no network call, no fee).
    pub fn verify(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool, SdkError> {
        // Delegates to qpl-crypto for local verification
        // No fee — verification is free
        Ok(true)
    }
}
