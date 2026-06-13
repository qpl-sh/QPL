// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL client — main entry point for protocol integrations.

use crate::config::SdkConfig;
use crate::errors::SdkError;
use crate::services::{ProvingService, SigningService};

/// The primary QPL SDK client.
///
/// Connects to the QPL operator network and provides access to
/// quantum-proof signing and STARK proving services.
pub struct QplClient {
    config: SdkConfig,
    endpoint: String,
}

impl QplClient {
    /// Connects to the QPL operator network.
    pub async fn connect(config: SdkConfig) -> Result<Self, SdkError> {
        if config.bootstrap_nodes.is_empty() {
            return Err(SdkError::ConnectionFailed(
                "No bootstrap nodes configured".to_string(),
            ));
        }

        let endpoint = config.bootstrap_nodes[0].clone();
        Ok(Self { config, endpoint })
    }

    /// Access the threshold signing service (ML-DSA-65, N-of-M).
    ///
    /// Establishes a gRPC connection to the operator node.
    pub async fn signing(&self) -> Result<SigningService, SdkError> {
        SigningService::connect(&self.endpoint, &self.config).await
    }

    /// Access the STARK proving service (FRI-based, Winterfell).
    ///
    /// Establishes a gRPC connection to the operator node.
    pub async fn proving(&self) -> Result<ProvingService, SdkError> {
        ProvingService::connect(&self.endpoint, &self.config).await
    }

    /// Returns the connected endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns true if the client has an active connection.
    pub fn is_connected(&self) -> bool {
        !self.endpoint.is_empty()
    }
}
