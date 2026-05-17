// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network protocol message types.
//!
//! Defines the envelope format for all messages exchanged between nodes
//! and between SDK clients and nodes.

use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Top-level network message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Unique message ID.
    pub id: uuid::Uuid,
    /// Sender operator ID (or client ID for SDK messages).
    pub sender: OperatorId,
    /// Message type.
    pub message_type: MessageType,
    /// Serialized payload.
    pub payload: Vec<u8>,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// ML-DSA signature over (id || message_type || payload || timestamp).
    pub signature: Vec<u8>,
}

/// Types of messages in the QPL network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    // === SDK → Node (External) ===
    /// Fee estimation request.
    EstimateFeeRequest,
    /// Fee estimation response.
    EstimateFeeResponse,
    /// Service request (sign, prove, workflow, etc.).
    ServiceRequest,
    /// Service response.
    ServiceResponse,
    /// Request status query.
    StatusQuery,
    /// Status response.
    StatusResponse,

    // === Node → Node (Internal) ===
    /// Operator handshake on first connection.
    Handshake,
    /// Handshake acknowledgment.
    HandshakeAck,
    /// Periodic heartbeat.
    Heartbeat,
    /// Heartbeat acknowledgment.
    HeartbeatAck,
    /// Request for partial signature from a shard holder.
    PartialSignRequest,
    /// Partial signature response.
    PartialSignResponse,
    /// Proof verification request to quorum member.
    VerifyProofRequest,
    /// Proof verification vote.
    VerifyProofVote,
    /// Forward a request to another operator.
    ForwardRequest,
    /// Acknowledgment of forwarded request.
    ForwardAck,
    /// Operator announcement (new operator or capability update).
    Announcement,
}

/// Service request payload — tagged union of all supported operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceRequestPayload {
    /// Threshold signing request.
    Sign {
        message: Vec<u8>,
        quorum: QuorumRequirement,
        fee_proof: FeePaymentProof,
    },
    /// STARK proof generation request.
    Prove {
        /// Serialized transaction batch.
        transactions: Vec<u8>,
        /// Proof configuration (security level, blowup factor, etc.).
        proof_config: ProofRequestConfig,
        fee_proof: FeePaymentProof,
    },
}

/// Service response payload — tagged union of all response types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceResponsePayload {
    /// Threshold signing result.
    Signature {
        /// ML-DSA-65 signature bytes.
        signature: Vec<u8>,
    },
    /// STARK proof result.
    Proof {
        /// Serialized STARK proof.
        proof: Vec<u8>,
        /// Public inputs for verification.
        public_inputs: Vec<u8>,
    },
    /// Error response.
    Error {
        code: u32,
        message: String,
    },
}

/// Configuration for a proof generation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequestConfig {
    /// Security level (96-bit or 128-bit).
    pub security_bits: u32,
    /// Number of FRI queries.
    pub num_queries: u32,
    /// Blowup factor for LDE.
    pub blowup_factor: u32,
}

impl Default for ProofRequestConfig {
    fn default() -> Self {
        Self {
            security_bits: 96,
            num_queries: 28,
            blowup_factor: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_types_distinct() {
        assert_ne!(MessageType::ServiceRequest, MessageType::ServiceResponse);
        assert_ne!(MessageType::Heartbeat, MessageType::HeartbeatAck);
    }

    #[test]
    fn test_service_request_serialization() {
        let payload = ServiceRequestPayload::Sign {
            message: b"hello quantum world".to_vec(),
            quorum: QuorumRequirement::three_of_five(),
            fee_proof: FeePaymentProof {
                tx_signature: vec![0xAB; 64],
                fee_quote_id: uuid::Uuid::new_v4(),
                slot: 12345,
            },
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ServiceRequestPayload = serde_json::from_str(&json).unwrap();

        match deserialized {
            ServiceRequestPayload::Sign { message, quorum, .. } => {
                assert_eq!(message, b"hello quantum world");
                assert_eq!(quorum.threshold, 3);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
