// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network protocol message types.
//!
//! Defines the envelope format for all messages exchanged between nodes
//! and between SDK clients and nodes. Includes anti-replay machinery
//! ([`SenderSequencer`] and [`ReplayGuard`]) used by both ends of a
//! connection to prevent message replay and reordering attacks (F-1).

use crate::errors::NetworkError;
use crate::types::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of nanoseconds a message timestamp may lag behind the
/// receiver's wall clock before it is rejected as stale (default 30s).
pub const MAX_SKEW_PAST_NANOS: u64 = 30 * 1_000_000_000;

/// Maximum number of nanoseconds a message timestamp may lead the receiver's
/// wall clock before it is rejected as too-far-future (default 5s).
pub const MAX_SKEW_FUTURE_NANOS: u64 = 5 * 1_000_000_000;

/// Top-level network message envelope.
///
/// In addition to the original signed payload, the envelope now carries two
/// anti-replay fields:
/// * [`NetworkMessage::timestamp_nanos`] — sender's wall-clock timestamp at
///   message creation, in nanoseconds since the UNIX epoch.
/// * [`NetworkMessage::sequence`] — strictly monotonic per-sender counter,
///   starting at 0 and incremented for every outgoing message.
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
    /// Sender's wall-clock timestamp at message creation, in nanoseconds
    /// since the UNIX epoch. Used for the receiver-side anti-replay window.
    pub timestamp_nanos: u64,
    /// Monotonic per-sender sequence number, starting at 0 and incremented
    /// for every outgoing message. Used for replay / reorder detection.
    pub sequence: u64,
    /// ML-DSA signature over (id || message_type || payload || timestamp ||
    /// timestamp_nanos || sequence).
    pub signature: Vec<u8>,
}

impl NetworkMessage {
    /// Constructs a new envelope. The `sequence` should be obtained from a
    /// per-peer [`SenderSequencer`]; the timestamp is captured here.
    ///
    /// `signature` is left empty — callers are expected to sign the resulting
    /// envelope and assign the signature bytes before transmission.
    pub fn new(
        sender: OperatorId,
        message_type: MessageType,
        payload: Vec<u8>,
        sequence: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4(),
            sender,
            message_type,
            payload,
            timestamp: now,
            timestamp_nanos: current_unix_nanos(),
            sequence,
            signature: Vec::new(),
        }
    }
}

/// Returns the current wall clock as nanoseconds since the UNIX epoch,
/// saturating at `u64::MAX` if the system clock is set absurdly far in the
/// future and at `0` if it's set before the epoch.
fn current_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
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
    Error { code: u32, message: String },
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

// =====================================================================
// Anti-replay machinery (F-1)
// =====================================================================

/// Sender-side per-peer monotonic sequence counter.
///
/// `next_sequence(peer)` returns the value to embed in the next outgoing
/// `NetworkMessage` to that peer, then increments the internal counter.
/// The first value handed out for a given peer is `0`.
///
/// Uses a `Mutex` for interior mutability so a single sequencer can be shared
/// across threads via `&self`.
#[derive(Debug, Default)]
pub struct SenderSequencer {
    counters: Mutex<HashMap<OperatorId, u64>>,
}

impl SenderSequencer {
    /// Creates a fresh sequencer with no per-peer state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the next sequence number for `peer` (post-increment-by-one).
    /// First call for a peer returns `0`, second returns `1`, and so on.
    pub fn next_sequence(&self, peer: &OperatorId) -> u64 {
        let mut guard = self.counters.lock().expect("sequencer mutex poisoned");
        let entry = guard.entry(peer.clone()).or_insert(0);
        let issued = *entry;
        *entry = entry.saturating_add(1);
        issued
    }

    /// Returns the next sequence that *would* be issued for `peer` without
    /// consuming it. Useful for diagnostics and tests.
    pub fn peek(&self, peer: &OperatorId) -> u64 {
        let guard = self.counters.lock().expect("sequencer mutex poisoned");
        guard.get(peer).copied().unwrap_or(0)
    }
}

/// Per-sender high-watermark used by [`ReplayGuard`]. Tracks the largest
/// sequence number observed so far and the wall-clock time of last update,
/// so stale entries can be pruned by the cleanup machinery.
#[derive(Debug, Clone, Copy)]
struct SequenceWatermark {
    last_sequence: u64,
    last_seen_at: DateTime<Utc>,
}

/// Receiver-side anti-replay validator.
///
/// Maintains a `HashMap<SenderId, last_sequence_seen>` and rejects any
/// message that:
///
/// * has a `timestamp_nanos` outside the configured skew window
///   (`max_skew_past_nanos` / `max_skew_future_nanos`), or
/// * carries a `(sender, sequence)` pair that has already been seen — i.e.
///   any sequence less-than-or-equal-to the recorded high-watermark for
///   that sender.
///
/// Old per-sender entries can be pruned with [`ReplayGuard::prune_idle`].
#[derive(Debug)]
pub struct ReplayGuard {
    last_seen: HashMap<OperatorId, SequenceWatermark>,
    /// Maximum nanoseconds the message timestamp is allowed to lag the
    /// receiver's clock.
    pub max_skew_past_nanos: u64,
    /// Maximum nanoseconds the message timestamp is allowed to lead the
    /// receiver's clock.
    pub max_skew_future_nanos: u64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_skew(MAX_SKEW_PAST_NANOS, MAX_SKEW_FUTURE_NANOS)
    }
}

impl ReplayGuard {
    /// Constructs a guard with the default skew window (30s past, 5s future).
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a guard with custom skew tolerances (in nanoseconds).
    pub fn with_skew(max_skew_past_nanos: u64, max_skew_future_nanos: u64) -> Self {
        Self {
            last_seen: HashMap::new(),
            max_skew_past_nanos,
            max_skew_future_nanos,
        }
    }

    /// Validates an incoming message. On success, records `(sender, sequence)`
    /// as the new high-watermark for that sender and returns `Ok(())`.
    ///
    /// Returns:
    /// * [`NetworkError::TimestampOutOfWindow`] if the sender's clock is
    ///   outside the allowed skew window relative to ours.
    /// * [`NetworkError::ReplayDetected`] if `(sender, sequence)` exactly
    ///   matches the recorded high-watermark.
    /// * [`NetworkError::NonMonotonicSequence`] if the sequence is strictly
    ///   less than the recorded high-watermark (out-of-order arrival).
    pub fn validate(&mut self, msg: &NetworkMessage) -> Result<(), NetworkError> {
        self.validate_at(msg, current_unix_nanos())
    }

    /// Same as [`validate`](Self::validate) but with an explicit "now" — used
    /// by tests to make the time check deterministic.
    pub fn validate_at(
        &mut self,
        msg: &NetworkMessage,
        now_nanos: u64,
    ) -> Result<(), NetworkError> {
        if !timestamp_in_window(
            now_nanos,
            msg.timestamp_nanos,
            self.max_skew_past_nanos,
            self.max_skew_future_nanos,
        ) {
            return Err(NetworkError::TimestampOutOfWindow {
                now_nanos,
                msg_nanos: msg.timestamp_nanos,
                max_skew_past_nanos: self.max_skew_past_nanos,
                max_skew_future_nanos: self.max_skew_future_nanos,
            });
        }

        if let Some(wm) = self.last_seen.get(&msg.sender).copied() {
            if msg.sequence == wm.last_sequence {
                return Err(NetworkError::ReplayDetected(
                    msg.sender.clone(),
                    msg.sequence,
                ));
            }
            if msg.sequence < wm.last_sequence {
                return Err(NetworkError::NonMonotonicSequence {
                    sender: msg.sender.clone(),
                    expected_gt: wm.last_sequence,
                    got: msg.sequence,
                });
            }
        }

        self.last_seen.insert(
            msg.sender.clone(),
            SequenceWatermark {
                last_sequence: msg.sequence,
                last_seen_at: Utc::now(),
            },
        );
        Ok(())
    }

    /// Removes entries whose last-seen timestamp is older than `max_age_secs`
    /// seconds. Intended to be called periodically by the network layer's
    /// existing cleanup machinery so the high-watermark map cannot grow
    /// without bound.
    pub fn prune_idle(&mut self, max_age_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        self.last_seen.retain(|_, wm| wm.last_seen_at > cutoff);
    }

    /// Number of distinct senders currently tracked. Test/diagnostic only.
    pub fn tracked_senders(&self) -> usize {
        self.last_seen.len()
    }
}

/// Returns true iff `msg_nanos` is inside `[now - max_past, now + max_future]`.
fn timestamp_in_window(
    now_nanos: u64,
    msg_nanos: u64,
    max_skew_past_nanos: u64,
    max_skew_future_nanos: u64,
) -> bool {
    if msg_nanos > now_nanos {
        msg_nanos - now_nanos <= max_skew_future_nanos
    } else {
        now_nanos - msg_nanos <= max_skew_past_nanos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sender(seed: u8) -> OperatorId {
        OperatorId::from_public_key(&[seed; 32])
    }

    fn make_msg(sender: &OperatorId, sequence: u64, ts_nanos: u64) -> NetworkMessage {
        NetworkMessage {
            id: uuid::Uuid::new_v4(),
            sender: sender.clone(),
            message_type: MessageType::Heartbeat,
            payload: Vec::new(),
            timestamp: Utc::now(),
            timestamp_nanos: ts_nanos,
            sequence,
            signature: Vec::new(),
        }
    }

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
            ServiceRequestPayload::Sign {
                message, quorum, ..
            } => {
                assert_eq!(message, b"hello quantum world");
                assert_eq!(quorum.threshold, 3);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_network_message_new_populates_replay_fields() {
        let sender = test_sender(1);
        let m1 = NetworkMessage::new(sender.clone(), MessageType::Heartbeat, vec![], 0);
        let m2 = NetworkMessage::new(sender.clone(), MessageType::Heartbeat, vec![], 1);
        assert_eq!(m1.sequence, 0);
        assert_eq!(m2.sequence, 1);
        assert!(m1.timestamp_nanos > 0);
        assert!(m2.timestamp_nanos >= m1.timestamp_nanos);
    }

    #[test]
    fn test_sender_sequencer_monotonic_per_peer() {
        let seq = SenderSequencer::new();
        let a = test_sender(1);
        let b = test_sender(2);
        assert_eq!(seq.next_sequence(&a), 0);
        assert_eq!(seq.next_sequence(&a), 1);
        assert_eq!(seq.next_sequence(&b), 0); // independent per peer
        assert_eq!(seq.next_sequence(&a), 2);
        assert_eq!(seq.next_sequence(&b), 1);
        assert_eq!(seq.peek(&a), 3);
    }

    // ---------- F-1 acceptance tests ----------

    /// (a) Valid message accepted.
    #[test]
    fn test_replay_guard_accepts_valid_message() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 1_000_000_000_000u64; // arbitrary fixed "now"
        let msg = make_msg(&sender, 0, now);
        assert!(guard.validate_at(&msg, now).is_ok());
    }

    /// (b) Stale timestamp rejected.
    #[test]
    fn test_replay_guard_rejects_stale_timestamp() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 60 * 1_000_000_000u64; // 60s in nanos
                                         // 31s in the past — beyond the 30s past-skew tolerance
        let msg_ts = now - 31 * 1_000_000_000;
        let msg = make_msg(&sender, 0, msg_ts);
        let err = guard.validate_at(&msg, now).unwrap_err();
        assert!(matches!(err, NetworkError::TimestampOutOfWindow { .. }));
    }

    /// (c) Future timestamp rejected.
    #[test]
    fn test_replay_guard_rejects_future_timestamp() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 60 * 1_000_000_000u64;
        // 6s in the future — beyond the 5s future-skew tolerance
        let msg_ts = now + 6 * 1_000_000_000;
        let msg = make_msg(&sender, 0, msg_ts);
        let err = guard.validate_at(&msg, now).unwrap_err();
        assert!(matches!(err, NetworkError::TimestampOutOfWindow { .. }));
    }

    /// (d) Duplicate (sender, sequence) rejected.
    #[test]
    fn test_replay_guard_rejects_duplicate_sequence() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 1_000_000_000_000u64;
        let m0 = make_msg(&sender, 0, now);
        guard.validate_at(&m0, now).unwrap();

        // Same (sender, 0) replayed
        let replay = make_msg(&sender, 0, now);
        let err = guard.validate_at(&replay, now).unwrap_err();
        assert!(matches!(err, NetworkError::ReplayDetected(_, 0)));
    }

    /// (e) Out-of-order with smaller sequence rejected.
    #[test]
    fn test_replay_guard_rejects_out_of_order_smaller_sequence() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 1_000_000_000_000u64;
        guard.validate_at(&make_msg(&sender, 5, now), now).unwrap();
        // Now an older sequence arrives — must be rejected.
        let stale = make_msg(&sender, 3, now);
        let err = guard.validate_at(&stale, now).unwrap_err();
        match err {
            NetworkError::NonMonotonicSequence {
                expected_gt, got, ..
            } => {
                assert_eq!(expected_gt, 5);
                assert_eq!(got, 3);
            }
            other => panic!("expected NonMonotonicSequence, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_guard_accepts_strictly_increasing_sequences() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 1_000_000_000_000u64;
        for s in 0..10 {
            guard.validate_at(&make_msg(&sender, s, now), now).unwrap();
        }
    }

    #[test]
    fn test_replay_guard_prune_idle_drops_old_entries() {
        let mut guard = ReplayGuard::new();
        let sender = test_sender(7);
        let now = 1_000_000_000_000u64;
        guard.validate_at(&make_msg(&sender, 0, now), now).unwrap();
        assert_eq!(guard.tracked_senders(), 1);
        // Pruning with a zero-second window should drop everything strictly
        // older than `now` — give the wall clock a moment to advance past
        // the recorded last_seen_at.
        std::thread::sleep(std::time::Duration::from_millis(5));
        guard.prune_idle(0);
        assert_eq!(guard.tracked_senders(), 0);
    }
}
