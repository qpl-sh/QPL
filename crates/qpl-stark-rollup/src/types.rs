// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core domain types for the STARK rollup settlement layer.

use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

/// Unique identifier for accounts (derived from ML-DSA public key hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct AccountId(pub [u8; 32]);

impl AccountId {
    /// Create an AccountId from an ML-DSA public key by hashing it with SHA-256
    pub fn from_public_key(pk_bytes: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(pk_bytes);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        AccountId(id)
    }

    /// Create an AccountId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        AccountId(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0[..8]))
    }
}

/// A settlement transaction in the rollup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// SHA-256 hash of transaction contents
    pub id: [u8; 32],
    /// Sender's account identifier (derived from sender_public_key)
    pub sender: AccountId,
    /// Sender's ML-DSA public key bytes
    pub sender_public_key: Vec<u8>,
    /// Receiver's account identifier
    pub receiver: AccountId,
    /// Transfer amount (in smallest currency unit)
    pub amount: u64,
    /// Transaction nonce (anti-replay)
    pub nonce: u64,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// ML-DSA signature bytes (from qpl-crypto)
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Create a new transaction with explicit sender AccountId (for legacy/testing use)
    /// 
    /// NOTE: For production use, prefer `new_signed()` which derives sender from public key.
    pub fn new(
        sender: AccountId,
        receiver: AccountId,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Self {
        Self::new_with_public_key(Vec::new(), sender, receiver, amount, nonce, timestamp, signature)
    }

    /// Create a new transaction with the sender's public key
    /// 
    /// The sender AccountId is derived from the public key via SHA-256 hash.
    pub fn new_from_public_key(
        sender_public_key: Vec<u8>,
        receiver: AccountId,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Self {
        let sender = AccountId::from_public_key(&sender_public_key);
        Self::new_with_public_key(sender_public_key, sender, receiver, amount, nonce, timestamp, signature)
    }

    /// Create a new transaction with explicit public key and sender
    fn new_with_public_key(
        sender_public_key: Vec<u8>,
        sender: AccountId,
        receiver: AccountId,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        signature: Vec<u8>,
    ) -> Self {
        let mut tx = Self {
            id: [0u8; 32],
            sender,
            sender_public_key,
            receiver,
            amount,
            nonce,
            timestamp,
            signature,
        };
        tx.compute_id();
        tx
    }

    /// Compute the transaction ID as SHA-256 hash of transaction data
    pub fn compute_id(&mut self) {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.sender.as_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(self.amount.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        let result = hasher.finalize();
        self.id.copy_from_slice(&result);
    }

    /// Get the message bytes that should be signed (excludes signature and id)
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.sender.as_bytes());
        msg.extend_from_slice(self.receiver.as_bytes());
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg
    }
}

/// Account balance in the rollup state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountBalance {
    /// Available balance
    pub balance: u64,
    /// Locked balance (in-flight settlements)
    pub locked: u64,
    /// Current nonce
    pub nonce: u64,
}

impl AccountBalance {
    /// Create a new account balance with given initial balance
    pub fn new(balance: u64) -> Self {
        Self { balance, locked: 0, nonce: 0 }
    }

    /// Get the available balance (total minus locked)
    pub fn available(&self) -> u64 {
        self.balance.saturating_sub(self.locked)
    }
}

impl Default for AccountBalance {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The complete rollup state (accounts + metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupState {
    /// Account balances indexed by AccountId
    pub accounts: BTreeMap<AccountId, AccountBalance>,
    /// Current state root (Merkle commitment)
    pub state_root: [u8; 32],
    /// Current batch height
    pub batch_height: u64,
}

impl RollupState {
    /// Create a new empty rollup state
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            state_root: [0u8; 32],
            batch_height: 0,
        }
    }

    /// Get or create an account
    pub fn get_or_create_account(&mut self, id: &AccountId) -> &mut AccountBalance {
        self.accounts.entry(id.clone()).or_insert_with(|| AccountBalance::new(0))
    }

    /// Get account balance (read-only)
    pub fn get_account(&self, id: &AccountId) -> Option<&AccountBalance> {
        self.accounts.get(id)
    }

    /// Compute state root as SHA-256 hash of all account data
    pub fn compute_state_root(&mut self) {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for (id, balance) in &self.accounts {
            hasher.update(id.as_bytes());
            hasher.update(balance.balance.to_le_bytes());
            hasher.update(balance.locked.to_le_bytes());
            hasher.update(balance.nonce.to_le_bytes());
        }
        let result = hasher.finalize();
        self.state_root.copy_from_slice(&result);
    }

    /// Get the number of accounts
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

impl Default for RollupState {
    fn default() -> Self {
        Self::new()
    }
}

/// Public inputs for the STARK proof (committed on-chain)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollupPublicInputs {
    /// State root before batch execution
    pub initial_state_root: [u8; 32],
    /// State root after batch execution
    pub final_state_root: [u8; 32],
    /// Number of transactions in the batch
    pub transaction_count: u64,
    /// Batch height / sequence number
    pub batch_height: u64,
}

impl RollupPublicInputs {
    /// Create new public inputs
    pub fn new(
        initial_state_root: [u8; 32],
        final_state_root: [u8; 32],
        transaction_count: u64,
        batch_height: u64,
    ) -> Self {
        Self {
            initial_state_root,
            final_state_root,
            transaction_count,
            batch_height,
        }
    }
}

/// A generated STARK proof for a settlement batch
#[derive(Debug, Clone)]
pub struct RollupProof {
    /// The serialized winterfell proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs for verification
    pub public_inputs: RollupPublicInputs,
    /// Proof metadata
    pub proof_size_bytes: usize,
}

impl RollupProof {
    /// Create a new rollup proof
    pub fn new(proof_bytes: Vec<u8>, public_inputs: RollupPublicInputs) -> Self {
        let proof_size_bytes = proof_bytes.len();
        Self {
            proof_bytes,
            public_inputs,
            proof_size_bytes,
        }
    }
}

/// A STARK proof bundled with a cryptographic commitment to the public inputs.
///
/// The `public_inputs_hash` field is a SHA-256 digest of the deterministic
/// serialisation of `SettlementPublicInputs`. A verifier **must** recompute
/// this hash from the supplied inputs and reject the proof if it does not
/// match, preventing public-inputs substitution attacks (S2 hardening).
#[derive(Debug, Clone)]
pub struct RollupProofWithCommitment {
    /// The serialized winterfell proof bytes
    pub proof_bytes: Vec<u8>,
    /// SHA-256 hash committing to the public inputs used during proving
    pub public_inputs_hash: [u8; 32],
}

impl RollupProofWithCommitment {
    /// Create a new committed proof.
    pub fn new(proof_bytes: Vec<u8>, public_inputs_hash: [u8; 32]) -> Self {
        Self {
            proof_bytes,
            public_inputs_hash,
        }
    }
}

/// Compute a deterministic SHA-256 commitment over `SettlementPublicInputs`.
///
/// The hash is computed by iterating `to_elements()` and hashing each
/// element's little-endian `u128` representation.
pub fn compute_public_inputs_commitment(
    pub_inputs: &crate::air::SettlementPublicInputs,
) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    use winterfell::math::{StarkField, ToElements};
    use winterfell::math::fields::f128::BaseElement;
    let mut hasher = Sha256::new();
    let elements: Vec<BaseElement> = pub_inputs.to_elements();
    for elem in &elements {
        hasher.update(&elem.as_int().to_le_bytes());
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Result of applying a transaction batch
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// New state after applying all transactions
    pub new_state: RollupState,
    /// Number of valid transactions applied
    pub applied_count: usize,
    /// Number of rejected transactions
    pub rejected_count: usize,
    /// Rejected transaction IDs with reasons
    pub rejections: Vec<(usize, String)>,
}

impl BatchResult {
    /// Create a new batch result
    pub fn new(
        new_state: RollupState,
        applied_count: usize,
        rejected_count: usize,
        rejections: Vec<(usize, String)>,
    ) -> Self {
        Self {
            new_state,
            applied_count,
            rejected_count,
            rejections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id_from_bytes() {
        let bytes = [42u8; 32];
        let id = AccountId::from_bytes(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn test_account_id_from_public_key() {
        let pk_bytes = vec![1u8; 100];
        let id = AccountId::from_public_key(&pk_bytes);
        
        // Verify it's a valid 32-byte hash
        assert_eq!(id.as_bytes().len(), 32);
        
        // Same input should produce same output
        let id2 = AccountId::from_public_key(&pk_bytes);
        assert_eq!(id, id2);
        
        // Different input should produce different output
        let different_pk = vec![2u8; 100];
        let id3 = AccountId::from_public_key(&different_pk);
        assert_ne!(id, id3);
    }

    #[test]
    fn test_account_id_display() {
        let bytes = [0xAB; 32];
        let id = AccountId::from_bytes(bytes);
        let display = format!("{}", id);
        assert!(display.starts_with("0x"));
        assert!(display.contains("ab")); // lowercase hex
    }

    #[test]
    fn test_account_balance_new() {
        let balance = AccountBalance::new(1000);
        assert_eq!(balance.balance, 1000);
        assert_eq!(balance.locked, 0);
        assert_eq!(balance.nonce, 0);
    }

    #[test]
    fn test_account_balance_available() {
        let mut balance = AccountBalance::new(1000);
        assert_eq!(balance.available(), 1000);
        
        balance.locked = 300;
        assert_eq!(balance.available(), 700);
        
        // Test saturating subtraction
        balance.locked = 1500;
        assert_eq!(balance.available(), 0);
    }

    #[test]
    fn test_rollup_state_new() {
        let state = RollupState::new();
        assert_eq!(state.accounts.len(), 0);
        assert_eq!(state.state_root, [0u8; 32]);
        assert_eq!(state.batch_height, 0);
    }

    #[test]
    fn test_rollup_state_get_or_create_account() {
        let mut state = RollupState::new();
        let id = AccountId::from_bytes([1u8; 32]);
        
        // Account doesn't exist yet
        assert!(state.get_account(&id).is_none());
        
        // Create it
        let balance = state.get_or_create_account(&id);
        balance.balance = 500;
        
        // Now it exists
        assert!(state.get_account(&id).is_some());
        assert_eq!(state.get_account(&id).unwrap().balance, 500);
        
        // Get again (should return existing)
        let balance2 = state.get_or_create_account(&id);
        assert_eq!(balance2.balance, 500);
    }

    #[test]
    fn test_rollup_state_compute_state_root() {
        let mut state1 = RollupState::new();
        let mut state2 = RollupState::new();
        
        // Empty states should have same root
        state1.compute_state_root();
        state2.compute_state_root();
        assert_eq!(state1.state_root, state2.state_root);
        
        // Adding same account to both should still match
        let id = AccountId::from_bytes([1u8; 32]);
        state1.get_or_create_account(&id).balance = 100;
        state2.get_or_create_account(&id).balance = 100;
        
        state1.compute_state_root();
        state2.compute_state_root();
        assert_eq!(state1.state_root, state2.state_root);
        
        // Different balance should produce different root
        state2.get_or_create_account(&id).balance = 200;
        state2.compute_state_root();
        assert_ne!(state1.state_root, state2.state_root);
    }

    #[test]
    fn test_transaction_creation() {
        let sender = AccountId::from_bytes([1u8; 32]);
        let receiver = AccountId::from_bytes([2u8; 32]);
        
        let tx = Transaction::new(
            sender.clone(),
            receiver.clone(),
            100,
            1,
            1234567890,
            vec![0u8; 64],
        );
        
        assert_eq!(tx.sender, sender);
        assert_eq!(tx.receiver, receiver);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.nonce, 1);
        // ID should be computed (non-zero)
        assert_ne!(tx.id, [0u8; 32]);
    }

    #[test]
    fn test_transaction_serialization_roundtrip() {
        let sender = AccountId::from_bytes([1u8; 32]);
        let receiver = AccountId::from_bytes([2u8; 32]);
        
        let tx = Transaction::new_with_public_key(
            vec![0xDE; 64],
            sender,
            receiver,
            100,
            1,
            1234567890,
            vec![0xAB; 64],
        );
        
        // Serialize to JSON
        let json = serde_json::to_string(&tx).expect("Serialization should succeed");
        
        // Deserialize back
        let tx2: Transaction = serde_json::from_str(&json).expect("Deserialization should succeed");
        
        assert_eq!(tx.id, tx2.id);
        assert_eq!(tx.sender, tx2.sender);
        assert_eq!(tx.sender_public_key, tx2.sender_public_key);
        assert_eq!(tx.receiver, tx2.receiver);
        assert_eq!(tx.amount, tx2.amount);
        assert_eq!(tx.nonce, tx2.nonce);
        assert_eq!(tx.signature, tx2.signature);
    }

    #[test]
    fn test_transaction_signing_message() {
        let sender = AccountId::from_bytes([1u8; 32]);
        let receiver = AccountId::from_bytes([2u8; 32]);
        
        let tx = Transaction::new(
            sender.clone(),
            receiver.clone(),
            100,
            1,
            1234567890,
            vec![],
        );
        
        let msg = tx.signing_message();
        
        // Should contain sender, receiver, amount, nonce, timestamp
        assert!(!msg.is_empty());
        assert_eq!(msg.len(), 32 + 32 + 8 + 8 + 8); // 88 bytes
    }

    #[test]
    fn test_rollup_public_inputs_creation() {
        let inputs = RollupPublicInputs::new(
            [1u8; 32],
            [2u8; 32],
            10,
            5,
        );
        
        assert_eq!(inputs.initial_state_root, [1u8; 32]);
        assert_eq!(inputs.final_state_root, [2u8; 32]);
        assert_eq!(inputs.transaction_count, 10);
        assert_eq!(inputs.batch_height, 5);
    }

    #[test]
    fn test_rollup_public_inputs_serialization() {
        let inputs = RollupPublicInputs::new(
            [1u8; 32],
            [2u8; 32],
            10,
            5,
        );
        
        let json = serde_json::to_string(&inputs).expect("Serialization should succeed");
        let inputs2: RollupPublicInputs = serde_json::from_str(&json).expect("Deserialization should succeed");
        
        assert_eq!(inputs, inputs2);
    }

    #[test]
    fn test_transaction_new_from_public_key() {
        let pk_bytes = vec![0xAB; 128];
        let receiver = AccountId::from_bytes([2u8; 32]);
        
        let tx = Transaction::new_from_public_key(
            pk_bytes.clone(),
            receiver.clone(),
            100,
            1,
            1234567890,
            vec![0xCD; 64],
        );
        
        // sender should be derived from public key
        let expected_sender = AccountId::from_public_key(&pk_bytes);
        assert_eq!(tx.sender, expected_sender);
        assert_eq!(tx.sender_public_key, pk_bytes);
        assert_eq!(tx.receiver, receiver);
        assert_eq!(tx.amount, 100);
    }

    #[test]
    fn test_batch_result_creation() {
        let state = RollupState::new();
        let result = BatchResult::new(
            state,
            5,
            2,
            vec![(3, "Insufficient balance".to_string())],
        );
        
        assert_eq!(result.applied_count, 5);
        assert_eq!(result.rejected_count, 2);
        assert_eq!(result.rejections.len(), 1);
    }
}
