// SPDX-License-Identifier: MIT OR Apache-2.0
//! Private Validium mode for off-chain data management.
//!
//! In Validium mode, sensitive banking transaction data is stored
//! off-chain while only quantum-secure proofs are posted on-chain.
//!
//! ## Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! |  Off-chain Data  |     |   On-chain       |
//! |  (Validium)      |     |   (L1/L2)        |
//! +------------------+     +------------------+
//! | - Full tx data   |     | - State roots    |
//! | - Account states |     | - STARK proofs   |
//! | - Merkle trees   |     | - Commitments    |
//! +------------------+     +------------------+
//!          |                       ^
//!          +-------Commitment------+
//! ```
//!
//! ## Privacy Guarantees
//!
//! - Individual transactions are never revealed on-chain
//! - Only aggregated state transitions are proven
//! - Banks retain full control of transaction data
//! - Auditors can request data availability proofs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::crypto::compute_merkle_root;
use crate::types::Transaction;

/// Errors that can occur in Validium operations
#[derive(Debug, Error)]
pub enum ValidiumError {
    /// Error storing data
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Error retrieving data
    #[error("Retrieval error: {0}")]
    RetrievalError(String),

    /// Data not found for the given commitment
    #[error("Data not found for commitment")]
    DataNotFound,

    /// Commitment verification failed
    #[error("Commitment verification failed: {0}")]
    VerificationFailed(String),

    /// Lock acquisition failed
    #[error("Lock error: {0}")]
    LockError(String),
}

/// Commitment to off-chain validium data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidiumCommitment {
    /// Merkle root of the off-chain data
    pub data_root: [u8; 32],
    /// Number of transactions in the committed data
    pub transaction_count: usize,
    /// Timestamp of the commitment
    pub timestamp: u64,
    /// Batch height this commitment corresponds to
    pub batch_height: u64,
}

impl ValidiumCommitment {
    /// Create a new validium commitment
    pub fn new(
        data_root: [u8; 32],
        transaction_count: usize,
        timestamp: u64,
        batch_height: u64,
    ) -> Self {
        Self {
            data_root,
            transaction_count,
            timestamp,
            batch_height,
        }
    }

    /// Compute commitment from transaction data
    pub fn from_transactions(
        transactions: &[Transaction],
        batch_height: u64,
        timestamp: u64,
    ) -> Self {
        // Compute merkle root of transaction IDs
        let tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.id).collect();
        let data_root = compute_merkle_root(&tx_hashes);

        Self {
            data_root,
            transaction_count: transactions.len(),
            timestamp,
            batch_height,
        }
    }
}

/// Off-chain data package for Validium mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidiumData {
    /// The transactions (stored off-chain)
    pub transactions: Vec<Transaction>,
    /// Commitment posted on-chain
    pub commitment: ValidiumCommitment,
}

impl ValidiumData {
    /// Create a new validium data package
    pub fn new(transactions: Vec<Transaction>, batch_height: u64, timestamp: u64) -> Self {
        let commitment =
            ValidiumCommitment::from_transactions(&transactions, batch_height, timestamp);
        Self {
            transactions,
            commitment,
        }
    }

    /// Verify that the commitment matches the transaction data
    pub fn verify_commitment(&self) -> bool {
        let computed = ValidiumCommitment::from_transactions(
            &self.transactions,
            self.commitment.batch_height,
            self.commitment.timestamp,
        );
        computed.data_root == self.commitment.data_root
    }
}

/// Create a commitment from a list of transactions
///
/// This is a convenience function that creates a ValidiumCommitment
/// without requiring a full ValidiumData structure.
pub fn create_commitment(
    transactions: &[Transaction],
    batch_height: u64,
    timestamp: u64,
) -> ValidiumCommitment {
    ValidiumCommitment::from_transactions(transactions, batch_height, timestamp)
}

/// Trait for pluggable Validium storage backends
///
/// Implementations of this trait can store validium data in various
/// backends: in-memory (for testing), local files, distributed storage,
/// or encrypted cloud storage.
pub trait ValidiumStore: Send + Sync {
    /// Store off-chain data and return a commitment
    ///
    /// # Arguments
    /// * `data` - The validium data to store
    ///
    /// # Returns
    /// * `Ok(ValidiumCommitment)` - The commitment to the stored data
    /// * `Err(ValidiumError)` - If storage fails
    fn store(&self, data: &ValidiumData) -> Result<ValidiumCommitment, ValidiumError>;

    /// Retrieve off-chain data by commitment
    ///
    /// # Arguments
    /// * `commitment` - The commitment to look up
    ///
    /// # Returns
    /// * `Ok(Some(ValidiumData))` - The data if found
    /// * `Ok(None)` - If no data exists for the commitment
    /// * `Err(ValidiumError)` - If retrieval fails
    fn retrieve(
        &self,
        commitment: &ValidiumCommitment,
    ) -> Result<Option<ValidiumData>, ValidiumError>;

    /// Verify data matches commitment
    ///
    /// # Arguments
    /// * `data` - The data to verify
    /// * `commitment` - The expected commitment
    ///
    /// # Returns
    /// * `Ok(true)` - If data matches commitment
    /// * `Ok(false)` - If data does not match
    /// * `Err(ValidiumError)` - If verification fails
    fn verify(
        &self,
        data: &ValidiumData,
        commitment: &ValidiumCommitment,
    ) -> Result<bool, ValidiumError>;

    /// Check if data exists for a commitment
    fn exists(&self, commitment: &ValidiumCommitment) -> Result<bool, ValidiumError>;

    /// Delete data for a commitment (for cleanup/expiration)
    fn delete(&self, commitment: &ValidiumCommitment) -> Result<bool, ValidiumError>;
}

/// In-memory implementation of ValidiumStore for testing
///
/// This implementation uses a HashMap protected by an RwLock
/// to store validium data. It's suitable for testing and development
/// but not for production use.
#[derive(Debug, Default)]
pub struct InMemoryValidiumStore {
    data: Arc<RwLock<HashMap<[u8; 32], ValidiumData>>>,
}

impl InMemoryValidiumStore {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of stored items
    pub fn len(&self) -> usize {
        self.data.read().map(|d| d.len()).unwrap_or(0)
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all stored data
    pub fn clear(&self) -> Result<(), ValidiumError> {
        let mut data = self
            .data
            .write()
            .map_err(|e| ValidiumError::LockError(e.to_string()))?;
        data.clear();
        Ok(())
    }
}

impl ValidiumStore for InMemoryValidiumStore {
    fn store(&self, data: &ValidiumData) -> Result<ValidiumCommitment, ValidiumError> {
        // Verify the data's internal commitment is correct
        if !data.verify_commitment() {
            return Err(ValidiumError::VerificationFailed(
                "Data does not match its commitment".to_string(),
            ));
        }

        let mut store = self
            .data
            .write()
            .map_err(|e| ValidiumError::LockError(e.to_string()))?;

        let commitment = data.commitment.clone();
        store.insert(commitment.data_root, data.clone());

        Ok(commitment)
    }

    fn retrieve(
        &self,
        commitment: &ValidiumCommitment,
    ) -> Result<Option<ValidiumData>, ValidiumError> {
        let store = self
            .data
            .read()
            .map_err(|e| ValidiumError::LockError(e.to_string()))?;

        Ok(store.get(&commitment.data_root).cloned())
    }

    fn verify(
        &self,
        data: &ValidiumData,
        commitment: &ValidiumCommitment,
    ) -> Result<bool, ValidiumError> {
        // Compute the commitment from the data
        let computed = ValidiumCommitment::from_transactions(
            &data.transactions,
            commitment.batch_height,
            commitment.timestamp,
        );

        // Check if it matches the expected commitment
        Ok(computed.data_root == commitment.data_root
            && computed.transaction_count == commitment.transaction_count)
    }

    fn exists(&self, commitment: &ValidiumCommitment) -> Result<bool, ValidiumError> {
        let store = self
            .data
            .read()
            .map_err(|e| ValidiumError::LockError(e.to_string()))?;

        Ok(store.contains_key(&commitment.data_root))
    }

    fn delete(&self, commitment: &ValidiumCommitment) -> Result<bool, ValidiumError> {
        let mut store = self
            .data
            .write()
            .map_err(|e| ValidiumError::LockError(e.to_string()))?;

        Ok(store.remove(&commitment.data_root).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AccountId;

    fn make_test_transaction(id_seed: u8) -> Transaction {
        Transaction::new(
            AccountId::from_bytes([id_seed; 32]),
            AccountId::from_bytes([id_seed + 1; 32]),
            100,
            0,
            1234567890,
            vec![],
        )
    }

    #[test]
    fn test_validium_commitment_creation() {
        let commitment = ValidiumCommitment::new([1u8; 32], 10, 1234567890, 5);

        assert_eq!(commitment.data_root, [1u8; 32]);
        assert_eq!(commitment.transaction_count, 10);
        assert_eq!(commitment.timestamp, 1234567890);
        assert_eq!(commitment.batch_height, 5);
    }

    #[test]
    fn test_validium_commitment_from_transactions() {
        let txs = vec![
            make_test_transaction(1),
            make_test_transaction(2),
            make_test_transaction(3),
        ];

        let commitment = ValidiumCommitment::from_transactions(&txs, 1, 1234567890);

        assert_eq!(commitment.transaction_count, 3);
        assert_eq!(commitment.batch_height, 1);
        assert_ne!(commitment.data_root, [0u8; 32]); // Should be non-zero
    }

    #[test]
    fn test_validium_data_creation() {
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];

        let data = ValidiumData::new(txs.clone(), 1, 1234567890);

        assert_eq!(data.transactions.len(), 2);
        assert_eq!(data.commitment.transaction_count, 2);
    }

    #[test]
    fn test_validium_data_verify_commitment() {
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];

        let data = ValidiumData::new(txs, 1, 1234567890);
        assert!(data.verify_commitment());
    }

    #[test]
    fn test_validium_commitment_serialization() {
        let commitment = ValidiumCommitment::new([42u8; 32], 5, 1234567890, 10);

        let json = serde_json::to_string(&commitment).expect("Serialization should succeed");
        let restored: ValidiumCommitment =
            serde_json::from_str(&json).expect("Deserialization should succeed");

        assert_eq!(commitment, restored);
    }

    #[test]
    fn test_create_commitment_function() {
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];

        let commitment = create_commitment(&txs, 5, 1234567890);

        assert_eq!(commitment.transaction_count, 2);
        assert_eq!(commitment.batch_height, 5);
        assert_eq!(commitment.timestamp, 1234567890);
    }

    // InMemoryValidiumStore tests

    #[test]
    fn test_store_and_retrieve() {
        let store = InMemoryValidiumStore::new();
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];
        let data = ValidiumData::new(txs, 1, 1234567890);

        // Store the data
        let commitment = store.store(&data).expect("Store should succeed");

        // Retrieve it
        let retrieved = store
            .retrieve(&commitment)
            .expect("Retrieve should succeed")
            .expect("Data should exist");

        assert_eq!(retrieved.transactions.len(), data.transactions.len());
        assert_eq!(retrieved.commitment, data.commitment);
    }

    #[test]
    fn test_verify_commitment() {
        let store = InMemoryValidiumStore::new();
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];
        let data = ValidiumData::new(txs, 1, 1234567890);

        let commitment = store.store(&data).expect("Store should succeed");

        // Verify should return true for correct data
        let is_valid = store
            .verify(&data, &commitment)
            .expect("Verify should succeed");
        assert!(is_valid, "Commitment should be valid");
    }

    #[test]
    fn test_verify_rejects_tampering() {
        let store = InMemoryValidiumStore::new();
        let txs = vec![make_test_transaction(1), make_test_transaction(2)];
        let data = ValidiumData::new(txs, 1, 1234567890);

        let commitment = store.store(&data).expect("Store should succeed");

        // Create tampered data with different transactions
        let tampered_txs = vec![make_test_transaction(3), make_test_transaction(4)];
        let tampered_data = ValidiumData {
            transactions: tampered_txs,
            commitment: commitment.clone(), // Keep same commitment
        };

        // Verify should return false for tampered data
        let is_valid = store
            .verify(&tampered_data, &commitment)
            .expect("Verify should succeed");
        assert!(!is_valid, "Tampered data should not be valid");
    }

    #[test]
    fn test_exists() {
        let store = InMemoryValidiumStore::new();
        let txs = vec![make_test_transaction(1)];
        let data = ValidiumData::new(txs, 1, 1234567890);

        let commitment = store.store(&data).expect("Store should succeed");

        assert!(
            store.exists(&commitment).expect("Exists should succeed"),
            "Data should exist"
        );

        // Non-existent commitment
        let fake_commitment = ValidiumCommitment::new([99u8; 32], 1, 0, 0);
        assert!(
            !store
                .exists(&fake_commitment)
                .expect("Exists should succeed"),
            "Fake commitment should not exist"
        );
    }

    #[test]
    fn test_delete() {
        let store = InMemoryValidiumStore::new();
        let txs = vec![make_test_transaction(1)];
        let data = ValidiumData::new(txs, 1, 1234567890);

        let commitment = store.store(&data).expect("Store should succeed");
        assert_eq!(store.len(), 1);

        // Delete the data
        let deleted = store.delete(&commitment).expect("Delete should succeed");
        assert!(deleted, "Delete should return true");
        assert_eq!(store.len(), 0);

        // Data should no longer exist
        assert!(
            !store.exists(&commitment).expect("Exists should succeed"),
            "Data should not exist after delete"
        );
    }

    #[test]
    fn test_clear() {
        let store = InMemoryValidiumStore::new();

        // Store multiple data entries
        for i in 1..=3 {
            let txs = vec![make_test_transaction(i)];
            let data = ValidiumData::new(txs, i as u64, 1234567890);
            store.store(&data).expect("Store should succeed");
        }

        assert_eq!(store.len(), 3);

        // Clear all data
        store.clear().expect("Clear should succeed");
        assert!(store.is_empty());
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let store = InMemoryValidiumStore::new();
        let fake_commitment = ValidiumCommitment::new([99u8; 32], 1, 0, 0);

        let result = store
            .retrieve(&fake_commitment)
            .expect("Retrieve should succeed");
        assert!(result.is_none(), "Non-existent data should return None");
    }
}
