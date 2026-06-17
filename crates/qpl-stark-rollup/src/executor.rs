// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transaction execution engine and quantum-secure state machine.
//!
//! Processes settlement transactions against the rollup state,
//! validating balances, nonces, and signatures before applying changes.
//!
//! ## State Machine Rules
//! 1. Sender must have sufficient available balance
//! 2. Transaction nonce must equal sender's current nonce
//! 3. Transfer amount must be > 0
//! 4. Sender and receiver must be different accounts
//! 5. State root is recomputed after each batch

use crate::types::{AccountId, BatchResult, RollupState, Transaction};
use std::collections::HashMap;
use std::fmt;

/// Errors that can occur during transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// Sender does not have enough available balance for the transfer.
    InsufficientBalance {
        account: AccountId,
        available: u64,
        required: u64,
    },
    /// Transaction nonce does not match the expected nonce for the sender.
    InvalidNonce {
        account: AccountId,
        expected: u64,
        got: u64,
    },
    /// Transfer amount must be greater than zero.
    ZeroAmount,
    /// Cannot transfer to oneself.
    SelfTransfer { account: AccountId },
    /// Signature verification failed.
    InvalidSignature(String),
    /// Nonce replay across independent batches.
    NonceAlreadyUsed {
        account: AccountId,
        nonce: u64,
        previous_batch: u64,
    },
    /// Batch cannot be empty.
    BatchEmpty,
    /// [QPL-009] Arithmetic overflow in balance computation.
    Overflow { account: AccountId },
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::InsufficientBalance {
                account,
                available,
                required,
            } => {
                write!(
                    f,
                    "Insufficient balance for {}: available {}, required {}",
                    account, available, required
                )
            }
            ExecutionError::InvalidNonce {
                account,
                expected,
                got,
            } => {
                write!(
                    f,
                    "Invalid nonce for {}: expected {}, got {}",
                    account, expected, got
                )
            }
            ExecutionError::ZeroAmount => write!(f, "Transfer amount must be greater than zero"),
            ExecutionError::SelfTransfer { account } => {
                write!(f, "Cannot transfer to self: {}", account)
            }
            ExecutionError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            ExecutionError::NonceAlreadyUsed {
                account,
                nonce,
                previous_batch,
            } => {
                write!(
                    f,
                    "Nonce {} for {} was already used in batch {}",
                    nonce, account, previous_batch
                )
            }
            ExecutionError::BatchEmpty => write!(f, "Batch cannot be empty"),
            ExecutionError::Overflow { account } => {
                write!(f, "Arithmetic overflow for account: {}", account)
            }
        }
    }
}

impl std::error::Error for ExecutionError {}

/// Transaction validator for pre-execution checks.
///
/// Validates transactions against the current rollup state without
/// modifying the state. Use this for dry-run validation before execution.
pub struct TransactionValidator;

impl TransactionValidator {
    /// Validate a single transaction against the current state.
    ///
    /// # Arguments
    /// * `tx` - The transaction to validate
    /// * `state` - The current rollup state
    ///
    /// # Returns
    /// * `Ok(())` if the transaction is valid
    /// * `Err(ExecutionError)` describing why validation failed
    pub fn validate_transaction(
        tx: &Transaction,
        state: &RollupState,
    ) -> Result<(), ExecutionError> {
        // Rule 3: Transfer amount must be > 0
        if tx.amount == 0 {
            return Err(ExecutionError::ZeroAmount);
        }

        // Rule 4: Sender and receiver must be different accounts
        if tx.sender == tx.receiver {
            return Err(ExecutionError::SelfTransfer {
                account: tx.sender.clone(),
            });
        }

        // Get sender account (must exist and have sufficient balance)
        let sender_account = state.get_account(&tx.sender);

        // If sender account doesn't exist, treat as zero balance
        let (available, nonce) = match sender_account {
            Some(account) => (account.available(), account.nonce),
            None => (0, 0),
        };

        // Rule 1: Sender must have sufficient available balance
        if available < tx.amount {
            return Err(ExecutionError::InsufficientBalance {
                account: tx.sender.clone(),
                available,
                required: tx.amount,
            });
        }

        // Rule 2: Transaction nonce must equal sender's current nonce
        if nonce != tx.nonce {
            return Err(ExecutionError::InvalidNonce {
                account: tx.sender.clone(),
                expected: nonce,
                got: tx.nonce,
            });
        }

        // Rule 5: Verify ML-DSA signature
        Self::verify_signature(tx)?;

        Ok(())
    }

    /// Validate a transaction without checking the ML-DSA signature.
    ///
    /// This is useful for internal operations where signature verification
    /// has already been performed or is not applicable (e.g., trace building).
    pub fn validate_transaction_skip_signature(
        tx: &Transaction,
        state: &RollupState,
    ) -> Result<(), ExecutionError> {
        // Rule 3: Transfer amount must be > 0
        if tx.amount == 0 {
            return Err(ExecutionError::ZeroAmount);
        }

        // Rule 4: Sender and receiver must be different accounts
        if tx.sender == tx.receiver {
            return Err(ExecutionError::SelfTransfer {
                account: tx.sender.clone(),
            });
        }

        // Get sender account (must exist and have sufficient balance)
        let sender_account = state.get_account(&tx.sender);

        // If sender account doesn't exist, treat as zero balance
        let (available, nonce) = match sender_account {
            Some(account) => (account.available(), account.nonce),
            None => (0, 0),
        };

        // Rule 1: Sender must have sufficient available balance
        if available < tx.amount {
            return Err(ExecutionError::InsufficientBalance {
                account: tx.sender.clone(),
                available,
                required: tx.amount,
            });
        }

        // Rule 2: Transaction nonce must equal sender's current nonce
        if nonce != tx.nonce {
            return Err(ExecutionError::InvalidNonce {
                account: tx.sender.clone(),
                expected: nonce,
                got: tx.nonce,
            });
        }

        Ok(())
    }

    /// Verify the ML-DSA signature on a transaction.
    fn verify_signature(tx: &Transaction) -> Result<(), ExecutionError> {
        // Check if public key is present
        if tx.sender_public_key.is_empty() {
            return Err(ExecutionError::InvalidSignature(
                "Empty public key".to_string(),
            ));
        }

        // Verify that AccountId matches the public key (prevent spoofing)
        let derived_sender = crate::types::AccountId::from_public_key(&tx.sender_public_key);
        if derived_sender != tx.sender {
            return Err(ExecutionError::InvalidSignature(
                "Public key does not match sender AccountId".to_string(),
            ));
        }

        // Verify the signature
        let message = tx.signing_message();
        match crate::crypto::verify_transaction_signature(
            &tx.sender_public_key,
            &message,
            &tx.signature,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ExecutionError::InvalidSignature(
                "Signature verification failed".to_string(),
            )),
            Err(e) => Err(ExecutionError::InvalidSignature(e)),
        }
    }

    /// Validate a batch of transactions.
    ///
    /// # Arguments
    /// * `txs` - The transactions to validate
    /// * `state` - The current rollup state
    ///
    /// # Returns
    /// A vector of (index, result) pairs for each transaction.
    pub fn validate_batch(
        txs: &[Transaction],
        state: &RollupState,
    ) -> Vec<(usize, Result<(), ExecutionError>)> {
        txs.iter()
            .enumerate()
            .map(|(idx, tx)| (idx, Self::validate_transaction(tx, state)))
            .collect()
    }
}

/// Global nonce registry that tracks (account, nonce) pairs across batches.
///
/// Prevents nonce-replay attacks when separate execution contexts are used
/// (S3 hardening). The registry maps `(account_id_bytes, nonce)` to the
/// `batch_height` where that nonce was first observed.
pub struct NonceRegistry {
    /// Maps (account_id_bytes, nonce) -> batch_height
    seen: HashMap<([u8; 32], u64), u64>,
}

impl NonceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// Record a nonce. Returns `Err` if the (account, nonce) pair was already seen.
    pub fn record(
        &mut self,
        account_id: &AccountId,
        nonce: u64,
        batch_height: u64,
    ) -> Result<(), ExecutionError> {
        let key = (*account_id.as_bytes(), nonce);
        if let Some(&prev_height) = self.seen.get(&key) {
            return Err(ExecutionError::NonceAlreadyUsed {
                account: account_id.clone(),
                nonce,
                previous_batch: prev_height,
            });
        }
        self.seen.insert(key, batch_height);
        Ok(())
    }

    /// Evict entries older than `current_height - retention` batches.
    pub fn cleanup(&mut self, current_height: u64, retention: u64) {
        let cutoff = current_height.saturating_sub(retention);
        self.seen.retain(|_, h| *h >= cutoff);
    }

    /// Number of entries currently tracked.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// State executor for applying transactions to the rollup state.
///
/// Handles the core state machine logic: validating transactions,
/// updating balances, incrementing nonces, and recomputing state roots.
pub struct StateExecutor;

impl StateExecutor {
    /// Create a new state executor.
    pub fn new() -> Self {
        Self
    }

    /// Execute a single transaction against the state.
    ///
    /// This method validates the transaction and applies the state changes
    /// if validation passes.
    ///
    /// # Arguments
    /// * `state` - The rollup state to modify
    /// * `tx` - The transaction to execute
    ///
    /// # Returns
    /// * `Ok(())` if the transaction was successfully executed
    /// * `Err(ExecutionError)` if validation or execution failed
    pub fn execute_transaction(
        state: &mut RollupState,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        // Validate the transaction first
        TransactionValidator::validate_transaction(tx, state)?;

        // Deduct amount from sender balance
        {
            let sender_account = state.get_or_create_account(&tx.sender);
            sender_account.balance = sender_account.balance.saturating_sub(tx.amount);
            sender_account.nonce += 1;
        }

        // Add amount to receiver balance (create account if needed)
        {
            let receiver_account = state.get_or_create_account(&tx.receiver);
            receiver_account.balance = receiver_account.balance.checked_add(tx.amount).ok_or(
                ExecutionError::Overflow {
                    account: tx.receiver.clone(),
                },
            )?;
        }

        Ok(())
    }

    /// Execute a batch of transactions.
    ///
    /// Executes transactions sequentially, skipping invalid ones and
    /// recording them as rejections. The state root is recomputed at the end.
    ///
    /// # Arguments
    /// * `state` - The rollup state to modify
    /// * `txs` - The transactions to execute
    ///
    /// # Returns
    /// A `BatchResult` containing the new state and execution statistics.
    pub fn execute_batch(state: &mut RollupState, txs: &[Transaction]) -> BatchResult {
        let mut applied_count = 0;
        let mut rejected_count = 0;
        let mut rejections: Vec<(usize, String)> = Vec::new();

        for (idx, tx) in txs.iter().enumerate() {
            match Self::execute_transaction(state, tx) {
                Ok(()) => {
                    applied_count += 1;
                }
                Err(e) => {
                    rejected_count += 1;
                    rejections.push((idx, e.to_string()));
                }
            }
        }

        // Recompute state root after batch execution
        state.compute_state_root();
        state.batch_height += 1;

        BatchResult::new(state.clone(), applied_count, rejected_count, rejections)
    }

    /// Execute a batch of transactions in strict mode.
    ///
    /// Unlike `execute_batch`, this method fails on the first invalid
    /// transaction. This is useful for proving mode where all transactions
    /// must be valid.
    ///
    /// # Arguments
    /// * `state` - The rollup state to modify
    /// * `txs` - The transactions to execute
    ///
    /// # Returns
    /// * `Ok(BatchResult)` if all transactions were successfully executed
    /// * `Err(ExecutionError)` if any transaction failed
    pub fn execute_batch_strict(
        state: &mut RollupState,
        txs: &[Transaction],
    ) -> Result<BatchResult, ExecutionError> {
        if txs.is_empty() {
            return Err(ExecutionError::BatchEmpty);
        }

        for tx in txs {
            Self::execute_transaction(state, tx)?;
        }

        // Recompute state root after batch execution
        state.compute_state_root();
        state.batch_height += 1;

        Ok(BatchResult::new(state.clone(), txs.len(), 0, vec![]))
    }
}

impl Default for StateExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Hook for the Multi-Tenant CDA Engine to observe state changes.
///
/// Implementors can react to settlements, token minting, etc.
/// This trait allows the CDA engine to monitor rollup state changes
/// without tight coupling to the executor implementation.
pub trait CdaEngineHook: Send + Sync {
    /// Called before a batch is executed.
    ///
    /// # Arguments
    /// * `batch_height` - The height of the batch being executed
    /// * `tx_count` - The number of transactions in the batch
    fn on_batch_start(&self, batch_height: u64, tx_count: usize);

    /// Called after each successful transaction.
    ///
    /// # Arguments
    /// * `tx` - The transaction that was settled
    /// * `new_sender_balance` - The sender's balance after the transaction
    /// * `new_receiver_balance` - The receiver's balance after the transaction
    fn on_transaction_settled(
        &self,
        tx: &Transaction,
        new_sender_balance: u64,
        new_receiver_balance: u64,
    );

    /// Called after a batch completes.
    ///
    /// # Arguments
    /// * `result` - The result of the batch execution
    fn on_batch_complete(&self, result: &BatchResult);
}

/// Default CDA hook implementation that does nothing.
///
/// Use this for standalone operation when no CDA engine integration is needed.
pub struct NoOpCdaHook;

impl CdaEngineHook for NoOpCdaHook {
    fn on_batch_start(&self, _batch_height: u64, _tx_count: usize) {
        // No-op
    }

    fn on_transaction_settled(
        &self,
        _tx: &Transaction,
        _new_sender_balance: u64,
        _new_receiver_balance: u64,
    ) {
        // No-op
    }

    fn on_batch_complete(&self, _result: &BatchResult) {
        // No-op
    }
}

/// State executor with CDA engine hooks.
///
/// This version of the executor notifies a `CdaEngineHook` implementation
/// about state changes during batch execution.
pub struct StateExecutorWithHooks {
    hook: Box<dyn CdaEngineHook>,
}

impl StateExecutorWithHooks {
    /// Create a new executor with the given CDA engine hook.
    ///
    /// # Arguments
    /// * `hook` - The CDA engine hook to receive state change notifications
    pub fn new(hook: Box<dyn CdaEngineHook>) -> Self {
        Self { hook }
    }

    /// Execute a batch of transactions with hook notifications.
    ///
    /// # Arguments
    /// * `state` - The rollup state to modify
    /// * `txs` - The transactions to execute
    ///
    /// # Returns
    /// A `BatchResult` containing the new state and execution statistics.
    pub fn execute_batch(&self, state: &mut RollupState, txs: &[Transaction]) -> BatchResult {
        let mut applied_count = 0;
        let mut rejected_count = 0;
        let mut rejections: Vec<(usize, String)> = Vec::new();

        // Notify hook of batch start
        self.hook.on_batch_start(state.batch_height, txs.len());

        for (idx, tx) in txs.iter().enumerate() {
            match TransactionValidator::validate_transaction(tx, state) {
                Ok(()) => {
                    // [QPL-009] Execute with checked arithmetic;
                    // reject on overflow instead of silent truncation.
                    let receiver_account = state.get_or_create_account(&tx.receiver);
                    if receiver_account.balance.checked_add(tx.amount).is_none() {
                        rejected_count += 1;
                        rejections.push((idx, format!("overflow crediting {}", tx.receiver)));
                        continue;
                    }

                    {
                        let sender_account = state.get_or_create_account(&tx.sender);
                        sender_account.balance = sender_account.balance.saturating_sub(tx.amount);
                        sender_account.nonce += 1;
                    }

                    {
                        let receiver_account = state.get_or_create_account(&tx.receiver);
                        receiver_account.balance = receiver_account
                            .balance
                            .checked_add(tx.amount)
                            .expect("overflow already checked above");
                    }

                    // Get new balances for hook notification
                    let new_sender_balance = state.get_account(&tx.sender).map_or(0, |a| a.balance);
                    let new_receiver_balance =
                        state.get_account(&tx.receiver).map_or(0, |a| a.balance);

                    // Notify hook of successful transaction
                    self.hook
                        .on_transaction_settled(tx, new_sender_balance, new_receiver_balance);

                    applied_count += 1;
                }
                Err(e) => {
                    rejected_count += 1;
                    rejections.push((idx, e.to_string()));
                }
            }
        }

        // Recompute state root after batch execution
        state.compute_state_root();
        state.batch_height += 1;

        let result = BatchResult::new(state.clone(), applied_count, rejected_count, rejections);

        // Notify hook of batch completion
        self.hook.on_batch_complete(&result);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Test keypair wrapper for creating signed transactions
    struct TestKeypair {
        keypair: qpl_crypto::ml_dsa::MlDsaKeyPair,
        account_id: AccountId,
    }

    impl TestKeypair {
        fn generate() -> Self {
            let keypair =
                qpl_crypto::ml_dsa::generate_keypair().expect("Key generation should succeed");
            let account_id = AccountId::from_public_key(keypair.public_key().as_bytes());
            Self {
                keypair,
                account_id,
            }
        }

        fn public_key_bytes(&self) -> Vec<u8> {
            self.keypair.public_key().as_bytes().to_vec()
        }

        fn account_id(&self) -> AccountId {
            self.account_id.clone()
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.keypair
                .sign(message)
                .expect("Signing should succeed")
                .as_bytes()
                .to_vec()
        }
    }

    /// Create a signed test transaction
    fn create_signed_transaction(
        sender: &TestKeypair,
        receiver: &AccountId,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let timestamp = 1234567890u64;

        // Build the signing message (same as Transaction::signing_message)
        let mut msg = Vec::new();
        msg.extend_from_slice(sender.account_id().as_bytes());
        msg.extend_from_slice(receiver.as_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());

        let signature = sender.sign(&msg);

        Transaction::new_from_public_key(
            sender.public_key_bytes(),
            receiver.clone(),
            amount,
            nonce,
            timestamp,
            signature,
        )
    }

    /// Helper to create a funded state with test keypairs
    fn funded_state_with_keypairs(
        sender: &TestKeypair,
        sender_balance: u64,
        receiver: &TestKeypair,
        receiver_balance: u64,
    ) -> RollupState {
        let mut state = RollupState::new();
        state.get_or_create_account(&sender.account_id()).balance = sender_balance;
        state.get_or_create_account(&receiver.account_id()).balance = receiver_balance;
        state
    }

    #[test]
    fn test_execute_valid_transfer() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 0);

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(result.is_ok());

        // Verify balances updated
        let sender_bal = state.get_account(&sender.account_id()).unwrap();
        let receiver_bal = state.get_account(&receiver.account_id()).unwrap();

        assert_eq!(sender_bal.balance, 900);
        assert_eq!(receiver_bal.balance, 600);
    }

    #[test]
    fn test_insufficient_balance() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 50, &receiver, 500);
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 0);

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(
            result,
            Err(ExecutionError::InsufficientBalance { .. })
        ));

        // Verify balances unchanged
        let sender_bal = state.get_account(&sender.account_id()).unwrap();
        assert_eq!(sender_bal.balance, 50);
    }

    #[test]
    fn test_invalid_nonce() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 5); // Wrong nonce (expected 0)

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::InvalidNonce { .. })));
    }

    #[test]
    fn test_zero_amount() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 0, 0);

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::ZeroAmount)));
    }

    #[test]
    fn test_self_transfer() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let tx = create_signed_transaction(&sender, &sender.account_id(), 100, 0); // Same sender and receiver

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::SelfTransfer { .. })));
    }

    #[test]
    fn test_execute_batch_mixed() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        let txs = vec![
            create_signed_transaction(&sender, &receiver.account_id(), 100, 0), // Valid
            create_signed_transaction(&sender, &receiver.account_id(), 5000, 1), // Invalid: insufficient balance
            create_signed_transaction(&sender, &receiver.account_id(), 200, 1), // Valid (after first tx, nonce is 1)
        ];

        let result = StateExecutor::execute_batch(&mut state, &txs);

        assert_eq!(result.applied_count, 2);
        assert_eq!(result.rejected_count, 1);
        assert_eq!(result.rejections.len(), 1);
        assert_eq!(result.rejections[0].0, 1); // Index of rejected tx
    }

    #[test]
    fn test_execute_batch_strict_fails_fast() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        let txs = vec![
            create_signed_transaction(&sender, &receiver.account_id(), 100, 0), // Valid
            create_signed_transaction(&sender, &receiver.account_id(), 5000, 1), // Invalid: insufficient balance
            create_signed_transaction(&sender, &receiver.account_id(), 200, 2), // Would be valid but won't be reached
        ];

        let result = StateExecutor::execute_batch_strict(&mut state, &txs);
        assert!(result.is_err());

        // First transaction should have been applied
        let sender_bal = state.get_account(&sender.account_id()).unwrap();
        assert_eq!(sender_bal.balance, 900);
        assert_eq!(sender_bal.nonce, 1);
    }

    #[test]
    fn test_state_root_changes() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let initial_root = state.state_root;

        let txs = vec![create_signed_transaction(
            &sender,
            &receiver.account_id(),
            100,
            0,
        )];
        let result = StateExecutor::execute_batch(&mut state, &txs);

        assert_ne!(result.new_state.state_root, initial_root);
    }

    #[test]
    fn test_receiver_account_creation() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = RollupState::new();

        // Only create sender account
        state.get_or_create_account(&sender.account_id()).balance = 1000;

        // Receiver doesn't exist yet
        assert!(state.get_account(&receiver.account_id()).is_none());

        let tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 0);
        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(result.is_ok());

        // Receiver should now exist with transferred amount
        let receiver_bal = state.get_account(&receiver.account_id()).unwrap();
        assert_eq!(receiver_bal.balance, 100);
    }

    #[test]
    fn test_nonce_increments() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        assert_eq!(state.get_account(&sender.account_id()).unwrap().nonce, 0);

        let tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 0);
        StateExecutor::execute_transaction(&mut state, &tx).unwrap();

        assert_eq!(state.get_account(&sender.account_id()).unwrap().nonce, 1);
    }

    #[test]
    fn test_multiple_transfers_same_sender() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 0);

        let txs = vec![
            create_signed_transaction(&sender, &receiver.account_id(), 100, 0),
            create_signed_transaction(&sender, &receiver.account_id(), 100, 1),
            create_signed_transaction(&sender, &receiver.account_id(), 100, 2),
        ];

        let result = StateExecutor::execute_batch(&mut state, &txs);

        assert_eq!(result.applied_count, 3);
        assert_eq!(result.rejected_count, 0);

        let sender_bal = result.new_state.get_account(&sender.account_id()).unwrap();
        let receiver_bal = result
            .new_state
            .get_account(&receiver.account_id())
            .unwrap();

        assert_eq!(sender_bal.balance, 700);
        assert_eq!(sender_bal.nonce, 3);
        assert_eq!(receiver_bal.balance, 300);
    }

    #[test]
    fn test_batch_ordering_matters() {
        // Account 1 has funds, account 2 has none
        // First tx: 1 -> 2 (funds account 2)
        // Second tx: 2 -> 3 (uses newly funded account 2)
        let account1 = TestKeypair::generate();
        let account2 = TestKeypair::generate();
        let account3 = TestKeypair::generate();

        let mut state = RollupState::new();
        state.get_or_create_account(&account1.account_id()).balance = 1000;

        let txs = vec![
            create_signed_transaction(&account1, &account2.account_id(), 500, 0), // Fund account 2
            create_signed_transaction(&account2, &account3.account_id(), 200, 0), // Account 2 sends to account 3
        ];

        let result = StateExecutor::execute_batch(&mut state, &txs);

        assert_eq!(result.applied_count, 2);
        assert_eq!(result.rejected_count, 0);

        let bal1 = result
            .new_state
            .get_account(&account1.account_id())
            .unwrap();
        let bal2 = result
            .new_state
            .get_account(&account2.account_id())
            .unwrap();
        let bal3 = result
            .new_state
            .get_account(&account3.account_id())
            .unwrap();

        assert_eq!(bal1.balance, 500);
        assert_eq!(bal2.balance, 300);
        assert_eq!(bal3.balance, 200);
    }

    #[test]
    fn test_cda_hook_receives_events() {
        use std::sync::{Arc, Mutex};

        // Mock CDA hook that records events
        #[derive(Default)]
        struct MockCdaHook {
            batch_starts: Mutex<Vec<(u64, usize)>>,
            transactions: Mutex<Vec<(u64, u64, u64)>>, // (amount, sender_balance, receiver_balance)
            batch_completes: Mutex<Vec<(usize, usize)>>, // (applied, rejected)
        }

        impl CdaEngineHook for MockCdaHook {
            fn on_batch_start(&self, batch_height: u64, tx_count: usize) {
                self.batch_starts
                    .lock()
                    .unwrap()
                    .push((batch_height, tx_count));
            }

            fn on_transaction_settled(
                &self,
                tx: &Transaction,
                new_sender_balance: u64,
                new_receiver_balance: u64,
            ) {
                self.transactions.lock().unwrap().push((
                    tx.amount,
                    new_sender_balance,
                    new_receiver_balance,
                ));
            }

            fn on_batch_complete(&self, result: &BatchResult) {
                self.batch_completes
                    .lock()
                    .unwrap()
                    .push((result.applied_count, result.rejected_count));
            }
        }

        let hook = Arc::new(MockCdaHook::default());
        let executor = StateExecutorWithHooks::new(Box::new(MockCdaHookWrapper(hook.clone())));

        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let txs = vec![
            create_signed_transaction(&sender, &receiver.account_id(), 100, 0),
            create_signed_transaction(&sender, &receiver.account_id(), 200, 1),
        ];

        let _result = executor.execute_batch(&mut state, &txs);

        // Verify batch_start was called
        let batch_starts = hook.batch_starts.lock().unwrap();
        assert_eq!(batch_starts.len(), 1);
        assert_eq!(batch_starts[0], (0, 2)); // batch_height=0, tx_count=2

        // Verify transactions were recorded
        let transactions = hook.transactions.lock().unwrap();
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].0, 100); // First tx amount
        assert_eq!(transactions[1].0, 200); // Second tx amount

        // Verify batch_complete was called
        let batch_completes = hook.batch_completes.lock().unwrap();
        assert_eq!(batch_completes.len(), 1);
        assert_eq!(batch_completes[0], (2, 0)); // 2 applied, 0 rejected
    }

    // Wrapper to allow Arc<MockCdaHook> to implement CdaEngineHook
    struct MockCdaHookWrapper<T: CdaEngineHook>(Arc<T>);

    impl<T: CdaEngineHook> CdaEngineHook for MockCdaHookWrapper<T> {
        fn on_batch_start(&self, batch_height: u64, tx_count: usize) {
            self.0.on_batch_start(batch_height, tx_count);
        }

        fn on_transaction_settled(
            &self,
            tx: &Transaction,
            new_sender_balance: u64,
            new_receiver_balance: u64,
        ) {
            self.0
                .on_transaction_settled(tx, new_sender_balance, new_receiver_balance);
        }

        fn on_batch_complete(&self, result: &BatchResult) {
            self.0.on_batch_complete(result);
        }
    }

    #[test]
    fn test_validate_batch() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        let txs = vec![
            create_signed_transaction(&sender, &receiver.account_id(), 100, 0), // Valid
            create_signed_transaction(&sender, &receiver.account_id(), 5000, 0), // Invalid: insufficient balance
            create_signed_transaction(&sender, &sender.account_id(), 100, 0), // Invalid: self transfer
        ];

        let results = TransactionValidator::validate_batch(&txs, &state);

        assert_eq!(results.len(), 3);
        assert!(results[0].1.is_ok());
        assert!(matches!(
            results[1].1,
            Err(ExecutionError::InsufficientBalance { .. })
        ));
        assert!(matches!(
            results[2].1,
            Err(ExecutionError::SelfTransfer { .. })
        ));
    }

    #[test]
    fn test_execution_error_display() {
        let keypair = TestKeypair::generate();
        let err = ExecutionError::InsufficientBalance {
            account: keypair.account_id(),
            available: 100,
            required: 500,
        };
        let display = format!("{}", err);
        assert!(display.contains("Insufficient balance"));
        assert!(display.contains("100"));
        assert!(display.contains("500"));

        let err = ExecutionError::ZeroAmount;
        assert!(format!("{}", err).contains("greater than zero"));
    }

    #[test]
    fn test_batch_empty_error() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let txs: Vec<Transaction> = vec![];

        let result = StateExecutor::execute_batch_strict(&mut state, &txs);
        assert!(matches!(result, Err(ExecutionError::BatchEmpty)));
    }

    #[test]
    fn test_batch_height_increments() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        assert_eq!(state.batch_height, 0);

        let txs = vec![create_signed_transaction(
            &sender,
            &receiver.account_id(),
            100,
            0,
        )];
        let result = StateExecutor::execute_batch(&mut state, &txs);

        assert_eq!(result.new_state.batch_height, 1);
    }

    #[test]
    fn test_locked_balance_affects_available() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = RollupState::new();

        // Set up sender with 1000 balance but 800 locked
        let sender_account = state.get_or_create_account(&sender.account_id());
        sender_account.balance = 1000;
        sender_account.locked = 800;

        state.get_or_create_account(&receiver.account_id()).balance = 0;

        // Available = 1000 - 800 = 200
        // Try to transfer 300 (more than available)
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 300, 0);
        let result = StateExecutor::execute_transaction(&mut state, &tx);

        assert!(matches!(
            result,
            Err(ExecutionError::InsufficientBalance {
                available: 200,
                required: 300,
                ..
            })
        ));

        // Transfer 150 (less than available) should work
        let tx = create_signed_transaction(&sender, &receiver.account_id(), 150, 0);
        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_noop_cda_hook() {
        // Just ensure NoOpCdaHook compiles and can be used
        let hook = NoOpCdaHook;
        let executor = StateExecutorWithHooks::new(Box::new(hook));

        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);
        let txs = vec![create_signed_transaction(
            &sender,
            &receiver.account_id(),
            100,
            0,
        )];

        let result = executor.execute_batch(&mut state, &txs);
        assert_eq!(result.applied_count, 1);
    }

    // --- Signature verification tests ---

    #[test]
    fn test_invalid_signature_empty_public_key() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        // Create transaction with empty public key
        let tx = Transaction::new(
            sender.account_id(),
            receiver.account_id(),
            100,
            0,
            1234567890,
            vec![0u8; 64],
        );

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::InvalidSignature(_))));
    }

    #[test]
    fn test_invalid_signature_wrong_key() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let wrong_signer = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        // Create transaction signed by wrong key
        let tx = create_signed_transaction(&wrong_signer, &receiver.account_id(), 100, 0);
        // But set sender to original sender (spoofing attempt)
        let mut tampered = tx;
        tampered.sender = sender.account_id();
        tampered.compute_id();

        let result = StateExecutor::execute_transaction(&mut state, &tampered);
        assert!(matches!(result, Err(ExecutionError::InvalidSignature(_))));
    }

    #[test]
    fn test_invalid_signature_bad_signature_bytes() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let mut state = funded_state_with_keypairs(&sender, 1000, &receiver, 500);

        // Create transaction with invalid signature
        let tx = Transaction::new_from_public_key(
            sender.public_key_bytes(),
            receiver.account_id(),
            100,
            0,
            1234567890,
            vec![0xBA; 64], // Invalid signature bytes
        );

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::InvalidSignature(_))));
    }

    #[test]
    fn test_invalid_signature_spoofed_account_id() {
        let sender = TestKeypair::generate();
        let receiver = TestKeypair::generate();
        let spoofed = TestKeypair::generate();
        let mut state = RollupState::new();

        // Fund the spoofed account (not the sender)
        state.get_or_create_account(&spoofed.account_id()).balance = 1000;
        state.get_or_create_account(&receiver.account_id()).balance = 0;

        // Create a valid signed transaction from sender
        let mut tx = create_signed_transaction(&sender, &receiver.account_id(), 100, 0);
        // But try to claim it's from spoofed account (AccountId spoofing)
        tx.sender = spoofed.account_id();
        tx.compute_id();

        let result = StateExecutor::execute_transaction(&mut state, &tx);
        assert!(matches!(result, Err(ExecutionError::InvalidSignature(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Public key does not match"));
    }
}
