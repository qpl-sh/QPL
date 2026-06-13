// SPDX-License-Identifier: MIT OR Apache-2.0
//! Execution trace builder for settlement transaction batches.
//!
//! Converts a batch of transactions into a STARK execution trace
//! that can be proved by the SettlementProver.
//!
//! ## Trace Structure
//!
//! The trace has TRACE_WIDTH columns (5):
//! - Column 0: Sender balance progression
//! - Column 1: Receiver balance progression
//! - Column 2: Transfer amount for each transaction
//! - Column 3: Sender nonce progression
//! - Column 4: Validity flag (1 = valid, 0 = invalid/padding)
//!
//! Each row represents one transaction step. The trace is padded
//! to the next power of 2 for FRI compatibility.

use winterfell::math::{fields::f128::BaseElement, FieldElement};

use crate::air::{columns, TRACE_WIDTH};
use crate::types::{AccountBalance, Transaction};

/// Result of building an execution trace
#[derive(Debug)]
pub struct TraceResult {
    /// The built trace as column vectors
    pub trace_columns: Vec<Vec<BaseElement>>,
    /// Trace length (rows)
    pub trace_length: usize,
    /// Number of valid transactions processed
    pub valid_count: usize,
    /// Number of invalid transactions skipped
    pub invalid_count: usize,
    /// Final sender balance
    pub final_sender_balance: u64,
    /// Final receiver balance
    pub final_receiver_balance: u64,
    /// Final sender nonce
    pub final_nonce: u64,
}

/// Build an execution trace for a settlement batch
///
/// # Arguments
/// * `transactions` - List of transactions to process
/// * `sender_initial` - Initial sender account state
/// * `receiver_initial` - Initial receiver account state
///
/// # Returns
/// A TraceResult containing the trace and execution statistics
pub fn build_settlement_trace(
    transactions: &[Transaction],
    sender_initial: &AccountBalance,
    receiver_initial: &AccountBalance,
) -> TraceResult {
    // Calculate trace length (must be power of 2, minimum 8)
    let min_length = (transactions.len() + 1).next_power_of_two().max(8);

    // Initialize columns
    let mut col_sender_balance = vec![BaseElement::ZERO; min_length];
    let mut col_receiver_balance = vec![BaseElement::ZERO; min_length];
    let mut col_amount = vec![BaseElement::ZERO; min_length];
    let mut col_nonce = vec![BaseElement::ZERO; min_length];
    let mut col_validity = vec![BaseElement::ZERO; min_length];

    // Track current state
    let mut sender_balance = sender_initial.balance;
    let mut receiver_balance = receiver_initial.balance;
    let mut nonce = sender_initial.nonce;
    let mut valid_count = 0;
    let mut invalid_count = 0;

    // Fill initial row (row 0)
    col_sender_balance[0] = BaseElement::from(sender_balance);
    col_receiver_balance[0] = BaseElement::from(receiver_balance);
    col_amount[0] = BaseElement::ZERO;
    col_nonce[0] = BaseElement::from(nonce);
    col_validity[0] = BaseElement::ZERO;

    // Process transactions
    for (i, tx) in transactions.iter().enumerate() {
        let row = i + 1;
        if row >= min_length {
            break;
        }

        // Check if transaction is valid
        let is_valid = tx.amount <= sender_balance && tx.nonce == nonce;

        if is_valid {
            // Apply the transaction
            sender_balance = sender_balance.saturating_sub(tx.amount);
            receiver_balance = receiver_balance.saturating_add(tx.amount);
            nonce += 1;
            valid_count += 1;

            col_amount[row - 1] = BaseElement::from(tx.amount);
            col_validity[row - 1] = BaseElement::ONE;
        } else {
            // Invalid transaction - no state change
            invalid_count += 1;

            col_amount[row - 1] = BaseElement::from(tx.amount);
            col_validity[row - 1] = BaseElement::ZERO;
        }

        // Update state columns for this row
        col_sender_balance[row] = BaseElement::from(sender_balance);
        col_receiver_balance[row] = BaseElement::from(receiver_balance);
        col_nonce[row] = BaseElement::from(nonce);
    }

    // Fill remaining rows (padding)
    let last_filled = transactions.len().min(min_length - 1);
    for row in (last_filled + 1)..min_length {
        col_sender_balance[row] = BaseElement::from(sender_balance);
        col_receiver_balance[row] = BaseElement::from(receiver_balance);
        col_nonce[row] = BaseElement::from(nonce);
        // Amount and validity already zero
    }

    let trace_columns = vec![
        col_sender_balance,
        col_receiver_balance,
        col_amount,
        col_nonce,
        col_validity,
    ];

    TraceResult {
        trace_columns,
        trace_length: min_length,
        valid_count,
        invalid_count,
        final_sender_balance: sender_balance,
        final_receiver_balance: receiver_balance,
        final_nonce: nonce,
    }
}

/// Validate that a trace satisfies the settlement AIR constraints
///
/// This is useful for testing and debugging before generating a proof.
pub fn validate_trace(
    trace: &TraceResult,
    initial_sender: u64,
    initial_receiver: u64,
    initial_nonce: u64,
    final_sender: u64,
    final_receiver: u64,
    final_nonce: u64,
) -> Result<(), String> {
    let len = trace.trace_length;

    if trace.trace_columns.len() != TRACE_WIDTH {
        return Err(format!(
            "Wrong number of columns: expected {}, got {}",
            TRACE_WIDTH,
            trace.trace_columns.len()
        ));
    }

    // Check initial values (row 0)
    if trace.trace_columns[columns::SENDER_BALANCE][0] != BaseElement::from(initial_sender) {
        return Err(format!(
            "Initial sender balance mismatch: expected {}, got {:?}",
            initial_sender,
            trace.trace_columns[columns::SENDER_BALANCE][0]
        ));
    }
    if trace.trace_columns[columns::RECEIVER_BALANCE][0] != BaseElement::from(initial_receiver) {
        return Err(format!(
            "Initial receiver balance mismatch: expected {}, got {:?}",
            initial_receiver,
            trace.trace_columns[columns::RECEIVER_BALANCE][0]
        ));
    }
    if trace.trace_columns[columns::NONCE][0] != BaseElement::from(initial_nonce) {
        return Err(format!(
            "Initial nonce mismatch: expected {}, got {:?}",
            initial_nonce,
            trace.trace_columns[columns::NONCE][0]
        ));
    }

    // Check final values (last row)
    let last = len - 1;
    if trace.trace_columns[columns::SENDER_BALANCE][last] != BaseElement::from(final_sender) {
        return Err(format!(
            "Final sender balance mismatch: expected {}, got {:?}",
            final_sender,
            trace.trace_columns[columns::SENDER_BALANCE][last]
        ));
    }
    if trace.trace_columns[columns::RECEIVER_BALANCE][last] != BaseElement::from(final_receiver) {
        return Err(format!(
            "Final receiver balance mismatch: expected {}, got {:?}",
            final_receiver,
            trace.trace_columns[columns::RECEIVER_BALANCE][last]
        ));
    }
    if trace.trace_columns[columns::NONCE][last] != BaseElement::from(final_nonce) {
        return Err(format!(
            "Final nonce mismatch: expected {}, got {:?}",
            final_nonce,
            trace.trace_columns[columns::NONCE][last]
        ));
    }

    // Check transition constraints for each step
    for i in 0..len - 1 {
        let sender_bal = trace.trace_columns[columns::SENDER_BALANCE][i];
        let receiver_bal = trace.trace_columns[columns::RECEIVER_BALANCE][i];
        let amount = trace.trace_columns[columns::AMOUNT][i];
        let nonce_val = trace.trace_columns[columns::NONCE][i];
        let valid = trace.trace_columns[columns::VALIDITY][i];

        let next_sender_bal = trace.trace_columns[columns::SENDER_BALANCE][i + 1];
        let next_receiver_bal = trace.trace_columns[columns::RECEIVER_BALANCE][i + 1];
        let next_nonce = trace.trace_columns[columns::NONCE][i + 1];

        // Check validity is binary
        if valid != BaseElement::ZERO && valid != BaseElement::ONE {
            return Err(format!(
                "Row {}: validity must be 0 or 1, got {:?}",
                i, valid
            ));
        }

        // Check sender balance transition
        let expected_sender = sender_bal - amount * valid;
        if next_sender_bal != expected_sender {
            return Err(format!(
                "Row {}: sender balance transition failed: expected {:?}, got {:?}",
                i, expected_sender, next_sender_bal
            ));
        }

        // Check receiver balance transition
        let expected_receiver = receiver_bal + amount * valid;
        if next_receiver_bal != expected_receiver {
            return Err(format!(
                "Row {}: receiver balance transition failed: expected {:?}, got {:?}",
                i, expected_receiver, next_receiver_bal
            ));
        }

        // Check nonce transition
        let expected_nonce = nonce_val + valid;
        if next_nonce != expected_nonce {
            return Err(format!(
                "Row {}: nonce transition failed: expected {:?}, got {:?}",
                i, expected_nonce, next_nonce
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AccountId;

    fn make_test_transaction(amount: u64, nonce: u64) -> Transaction {
        // For trace building tests, we use the legacy new() method
        // since trace building doesn't verify signatures
        Transaction::new(
            AccountId::from_bytes([1u8; 32]),
            AccountId::from_bytes([2u8; 32]),
            amount,
            nonce,
            0,
            vec![],
        )
    }

    #[test]
    fn test_build_empty_trace() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);

        let result = build_settlement_trace(&[], &sender, &receiver);

        assert_eq!(result.valid_count, 0);
        assert_eq!(result.invalid_count, 0);
        assert_eq!(result.final_sender_balance, 1000);
        assert_eq!(result.final_receiver_balance, 0);
        assert_eq!(result.trace_length, 8); // minimum power of 2
    }

    #[test]
    fn test_build_single_valid_transaction() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let txs = vec![make_test_transaction(100, 0)];

        let result = build_settlement_trace(&txs, &sender, &receiver);

        assert_eq!(result.valid_count, 1);
        assert_eq!(result.invalid_count, 0);
        assert_eq!(result.final_sender_balance, 900);
        assert_eq!(result.final_receiver_balance, 100);
        assert_eq!(result.final_nonce, 1);
    }

    #[test]
    fn test_build_invalid_insufficient_balance() {
        let sender = AccountBalance::new(50); // Only 50 available
        let receiver = AccountBalance::new(0);
        let txs = vec![make_test_transaction(100, 0)]; // Trying to send 100

        let result = build_settlement_trace(&txs, &sender, &receiver);

        assert_eq!(result.valid_count, 0);
        assert_eq!(result.invalid_count, 1);
        assert_eq!(result.final_sender_balance, 50); // Unchanged
        assert_eq!(result.final_receiver_balance, 0); // Unchanged
    }

    #[test]
    fn test_build_invalid_nonce() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let txs = vec![make_test_transaction(100, 5)]; // Wrong nonce (should be 0)

        let result = build_settlement_trace(&txs, &sender, &receiver);

        assert_eq!(result.valid_count, 0);
        assert_eq!(result.invalid_count, 1);
        assert_eq!(result.final_sender_balance, 1000);
    }

    #[test]
    fn test_build_multiple_transactions() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let txs = vec![
            make_test_transaction(100, 0),
            make_test_transaction(200, 1),
            make_test_transaction(50, 2),
        ];

        let result = build_settlement_trace(&txs, &sender, &receiver);

        assert_eq!(result.valid_count, 3);
        assert_eq!(result.invalid_count, 0);
        assert_eq!(result.final_sender_balance, 650);
        assert_eq!(result.final_receiver_balance, 350);
        assert_eq!(result.final_nonce, 3);
    }

    #[test]
    fn test_validate_correct_trace() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let txs = vec![make_test_transaction(100, 0), make_test_transaction(200, 1)];

        let result = build_settlement_trace(&txs, &sender, &receiver);

        let validation = validate_trace(
            &result,
            1000, // initial sender
            0,    // initial receiver
            0,    // initial nonce
            result.final_sender_balance,
            result.final_receiver_balance,
            result.final_nonce,
        );

        assert!(
            validation.is_ok(),
            "Trace should be valid: {:?}",
            validation
        );
    }

    #[test]
    fn test_trace_power_of_two_length() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);

        // 3 transactions should result in trace length 8 (next power of 2 of 4)
        let txs: Vec<_> = (0..3).map(|i| make_test_transaction(10, i)).collect();
        let result = build_settlement_trace(&txs, &sender, &receiver);
        assert_eq!(result.trace_length, 8);

        // 7 transactions should result in trace length 8
        let txs: Vec<_> = (0..7).map(|i| make_test_transaction(10, i)).collect();
        let result = build_settlement_trace(&txs, &sender, &receiver);
        assert_eq!(result.trace_length, 8);

        // 9 transactions should result in trace length 16
        let txs: Vec<_> = (0..9).map(|i| make_test_transaction(10, i)).collect();
        let result = build_settlement_trace(&txs, &sender, &receiver);
        assert_eq!(result.trace_length, 16);
    }

    #[test]
    fn test_trace_columns_structure() {
        let sender = AccountBalance::new(1000);
        let receiver = AccountBalance::new(0);
        let txs = vec![make_test_transaction(100, 0)];

        let result = build_settlement_trace(&txs, &sender, &receiver);

        assert_eq!(result.trace_columns.len(), TRACE_WIDTH);
        for col in &result.trace_columns {
            assert_eq!(col.len(), result.trace_length);
        }
    }
}
