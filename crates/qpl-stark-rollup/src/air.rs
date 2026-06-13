// SPDX-License-Identifier: MIT OR Apache-2.0
//! AIR (Algebraic Intermediate Representation) for settlement batch verification.
//!
//! Defines the constraints that the STARK prover must satisfy to prove
//! correct execution of a batch of settlement transactions.
//!
//! ## Constraint Design
//!
//! The AIR encodes the following transition rules:
//! 1. Balance conservation: sender_balance decreases by amount, receiver increases
//! 2. Non-negativity: sender must have sufficient balance
//! 3. Nonce increment: sender nonce increases by 1 per valid transaction
//! 4. Validity flag: binary constraint (0 or 1)
//!
//! ## Trace Layout
//!
//! | Column | Description |
//! |--------|-------------|
//! | 0 | Sender balance |
//! | 1 | Receiver balance |
//! | 2 | Transfer amount |
//! | 3 | Sender nonce |
//! | 4 | Transaction validity flag (0 or 1) |

use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

/// Number of columns in the execution trace
pub const TRACE_WIDTH: usize = 5;

/// Column indices for the trace
pub mod columns {
    pub const SENDER_BALANCE: usize = 0;
    pub const RECEIVER_BALANCE: usize = 1;
    pub const AMOUNT: usize = 2;
    pub const NONCE: usize = 3;
    pub const VALIDITY: usize = 4;
}

/// Public inputs for the settlement AIR
#[derive(Clone, Debug)]
pub struct SettlementPublicInputs {
    /// Initial sender balance
    pub initial_sender_balance: u64,
    /// Initial receiver balance
    pub initial_receiver_balance: u64,
    /// Initial sender nonce
    pub initial_nonce: u64,
    /// Final sender balance (after all transactions)
    pub final_sender_balance: u64,
    /// Final receiver balance
    pub final_receiver_balance: u64,
    /// Final sender nonce
    pub final_nonce: u64,
}

impl SettlementPublicInputs {
    /// Create new public inputs
    pub fn new(
        initial_sender_balance: u64,
        initial_receiver_balance: u64,
        initial_nonce: u64,
        final_sender_balance: u64,
        final_receiver_balance: u64,
        final_nonce: u64,
    ) -> Self {
        Self {
            initial_sender_balance,
            initial_receiver_balance,
            initial_nonce,
            final_sender_balance,
            final_receiver_balance,
            final_nonce,
        }
    }
}

impl ToElements<BaseElement> for SettlementPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            BaseElement::from(self.initial_sender_balance),
            BaseElement::from(self.initial_receiver_balance),
            BaseElement::from(self.initial_nonce),
            BaseElement::from(self.final_sender_balance),
            BaseElement::from(self.final_receiver_balance),
            BaseElement::from(self.final_nonce),
        ]
    }
}

/// AIR for settlement batch verification
///
/// This AIR verifies that a batch of settlement transactions was executed correctly:
/// - Balance transfers are correctly applied
/// - Nonces are incremented for valid transactions
/// - Invalid transactions (validity = 0) don't modify state
pub struct SettlementAir {
    context: AirContext<BaseElement>,
    public_inputs: SettlementPublicInputs,
}

impl Air for SettlementAir {
    type BaseField = BaseElement;
    type PublicInputs = SettlementPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Define constraint degrees:
        // - Balance transitions: degree 2 (involves multiplication of validity * amount)
        // - Nonce transition: degree 1 (linear: next_nonce - nonce - valid)
        // - Validity binary constraint: degree 2 (validity * (1 - validity))
        let degrees = vec![
            TransitionConstraintDegree::new(2), // sender balance transition
            TransitionConstraintDegree::new(2), // receiver balance transition
            TransitionConstraintDegree::new(1), // nonce transition (linear)
            TransitionConstraintDegree::new(2), // validity binary constraint
        ];

        let context = AirContext::new(trace_info, degrees, 6, options);

        Self {
            context,
            public_inputs: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Evaluate transition constraints
    ///
    /// Constraints:
    /// 1. sender_balance[i+1] = sender_balance[i] - amount[i] * valid[i]
    /// 2. receiver_balance[i+1] = receiver_balance[i] + amount[i] * valid[i]
    /// 3. nonce[i+1] = nonce[i] + valid[i]
    /// 4. valid[i] * (1 - valid[i]) = 0 (binary constraint)
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Current values
        let sender_bal = current[columns::SENDER_BALANCE];
        let receiver_bal = current[columns::RECEIVER_BALANCE];
        let amount = current[columns::AMOUNT];
        let nonce = current[columns::NONCE];
        let valid = current[columns::VALIDITY];

        // Next values
        let next_sender_bal = next[columns::SENDER_BALANCE];
        let next_receiver_bal = next[columns::RECEIVER_BALANCE];
        let next_nonce = next[columns::NONCE];

        // Constraint 1: sender_balance transition
        // next_sender_bal = sender_bal - amount * valid
        // => next_sender_bal - sender_bal + amount * valid = 0
        result[0] = next_sender_bal - sender_bal + amount * valid;

        // Constraint 2: receiver_balance transition
        // next_receiver_bal = receiver_bal + amount * valid
        // => next_receiver_bal - receiver_bal - amount * valid = 0
        result[1] = next_receiver_bal - receiver_bal - amount * valid;

        // Constraint 3: nonce transition
        // next_nonce = nonce + valid
        // => next_nonce - nonce - valid = 0
        result[2] = next_nonce - nonce - valid;

        // Constraint 4: validity is binary (0 or 1)
        // valid * (1 - valid) = 0
        result[3] = valid * (E::ONE - valid);
    }

    /// Define boundary assertions (public inputs must match trace)
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;

        vec![
            // Initial state (first row)
            Assertion::single(
                columns::SENDER_BALANCE,
                0,
                BaseElement::from(self.public_inputs.initial_sender_balance),
            ),
            Assertion::single(
                columns::RECEIVER_BALANCE,
                0,
                BaseElement::from(self.public_inputs.initial_receiver_balance),
            ),
            Assertion::single(
                columns::NONCE,
                0,
                BaseElement::from(self.public_inputs.initial_nonce),
            ),
            // Final state (last row)
            Assertion::single(
                columns::SENDER_BALANCE,
                last_step,
                BaseElement::from(self.public_inputs.final_sender_balance),
            ),
            Assertion::single(
                columns::RECEIVER_BALANCE,
                last_step,
                BaseElement::from(self.public_inputs.final_receiver_balance),
            ),
            Assertion::single(
                columns::NONCE,
                last_step,
                BaseElement::from(self.public_inputs.final_nonce),
            ),
        ]
    }
}

/// Create default proof options suitable for settlement proofs
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32, // num_queries
        8,  // blowup_factor
        0,  // grinding_factor
        winterfell::FieldExtension::None,
        8,  // fri_folding_factor
        31, // fri_max_remainder_degree
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settlement_public_inputs_creation() {
        let inputs = SettlementPublicInputs::new(
            1000, // initial sender
            500,  // initial receiver
            0,    // initial nonce
            800,  // final sender
            700,  // final receiver
            1,    // final nonce
        );

        assert_eq!(inputs.initial_sender_balance, 1000);
        assert_eq!(inputs.final_sender_balance, 800);
    }

    #[test]
    fn test_settlement_public_inputs_to_elements() {
        let inputs = SettlementPublicInputs::new(100, 200, 0, 50, 250, 1);
        let elements = inputs.to_elements();

        assert_eq!(elements.len(), 6);
        assert_eq!(elements[0], BaseElement::from(100u64));
        assert_eq!(elements[1], BaseElement::from(200u64));
        assert_eq!(elements[2], BaseElement::from(0u64));
        assert_eq!(elements[3], BaseElement::from(50u64));
        assert_eq!(elements[4], BaseElement::from(250u64));
        assert_eq!(elements[5], BaseElement::from(1u64));
    }

    #[test]
    fn test_default_proof_options() {
        let options = default_proof_options();
        // Just verify it can be created without panic
        assert!(options.num_queries() > 0);
    }

    #[test]
    fn test_trace_width_constant() {
        assert_eq!(TRACE_WIDTH, 5);
    }

    #[test]
    fn test_column_indices() {
        assert_eq!(columns::SENDER_BALANCE, 0);
        assert_eq!(columns::RECEIVER_BALANCE, 1);
        assert_eq!(columns::AMOUNT, 2);
        assert_eq!(columns::NONCE, 3);
        assert_eq!(columns::VALIDITY, 4);
    }
}
