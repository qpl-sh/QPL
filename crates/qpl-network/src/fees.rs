// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fee schedule and calculation for QPL network operations.
//!
//! Each service type has a base fee. Total fee is calculated as:
//! `total = base_fee * quorum_multiplier * urgency_multiplier`
//!
//! Fees are split: 40% coordinator, 50% participants, 10% protocol treasury.

use crate::errors::NetworkError;
use crate::types::*;
use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Fee split ratios (must sum to 100).
pub const COORDINATOR_SHARE_PCT: u8 = 40;
pub const PARTICIPANT_SHARE_PCT: u8 = 50;
pub const TREASURY_SHARE_PCT: u8 = 10;

/// Per-operation base fees in USD micro-units (1 unit = $0.000001).
/// Example: 25_000 = $0.025
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Fee per threshold signature ($0.025)
    pub signing_base: u64,
    /// Fee per STARK proof generation — small batch ($1.00)
    pub proving_small_base: u64,
    /// Fee per STARK proof generation — large batch ($2.50)
    pub proving_large_base: u64,
    /// Fee per proof verification ($0.025)
    pub verification_base: u64,
    /// Batch size threshold for proving (transactions).
    pub proving_large_threshold: u32,
    /// Minimum total fee to prevent dust (micro-units).
    pub min_total_fee: u64,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            signing_base: 25_000,          // $0.025
            proving_small_base: 1_000_000, // $1.00
            proving_large_base: 2_500_000, // $2.50
            verification_base: 25_000,     // $0.025
            proving_large_threshold: 100,
            min_total_fee: 25_000,         // $0.025 minimum
        }
    }
}

/// Specific operation being requested (determines base fee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeOperation {
    Sign,
    ProveSmallBatch,
    ProveLargeBatch,
    VerifyProof,
}

/// A fee estimate returned to the protocol before payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Unique quote ID — must be referenced in on-chain payment.
    pub quote_id: Uuid,
    /// The request this quote is for.
    pub request_id: RequestId,
    /// Base fee in USD micro-units.
    pub base_fee: u64,
    /// Quorum multiplier applied.
    pub quorum_multiplier: f64,
    /// Urgency multiplier applied.
    pub urgency_multiplier: f64,
    /// Total fee in USD micro-units.
    pub total_fee: u64,
    /// Number of operators involved.
    pub operator_count: u8,
    /// When this quote expires.
    pub expires_at: DateTime<Utc>,
}

/// Breakdown of how a fee is split among participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeSplit {
    /// Amount for the coordinator operator.
    pub coordinator_amount: u64,
    /// Amount per participating operator (split equally).
    pub per_participant_amount: u64,
    /// Number of participants (excluding coordinator).
    pub participant_count: u8,
    /// Amount for protocol treasury.
    pub treasury_amount: u64,
}

/// Fee calculator for the QPL network.
#[derive(Debug, Clone)]
pub struct FeeCalculator {
    schedule: FeeSchedule,
    quote_expiry_secs: u64,
}

impl FeeCalculator {
    pub fn new(schedule: FeeSchedule, quote_expiry_secs: u64) -> Self {
        Self {
            schedule,
            quote_expiry_secs,
        }
    }

    /// Calculates a fee estimate for a given operation.
    pub fn estimate(
        &self,
        request_id: RequestId,
        operation: &FeeOperation,
        quorum: Option<QuorumRequirement>,
        urgency: Urgency,
    ) -> FeeEstimate {
        let base_fee = self.base_fee_for(operation);
        let quorum_multiplier = quorum
            .map(|q| q.threshold as f64)
            .unwrap_or(1.0);
        let urgency_multiplier = urgency.multiplier();

        let total = (base_fee as f64 * quorum_multiplier * urgency_multiplier) as u64;
        let operator_count = quorum.map(|q| q.threshold).unwrap_or(1);

        FeeEstimate {
            quote_id: Uuid::new_v4(),
            request_id,
            base_fee,
            quorum_multiplier,
            urgency_multiplier,
            total_fee: total,
            operator_count,
            expires_at: Utc::now() + Duration::seconds(self.quote_expiry_secs as i64),
        }
    }

    /// Validates that a fee quote has not expired.
    pub fn validate_quote(&self, estimate: &FeeEstimate) -> Result<(), NetworkError> {
        if Utc::now() > estimate.expires_at {
            return Err(NetworkError::FeeQuoteExpired(format!(
                "Quote {} expired at {}",
                estimate.quote_id, estimate.expires_at
            )));
        }
        Ok(())
    }

    /// Calculates how to split a paid fee among participants.
    pub fn split_fee(&self, total_fee: u64, participant_count: u8) -> FeeSplit {
        let coordinator_amount = total_fee * COORDINATOR_SHARE_PCT as u64 / 100;
        let treasury_amount = total_fee * TREASURY_SHARE_PCT as u64 / 100;
        let participant_pool = total_fee - coordinator_amount - treasury_amount;
        let per_participant = if participant_count > 0 {
            participant_pool / participant_count as u64
        } else {
            0
        };

        FeeSplit {
            coordinator_amount,
            per_participant_amount: per_participant,
            participant_count,
            treasury_amount,
        }
    }

    /// Returns the base fee (USD micro-units) for an operation.
    fn base_fee_for(&self, operation: &FeeOperation) -> u64 {
        match operation {
            FeeOperation::Sign => self.schedule.signing_base,
            FeeOperation::ProveSmallBatch => self.schedule.proving_small_base,
            FeeOperation::ProveLargeBatch => self.schedule.proving_large_base,
            FeeOperation::VerifyProof => self.schedule.verification_base,
        }
    }

    /// Converts USD micro-units to a human-readable string.
    pub fn format_usd(micro_units: u64) -> String {
        let dollars = Decimal::new(micro_units as i64, 6);
        format!("${}", dollars)
    }
}

impl Default for FeeCalculator {
    fn default() -> Self {
        Self::new(FeeSchedule::default(), 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_fee_schedule() {
        let schedule = FeeSchedule::default();
        assert_eq!(schedule.signing_base, 25_000); // $0.025
        assert_eq!(schedule.proving_small_base, 1_000_000); // $1.00
        assert_eq!(schedule.proving_large_base, 2_500_000); // $2.50
        assert_eq!(schedule.verification_base, 25_000); // $0.025
    }

    #[test]
    fn test_fee_estimate_basic() {
        let calc = FeeCalculator::default();
        let estimate = calc.estimate(
            RequestId::new(),
            &FeeOperation::Sign,
            Some(QuorumRequirement::three_of_five()),
            Urgency::Standard,
        );

        // base $0.025 * 3 operators * 1.0 urgency = $0.075
        assert_eq!(estimate.total_fee, 75_000);
        assert_eq!(estimate.operator_count, 3);
    }

    #[test]
    fn test_fee_estimate_with_urgency() {
        let calc = FeeCalculator::default();
        let estimate = calc.estimate(
            RequestId::new(),
            &FeeOperation::Sign,
            Some(QuorumRequirement::three_of_five()),
            Urgency::Instant,
        );

        // base $0.025 * 3 operators * 2.0 urgency = $0.150
        assert_eq!(estimate.total_fee, 150_000);
    }

    #[test]
    fn test_fee_split() {
        let calc = FeeCalculator::default();
        let split = calc.split_fee(10_000, 2); // $0.01 total, 2 participants

        assert_eq!(split.coordinator_amount, 4_000); // 40%
        assert_eq!(split.treasury_amount, 1_000); // 10%
        // 50% = 5_000, split between 2 participants
        assert_eq!(split.per_participant_amount, 2_500);
        assert_eq!(split.participant_count, 2);
    }

    #[test]
    fn test_fee_quote_expiry() {
        let calc = FeeCalculator::new(FeeSchedule::default(), 60);
        let estimate = calc.estimate(
            RequestId::new(),
            &FeeOperation::Sign,
            None,
            Urgency::Standard,
        );

        // Fresh quote should be valid
        assert!(calc.validate_quote(&estimate).is_ok());
    }

    #[test]
    fn test_format_usd() {
        assert_eq!(FeeCalculator::format_usd(25_000), "$0.025000");
        assert_eq!(FeeCalculator::format_usd(1_000_000), "$1.000000");
        assert_eq!(FeeCalculator::format_usd(2_500_000), "$2.500000");
    }
}
