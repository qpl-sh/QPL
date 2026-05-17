// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fee estimation handler.

use crate::server::FeeEstimateResponse;
use crate::state::NodeState;
use qpl_network::fees::FeeOperation;
use qpl_network::types::{RequestId, Urgency};

/// Estimate the fee for a given service + urgency combination.
pub async fn estimate_fee(
    state: &NodeState,
    service_type: &str,
    urgency: &str,
) -> Result<FeeEstimateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let operation = parse_operation(service_type)?;
    let urg = parse_urgency(urgency)?;

    let request_id = RequestId::new();
    let estimate = state.fee_calculator.estimate(request_id, &operation, None, urg);

    // Check operator minimum
    let fee = estimate.total_fee.max(state.config.fees.min_fee_micro_usd);

    let breakdown = serde_json::json!({
        "base_fee_micro_usd": estimate.base_fee,
        "urgency_multiplier": estimate.urgency_multiplier,
        "quorum_multiplier": estimate.quorum_multiplier,
        "operator_min_fee": state.config.fees.min_fee_micro_usd,
        "final_fee_micro_usd": fee,
        "service": service_type,
        "urgency": urgency,
    });

    Ok(FeeEstimateResponse {
        fee_micro_usd: fee,
        quote_id: estimate.quote_id.to_string(),
        breakdown_json: breakdown.to_string(),
    })
}

fn parse_operation(s: &str) -> Result<FeeOperation, Box<dyn std::error::Error + Send + Sync>> {
    match s.to_lowercase().as_str() {
        "signing" | "sign" => Ok(FeeOperation::Sign),
        "proving" | "prove" => Ok(FeeOperation::ProveSmallBatch),
        "proving_large" | "prove_large" => Ok(FeeOperation::ProveLargeBatch),
        "verification" | "verify" => Ok(FeeOperation::VerifyProof),
        _ => Err(format!("unknown service type: {}", s).into()),
    }
}

fn parse_urgency(s: &str) -> Result<Urgency, Box<dyn std::error::Error + Send + Sync>> {
    match s.to_lowercase().as_str() {
        "standard" | "low" | "normal" | "" => Ok(Urgency::Standard),
        "fast" | "high" => Ok(Urgency::Fast),
        "instant" | "critical" => Ok(Urgency::Instant),
        _ => Err(format!("unknown urgency: {}", s).into()),
    }
}
