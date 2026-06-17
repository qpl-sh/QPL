//! QPL E2E integration tests — signing + proving pipelines.

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use qpl_network::coordination::{CoordinationManager, PartialResponse, RoundStatus};
    use qpl_network::fees::{FeeCalculator, FeeOperation};
    use qpl_network::types::{OperatorId, QuorumRequirement, RequestId, Urgency};

    /// Test the full fee estimation flow.
    #[test]
    fn test_fee_estimation_pipeline() {
        let calc = FeeCalculator::default();
        let req_id = RequestId::new();
        let quorum = QuorumRequirement::three_of_five();

        let estimate = calc
            .estimate(req_id, &FeeOperation::Sign, Some(quorum), Urgency::Standard)
            .unwrap();

        // Base signing fee = $0.025 * 3 operators * 1.0x urgency = $0.075
        assert_eq!(estimate.base_fee, 25_000);
        assert_eq!(estimate.total_fee, 75_000);
        assert_eq!(estimate.operator_count, 3);
    }

    /// Test coordination round lifecycle (threshold collection).
    #[test]
    fn test_coordination_round_lifecycle() {
        let mut mgr = CoordinationManager::new();
        let req_id = RequestId::new();
        let coordinator = OperatorId::from_public_key(&[0u8; 32]);

        // Start round: threshold=3, total=5, timeout=60s
        let _ = mgr.start_round(req_id.clone(), coordinator, 3, 5, 60);
        assert!(mgr.get_round(&req_id).is_some());

        // Submit partial responses
        let op1 = OperatorId::from_public_key(&[1u8; 32]);
        let op2 = OperatorId::from_public_key(&[2u8; 32]);
        let op3 = OperatorId::from_public_key(&[3u8; 32]);

        let s1 = mgr
            .add_partial(
                &req_id,
                PartialResponse {
                    operator_id: op1,
                    shard_index: 0,
                    payload: vec![0xAA],
                    received_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(s1, RoundStatus::Collecting);

        let s2 = mgr
            .add_partial(
                &req_id,
                PartialResponse {
                    operator_id: op2,
                    shard_index: 1,
                    payload: vec![0xBB],
                    received_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(s2, RoundStatus::Collecting);

        let s3 = mgr
            .add_partial(
                &req_id,
                PartialResponse {
                    operator_id: op3,
                    shard_index: 2,
                    payload: vec![0xCC],
                    received_at: Utc::now(),
                },
            )
            .unwrap();
        assert_eq!(s3, RoundStatus::ThresholdReached);

        // Verify threshold reached
        let round = mgr.get_round(&req_id).unwrap();
        assert!(round.threshold_reached());
    }

    /// Test SDK config presets.
    #[test]
    fn test_sdk_config_presets() {
        let testnet = qpl_sdk::SdkConfig::testnet();
        assert_eq!(testnet.bootstrap_nodes.len(), 3);
        assert_eq!(testnet.solana_rpc, "http://localhost:8899");

        let mainnet = qpl_sdk::SdkConfig::mainnet(
            vec!["https://qpl-1.example.com".to_string()],
            "https://api.mainnet-beta.solana.com".to_string(),
        );
        assert_eq!(mainnet.solana_rpc, "https://api.mainnet-beta.solana.com");
        assert_eq!(mainnet.max_retries, 5);
    }
} // mod tests
