// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for ML-DSA test vectors.
//!
//! This module runs the generated ML-DSA test vectors through the runner
//! and validates that all tests pass. It also tests JSON serialization roundtrip.

use qpl_crypto::vectors::{generate_ml_dsa_test_vectors, run_ml_dsa_test_vectors, TestVectorFile};

#[test]
fn test_ml_dsa_vectors_all_pass() {
    // Generate test vectors
    let vectors = generate_ml_dsa_test_vectors();

    // Verify we have the expected structure
    assert_eq!(vectors.algorithm, "ML-DSA-65");
    assert!(!vectors.test_groups.is_empty(), "Should have test groups");
    assert!(vectors.number_of_tests >= 10, "Should have at least 10 test cases");

    // Run all test vectors
    let results = run_ml_dsa_test_vectors(&vectors);

    // All tests should pass
    assert_eq!(
        results.failed, 0,
        "All ML-DSA test vectors should pass.\n\
         Total: {}, Passed: {}, Failed: {}\n\
         Failures: {:?}",
        results.total, results.passed, results.failed, results.failures
    );
    assert_eq!(results.passed, results.total);
}

#[test]
fn test_ml_dsa_valid_signatures_group() {
    let vectors = generate_ml_dsa_test_vectors();

    // Find the valid_signatures group
    let valid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "valid_signatures")
        .expect("Should have valid_signatures group");

    // Should have at least 5 valid signature tests
    assert!(
        valid_group.tests.len() >= 5,
        "Should have at least 5 valid signature tests, got {}",
        valid_group.tests.len()
    );

    // All tests in this group should expect "valid" result
    for test in &valid_group.tests {
        assert_eq!(
            test.result, "valid",
            "All tests in valid_signatures group should expect valid result"
        );
        assert!(
            test.flags.contains(&"valid".to_string()),
            "Valid tests should have 'valid' flag"
        );
    }
}

#[test]
fn test_ml_dsa_invalid_signatures_group() {
    let vectors = generate_ml_dsa_test_vectors();

    // Find the invalid_signatures group
    let invalid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "invalid_signatures")
        .expect("Should have invalid_signatures group");

    // Should have at least 5 invalid signature tests
    assert!(
        invalid_group.tests.len() >= 5,
        "Should have at least 5 invalid signature tests, got {}",
        invalid_group.tests.len()
    );

    // All tests in this group should expect "invalid" result
    for test in &invalid_group.tests {
        assert_eq!(
            test.result, "invalid",
            "All tests in invalid_signatures group should expect invalid result"
        );
        assert!(
            test.flags.contains(&"invalid".to_string()),
            "Invalid tests should have 'invalid' flag"
        );
    }
}

#[test]
fn test_ml_dsa_json_serialization_roundtrip() {
    // Generate test vectors
    let original = generate_ml_dsa_test_vectors();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&original).expect("JSON serialization should succeed");

    // Verify JSON is non-empty and contains expected content
    assert!(!json.is_empty(), "JSON should not be empty");
    assert!(json.contains("ML-DSA-65"), "JSON should contain algorithm name");
    assert!(
        json.contains("valid_signatures"),
        "JSON should contain valid_signatures group"
    );
    assert!(
        json.contains("invalid_signatures"),
        "JSON should contain invalid_signatures group"
    );

    // Deserialize back
    let restored: TestVectorFile =
        serde_json::from_str(&json).expect("JSON deserialization should succeed");

    // Verify structure matches
    assert_eq!(original.algorithm, restored.algorithm);
    assert_eq!(original.generator_version, restored.generator_version);
    assert_eq!(original.number_of_tests, restored.number_of_tests);
    assert_eq!(original.test_groups.len(), restored.test_groups.len());

    // Run the restored vectors
    let results = run_ml_dsa_test_vectors(&restored);

    // All restored tests should pass
    assert_eq!(
        results.failed, 0,
        "All restored ML-DSA test vectors should pass.\n\
         Total: {}, Passed: {}, Failed: {}\n\
         Failures: {:?}",
        results.total, results.passed, results.failed, results.failures
    );
}

#[test]
fn test_ml_dsa_test_vector_fields() {
    let vectors = generate_ml_dsa_test_vectors();

    for group in &vectors.test_groups {
        for test in &group.tests {
            // All tests should have tc_id
            assert!(test.tc_id > 0, "tc_id should be positive");

            // All tests should have a comment
            assert!(!test.comment.is_empty(), "comment should not be empty");

            // All tests should have at least one flag
            assert!(!test.flags.is_empty(), "flags should not be empty");

            // All tests should have a public key for signature tests
            assert!(test.pk.is_some(), "pk should be present for signature tests");

            // All tests should have a signature
            assert!(test.sig.is_some(), "sig should be present for signature tests");

            // Result should be either "valid" or "invalid"
            assert!(
                test.result == "valid" || test.result == "invalid",
                "result should be 'valid' or 'invalid', got '{}'",
                test.result
            );

            // Verify hex encoding is valid
            let pk = test.pk.as_ref().unwrap();
            assert!(
                hex::decode(pk).is_ok(),
                "pk should be valid hex encoding"
            );

            let sig = test.sig.as_ref().unwrap();
            assert!(
                hex::decode(sig).is_ok(),
                "sig should be valid hex encoding"
            );

            assert!(
                hex::decode(&test.msg).is_ok(),
                "msg should be valid hex encoding"
            );
        }
    }
}

#[test]
fn test_ml_dsa_edge_cases() {
    let vectors = generate_ml_dsa_test_vectors();

    let valid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "valid_signatures")
        .expect("Should have valid_signatures group");

    // Check for specific edge cases
    let has_empty_message = valid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"empty_message".to_string()));
    assert!(has_empty_message, "Should have empty message test case");

    let has_large_message = valid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"large_message".to_string()));
    assert!(has_large_message, "Should have large message test case");

    let has_single_byte = valid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"single_byte".to_string()));
    assert!(has_single_byte, "Should have single byte message test case");

    let has_all_zeros = valid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"all_zeros".to_string()));
    assert!(has_all_zeros, "Should have all zeros message test case");
}

#[test]
fn test_ml_dsa_invalid_cases() {
    let vectors = generate_ml_dsa_test_vectors();

    let invalid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "invalid_signatures")
        .expect("Should have invalid_signatures group");

    // Check for specific invalid cases
    let has_tampered_signature = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"tampered_signature".to_string()));
    assert!(
        has_tampered_signature,
        "Should have tampered signature test case"
    );

    let has_tampered_message = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"tampered_message".to_string()));
    assert!(
        has_tampered_message,
        "Should have tampered message test case"
    );

    let has_wrong_key = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"wrong_key".to_string()));
    assert!(has_wrong_key, "Should have wrong key test case");

    let has_truncated = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"truncated_signature".to_string()));
    assert!(has_truncated, "Should have truncated signature test case");

    let has_zero_sig = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"zero_signature".to_string()));
    assert!(has_zero_sig, "Should have all-zero signature test case");
}
