// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for ML-KEM test vectors.
//!
//! This module runs the generated ML-KEM test vectors through the runner
//! and validates that all tests pass. It also tests JSON serialization roundtrip.

use qpl_crypto::ml_kem::CIPHERTEXT_BYTES;
use qpl_crypto::vectors::{generate_ml_kem_test_vectors, run_ml_kem_test_vectors, TestVectorFile};

#[test]
fn test_ml_kem_vectors_all_pass() {
    // Generate test vectors
    let vectors = generate_ml_kem_test_vectors();

    // Verify we have the expected structure
    assert_eq!(vectors.algorithm, "ML-KEM-1024");
    assert!(!vectors.test_groups.is_empty(), "Should have test groups");
    assert!(
        vectors.number_of_tests >= 6,
        "Should have at least 6 test cases"
    );

    // Run all test vectors
    let results = run_ml_kem_test_vectors(&vectors);

    // All tests should pass
    assert_eq!(
        results.failed, 0,
        "All ML-KEM test vectors should pass.\n\
         Total: {}, Passed: {}, Failed: {}\n\
         Failures: {:?}",
        results.total, results.passed, results.failed, results.failures
    );
    assert_eq!(results.passed, results.total);
}

#[test]
fn test_ml_kem_valid_encapsulation_group() {
    let vectors = generate_ml_kem_test_vectors();

    // Find the valid_encapsulation group
    let valid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "valid_encapsulation")
        .expect("Should have valid_encapsulation group");

    // Should have at least 3 valid encapsulation tests
    assert!(
        valid_group.tests.len() >= 3,
        "Should have at least 3 valid encapsulation tests, got {}",
        valid_group.tests.len()
    );

    // All tests in this group should expect "valid" result
    for test in &valid_group.tests {
        assert_eq!(
            test.result, "valid",
            "All tests in valid_encapsulation group should expect valid result"
        );
        assert!(
            test.flags.contains(&"valid".to_string()),
            "Valid tests should have 'valid' flag"
        );
    }
}

#[test]
fn test_ml_kem_invalid_decapsulation_group() {
    let vectors = generate_ml_kem_test_vectors();

    // Find the invalid_decapsulation group
    let invalid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "invalid_decapsulation")
        .expect("Should have invalid_decapsulation group");

    // Should have at least 3 invalid decapsulation tests
    assert!(
        invalid_group.tests.len() >= 3,
        "Should have at least 3 invalid decapsulation tests, got {}",
        invalid_group.tests.len()
    );

    // All tests in this group should expect "invalid" result
    for test in &invalid_group.tests {
        assert_eq!(
            test.result, "invalid",
            "All tests in invalid_decapsulation group should expect invalid result"
        );
        assert!(
            test.flags.contains(&"invalid".to_string()),
            "Invalid tests should have 'invalid' flag"
        );
    }
}

#[test]
fn test_ml_kem_json_serialization_roundtrip() {
    // Generate test vectors
    let original = generate_ml_kem_test_vectors();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&original).expect("JSON serialization should succeed");

    // Verify JSON is non-empty and contains expected content
    assert!(!json.is_empty(), "JSON should not be empty");
    assert!(
        json.contains("ML-KEM-1024"),
        "JSON should contain algorithm name"
    );
    assert!(
        json.contains("valid_encapsulation"),
        "JSON should contain valid_encapsulation group"
    );
    assert!(
        json.contains("invalid_decapsulation"),
        "JSON should contain invalid_decapsulation group"
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
    let results = run_ml_kem_test_vectors(&restored);

    // All restored tests should pass
    assert_eq!(
        results.failed, 0,
        "All restored ML-KEM test vectors should pass.\n\
         Total: {}, Passed: {}, Failed: {}\n\
         Failures: {:?}",
        results.total, results.passed, results.failed, results.failures
    );
}

#[test]
fn test_ml_kem_test_vector_fields() {
    let vectors = generate_ml_kem_test_vectors();

    for group in &vectors.test_groups {
        for test in &group.tests {
            // All tests should have tc_id
            assert!(test.tc_id > 0, "tc_id should be positive");

            // All tests should have a comment
            assert!(!test.comment.is_empty(), "comment should not be empty");

            // All tests should have at least one flag
            assert!(!test.flags.is_empty(), "flags should not be empty");

            // KEM tests should have ciphertext
            assert!(test.ct.is_some(), "ct should be present for KEM tests");

            // KEM tests should have shared secret
            assert!(test.ss.is_some(), "ss should be present for KEM tests");

            // KEM tests should have secret key
            assert!(test.sk.is_some(), "sk should be present for KEM tests");

            // Result should be either "valid" or "invalid"
            assert!(
                test.result == "valid" || test.result == "invalid",
                "result should be 'valid' or 'invalid', got '{}'",
                test.result
            );

            // Verify hex encoding is valid
            let ct = test.ct.as_ref().unwrap();
            assert!(hex::decode(ct).is_ok(), "ct should be valid hex encoding");

            let ss = test.ss.as_ref().unwrap();
            assert!(hex::decode(ss).is_ok(), "ss should be valid hex encoding");

            let sk = test.sk.as_ref().unwrap();
            assert!(hex::decode(sk).is_ok(), "sk should be valid hex encoding");
        }
    }
}

#[test]
fn test_ml_kem_invalid_cases() {
    let vectors = generate_ml_kem_test_vectors();

    let invalid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "invalid_decapsulation")
        .expect("Should have invalid_decapsulation group");

    // Check for specific invalid cases
    let has_wrong_sk = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"wrong_secret_key".to_string()));
    assert!(has_wrong_sk, "Should have wrong secret key test case");

    let has_tampered_ct = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"tampered_ciphertext".to_string()));
    assert!(has_tampered_ct, "Should have tampered ciphertext test case");

    let has_truncated_ct = invalid_group
        .tests
        .iter()
        .any(|t| t.flags.contains(&"truncated_ciphertext".to_string()));
    assert!(
        has_truncated_ct,
        "Should have truncated ciphertext test case"
    );
}

#[test]
fn test_ml_kem_shared_secret_length() {
    let vectors = generate_ml_kem_test_vectors();

    // ML-KEM-1024 shared secrets should be 32 bytes
    for group in &vectors.test_groups {
        for test in &group.tests {
            if let Some(ss_hex) = &test.ss {
                let ss_bytes = hex::decode(ss_hex).expect("ss should be valid hex");
                assert_eq!(
                    ss_bytes.len(),
                    32,
                    "ML-KEM-1024 shared secret should be 32 bytes"
                );
            }
        }
    }
}

#[test]
fn test_ml_kem_ciphertext_length() {
    let vectors = generate_ml_kem_test_vectors();

    // Only check valid encapsulations for correct ciphertext length
    // Invalid tests may have truncated ciphertexts
    let valid_group = vectors
        .test_groups
        .iter()
        .find(|g| g.group_type == "valid_encapsulation")
        .expect("Should have valid_encapsulation group");

    for test in &valid_group.tests {
        if let Some(ct_hex) = &test.ct {
            let ct_bytes = hex::decode(ct_hex).expect("ct should be valid hex");
            assert_eq!(
                ct_bytes.len(),
                CIPHERTEXT_BYTES,
                "ML-KEM-1024 ciphertext should be {} bytes",
                CIPHERTEXT_BYTES
            );
        }
    }
}

#[test]
fn test_ml_kem_unique_test_ids() {
    let vectors = generate_ml_kem_test_vectors();

    let mut seen_ids = std::collections::HashSet::new();
    for group in &vectors.test_groups {
        for test in &group.tests {
            assert!(
                seen_ids.insert(test.tc_id),
                "Duplicate test case ID: {}",
                test.tc_id
            );
        }
    }
}
