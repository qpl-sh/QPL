// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration tests for the PKCS#11 HSM provider using SoftHSM2.
//!
//! These tests require:
//! - SoftHSM2 installed on the system
//! - The `cloudhsm` feature enabled: `cargo test --features cloudhsm`
//!
//! Environment variables (optional):
//! - `SOFTHSM2_LIB`: Path to the SoftHSM2 PKCS#11 library
//!   (defaults to common system paths)
//! - `SOFTHSM2_CONF`: Path to the SoftHSM2 config file
//!   (defaults to `tests/softhsm2.conf` in the crate root)

#![cfg(feature = "cloudhsm")]

use qpl_crypto::hsm::{HsmError, HsmProvider, KeyHandle, KeyType, Pkcs11HsmProvider};
use std::sync::Once;

static INIT: Once = Once::new();

/// Default SoftHSM2 user PIN used for test tokens.
const TEST_PIN: &str = "1234";

/// Default SoftHSM2 SO (security officer) PIN used for token initialization.
const TEST_SO_PIN: &str = "0000";

/// Token label used for test tokens.
const TEST_TOKEN_LABEL: &str = "qpl-test-token";

/// Returns the path to the SoftHSM2 PKCS#11 shared library.
///
/// Checks the `SOFTHSM2_LIB` env var first, then common system paths.
fn softhsm2_lib_path() -> String {
    if let Ok(path) = std::env::var("SOFTHSM2_LIB") {
        return path;
    }

    // Common paths across operating systems
    let candidates = [
        // Linux (Debian/Ubuntu)
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        // macOS (Homebrew)
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        // Windows (Chocolatey / manual install)
        "C:\\SoftHSM2\\lib\\softhsm2-x64.dll",
        "C:\\SoftHSM2\\lib\\softhsm2.dll",
        "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll",
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }

    // Return a default and let the test fail with a meaningful error
    "/usr/lib/softhsm/libsofthsm2.so".to_string()
}

/// Initializes the SoftHSM2 token directory and creates a test token.
///
/// This is idempotent — safe to call multiple times, but the `Once` guard
/// ensures initialization happens exactly once per test run.
fn ensure_softhsm_initialized() {
    INIT.call_once(|| {
        // Ensure the token directory exists
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let token_dir = crate_root.join("tests").join("softhsm-tokens");
        std::fs::create_dir_all(&token_dir).expect("Failed to create softhsm-tokens directory");

        // Point SoftHSM2 at our config
        let conf_path = crate_root.join("tests").join("softhsm2.conf");
        std::env::set_var("SOFTHSM2_CONF", conf_path.to_str().unwrap());

        // Initialize a test token using softhsm2-util
        let output = std::process::Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--slot",
                "0",
                "--label",
                TEST_TOKEN_LABEL,
                "--pin",
                TEST_PIN,
                "--so-pin",
                TEST_SO_PIN,
            ])
            .output();

        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);
                // Token may already exist — that's fine
                if !result.status.success()
                    && !stderr.contains("already initialized")
                    && !stderr.contains("CKR_OK")
                {
                    eprintln!(
                        "softhsm2-util init-token warning:\nstdout: {}\nstderr: {}",
                        stdout, stderr
                    );
                }
            }
            Err(e) => {
                panic!(
                    "softhsm2-util not found or failed to execute: {}.\n\
                     Install SoftHSM2 to run PKCS#11 integration tests.",
                    e
                );
            }
        }
    });
}

/// Creates a Pkcs11HsmProvider backed by SoftHSM2 for testing.
fn setup_provider() -> Pkcs11HsmProvider {
    ensure_softhsm_initialized();

    // Ensure SOFTHSM2_CONF is set (might be in a different thread after Once)
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let conf_path = crate_root.join("tests").join("softhsm2.conf");
    std::env::set_var("SOFTHSM2_CONF", conf_path.to_str().unwrap());

    let lib_path = softhsm2_lib_path();
    Pkcs11HsmProvider::new(&lib_path, 0, TEST_PIN)
        .expect("Failed to create Pkcs11HsmProvider with SoftHSM2")
}

// ============================================================================
// ML-DSA Tests
// ============================================================================

#[tokio::test]
async fn test_pkcs11_ml_dsa_keygen() {
    let hsm = setup_provider();
    let handle = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair generation should succeed");

    assert_eq!(handle.key_type(), KeyType::MlDsa);
    assert!(!handle.id().is_empty());
    assert!(handle.id().starts_with("pkcs11-"));
}

#[tokio::test]
async fn test_pkcs11_ml_dsa_sign_verify() {
    let hsm = setup_provider();
    let handle = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair generation should succeed");

    let message = b"Hello, quantum-safe PKCS#11 world!";
    let signature = hsm
        .sign(&handle, message)
        .await
        .expect("Signing should succeed");

    let is_valid = hsm
        .verify(&handle, message, &signature)
        .await
        .expect("Verification should succeed");

    assert!(is_valid, "Signature should be valid");

    // Tampered message should fail verification
    let tampered = b"Hello, tampered PKCS#11 world!";
    let is_valid_tampered = hsm
        .verify(&handle, tampered, &signature)
        .await
        .expect("Verification of tampered message should not error");

    assert!(
        !is_valid_tampered,
        "Signature should be invalid for tampered message"
    );
}

#[tokio::test]
async fn test_pkcs11_ml_dsa_sign_wrong_key() {
    let hsm = setup_provider();

    let handle_a = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair A generation should succeed");
    let handle_b = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair B generation should succeed");

    let message = b"Test message for wrong key verification";
    let signature = hsm
        .sign(&handle_a, message)
        .await
        .expect("Signing with key A should succeed");

    let is_valid = hsm
        .verify(&handle_b, message, &signature)
        .await
        .expect("Verification with key B should succeed (returns false)");

    assert!(
        !is_valid,
        "Signature from key A should not verify with key B"
    );
}

// ============================================================================
// ML-KEM Tests
// ============================================================================

#[tokio::test]
async fn test_pkcs11_ml_kem_keygen() {
    let hsm = setup_provider();
    let handle = hsm
        .generate_ml_kem_keypair()
        .await
        .expect("ML-KEM keypair generation should succeed");

    assert_eq!(handle.key_type(), KeyType::MlKem);
    assert!(!handle.id().is_empty());
    assert!(handle.id().starts_with("pkcs11-"));
}

#[tokio::test]
async fn test_pkcs11_ml_kem_encap_decap() {
    let hsm = setup_provider();
    let handle = hsm
        .generate_ml_kem_keypair()
        .await
        .expect("ML-KEM keypair generation should succeed");

    let (ciphertext, shared_secret_sender) = hsm
        .encapsulate(&handle)
        .await
        .expect("Encapsulation should succeed");

    let shared_secret_receiver = hsm
        .decapsulate(&handle, &ciphertext)
        .await
        .expect("Decapsulation should succeed");

    assert_eq!(
        shared_secret_sender.as_bytes(),
        shared_secret_receiver.as_bytes(),
        "Shared secrets from encapsulate and decapsulate must match"
    );
}

// ============================================================================
// Key Lifecycle Tests
// ============================================================================

#[tokio::test]
async fn test_pkcs11_key_deletion() {
    let hsm = setup_provider();
    let handle = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair generation should succeed");

    let message = b"Test before deletion";
    let _sig = hsm
        .sign(&handle, message)
        .await
        .expect("Signing should succeed before deletion");

    // Delete the key
    hsm.delete_key(&handle)
        .await
        .expect("Key deletion should succeed");

    // Operations with deleted handle should fail with KeyNotFound
    let sign_result = hsm.sign(&handle, message).await;
    assert!(
        matches!(sign_result, Err(HsmError::KeyNotFound(_))),
        "Signing with deleted key should return KeyNotFound, got {:?}",
        sign_result
    );

    // Deleting again should also fail
    let delete_result = hsm.delete_key(&handle).await;
    assert!(
        matches!(delete_result, Err(HsmError::KeyNotFound(_))),
        "Double-deleting should return KeyNotFound, got {:?}",
        delete_result
    );
}

#[tokio::test]
async fn test_pkcs11_invalid_handle() {
    let hsm = setup_provider();

    // Fabricate a handle that doesn't exist in the provider
    let bogus = KeyHandle::new("nonexistent-key-id".to_string(), KeyType::MlDsa);

    let sign_result = hsm.sign(&bogus, b"test").await;
    assert!(
        matches!(sign_result, Err(HsmError::KeyNotFound(_))),
        "Signing with bogus handle should return KeyNotFound, got {:?}",
        sign_result
    );

    let verify_result = hsm
        .verify(
            &bogus,
            b"test",
            &qpl_crypto::ml_dsa::MlDsaSignature::from_bytes(&[0u8; 3309]).unwrap(),
        )
        .await;
    assert!(
        matches!(verify_result, Err(HsmError::KeyNotFound(_))),
        "Verifying with bogus handle should return KeyNotFound, got {:?}",
        verify_result
    );

    let delete_result = hsm.delete_key(&bogus).await;
    assert!(
        matches!(delete_result, Err(HsmError::KeyNotFound(_))),
        "Deleting bogus handle should return KeyNotFound, got {:?}",
        delete_result
    );
}

// ============================================================================
// Wrong Key Type Tests
// ============================================================================

#[tokio::test]
async fn test_pkcs11_wrong_key_type() {
    let hsm = setup_provider();

    let dsa_handle = hsm
        .generate_ml_dsa_keypair()
        .await
        .expect("ML-DSA keypair generation should succeed");

    let kem_handle = hsm
        .generate_ml_kem_keypair()
        .await
        .expect("ML-KEM keypair generation should succeed");

    // Try to sign with a KEM key
    let sign_result = hsm.sign(&kem_handle, b"test").await;
    assert!(
        matches!(sign_result, Err(HsmError::SigningFailed(_))),
        "Signing with KEM key should fail, got {:?}",
        sign_result
    );

    // Try to encapsulate with a DSA key
    let encap_result = hsm.encapsulate(&dsa_handle).await;
    assert!(
        matches!(encap_result, Err(HsmError::EncapsulationFailed(_))),
        "Encapsulation with DSA key should fail, got {:?}",
        encap_result
    );
}

// ============================================================================
// Concurrency Test
// ============================================================================

#[tokio::test]
async fn test_pkcs11_concurrent_operations() {
    let hsm = std::sync::Arc::new(setup_provider());
    let mut handles = Vec::new();

    // Spawn 4 concurrent tasks, each doing keygen + sign + verify
    for i in 0..4u32 {
        let hsm_clone = hsm.clone();
        let handle = tokio::spawn(async move {
            let key = hsm_clone
                .generate_ml_dsa_keypair()
                .await
                .expect("Concurrent keygen should succeed");

            let message = format!("Concurrent message #{}", i);
            let sig = hsm_clone
                .sign(&key, message.as_bytes())
                .await
                .expect("Concurrent signing should succeed");

            let valid = hsm_clone
                .verify(&key, message.as_bytes(), &sig)
                .await
                .expect("Concurrent verification should succeed");

            assert!(valid, "Concurrent signature {} should verify", i);
            key
        });
        handles.push(handle);
    }

    // Await all tasks
    let keys: Vec<KeyHandle> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task should not panic"))
        .collect();

    // Verify all keys are unique
    let ids: std::collections::HashSet<&str> = keys.iter().map(|k| k.id()).collect();
    assert_eq!(ids.len(), keys.len(), "All concurrent key IDs should be unique");
}
