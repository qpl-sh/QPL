//! Fuzz target for Ed25519 signature verification.
//!
//! Feeds arbitrary bytes as public key, message, and signature to ensure
//! no panics on invalid inputs. Uses ed25519-dalek directly since the
//! qpl-crypto agility layer doesn't expose a standalone Ed25519 verify.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};

/// Ed25519 public key is 32 bytes, signature is 64 bytes.
const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

fuzz_target!(|data: &[u8]| {
    let min_len = ED25519_PK_LEN + ED25519_SIG_LEN;
    if data.len() < min_len {
        // Exercise construction with invalid-length bytes
        if data.len() >= ED25519_PK_LEN {
            let _ = VerifyingKey::from_bytes(data[..ED25519_PK_LEN].try_into().unwrap_or(&[0u8; 32]));
        }
        return;
    }

    // Split input into public key bytes, signature bytes, and message
    let (pk_bytes, rest) = data.split_at(ED25519_PK_LEN);
    let (sig_bytes, message) = rest.split_at(ED25519_SIG_LEN);

    // Attempt to parse the public key — may fail for invalid curve points
    let pk_array: [u8; 32] = match pk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(vk) => vk,
        Err(_) => return, // Invalid public key point
    };

    // Attempt to parse the signature
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return,
    };
    let signature = Signature::from_bytes(&sig_array);

    // Call verify — must not panic regardless of content
    let _ = verifying_key.verify(message, &signature);
});
