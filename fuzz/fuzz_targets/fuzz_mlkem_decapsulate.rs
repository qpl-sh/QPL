//! Fuzz target for ML-KEM-1024 decapsulation.
//!
//! Feeds arbitrary bytes as ciphertext and secret key to verify
//! graceful handling of malformed inputs without panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qpl_crypto::ml_kem::{self, MlKemCiphertext, MlKemSecretKey, CIPHERTEXT_BYTES, SECRET_KEY_BYTES};

fuzz_target!(|data: &[u8]| {
    // We need enough bytes for a ciphertext + secret key
    let min_len = CIPHERTEXT_BYTES + SECRET_KEY_BYTES;
    if data.len() < min_len {
        // Exercise error paths with wrong-length inputs
        let _ = MlKemCiphertext::from_bytes(data);
        let _ = MlKemSecretKey::from_bytes(data);
        return;
    }

    // Split input into ciphertext bytes and secret key bytes
    let (ct_bytes, sk_bytes) = data.split_at(CIPHERTEXT_BYTES);
    let sk_bytes = &sk_bytes[..SECRET_KEY_BYTES];

    // Attempt to construct types from arbitrary bytes
    let ct = match MlKemCiphertext::from_bytes(ct_bytes) {
        Ok(ct) => ct,
        Err(_) => return,
    };

    let sk = match MlKemSecretKey::from_bytes(sk_bytes) {
        Ok(sk) => sk,
        Err(_) => return,
    };

    // Call decapsulate — must not panic regardless of content.
    // ML-KEM is IND-CCA2: wrong keys produce pseudorandom output, not errors.
    let _ = ml_kem::decapsulate(&ct, &sk);
});
