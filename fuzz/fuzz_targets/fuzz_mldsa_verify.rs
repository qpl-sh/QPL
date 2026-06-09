//! Fuzz target for ML-DSA-65 signature verification.
//!
//! Feeds arbitrary bytes as public key, message, and signature to ensure
//! the verification path never panics on malformed inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qpl_crypto::ml_dsa::{self, MlDsaPublicKey, MlDsaSignature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

fuzz_target!(|data: &[u8]| {
    // We need at least enough bytes for a public key + signature + 1 byte message
    let min_len = PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH;
    if data.len() < min_len {
        // Try with whatever bytes we have using from_bytes (will likely fail on length check)
        // This exercises the error path
        let _ = MlDsaPublicKey::from_bytes(data);
        let _ = MlDsaSignature::from_bytes(data);
        return;
    }

    // Split input into public key bytes, signature bytes, and message
    let (pk_bytes, rest) = data.split_at(PUBLIC_KEY_LENGTH);
    let (sig_bytes, message) = rest.split_at(SIGNATURE_LENGTH);

    // Attempt to construct types from arbitrary bytes
    let pk = match MlDsaPublicKey::from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return, // Length mismatch is expected for some inputs
    };

    let sig = match MlDsaSignature::from_bytes(sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return,
    };

    // Call verify — must not panic regardless of content
    let _ = ml_dsa::verify(&pk, message, &sig);
});
