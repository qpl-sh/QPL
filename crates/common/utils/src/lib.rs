// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared utility functions: logging, serialization, error handling.

use chrono::Utc;
use sha2::{Digest, Sha256};
use sql_types::Timestamp;

/// Generates a unique ID with the given prefix using SHA-256 of random bytes.
pub fn generate_id(prefix: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);

    let hash = hasher.finish();
    format!("{}_{:016x}", prefix, hash)
}

/// Returns the current UTC timestamp.
pub fn now() -> Timestamp {
    Utc::now()
}

/// Computes the SHA-256 hash of the given data.
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
