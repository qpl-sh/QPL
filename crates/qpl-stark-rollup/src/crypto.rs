// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cryptographic integration layer.
//!
//! Provides hash commitment functions and ML-DSA signature verification
//! for the rollup. Uses qpl-crypto for post-quantum operations.

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash commitment for a transaction
pub fn transaction_commitment(tx_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tx_bytes);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute Merkle root from a list of leaf hashes (simple binary tree)
///
/// Uses SHA-256 for internal node hashing. If the number of leaves
/// is odd, the last leaf is duplicated.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to even length
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    if !current_level.len().is_multiple_of(2) {
        current_level.push(*current_level.last().unwrap());
    }

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            next_level.push(hash);
        }
        current_level = next_level;
        if current_level.len() > 1 && !current_level.len().is_multiple_of(2) {
            current_level.push(*current_level.last().unwrap());
        }
    }

    current_level[0]
}

/// Verify an ML-DSA signature for a transaction
///
/// # Arguments
/// * `sender_pk_bytes` - The sender's ML-DSA public key bytes
/// * `message` - The message that was signed
/// * `signature_bytes` - The ML-DSA signature bytes
///
/// # Returns
/// * `Ok(true)` if the signature is valid
/// * `Ok(false)` if the signature is invalid
/// * `Err(...)` if there was an error parsing keys or signature
pub fn verify_transaction_signature(
    sender_pk_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let pk = qpl_crypto::ml_dsa::MlDsaPublicKey::from_bytes(sender_pk_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let sig = qpl_crypto::ml_dsa::MlDsaSignature::from_bytes(signature_bytes)
        .map_err(|e| format!("Invalid signature: {}", e))?;
    qpl_crypto::ml_dsa::verify(&pk, message, &sig).map_err(|e| format!("Verification error: {}", e))
}

/// Hash data using SHA-256
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Concatenate and hash multiple byte slices
pub fn hash_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_commitment_consistency() {
        let data = b"test transaction data";
        let hash1 = transaction_commitment(data);
        let hash2 = transaction_commitment(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_transaction_commitment_different_inputs() {
        let data1 = b"transaction 1";
        let data2 = b"transaction 2";
        let hash1 = transaction_commitment(data1);
        let hash2 = transaction_commitment(data2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_merkle_root_empty() {
        let leaves: Vec<[u8; 32]> = vec![];
        let root = compute_merkle_root(&leaves);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = [42u8; 32];
        let leaves = vec![leaf];
        let root = compute_merkle_root(&leaves);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaves = vec![leaf1, leaf2];
        let root = compute_merkle_root(&leaves);

        // Manually compute expected root
        let mut hasher = Sha256::new();
        hasher.update(leaf1);
        hasher.update(leaf2);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_four_leaves() {
        let leaves: Vec<[u8; 32]> = (1..=4).map(|i| [i as u8; 32]).collect();
        let root = compute_merkle_root(&leaves);

        // Should be non-zero
        assert_ne!(root, [0u8; 32]);

        // Same input should produce same output
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_root_odd_leaves() {
        // 3 leaves should work (last one duplicated)
        let leaves: Vec<[u8; 32]> = (1..=3).map(|i| [i as u8; 32]).collect();
        let root = compute_merkle_root(&leaves);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);

        // Known SHA-256 hash of "hello world"
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hash_concat() {
        let part1 = b"hello ";
        let part2 = b"world";
        let combined_hash = hash_concat(&[part1, part2]);

        // Should equal hash of "hello world"
        let direct_hash = sha256_hash(b"hello world");
        assert_eq!(combined_hash, direct_hash);
    }

    #[test]
    fn test_verify_transaction_signature_integration() {
        // Generate a keypair
        let keypair =
            qpl_crypto::ml_dsa::generate_keypair().expect("Key generation should succeed");

        // Create a message (simulating transaction data)
        let message = b"sender:abc receiver:xyz amount:100 nonce:1";

        // Sign it
        let signature = keypair.sign(message).expect("Signing should succeed");

        // Verify using our function
        let result = verify_transaction_signature(
            keypair.public_key().as_bytes(),
            message,
            signature.as_bytes(),
        );

        assert!(result.is_ok());
        assert!(result.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_verify_transaction_signature_wrong_message() {
        let keypair =
            qpl_crypto::ml_dsa::generate_keypair().expect("Key generation should succeed");
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = keypair.sign(message).expect("Signing should succeed");

        let result = verify_transaction_signature(
            keypair.public_key().as_bytes(),
            wrong_message,
            signature.as_bytes(),
        );

        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Signature should be invalid for wrong message"
        );
    }

    #[test]
    fn test_verify_transaction_signature_invalid_public_key() {
        let keypair =
            qpl_crypto::ml_dsa::generate_keypair().expect("Key generation should succeed");
        let message = b"test message";
        let signature = keypair.sign(message).expect("Signing should succeed");

        // Use invalid public key bytes
        let invalid_pk = vec![0u8; 100]; // Wrong length

        let result = verify_transaction_signature(&invalid_pk, message, signature.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_transaction_signature_invalid_signature() {
        let keypair =
            qpl_crypto::ml_dsa::generate_keypair().expect("Key generation should succeed");
        let message = b"test message";

        // Use invalid signature bytes
        let invalid_sig = vec![0u8; 100]; // Wrong length

        let result =
            verify_transaction_signature(keypair.public_key().as_bytes(), message, &invalid_sig);
        assert!(result.is_err());
    }
}
