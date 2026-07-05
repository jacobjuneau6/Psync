//! Content integrity verification via SHA-256.
//! Stub — full implementation in commit 19.

use crate::error::Result;
use sha2::{Sha256, Digest};
use std::path::Path;

/// Compute the SHA-256 hash of a file's contents as a hex string.
pub fn hash_file(_path: &Path) -> Result<String> {
    // Stub — will be implemented in commit 19
    Ok(String::new())
}

/// Compute the SHA-256 hash of an in-memory byte slice as a hex string.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Verify that a blob's hash matches the expected value.
pub fn verify_hash(data: &[u8], expected_hex: &str) -> bool {
    hash_bytes(data) == expected_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_known_value() {
        let hash = hash_bytes(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_hash_match() {
        let data = b"test data";
        let hash = hash_bytes(data);
        assert!(verify_hash(data, &hash));
    }

    #[test]
    fn test_verify_hash_mismatch() {
        assert!(!verify_hash(b"foo", "deadbeef"));
    }
}
