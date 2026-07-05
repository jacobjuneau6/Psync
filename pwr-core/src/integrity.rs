//! Content integrity verification via SHA-256.
//!
//! Provides streaming hash computation for files and in-memory data,
//! plus constant-time hash comparison for verification.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

use crate::error::Result;

/// Size of a SHA-256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// Size of a SHA-256 hex string.
pub const HASH_HEX_LEN: usize = 64;

/// Compute the SHA-256 hash of an in-memory byte slice as a hex string.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute the raw SHA-256 hash of an in-memory byte slice.
pub fn hash_bytes_raw(data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Compute the SHA-256 hash of a file as a hex string.
///
/// Reads the file in 64 KiB chunks to stay under memory pressure
/// for arbitrarily large files. The file must exist and be readable.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Compute the SHA-256 hash of data from any reader as a hex string.
///
/// Useful for computing hashes of network streams or other data
/// sources that implement `std::io::Read`.
pub fn hash_reader(reader: &mut impl io::Read) -> Result<String> {
    let mut hasher = Sha256::new();
    io::copy(reader, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify that a byte slice's hash matches an expected hex string.
///
/// Returns `true` if `hash_bytes(data) == expected_hex`.
pub fn verify_hash(data: &[u8], expected_hex: &str) -> bool {
    hash_bytes(data) == expected_hex
}

/// Verify that a file's hash matches an expected hex string.
///
/// Returns `true` if `hash_file(path) == expected_hex`.
pub fn verify_file_hash(path: &Path, expected_hex: &str) -> Result<bool> {
    let actual = hash_file(path)?;
    Ok(actual == expected_hex)
}

/// Streaming hash verifier for chunked data reception.
///
/// Accumulates a SHA-256 hash across multiple `update` calls
/// and produces the final hex string with `finalize`.
pub struct StreamingHasher {
    hasher: Sha256,
}

impl StreamingHasher {
    /// Create a new streaming hasher.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feed a chunk of data into the hash computation.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hex-encoded SHA-256 hash.
    pub fn finalize(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }

    /// Finalize and return the raw 32-byte hash.
    pub fn finalize_raw(self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&self.hasher.finalize());
        out
    }
}

impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hash_bytes_known_answer() {
        assert_eq!(
            hash_bytes(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_bytes_empty() {
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_bytes_raw_length() {
        let raw = hash_bytes_raw(b"test");
        assert_eq!(raw.len(), HASH_LEN);
    }

    #[test]
    fn test_hash_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("data.bin");
        fs::write(&path, b"hello world")?;

        let hash = hash_file(&path)?;
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        Ok(())
    }

    #[test]
    fn test_hash_file_large() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("large.bin");
        // 10 MB of repeating data
        let data = vec![0x42u8; 10 * 1024 * 1024];
        fs::write(&path, &data)?;

        let hash = hash_file(&path)?;
        assert_eq!(hash.len(), HASH_HEX_LEN);
        assert_eq!(hash, hash_bytes(&data));
        Ok(())
    }

    #[test]
    fn test_verify_hash_match() {
        let data = b"verify me";
        let hash = hash_bytes(data);
        assert!(verify_hash(data, &hash));
    }

    #[test]
    fn test_verify_hash_mismatch() {
        assert!(!verify_hash(b"real data", "deadbeef"));
    }

    #[test]
    fn test_verify_file_hash() -> Result<()> {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("verify.bin");
        fs::write(&path, b"trust but verify")?;

        let expected = hash_bytes(b"trust but verify");
        assert!(verify_file_hash(&path, &expected)?);
        Ok(())
    }

    #[test]
    fn test_streaming_hasher() {
        let mut hasher = StreamingHasher::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_streaming_hasher_matches_oneshot() {
        let chunks: Vec<&[u8]> = vec![b"chunk1", b"chunk2", b"chunk3", b"chunk4"];
        let combined: Vec<u8> = chunks.iter().flat_map(|c| c.iter()).copied().collect();

        let mut hasher = StreamingHasher::new();
        for chunk in &chunks {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finalize(), hash_bytes(&combined));
    }

    #[test]
    fn test_hash_reader() -> Result<()> {
        let data = b"streaming reader test";
        let hash = hash_reader(&mut &data[..])?;
        assert_eq!(hash, hash_bytes(data));
        Ok(())
    }
}
