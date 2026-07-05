//! Archive packaging and extraction pipelines.
//! Stub — full implementation in commits 17-18.

use crate::error::Result;
use std::path::Path;

/// Create an encrypted archive of a project directory.
/// Steps: tar → gzip → age-encrypt → SHA-256 hash.
/// Returns the encrypted blob and its hash.
pub fn create_archive(
    _project_dir: &Path,
    _public_key: &str,
) -> Result<(Vec<u8>, String)> {
    // Stub — will be implemented in commit 17
    Ok((Vec::new(), String::new()))
}

/// Extract an encrypted archive into a target directory.
/// Steps: SHA-256 verify → age-decrypt → gunzip → untar.
pub fn extract_archive(
    _encrypted_blob: &[u8],
    _identity_path: &Path,
    _target_dir: &Path,
    _expected_hash: &str,
) -> Result<()> {
    // Stub — will be implemented in commit 18
    Ok(())
}
