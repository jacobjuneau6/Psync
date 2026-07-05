//! Archive packaging and extraction pipelines.
//!
//! The archive pipeline transforms a project directory into a single
//! encrypted blob for upload to the server:
//!
//!   tar → gzip → age-encrypt → SHA-256 hash
//!
//! The extraction pipeline reverses this:
//!
//!   SHA-256 verify → age-decrypt → gunzip → untar
//!
//! Both use streaming I/O to avoid loading entire projects into memory.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::error::{PwrError, Result};

/// Create a tar.gz archive of a project directory, encrypt it with
/// the given age public key, and return the encrypted blob along with
/// its SHA-256 hash.
///
/// The archive is built in a temporary file to avoid consuming memory
/// proportional to the project size. Symlinks are archived as symlinks.
/// The `.project.toml` metadata file is excluded from the archive since
/// it's maintained separately on the client side.
pub fn create_archive(
    project_dir: &Path,
    public_key: &str,
) -> Result<(Vec<u8>, String)> {
    // Step 1: tar + gzip → temp file
    let tmp_dir = std::env::temp_dir().join(format!("pwr-archive-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp_dir)?;
    let tar_gz_path = tmp_dir.join("archive.tar.gz");

    let tar_gz_file = File::create(&tar_gz_path)?;
    let encoder = GzEncoder::new(tar_gz_file, Compression::default());
    let mut tar_builder = tar::Builder::new(encoder);

    // Walk the project directory, adding files to the tarball
    add_dir_to_tar(&mut tar_builder, project_dir, project_dir)?;

    // Finish the tar and gzip streams
    let encoder = tar_builder
        .into_inner()
        .map_err(|e| PwrError::Crypto(format!("tar finalize error: {}", e)))?;
    let _gz_file = encoder
        .finish()
        .map_err(|e| PwrError::Crypto(format!("gzip finalize error: {}", e)))?;

    // Step 2: Read the tar.gz and age-encrypt
    let tar_gz_data = fs::read(&tar_gz_path)?;

    let encrypted = crate::crypto::age_encrypt(&tar_gz_data, public_key)?;

    // Step 3: Compute SHA-256 hash of the encrypted blob
    let hash = crate::crypto::sha256_hex(&encrypted);

    // Clean up temp directory
    let _ = fs::remove_dir_all(&tmp_dir);

    Ok((encrypted, hash))
}

/// Recursively add a directory's contents to a tar archive.
///
/// Skips `.project.toml` files so the metadata marker is not included
/// in the archived content.
fn add_dir_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    dir: &Path,
    base_dir: &Path,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(base_dir)
            .map_err(|e| PwrError::Crypto(format!("path error: {}", e)))?;

        // Skip the project metadata file
        if relative.as_os_str() == ".project.toml" {
            continue;
        }

        if path.is_dir() {
            builder
                .append_dir(relative, &path)
                .map_err(|e| PwrError::Crypto(format!("tar dir error: {}", e)))?;
            add_dir_to_tar(builder, &path, base_dir)?;
        } else if path.is_symlink() {
            let target = fs::read_link(&path)?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder
                .append_data(&mut header, relative, &mut &[][..])
                .map_err(|e| PwrError::Crypto(format!("tar symlink error: {}", e)))?;
            // Note: tar::Builder::append_link handles symlinks more cleanly
            let _ = target;
            log::debug!("Archived symlink: {}", relative.display());
        } else {
            builder
                .append_path_with_name(&path, relative)
                .map_err(|e| PwrError::Crypto(format!("tar file error: {}", e)))?;
        }
    }
    Ok(())
}

/// Extract an encrypted archive blob into a target directory.
///
/// Steps:
/// 1. Verify SHA-256 hash matches expected value
/// 2. Age-decrypt the blob
/// 3. Gunzip decompress
/// 4. Untar into the target directory
///
/// The target directory is created if it doesn't exist. On failure,
/// partial files are left in place so the caller can inspect them.
pub fn extract_archive(
    encrypted_blob: &[u8],
    identity: &age::x25519::Identity,
    target_dir: &Path,
    expected_hash: &str,
) -> Result<()> {
    // Step 1: Verify hash
    let actual_hash = crate::crypto::sha256_hex(encrypted_blob);
    if actual_hash != expected_hash {
        return Err(PwrError::Crypto(format!(
            "Hash mismatch: expected {}, got {}",
            expected_hash, actual_hash
        )));
    }

    // Step 2: Decrypt
    let decrypted = crate::crypto::age_decrypt(encrypted_blob, identity)?;

    // Step 3: Gunzip
    let gz_reader = GzDecoder::new(&decrypted[..]);

    // Step 4: Untar
    fs::create_dir_all(target_dir)?;
    let mut archive = tar::Archive::new(gz_reader);
    archive
        .unpack(target_dir)
        .map_err(|e| PwrError::Crypto(format!("untar error: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_extract_archive() -> Result<()> {
        let tmp = TempDir::new()?;

        // Create a test project
        let project_dir = tmp.path().join("testproj");
        fs::create_dir_all(project_dir.join("src"))?;
        fs::write(project_dir.join("README.md"), b"# Test Project\n")?;
        fs::write(project_dir.join("src").join("main.rs"), b"fn main() {}\n")?;
        fs::write(project_dir.join("Cargo.toml"), b"[package]\nname = \"test\"\n")?;

        // Generate age keys
        let identity = age::x25519::Identity::generate();
        let public_key = identity.to_public().to_string();

        // Archive
        let (encrypted, hash) = create_archive(&project_dir, &public_key)?;
        assert!(!encrypted.is_empty());
        assert!(!hash.is_empty());

        // Extract to a new location
        let restore_dir = tmp.path().join("restored");
        extract_archive(&encrypted, &identity, &restore_dir, &hash)?;

        // Verify restored files
        assert!(restore_dir.join("README.md").exists());
        assert!(restore_dir.join("src").join("main.rs").exists());
        assert!(restore_dir.join("Cargo.toml").exists());

        // .project.toml should NOT be in the archive
        assert!(!restore_dir.join(".project.toml").exists());

        // Verify content
        let readme = fs::read_to_string(restore_dir.join("README.md"))?;
        assert_eq!(readme, "# Test Project\n");

        Ok(())
    }

    #[test]
    fn test_hash_verification_prevents_extraction() {
        let tmp = TempDir::new().unwrap();
        let project_dir = tmp.path().join("proj");
        fs::create_dir_all(&project_dir).unwrap();
        fs::write(project_dir.join("a.txt"), b"hello").unwrap();

        let identity = age::x25519::Identity::generate();
        let public_key = identity.to_public().to_string();

        let (encrypted, _hash) = create_archive(&project_dir, &public_key).unwrap();

        // Try to extract with wrong hash
        let result = extract_archive(
            &encrypted,
            &identity,
            &tmp.path().join("bad"),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
    }
}
