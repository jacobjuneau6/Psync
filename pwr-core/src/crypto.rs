//! Cryptographic operations for the pwr protocol.
//!
//! Provides three layers of security:
//! 1. **Authentication**: PSK-based HMAC-SHA256 challenge-response handshake
//! 2. **At-rest encryption**: age (X25519) encryption of project archives
//! 3. **Integrity**: SHA-256 hashing of transferred data
//!
//! The server never sees plaintext project data. Archives are encrypted
//! on the client side before upload and decrypted after download.

use age::x25519::{Identity, Recipient};
use ring::rand::SecureRandom;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::config::identity_path;
use crate::error::{PwrError, Result};

// ---------------------------------------------------------------------------
// PSK authentication (pre-shared key)
// ---------------------------------------------------------------------------

/// Generate a cryptographically random 256-bit pre-shared key.
///
/// Returns 32 bytes suitable for hex-encoding and storing in both the
/// client and server config files.
pub fn generate_psk() -> [u8; 32] {
    let rng = ring::rand::SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).expect("CSPRNG failure: cannot generate PSK");
    key
}

/// Decode a hex string to bytes.
fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i, e))
        })
        .collect()
}

/// Encode bytes as a lowercase hex string.
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a hex-encoded PSK string back to bytes.
pub fn psk_from_hex(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(hex_str)
        .map_err(|e| PwrError::Crypto(format!("invalid PSK hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(PwrError::Crypto(format!(
            "PSK must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Convert a 32-byte PSK to a hex string for storage in config files.
pub fn psk_to_hex(key: &[u8; 32]) -> String {
    encode_hex(key)
}

/// Authentication context string prevents cross-protocol attacks.
const AUTH_CONTEXT: &[u8] = b"pwr-auth-v1";

/// Compute the HMAC-SHA256 proof for the PSK handshake (client side).
///
/// Formula: HMAC-SHA256(client_nonce || AUTH_CONTEXT, PSK)
pub fn compute_client_proof(psk: &[u8; 32], client_nonce: &[u8; 32]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, psk);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(client_nonce);
    ctx.update(AUTH_CONTEXT);
    let tag = ctx.sign();
    let mut proof = [0u8; 32];
    proof.copy_from_slice(tag.as_ref());
    proof
}

/// Compute the server proof for mutual authentication.
///
/// Formula: HMAC-SHA256(client_nonce || server_nonce || AUTH_CONTEXT, PSK)
/// Including both nonces prevents replay attacks and proves the server
/// knows the shared secret.
pub fn compute_server_proof(
    psk: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, psk);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(client_nonce);
    ctx.update(server_nonce);
    ctx.update(AUTH_CONTEXT);
    let tag = ctx.sign();
    let mut proof = [0u8; 32];
    proof.copy_from_slice(tag.as_ref());
    proof
}

// ---------------------------------------------------------------------------
// Age key management (at-rest encryption)
// ---------------------------------------------------------------------------

/// Generate a new age X25519 identity and save it to disk.
///
/// The identity is stored at `~/.config/pwr/identity` with restrictive
/// file permissions (0o600 on Unix). Returns the identity and its
/// corresponding public key as a Bech32-encoded string.
pub fn generate_age_identity() -> Result<(Identity, String)> {
    let identity = Identity::generate();
    let public_key = identity.to_public().to_string();

    let path = identity_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // SecretString exposes its inner value via ExposeSecret
    use age::secrecy::ExposeSecret;
    let secret_str = identity.to_string();
    let exposed: &str = secret_str.expose_secret();
    fs::write(&path, exposed.as_bytes())?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    log::info!("Age identity saved to {}", path.display());
    Ok((identity, public_key))
}

/// Load the age identity from disk.
///
/// Returns an error if the identity file does not exist or contains
/// invalid data.
pub fn load_age_identity() -> Result<Identity> {
    let path = identity_path();
    if !path.exists() {
        return Err(PwrError::Crypto(
            "No age identity found. Run 'pwr init' to generate one.".into(),
        ));
    }

    let contents = fs::read_to_string(&path)?;
    let contents = contents.trim();

    Identity::from_str(contents)
        .map_err(|e| PwrError::Crypto(format!("Failed to parse age identity: {}", e)))
}

/// Check whether an age identity file exists on disk.
pub fn age_identity_exists() -> bool {
    identity_path().exists()
}

// ---------------------------------------------------------------------------
// Age encryption / decryption (one-shot API)
// ---------------------------------------------------------------------------

/// Encrypt data using an age X25519 public key.
///
/// Uses the one-shot `age::encrypt` function which handles the
/// full age file format including header, stanza, and body.
pub fn age_encrypt(plaintext: &[u8], public_key: &str) -> Result<Vec<u8>> {
    let recipient = Recipient::from_str(public_key)
        .map_err(|e| PwrError::Crypto(format!("Invalid age public key: {}", e)))?;

    let encryptor = age::Encryptor::with_recipients([&recipient as &dyn age::Recipient].into_iter())
        .map_err(|e| PwrError::Crypto(format!("Age encrypt setup failed: {}", e)))?;

    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| PwrError::Crypto(format!("Age encrypt wrap failed: {}", e)))?;

    std::io::copy(&mut &plaintext[..], &mut writer)
        .map_err(|e| PwrError::Crypto(format!("Age encrypt write failed: {}", e)))?;

    writer
        .finish()
        .map_err(|e| PwrError::Crypto(format!("Age encrypt finish failed: {}", e)))?;

    Ok(encrypted)
}

/// Decrypt data using an age X25519 identity.
///
/// Uses the one-shot `age::decrypt` function. If the encrypted data
/// was produced with a passphrase instead of an X25519 key, an error
/// is returned since pwr only supports key-based encryption.
pub fn age_decrypt(encrypted: &[u8], identity: &Identity) -> Result<Vec<u8>> {
    // age::decrypt is a simple one-shot function
    let decrypted = age::decrypt(identity, encrypted)
        .map_err(|e| PwrError::Crypto(format!("Age decryption failed: {}", e)))?;

    Ok(decrypted)
}

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

/// Derive a per-project encryption key from the master PSK using HKDF-SHA256.
///
/// Uses the project UUID bytes as the info parameter to bind the derived
/// key to a specific project. The same PSK and UUID always produce the
/// same 256-bit key, enabling deterministic re-derivation without storing
/// per-project keys on disk.
///
/// The key derivation uses HKDF-Expand with SHA-256, taking the PSK as
/// the initial key material and the project UUID as context info.
pub fn derive_project_key(psk: &[u8; 32], project_uuid: &uuid::Uuid) -> [u8; 32] {
    use ring::hkdf::{Salt, HKDF_SHA256};

    // Use the PSK as the salt for HKDF-Extract
    let salt = Salt::new(HKDF_SHA256, psk);
    // Use the project UUID bytes as the info for HKDF-Expand
    let info = project_uuid.as_bytes();

    // Extract + expand to produce 32 bytes of output key material
    let mut derived = [0u8; 32];
    salt.extract(&[])
        .expand(&[info], HKDF_SHA256)
        .expect("HKDF-Expand failure")
        .fill(&mut derived)
        .expect("HKDF fill failure: output length exceeds limit");

    derived
}

// ---------------------------------------------------------------------------
// SHA-256 hashing (delegates to integrity module)
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hash of a byte slice, returned as a hex string.
/// Delegates to the integrity module for the canonical implementation.
pub fn sha256_hex(data: &[u8]) -> String {
    crate::integrity::hash_bytes(data)
}

/// Compute the SHA-256 hash of a file, returned as a hex string.
/// Delegates to the integrity module for the canonical implementation.
pub fn sha256_file(path: &Path) -> Result<String> {
    crate::integrity::hash_file(path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // PSK tests
    #[test]
    fn test_generate_psk_is_random() {
        let psk1 = generate_psk();
        let psk2 = generate_psk();
        assert_ne!(psk1, psk2);
        assert_eq!(psk1.len(), 32);
    }

    #[test]
    fn test_psk_hex_round_trip() {
        let psk = generate_psk();
        let hex = psk_to_hex(&psk);
        let decoded = psk_from_hex(&hex).unwrap();
        assert_eq!(psk, decoded);
    }

    #[test]
    fn test_psk_from_hex_rejects_short() {
        assert!(psk_from_hex("abcdef").is_err());
    }

    #[test]
    fn test_client_proof_deterministic() {
        let psk = [0x42; 32];
        let nonce = [0x99; 32];
        let proof1 = compute_client_proof(&psk, &nonce);
        let proof2 = compute_client_proof(&psk, &nonce);
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_client_and_server_proofs_differ() {
        let psk = [0x42; 32];
        let c_nonce = [0x11; 32];
        let s_nonce = [0x22; 32];

        let client_proof = compute_client_proof(&psk, &c_nonce);
        let server_proof = compute_server_proof(&psk, &c_nonce, &s_nonce);
        assert_ne!(client_proof, server_proof);
    }

    // Age encryption tests
    #[test]
    fn test_age_encrypt_decrypt_round_trip() -> Result<()> {
        let identity = Identity::generate();
        let public_key = identity.to_public().to_string();

        let plaintext = b"Project archive contents - this must remain confidential at rest.";
        let encrypted = age_encrypt(plaintext, &public_key)?;
        let decrypted = age_decrypt(&encrypted, &identity)?;

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_age_encrypt_empty() -> Result<()> {
        let identity = Identity::generate();
        let public_key = identity.to_public().to_string();

        let encrypted = age_encrypt(b"", &public_key)?;
        let decrypted = age_decrypt(&encrypted, &identity)?;
        assert!(decrypted.is_empty());
        Ok(())
    }

    #[test]
    fn test_age_decrypt_wrong_identity_fails() -> Result<()> {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let public_key = id1.to_public().to_string();

        let encrypted = age_encrypt(b"secret message", &public_key)?;
        let result = age_decrypt(&encrypted, &id2);
        assert!(result.is_err());
        Ok(())
    }

    // SHA-256 tests
    #[test]
    fn test_sha256_hex_known() {
        assert_eq!(
            sha256_hex(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_file() -> Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let path = tmp.path().join("test.txt");
        fs::write(&path, b"hello world")?;

        let hash = sha256_file(&path)?;
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        Ok(())
    }

    // HKDF tests
    #[test]
    fn test_derive_project_key_deterministic() {
        let psk = [0x42; 32];
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let key1 = derive_project_key(&psk, &uuid);
        let key2 = derive_project_key(&psk, &uuid);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_project_key_different_uuids_produce_different_keys() {
        let psk = [0x42; 32];
        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();

        let key1 = derive_project_key(&psk, &uuid1);
        let key2 = derive_project_key(&psk, &uuid2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_project_key_different_psks_produce_different_keys() {
        let psk1 = [0x11; 32];
        let psk2 = [0x22; 32];
        let uuid = uuid::Uuid::new_v4();

        let key1 = derive_project_key(&psk1, &uuid);
        let key2 = derive_project_key(&psk2, &uuid);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_project_key_output_length() {
        let psk = generate_psk();
        let uuid = uuid::Uuid::new_v4();
        let key = derive_project_key(&psk, &uuid);
        assert_eq!(key.len(), 32);
    }
}
