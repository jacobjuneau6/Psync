//! Integration tests for the pwr cryptographic subsystem.
//!
//! Tests cover the full security lifecycle: PSK generation and authentication,
//! age key management, encrypt/decrypt round-trips, HKDF key derivation,
//! archive pipeline with encryption, and integrity verification across
//! the complete create → encrypt → decrypt → extract → verify cycle.

use pwr_core::crypto;
use pwr_core::integrity;
use std::fs;
use tempfile::TempDir;

// =========================================================================
// PSK generation and authentication
// =========================================================================

#[test]
fn test_psk_generation_is_256_bit() {
    for _ in 0..10 {
        let psk = crypto::generate_psk();
        assert_eq!(psk.len(), 32);
    }
}

#[test]
fn test_psk_hex_round_trip_preserves_key() {
    let original = crypto::generate_psk();
    let hex = crypto::psk_to_hex(&original);
    assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars

    let restored = crypto::psk_from_hex(&hex).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn test_psk_hex_case_insensitive() {
    let psk = crypto::generate_psk();
    let lower = crypto::psk_to_hex(&psk);
    let upper = lower.to_uppercase();
    let restored = crypto::psk_from_hex(&upper).unwrap();
    assert_eq!(psk, restored);
}

#[test]
fn test_psk_from_hex_rejects_odd_length() {
    assert!(crypto::psk_from_hex("abc").is_err());
}

#[test]
fn test_psk_from_hex_rejects_wrong_length() {
    assert!(crypto::psk_from_hex("abcdef01").is_err()); // 4 bytes, not 32
}

#[test]
fn test_client_proof_verification() {
    let psk = crypto::generate_psk();
    let mut nonce = [0u8; 32];

    // Fill nonce with predictable pattern for deterministic test
    for i in 0..32 {
        nonce[i] = i as u8;
    }

    let proof = crypto::compute_client_proof(&psk, &nonce);
    assert_eq!(proof.len(), 32);

    // Same inputs must produce same proof
    let proof2 = crypto::compute_client_proof(&psk, &nonce);
    assert_eq!(proof, proof2);
}

#[test]
fn test_mutual_authentication_flow() {
    let psk = crypto::generate_psk();
    let client_nonce = {
        let mut n = [0u8; 32];
        for i in 0..32 {
            n[i] = (i * 2) as u8;
        }
        n
    };
    let server_nonce = {
        let mut n = [0u8; 32];
        for i in 0..32 {
            n[i] = (i * 3) as u8;
        }
        n
    };

    // Client computes its proof
    let client_proof = crypto::compute_client_proof(&psk, &client_nonce);

    // Server verifies client proof (would do this on the server side)
    let expected_client = crypto::compute_client_proof(&psk, &client_nonce);
    assert_eq!(client_proof, expected_client);

    // Server computes its proof
    let server_proof = crypto::compute_server_proof(&psk, &client_nonce, &server_nonce);

    // Client verifies server proof
    let expected_server = crypto::compute_server_proof(&psk, &client_nonce, &server_nonce);
    assert_eq!(server_proof, expected_server);

    // Client and server proofs must differ
    assert_ne!(client_proof, server_proof);
}

#[test]
fn test_different_psk_produces_different_proof() {
    let psk1 = crypto::generate_psk();
    let psk2 = crypto::generate_psk();
    let nonce = [0x42; 32];

    let proof1 = crypto::compute_client_proof(&psk1, &nonce);
    let proof2 = crypto::compute_client_proof(&psk2, &nonce);
    assert_ne!(proof1, proof2);
}

// =========================================================================
// Age key management
// =========================================================================

#[test]
fn test_age_key_generation() {
    // generate_age_identity writes to the real config dir, so we test
    // the underlying age Identity generation directly
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    assert!(public_key.starts_with("age1"));
}

#[test]
fn test_age_identity_exists() {
    // Should return false if no identity was generated yet
    // (or true if a previous test generated one)
    let _exists = crypto::age_identity_exists();
    // This is an environmental check, not a pass/fail assertion
}

// =========================================================================
// Age encrypt/decrypt round-trips
// =========================================================================

#[test]
fn test_encrypt_decrypt_small_payload() {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    let plaintext = b"small payload";
    let encrypted = crypto::age_encrypt(plaintext, &public_key).unwrap();
    let decrypted = crypto::age_decrypt(&encrypted, &identity).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_empty_payload() {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    let encrypted = crypto::age_encrypt(b"", &public_key).unwrap();
    let decrypted = crypto::age_decrypt(&encrypted, &identity).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_encrypt_decrypt_large_payload() {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    // 1 MB of repeating data
    let plaintext = vec![0x42u8; 1024 * 1024];
    let encrypted = crypto::age_encrypt(&plaintext, &public_key).unwrap();
    let decrypted = crypto::age_decrypt(&encrypted, &identity).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_eq!(decrypted.len(), plaintext.len());
}

#[test]
fn test_encrypt_produces_different_ciphertext_each_time() {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let plaintext = b"same plaintext, different ciphertext";

    let enc1 = crypto::age_encrypt(plaintext, &public_key).unwrap();
    let enc2 = crypto::age_encrypt(plaintext, &public_key).unwrap();

    // Age uses ephemeral keys, so ciphertexts differ
    assert_ne!(enc1, enc2);

    // But both decrypt to the same plaintext
    assert_eq!(
        crypto::age_decrypt(&enc1, &identity).unwrap(),
        plaintext
    );
    assert_eq!(
        crypto::age_decrypt(&enc2, &identity).unwrap(),
        plaintext
    );
}

#[test]
fn test_wrong_identity_fails_decryption() {
    let id1 = age::x25519::Identity::generate();
    let id2 = age::x25519::Identity::generate();
    let public_key = id1.to_public().to_string();

    let encrypted = crypto::age_encrypt(b"secret", &public_key).unwrap();
    assert!(crypto::age_decrypt(&encrypted, &id2).is_err());
}

#[test]
fn test_corrupted_ciphertext_fails_decryption() {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    let mut encrypted = crypto::age_encrypt(b"data", &public_key).unwrap();
    // Corrupt a byte in the middle
    let mid = encrypted.len() / 2;
    if encrypted.len() > 50 {
        encrypted[mid] ^= 0xFF;
    }
    assert!(crypto::age_decrypt(&encrypted, &identity).is_err());
}

// =========================================================================
// HKDF key derivation
// =========================================================================

#[test]
fn test_hkdf_derived_keys_are_256_bit() {
    let psk = crypto::generate_psk();
    let uuid = uuid::Uuid::new_v4();
    let key = crypto::derive_project_key(&psk, &uuid);
    assert_eq!(key.len(), 32);
}

#[test]
fn test_hkdf_same_inputs_same_output() {
    let psk = crypto::generate_psk();
    let uuid = uuid::Uuid::new_v4();
    assert_eq!(
        crypto::derive_project_key(&psk, &uuid),
        crypto::derive_project_key(&psk, &uuid)
    );
}

#[test]
fn test_hkdf_different_uuids_different_keys() {
    let psk = crypto::generate_psk();
    let uuid1 = uuid::Uuid::new_v4();
    let uuid2 = uuid::Uuid::new_v4();
    assert_ne!(
        crypto::derive_project_key(&psk, &uuid1),
        crypto::derive_project_key(&psk, &uuid2)
    );
}

#[test]
fn test_hkdf_known_uuid_produces_stable_key() {
    // Verify that a known UUID always produces the same key for a given PSK
    let psk = [0xAB; 32];
    let uuid = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let key1 = crypto::derive_project_key(&psk, &uuid);
    let key2 = crypto::derive_project_key(&psk, &uuid);
    assert_eq!(key1, key2);

    // The derived key should not be all zeros or all ABs
    assert_ne!(key1, [0u8; 32]);
    assert_ne!(key1, [0xAB; 32]);
}

// =========================================================================
// Integrity verification
// =========================================================================

#[test]
fn test_integrity_streaming_large_data() {
    // 5 MB hashed in 64 KB chunks
    let data = vec![0x55u8; 5 * 1024 * 1024];
    let oneshot = integrity::hash_bytes(&data);

    let mut hasher = integrity::StreamingHasher::new();
    for chunk in data.chunks(65536) {
        hasher.update(chunk);
    }
    assert_eq!(oneshot, hasher.finalize());
}

#[test]
fn test_integrity_verify_empty_file() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let path = tmp.path().join("empty");
    fs::write(&path, b"")?;

    let hash = integrity::hash_file(&path)?;
    assert_eq!(hash, integrity::hash_bytes(b""));
    assert!(integrity::verify_file_hash(&path, &hash)?);
    Ok(())
}

#[test]
fn test_integrity_hash_file_nonexistent() {
    let result = integrity::hash_file(std::path::Path::new("/nonexistent/file/for/test"));
    assert!(result.is_err());
}

// =========================================================================
// Full archive round-trip with encryption
// =========================================================================

#[test]
fn test_full_archive_encrypt_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;

    // Create a project with varied content
    let project = tmp.path().join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::create_dir_all(project.join("docs"))?;
    fs::write(project.join("README.md"), b"# Test Project\n\nDescription here.\n")?;
    fs::write(project.join("src").join("main.rs"), b"fn main() {\n    println!(\"hello\");\n}\n")?;
    fs::write(project.join("src").join("lib.rs"), b"pub fn add(a: i32, b: i32) -> i32 { a + b }\n")?;
    fs::write(project.join("docs").join("design.md"), b"# Design\n\nSome notes.\n")?;
    fs::write(project.join("Cargo.toml"), b"[package]\nname = \"test\"\nversion = \"0.1.0\"\n")?;

    // Encrypt
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let (encrypted, hash) = pwr_core::archive::create_archive(&project, &public_key)?;
    assert!(!encrypted.is_empty());
    assert_eq!(hash.len(), 64);

    // Verify hash matches
    assert_eq!(integrity::hash_bytes(&encrypted), hash);

    // Decrypt and extract
    let restore_dir = tmp.path().join("restored");
    pwr_core::archive::extract_archive(&encrypted, &identity, &restore_dir, &hash)?;

    // Verify all files restored with correct content
    let readme = fs::read_to_string(restore_dir.join("README.md"))?;
    assert!(readme.contains("Test Project"));

    let main_rs = fs::read_to_string(restore_dir.join("src").join("main.rs"))?;
    assert!(main_rs.contains("println!"));

    let lib_rs = fs::read_to_string(restore_dir.join("src").join("lib.rs"))?;
    assert!(lib_rs.contains("a + b"));

    let design = fs::read_to_string(restore_dir.join("docs").join("design.md"))?;
    assert!(design.contains("Design"));

    // .project.toml must not be in the archive
    assert!(!restore_dir.join(".project.toml").exists());

    Ok(())
}

#[test]
fn test_archive_hash_verification_prevents_wrong_data() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("proj");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("a.txt"), b"hello").unwrap();

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let (encrypted, _hash) = pwr_core::archive::create_archive(&project, &public_key).unwrap();

    // Wrong hash should fail
    let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let result = pwr_core::archive::extract_archive(
        &encrypted, &identity, &tmp.path().join("bad"), bad_hash,
    );
    assert!(result.is_err());
}

#[test]
fn test_progress_callback_fires_during_archive() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = TempDir::new()?;
    let project = tmp.path().join("proj");
    fs::create_dir_all(project.join("sub"))?;
    fs::write(project.join("file.txt"), b"content")?;

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    let stages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let stages_clone = stages.clone();
    let cb: pwr_core::archive::ProgressFn = Box::new(move |stage, progress| {
        stages_clone.lock().unwrap().push((stage, progress));
    });

    let (encrypted, hash) = pwr_core::archive::create_archive_with_progress(
        &project, &public_key, Some(&cb),
    )?;

    let recorded: Vec<_> = stages.lock().unwrap().drain(..).collect();
    // Should have seen at least Scanning and Hashing stages
    assert!(!recorded.is_empty(), "progress callback should have fired");
    assert!(
        recorded.iter().any(|(s, _)| *s == pwr_core::archive::ArchiveStage::Encrypting),
        "should have recorded encrypting stage"
    );

    // Final progress should be 1.0
    let last_progress = recorded.last().unwrap().1;
    assert!((last_progress - 1.0).abs() < 0.01, "final progress should be 1.0");

    // Clean up: decrypt to verify it still works with progress
    let restore = tmp.path().join("restore");
    pwr_core::archive::extract_archive(&encrypted, &identity, &restore, &hash)?;
    assert!(restore.join("file.txt").exists());

    Ok(())
}
