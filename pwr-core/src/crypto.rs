//! Cryptographic operations: key management, encryption, hashing.
//! Stub — full implementation in commits 14-16.

use crate::error::Result;

/// Generate a random 256-bit pre-shared key for client-server authentication.
pub fn generate_psk() -> [u8; 32] {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key).expect("CSPRNG failure");
    key
}

/// Derive a project-specific encryption key from the master PSK.
/// Uses HKDF-SHA256 with the project UUID as the info parameter.
pub fn derive_project_key(_psk: &[u8; 32], _project_uuid: &uuid::Uuid) -> Result<[u8; 32]> {
    // Stub — full HKDF implementation in commit 14
    Ok([0u8; 32])
}
