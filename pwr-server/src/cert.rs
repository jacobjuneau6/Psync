//! TLS certificate generation for pwr-server.
//!
//! Generates self-signed ECDSA P-256 certificates for TLS 1.3.
//! The certificate fingerprint is printed so the user can pin it
//! in the client config for MITM protection.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::fs;
use std::path::Path;

/// Generate a self-signed TLS certificate and private key.
///
/// Returns (cert_pem, key_pem, fingerprint_sha256).
/// The certificate is valid for 365 days from issuance.
pub fn generate_certificate(
    common_name: &str,
) -> Result<(String, String, String), String> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| format!("cert params: {}", e))?;

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;

    // Generate ECDSA P-256 key pair
    let key_pair = KeyPair::generate()
        .map_err(|e| format!("key gen: {}", e))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("self-sign: {}", e))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Compute SHA-256 fingerprint for certificate pinning
    let fingerprint = pwr_core::crypto::sha256_hex(cert_pem.as_bytes());

    Ok((cert_pem, key_pem, fingerprint))
}

/// Write certificate and key to files with appropriate permissions.
pub fn save_certificate(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), String> {
    // Create parent directories
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
    }

    // Write certificate (world-readable)
    fs::write(cert_path, cert_pem)
        .map_err(|e| format!("write cert: {}", e))?;

    // Write private key (owner-only)
    fs::write(key_path, key_pem)
        .map_err(|e| format!("write key: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(key_path)
            .map_err(|e| format!("stat key: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(key_path, perms)
            .map_err(|e| format!("chmod key: {}", e))?;
    }

    Ok(())
}

/// Generate a fresh server configuration with TLS certificates and PSK.
pub fn init_server(
    config_path: &Path,
    hostname: &str,
) -> Result<(), String> {
    use crate::config::{save_config, ServerConfig};

    let (cert_pem, key_pem, fingerprint) = generate_certificate(hostname)?;

    let cert_path = Path::new("/etc/pwr/server.crt");
    let key_path = Path::new("/etc/pwr/server.key");

    save_certificate(cert_path, key_path, &cert_pem, &key_pem)?;

    // Generate PSK
    let psk = pwr_core::crypto::generate_psk();
    let psk_hex = pwr_core::crypto::psk_to_hex(&psk);

    let mut config = ServerConfig::default();
    config.auth_token = psk_hex.clone();
    config.tls_cert_path = cert_path.to_path_buf();
    config.tls_key_path = key_path.to_path_buf();

    save_config(&config, config_path)?;

    println!("Server initialized successfully.");
    println!("  Config:     {}", config_path.display());
    println!("  Certificate: {}", cert_path.display());
    println!("  Private key: {}", key_path.display());
    println!("  PSK:        {}", psk_hex);
    println!("  Fingerprint: {}", fingerprint);
    println!();
    println!("Copy the PSK to your client config:");
    println!("  pwr init --server-host {} --psk {}", hostname, psk_hex);

    Ok(())
}
