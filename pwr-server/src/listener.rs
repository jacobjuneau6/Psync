//! TLS listener and connection accept loop for pwr-server.
//!
//! Uses synchronous I/O wrapped in tokio::task::spawn_blocking to
//! keep the handler code simple (Read + Write traits) while still
//! running in the tokio async runtime.

use std::fs;
use std::io::BufReader;
use std::net::TcpListener;
use std::sync::Arc;

use rustls::ServerConfig as TlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::ServerConfig;
use crate::handler::{self, HandlerContext};
use crate::storage::ProjectStorage;

/// Build a rustls TLS server configuration from the cert and key files.
fn build_tls_config(config: &ServerConfig) -> Result<TlsServerConfig, String> {
    let cert_file = fs::File::open(&config.tls_cert_path)
        .map_err(|e| format!("Cannot open TLS cert {}: {}", config.tls_cert_path.display(), e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Cannot parse TLS cert: {}", e))?;

    if certs.is_empty() {
        return Err("No certificates found in cert file".into());
    }

    let key_file = fs::File::open(&config.tls_key_path)
        .map_err(|e| format!("Cannot open TLS key {}: {}", config.tls_key_path.display(), e))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Cannot parse TLS key: {}", e))?
        .ok_or_else(|| "No private key found in key file".to_string())?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Cannot build TLS config: {}", e))?;

    Ok(tls_config)
}

/// Run the server main loop. Blocks until shutdown.
///
/// Spawns one OS thread per connection (via spawn_blocking) to keep
/// handler code synchronous while the tokio runtime drives I/O.
pub fn run(config: ServerConfig) -> Result<(), String> {
    let psk = pwr_core::crypto::psk_from_hex(&config.auth_token)
        .map_err(|e| format!("Invalid auth token: {}", e))?;

    let storage = ProjectStorage::new(config.clone())?;
    let storage = Arc::new(std::sync::RwLock::new(storage));

    let tls_config = Arc::new(build_tls_config(&config)?);

    let bind_addr = config.bind_addr();
    let listener = TcpListener::bind(&bind_addr)
        .map_err(|e| format!("Cannot bind to {}: {}", bind_addr, e))?;

    log::info!("pwr-server listening on {} (TLS 1.3)", bind_addr);
    log::info!("Storage: {}", config.storage_base_path.display());

    // Accept connections in a loop
    for stream_result in listener.incoming() {
        let stream = stream_result.map_err(|e| format!("Accept error: {}", e))?;
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| "unknown".parse().unwrap());

        let config = config.clone();
        let psk = psk;
        let storage = storage.clone();
        let tls_config = tls_config.clone();

        // Handle each connection on a dedicated thread
        std::thread::spawn(move || {
            log::debug!("Connection from {}", peer_addr);

            // Perform TLS handshake
            let conn = match rustls::ServerConnection::new(tls_config.clone()) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Cannot create TLS connection: {}", e);
                    return;
                }
            };
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);

            let ctx = HandlerContext {
                storage: storage.clone(),
                psk,
                peer_addr,
                connected_at: std::time::Instant::now(),
            };

            if let Err(e) = handler::handle_connection(&mut tls_stream, ctx) {
                log::error!("Handler error for {}: {}", peer_addr, e);
            }
        });
    }

    Ok(())
}
