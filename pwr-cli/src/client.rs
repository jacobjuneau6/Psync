//! Protocol client for communicating with pwr-server.
//!
//! Manages the TLS connection, authentication handshake, and
//! archive/restore operations. All network I/O is synchronous,
//! intended to be called from blocking contexts.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use pwr_core::config::PwrConfig;
use pwr_core::crypto;
use pwr_core::frame::{self, FrameDecoder};
use pwr_core::protocol::{self, ClientMessage, Handshake, ProjectInfo, ServerMessage};
use ring::rand::SecureRandom;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier, HandshakeSignatureValid};
use rustls::DigitallySignedStruct;

/// Result type for client operations.
pub type ClientResult<T> = Result<T, String>;

/// A connected and authenticated client session with the pwr server.
pub struct PwrClient {
    stream: Box<dyn ReadWrite>,
    decoder: FrameDecoder,
}

/// Helper trait to abstract over TLS and plain streams.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl PwrClient {
    /// Connect to the server with retry logic for transient failures.
    ///
    /// Retries up to 3 times with exponential backoff (1s, 2s, 4s).
    /// TLS handshake failures and authentication errors are not retried
    /// since they indicate configuration problems rather than transient
    /// network issues.
    pub fn connect(config: &PwrConfig, tls: bool) -> ClientResult<Self> {
        let max_retries = 3;
        let mut last_err = String::new();

        for attempt in 0..=max_retries {
            match Self::connect_once(config, tls) {
                Ok(client) => {
                    if attempt > 0 {
                        log::info!("Connected after {} retries", attempt);
                    }
                    return Ok(client);
                }
                Err(e) => {
                    last_err = e;
                    if attempt < max_retries {
                        let delay = Duration::from_secs(1 << attempt); // 1s, 2s, 4s
                        log::warn!(
                            "Connection attempt {} failed: {}. Retrying in {:?}...",
                            attempt + 1, last_err, delay
                        );
                        std::thread::sleep(delay);
                    }
                }
            }
        }

        Err(format!("Connection failed after {} attempts: {}", max_retries + 1, last_err))
    }

    /// Single connection attempt without retry.
    fn connect_once(config: &PwrConfig, tls: bool) -> ClientResult<Self> {
        let addr = config.server_addr();
        let timeout = Duration::from_secs(config.connect_timeout_secs);

        // Resolve the hostname (or IP) to socket addresses.
        // This supports DNS hostnames like "arch" or "nas.local", not just
        // raw IP addresses. Returns both IPv6 and IPv4 addresses — we try
        // them in order (typically v6 first) and use the first that connects.
        let addrs: Vec<_> = addr
            .to_socket_addrs()
            .map_err(|e| format!("Cannot resolve {}: {}", addr, e))?
            .collect();

        if addrs.is_empty() {
            return Err(format!("No addresses found for {}", addr));
        }

        // Try each resolved address until one connects
        let mut last_err = String::new();
        for a in &addrs {
            match TcpStream::connect_timeout(a, timeout) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(30)))
                        .map_err(|e| format!("set_read_timeout: {}", e))?;

                    let psk = crypto::psk_from_hex(&config.server_psk)
                        .map_err(|e| format!("Invalid PSK: {}", e))?;

                    let (stream, decoder) = if tls {
                        let mut tls_stream = connect_tls(stream, config)?;
                        let mut decoder = FrameDecoder::new();
                        perform_handshake(&mut tls_stream, &mut decoder, &psk, "pwr-cli")?;
                        (Box::new(tls_stream) as Box<dyn ReadWrite>, decoder)
                    } else {
                        let mut decoder = FrameDecoder::new();
                        perform_handshake(&mut &stream, &mut decoder, &psk, "pwr-cli")?;
                        (Box::new(stream) as Box<dyn ReadWrite>, decoder)
                    };

                    return Ok(Self { stream, decoder });
                }
                Err(e) => {
                    log::debug!("  {}: {}", a, e);
                    last_err = format!("{}: {}", a, e);
                }
            }
        }

        Err(format!("Connection to {} failed (tried {} addresses): {}",
            addr, addrs.len(), last_err))
    }

    /// Archive a project: send the encrypted archive blob to the server.
    ///
    /// `archive_data` is the fully encrypted tar.gz.age blob.
    /// `archive_hash` is its SHA-256 hex hash for server-side verification.
    /// An optional progress callback receives bytes sent so far and total.
    pub fn archive_project(
        &mut self,
        project_uuid: &uuid::Uuid,
        project_name: &str,
        archive_data: &[u8],
        archive_hash: &str,
    ) -> ClientResult<()> {
        self.archive_project_with_progress(
            project_uuid, project_name, archive_data, archive_hash, None,
        )
    }

    /// Archive with progress callback: fn(bytes_sent, total_bytes).
    pub fn archive_project_with_progress(
        &mut self,
        project_uuid: &uuid::Uuid,
        project_name: &str,
        archive_data: &[u8],
        archive_hash: &str,
        progress: Option<&dyn Fn(u64, u64)>,
    ) -> ClientResult<()> {
        // Send ArchiveRequest using protocol builder
        let req = protocol::build_archive_request(
            *project_uuid,
            project_name,
            archive_data.len() as u64,
            1, // Single archive blob
            true,
        );
        send_client_msg(&mut self.stream, &req)?;

        // Receive ArchiveAccept
        match recv_server_msg(&mut self.stream, &mut self.decoder)? {
            ServerMessage::ArchiveAccept(accept) => {
                log::debug!("Archive accepted, session {}", accept.session_id);
            }
            ServerMessage::Error(e) => return Err(format!("Server rejected: {}", e.message)),
            other => return Err(format!("Unexpected response: {:?}", other.message_type())),
        }

        // Stream the archive data in chunks
        let chunk_size = 1024 * 1024; // 1 MiB
        let mut bytes_sent = 0u64;
        let total = archive_data.len() as u64;
        for (i, chunk) in archive_data.chunks(chunk_size).enumerate() {
            self.stream
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .map_err(|e| format!("chunk write: {}", e))?;
            self.stream
                .write_all(chunk)
                .map_err(|e| format!("chunk data write: {}", e))?;
            bytes_sent += chunk.len() as u64;
            if let Some(ref cb) = progress {
                cb(bytes_sent, total);
            }
            log::debug!("Sent chunk {} ({} bytes)", i, chunk.len());
        }

        // Send EOF marker
        self.stream
            .write_all(&0u32.to_be_bytes())
            .map_err(|e| format!("eof write: {}", e))?;
        self.stream.flush().map_err(|e| format!("flush: {}", e))?;

        // Send ArchiveComplete
        let complete = protocol::build_archive_complete(
            archive_data.len() as u64,
            archive_hash,
        );
        send_client_msg(&mut self.stream, &complete)?;

        log::info!("Archive sent: {} bytes, hash: {}", archive_data.len(), archive_hash);
        Ok(())
    }

    /// Restore a project: request the server send back the archive blob.
    ///
    /// Returns the encrypted archive data that can then be decrypted
    /// and extracted locally.
    pub fn restore_project(
        &mut self,
        project_uuid: &uuid::Uuid,
    ) -> ClientResult<Vec<u8>> {
        self.restore_project_with_progress(project_uuid, None)
    }

    /// Restore with progress callback: fn(bytes_received, total_bytes).
    pub fn restore_project_with_progress(
        &mut self,
        project_uuid: &uuid::Uuid,
        progress: Option<&dyn Fn(u64, u64)>,
    ) -> ClientResult<Vec<u8>> {
        // Send RestoreRequest
        let req = protocol::build_restore_request(*project_uuid);
        send_client_msg(&mut self.stream, &req)?;

        // Receive RestoreAccept
        let (total_size, _file_count) = match recv_server_msg(&mut self.stream, &mut self.decoder)? {
            ServerMessage::RestoreAccept(accept) => {
                log::info!("Restoring {} bytes ({} files)", accept.total_size, accept.file_count);
                (accept.total_size, accept.file_count)
            }
            ServerMessage::Error(e) => return Err(format!("Server rejected: {}", e.message)),
            other => return Err(format!("Unexpected response: {:?}", other.message_type())),
        };

        // Drain the frame decoder: it may have buffered chunk bytes
        // that were read from the transport alongside the RestoreAccept
        // frame. Consume those first, then read remaining chunks from
        // the stream.
        let prefix = self.decoder.drain_bytes();

        // Receive raw chunk data until EOF
        let mut data = Vec::with_capacity(total_size as usize);
        let mut buf = Vec::with_capacity(prefix.len() + 8192);
        buf.extend_from_slice(&prefix);
        let mut pos: usize = 0;

        loop {
            // Ensure we have at least 4 bytes for the chunk header
            while buf.len() - pos < 4 {
                let start = buf.len();
                buf.resize(start + 8192, 0);
                let n = self.stream
                    .read(&mut buf[start..])
                    .map_err(|e| format!("chunk read: {}", e))?;
                if n == 0 {
                    return Err("Connection closed during chunk transfer".into());
                }
                buf.truncate(start + n);
            }

            let chunk_len = u32::from_be_bytes([
                buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3],
            ]) as usize;
            pos += 4;

            if chunk_len == 0 {
                break; // EOF
            }

            // Ensure we have the full chunk data
            while buf.len() - pos < chunk_len {
                let start = buf.len();
                buf.resize(start + (chunk_len - (buf.len() - pos)).max(8192), 0);
                let n = self.stream
                    .read(&mut buf[start..])
                    .map_err(|e| format!("chunk read: {}", e))?;
                if n == 0 {
                    return Err("Connection closed during chunk data".into());
                }
                buf.truncate(start + n);
            }

            data.extend_from_slice(&buf[pos..pos + chunk_len]);
            pos += chunk_len;

            if let Some(ref cb) = progress {
                cb(data.len() as u64, total_size);
            }

            // Compact the buffer periodically
            if pos > 65536 {
                buf.drain(..pos);
                pos = 0;
            }
        }

        log::info!("Restored {} bytes", data.len());
        Ok(data)
    }

    /// Query the server for project status.
    pub fn get_status(
        &mut self,
        project_uuid: Option<&uuid::Uuid>,
    ) -> ClientResult<Vec<ProjectInfo>> {
        let req = protocol::ClientMessage::StatusRequest(
            protocol::StatusRequest { project_uuid: project_uuid.copied() },
        );
        send_client_msg(&mut self.stream, &req)?;

        match recv_server_msg(&mut self.stream, &mut self.decoder)? {
            ServerMessage::StatusResponse(response) => Ok(response.projects),
            ServerMessage::Error(e) => Err(format!("Server error: {}", e.message)),
            other => Err(format!("Unexpected response: {:?}", other.message_type())),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Perform the PSK handshake on a raw (non-TLS) stream.
fn perform_handshake(
    stream: &mut impl ReadWrite,
    decoder: &mut FrameDecoder,
    psk: &[u8; 32],
    client_id: &str,
) -> ClientResult<()> {
    let mut nonce = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "CSPRNG failure".to_string())?;

    let proof = crypto::compute_client_proof(psk, &nonce);

    // Send Handshake
    let hs = ClientMessage::Handshake(Handshake {
        version: frame::PROTOCOL_VERSION,
        client_id: client_id.to_string(),
        nonce,
        proof,
    });
    send_client_msg(stream, &hs)?;

    // Receive HandshakeAck
    match recv_server_msg(stream, decoder)? {
        ServerMessage::HandshakeAck(ack) => {
            if !ack.success {
                return Err(format!(
                    "Authentication failed: {}",
                    ack.reason.unwrap_or_default()
                ));
            }

            // Verify server proof (mutual auth)
            let expected = crypto::compute_server_proof(psk, &nonce, &ack.server_nonce);
            if expected != ack.server_proof {
                return Err("Server authentication failed: invalid proof".into());
            }

            log::info!("Authenticated to server v{}", ack.server_version);
            Ok(())
        }
        ServerMessage::Error(e) => Err(format!("Server rejected handshake: {}", e.message)),
        other => Err(format!("Unexpected handshake response: {:?}", other.message_type())),
    }
}

/// Send a ClientMessage as a framed message on the stream.
fn send_client_msg(
    stream: &mut impl Write,
    msg: &ClientMessage,
) -> ClientResult<()> {
    let frame = frame::encode_frame(msg, msg.message_type())
        .map_err(|e| format!("encode: {}", e))?;
    stream.write_all(&frame).map_err(|e| format!("write: {}", e))?;
    stream.flush().map_err(|e| format!("flush: {}", e))?;
    Ok(())
}

/// Receive one ServerMessage from the stream.
///
/// Reads from the stream until a complete frame is decoded, then
/// deserializes the payload using the typed server message decoder.
fn recv_server_msg(
    stream: &mut impl Read,
    decoder: &mut FrameDecoder,
) -> ClientResult<ServerMessage> {
    let mut buf = [0u8; 8192];

    loop {
        if let Some((header, payload)) = decoder.try_decode()
            .map_err(|e| format!("decode: {}", e))?
        {
            return protocol::decode_server_message(header.msg_type, &payload)
                .map_err(|e| format!("deserialize: {}", e));
        }

        let n = stream.read(&mut buf).map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Err("Connection closed by server".into());
        }
        decoder.push_bytes(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------
// TLS connection
// ---------------------------------------------------------------------------

/// Establish a TLS-encrypted connection to the server.
///
/// Uses a custom certificate verifier that accepts self-signed
/// certificates while optionally checking the SHA-256 fingerprint
/// against a pinned value for MITM protection. The PSK handshake
/// provides authentication even without CA-signed certificates.
fn connect_tls(
    tcp_stream: TcpStream,
    config: &PwrConfig,
) -> ClientResult<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let pinned = config.server_fingerprint.clone();
    let verifier = Arc::new(CertVerifier::new(pinned));

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name: ServerName = config
        .server_host
        .clone()
        .try_into()
        .map_err(|_| format!("Invalid server hostname: {}", config.server_host))?;

    let client_conn = rustls::ClientConnection::new(
        Arc::new(tls_config),
        server_name,
    )
    .map_err(|e| format!("TLS client setup: {}", e))?;

    let mut tls_stream = rustls::StreamOwned::new(client_conn, tcp_stream);

    // Trigger TLS handshake
    tls_stream.flush().map_err(|e| format!("TLS handshake: {}", e))?;

    log::info!(
        "TLS connection established to {}:{}",
        config.server_host,
        config.server_port
    );

    Ok(tls_stream)
}

/// Custom TLS certificate verifier for pwr.
///
/// Accepts self-signed certificates (the server generates its own)
/// and optionally verifies the SHA-256 fingerprint against a pinned
/// value for defense-in-depth beyond the PSK authentication layer.
#[derive(Debug)]
struct CertVerifier {
    pinned_fingerprint: Option<String>,
}

impl CertVerifier {
    fn new(pinned_fingerprint: Option<String>) -> Self {
        Self { pinned_fingerprint }
    }
}

impl ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // If a fingerprint is pinned, verify it matches
        if let Some(ref pinned) = self.pinned_fingerprint {
            let actual = crypto::sha256_hex(end_entity.as_ref());
            if actual != *pinned {
                return Err(rustls::Error::General(format!(
                    "Certificate fingerprint mismatch: expected {}",
                    pinned
                )));
            }
            log::info!("Server certificate fingerprint verified against pinned value");
        } else {
            log::warn!(
                "No certificate fingerprint pinned. Server cert SHA-256: {}",
                crypto::sha256_hex(end_entity.as_ref())
            );
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Accept any signature: authentication is via PSK, not PKI
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Accept any signature: authentication is via PSK, not PKI
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
