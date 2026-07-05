//! Protocol client for communicating with pwr-server.
//!
//! Manages the TLS connection, authentication handshake, and
//! archive/restore operations. All network I/O is synchronous,
//! intended to be called from blocking contexts.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use pwr_core::config::PwrConfig;
use pwr_core::crypto;
use pwr_core::frame::{self, FrameDecoder};
use pwr_core::protocol::*;

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
    /// Connect to the server, complete TLS handshake, and authenticate.
    ///
    /// `psk_hex` is the hex-encoded pre-shared key from the client config.
    /// `tls` controls whether TLS is enabled (production) or disabled (testing).
    pub fn connect(config: &PwrConfig, tls: bool) -> ClientResult<Self> {
        let addr = config.server_addr();
        let timeout = Duration::from_secs(config.connect_timeout_secs);

        let tcp_stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
            timeout,
        )
        .map_err(|e| format!("Connection to {} failed: {}", addr, e))?;

        tcp_stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set_read_timeout: {}", e))?;

        // Authenticate
        let psk = crypto::psk_from_hex(&config.server_psk)
            .map_err(|e| format!("Invalid PSK: {}", e))?;

        let (stream, decoder) = if tls {
            // TLS path — not yet implemented, use plaintext
            return Err("TLS not yet implemented in client".into());
        } else {
            // Plaintext path (for testing)
            let mut decoder = FrameDecoder::new();
            perform_handshake(&mut &tcp_stream, &mut decoder, &psk, "pwr-cli")?;
            (Box::new(tcp_stream) as Box<dyn ReadWrite>, decoder)
        };

        Ok(Self { stream, decoder })
    }

    /// Archive a project: send the encrypted archive blob to the server.
    ///
    /// `archive_data` is the fully encrypted tar.gz.age blob.
    /// `archive_hash` is its SHA-256 hex hash for server-side verification.
    pub fn archive_project(
        &mut self,
        project_uuid: &uuid::Uuid,
        project_name: &str,
        archive_data: &[u8],
        archive_hash: &str,
    ) -> ClientResult<()> {
        // Send ArchiveRequest
        let req = ArchiveRequest {
            project_uuid: *project_uuid,
            project_name: project_name.to_string(),
            total_size: archive_data.len() as u64,
            file_count: 1, // Single archive blob
            compression: true,
        };
        send_frame(&mut self.stream, &req, MessageType::ArchiveRequest)?;

        // Receive ArchiveAccept
        let (_header, payload) = recv_frame(&mut self.stream, &mut self.decoder)?;
        let _accept: ArchiveAccept = serde_json::from_slice(&payload)
            .map_err(|e| format!("bad ArchiveAccept: {}", e))?;

        // Stream the archive data in chunks
        let chunk_size = 1024 * 1024; // 1 MiB
        for (i, chunk) in archive_data.chunks(chunk_size).enumerate() {
            // Send raw chunk data (4-byte length prefix + data)
            self.stream
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .map_err(|e| format!("chunk write error: {}", e))?;
            self.stream
                .write_all(chunk)
                .map_err(|e| format!("chunk data write error: {}", e))?;

            log::debug!("Sent chunk {} ({} bytes)", i, chunk.len());
        }

        // Send EOF marker
        self.stream
            .write_all(&0u32.to_be_bytes())
            .map_err(|e| format!("eof write error: {}", e))?;
        self.stream
            .flush()
            .map_err(|e| format!("flush error: {}", e))?;

        // Send ArchiveComplete
        let complete = ArchiveComplete {
            success: true,
            total_size: archive_data.len() as u64,
            archive_hash: archive_hash.to_string(),
            error: None,
        };
        send_frame(&mut self.stream, &complete, MessageType::ArchiveComplete)?;

        log::info!(
            "Archive sent: {} bytes, hash: {}",
            archive_data.len(),
            archive_hash
        );

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
        // Send RestoreRequest
        let req = RestoreRequest {
            project_uuid: *project_uuid,
        };
        send_frame(&mut self.stream, &req, MessageType::RestoreRequest)?;

        // Receive RestoreAccept
        let (_header, payload) = recv_frame(&mut self.stream, &mut self.decoder)?;
        let accept: RestoreAccept = serde_json::from_slice(&payload)
            .map_err(|e| format!("bad RestoreAccept: {}", e))?;

        log::info!(
            "Restoring {} bytes ({} files)",
            accept.total_size,
            accept.file_count
        );

        // Receive raw chunk data until EOF
        let mut data = Vec::with_capacity(accept.total_size as usize);
        let mut header_buf = [0u8; 4];

        loop {
            // Read 4-byte chunk length
            self.stream
                .read_exact(&mut header_buf)
                .map_err(|e| format!("chunk header read: {}", e))?;

            let chunk_len = u32::from_be_bytes(header_buf) as usize;

            if chunk_len == 0 {
                break; // EOF
            }

            let start = data.len();
            data.resize(start + chunk_len, 0);
            self.stream
                .read_exact(&mut data[start..])
                .map_err(|e| format!("chunk data read: {}", e))?;
        }

        log::info!("Restored {} bytes", data.len());

        Ok(data)
    }

    /// Query the server for project status.
    pub fn get_status(
        &mut self,
        project_uuid: Option<&uuid::Uuid>,
    ) -> ClientResult<Vec<ProjectInfo>> {
        let req = StatusRequest {
            project_uuid: project_uuid.copied(),
        };
        send_frame(&mut self.stream, &req, MessageType::StatusRequest)?;

        let (_header, payload) = recv_frame(&mut self.stream, &mut self.decoder)?;
        let response: StatusResponse = serde_json::from_slice(&payload)
            .map_err(|e| format!("bad StatusResponse: {}", e))?;

        Ok(response.projects)
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
    // Generate nonce and proof
    let mut nonce = [0u8; 32];
    ring::rand::SecureRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "CSPRNG failure".to_string())?;

    let proof = crypto::compute_client_proof(psk, &nonce);

    // Send Handshake
    let hs = Handshake {
        version: frame::PROTOCOL_VERSION,
        client_id: client_id.to_string(),
        nonce,
        proof,
    };
    send_frame(stream, &hs, MessageType::Handshake)?;

    // Receive HandshakeAck
    let (_header, payload) = recv_frame(stream, decoder)?;
    let ack: HandshakeAck = serde_json::from_slice(&payload)
        .map_err(|e| format!("bad HandshakeAck: {}", e))?;

    if !ack.success {
        return Err(format!(
            "Authentication failed: {}",
            ack.reason.unwrap_or_default()
        ));
    }

    // Verify server proof (mutual auth)
    let expected_server_proof =
        crypto::compute_server_proof(psk, &nonce, &ack.server_nonce);

    use ring::constant_time::verify_slices_are_equal;
    if verify_slices_are_equal(&expected_server_proof, &ack.server_proof).is_err() {
        return Err("Server authentication failed: invalid server proof".into());
    }

    log::info!("Authenticated to server v{}", ack.server_version);
    Ok(())
}

/// Send a framed message on the stream.
fn send_frame(
    stream: &mut impl Write,
    msg: &impl serde::Serialize,
    msg_type: MessageType,
) -> ClientResult<()> {
    let frame = frame::encode_frame(msg, msg_type)
        .map_err(|e| format!("encode: {}", e))?;
    stream
        .write_all(&frame)
        .map_err(|e| format!("write: {}", e))?;
    stream.flush().map_err(|e| format!("flush: {}", e))?;
    Ok(())
}

/// Receive one framed message from the stream.
///
/// Reads from the stream until a complete frame is decoded.
fn recv_frame(
    stream: &mut impl Read,
    decoder: &mut FrameDecoder,
) -> ClientResult<(frame::FrameHeader, Vec<u8>)> {
    let mut buf = [0u8; 8192];

    loop {
        if let Some(result) = decoder.try_decode().map_err(|e| format!("decode: {}", e))? {
            return Ok(result);
        }

        let n = stream.read(&mut buf).map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Err("Connection closed by server".into());
        }
        decoder.push_bytes(&buf[..n]);
    }
}
