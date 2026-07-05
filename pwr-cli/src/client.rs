//! Protocol client for communicating with pwr-server.
//!
//! Manages the TLS connection, authentication handshake, and
//! archive/restore operations. All network I/O is synchronous,
//! intended to be called from blocking contexts.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use pwr_core::config::PwrConfig;
use pwr_core::crypto;
use pwr_core::frame::{self, FrameDecoder};
use pwr_core::protocol::{self, ClientMessage, Handshake, ProjectInfo, ServerMessage};
use ring::rand::SecureRandom;

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
        for (i, chunk) in archive_data.chunks(chunk_size).enumerate() {
            self.stream
                .write_all(&(chunk.len() as u32).to_be_bytes())
                .map_err(|e| format!("chunk write: {}", e))?;
            self.stream
                .write_all(chunk)
                .map_err(|e| format!("chunk data write: {}", e))?;
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

        // Receive raw chunk data until EOF
        let mut data = Vec::with_capacity(total_size as usize);
        let mut header_buf = [0u8; 4];

        loop {
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
