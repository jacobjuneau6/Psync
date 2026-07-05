//! Per-connection request handler for pwr-server.
//!
//! Each TCP connection progresses through a state machine:
//! AwaitingHandshake → Authenticated → (Archiving | Restoring | Idle).
//! After authentication, the handler loops reading frames and dispatching
//! to the appropriate operation handler until the client disconnects.

use pwr_core::frame::{FrameDecoder, FrameHeader, HEADER_SIZE};
use pwr_core::protocol::{
    ArchiveAccept, ArchiveComplete, ArchiveRequest, ErrorMessage, FileEnd, FileHeader,
    Handshake, HandshakeAck, MessageType, ProjectInfo, RestoreAccept, RestoreComplete,
    RestoreRequest, StatusRequest, StatusResponse,
};
use pwr_core::crypto;
use ring::rand::SecureRandom;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

use crate::storage::{ProjectStorage, StoredProject};

/// States of a client connection.
#[derive(Debug)]
enum ConnState {
    /// Waiting for the Handshake message.
    AwaitingHandshake,
    /// Handshake completed, client is authenticated.
    Authenticated,
    /// Currently receiving an archive.
    Archiving(ArchiveSession),
    /// Currently sending a restore.
    Restoring(RestoreSession),
    /// Connection is closing.
    Closed,
}

#[derive(Debug)]
struct ArchiveSession {
    session_id: Uuid,
    project_uuid: Uuid,
    project_name: String,
    total_size: u64,
    file_count: u32,
    compression: bool,
    bytes_received: u64,
}

#[derive(Debug)]
struct RestoreSession {
    session_id: Uuid,
    project_uuid: Uuid,
    total_size: u64,
    file_count: u32,
    bytes_sent: u64,
}

/// Context passed to every handler method.
pub struct HandlerContext {
    pub storage: Arc<RwLock<ProjectStorage>>,
    pub psk: [u8; 32],
    pub peer_addr: SocketAddr,
    pub connected_at: Instant,
}

/// Run the connection handler loop.
///
/// `stream` is a TLS-encrypted TCP stream. The handler reads framed
/// messages, dispatches them based on the current state, and writes
/// responses. On any protocol error, an Error frame is sent and the
/// connection is closed.
pub fn handle_connection(
    mut stream: impl Read + Write,
    ctx: HandlerContext,
) -> Result<(), String> {
    let mut state = ConnState::AwaitingHandshake;
    let mut decoder = FrameDecoder::new();
    let mut read_buf = vec![0u8; 8192];

    loop {
        // Read raw bytes from the stream
        let n = stream
            .read(&mut read_buf)
            .map_err(|e| format!("read error: {}", e))?;

        if n == 0 {
            // Client closed connection
            break;
        }

        decoder.push_bytes(&read_buf[..n]);

        // Process all complete frames in the buffer
        loop {
            match decoder.try_decode() {
                Ok(Some((header, payload))) => {
                    let result =
                        dispatch(&mut stream, &mut state, header, &payload, &ctx);
                    if let Err(e) = result {
                        // Send error frame and close
                        let err_msg = ErrorMessage {
                            code: 1,
                            message: e.clone(),
                        };
                        let _ = send_frame(&mut stream, &err_msg, MessageType::Error);
                        return Err(e);
                    }
                }
                Ok(None) => break, // Need more data
                Err(e) => {
                    let err_msg = ErrorMessage {
                        code: 2,
                        message: format!("Frame error: {}", e),
                    };
                    let _ = send_frame(&mut stream, &err_msg, MessageType::Error);
                    return Err(format!("Frame error: {}", e));
                }
            }
        }
    }

    Ok(())
}

/// Dispatch a decoded frame to the appropriate handler.
fn dispatch(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    header: FrameHeader,
    payload: &[u8],
    ctx: &HandlerContext,
) -> Result<(), String> {
    match (&state, header.msg_type) {
        // Handshake must be the first message
        (ConnState::AwaitingHandshake, MessageType::Handshake) => {
            let handshake: Handshake = serde_json::from_slice(payload)
                .map_err(|e| format!("bad handshake: {}", e))?;
            handle_handshake(stream, state, &handshake, ctx)
        }

        // All other messages require authentication first
        (ConnState::AwaitingHandshake, _) => {
            Err("Handshake required before any other message".into())
        }

        (ConnState::Closed, _) => Err("Connection is closed".into()),

        // Authenticated state: dispatch based on message type
        (ConnState::Authenticated, MessageType::ArchiveRequest) => {
            let req: ArchiveRequest = serde_json::from_slice(payload)
                .map_err(|e| format!("bad ArchiveRequest: {}", e))?;
            handle_archive_start(stream, state, &req, ctx)
        }

        (ConnState::Authenticated, MessageType::RestoreRequest) => {
            let req: RestoreRequest = serde_json::from_slice(payload)
                .map_err(|e| format!("bad RestoreRequest: {}", e))?;
            handle_restore_start(stream, state, &req, ctx)
        }

        (ConnState::Authenticated, MessageType::StatusRequest) => {
            let req: StatusRequest = serde_json::from_slice(payload)
                .map_err(|e| format!("bad StatusRequest: {}", e))?;
            handle_status(stream, &req, ctx)
        }

        // Archive session: accept chunks and file headers
        (ConnState::Archiving(_), MessageType::FileHeader) => {
            let fh: FileHeader = serde_json::from_slice(payload)
                .map_err(|e| format!("bad FileHeader: {}", e))?;
            // During archive, the server receives file headers but
            // the actual file data comes as raw chunks (not framed).
            // For now, acknowledge the header.
            let ack = ErrorMessage {
                code: 0,
                message: "FileHeader received, awaiting chunk data".into(),
            };
            send_frame(stream, &ack, MessageType::Error)
        }

        (ConnState::Archiving(_), MessageType::ArchiveComplete) => {
            let complete: ArchiveComplete = serde_json::from_slice(payload)
                .map_err(|e| format!("bad ArchiveComplete: {}", e))?;
            handle_archive_finish(stream, state, &complete, ctx)
        }

        // Unsupported in current state
        (_, msg_type) => Err(format!(
            "Unexpected message type {:?} in state {:?}",
            msg_type,
            std::mem::discriminant(state)
        )),
    }
}

/// Handle the initial PSK handshake.
fn handle_handshake(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    hs: &Handshake,
    ctx: &HandlerContext,
) -> Result<(), String> {
    // Verify client proof
    let expected_proof = crypto::compute_client_proof(&ctx.psk, &hs.nonce);

    // Verify client proof
    if expected_proof != hs.proof {
        *state = ConnState::Closed;
        let ack = HandshakeAck {
            success: false,
            server_version: env!("CARGO_PKG_VERSION").into(),
            server_nonce: [0u8; 32],
            server_proof: [0u8; 32],
            reason: Some("Authentication failed: invalid proof".into()),
        };
        send_frame(stream, &ack, MessageType::HandshakeAck)?;
        return Err("Authentication failed".into());
    }

    // Generate server nonce and proof
    let mut server_nonce = [0u8; 32];
    let rng = SecureRandom::new();
    rng.fill(&mut server_nonce)
        .map_err(|_| "CSPRNG failure".to_string())?;

    let server_proof =
        crypto::compute_server_proof(&ctx.psk, &hs.nonce, &server_nonce);

    // Success
    *state = ConnState::Authenticated;
    let ack = HandshakeAck {
        success: true,
        server_version: env!("CARGO_PKG_VERSION").into(),
        server_nonce,
        server_proof,
        reason: None,
    };
    send_frame(stream, &ack, MessageType::HandshakeAck)?;

    log::info!(
        "Client '{}' authenticated from {}",
        hs.client_id,
        ctx.peer_addr
    );

    Ok(())
}

/// Handle the start of an archive transfer.
fn handle_archive_start(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    req: &ArchiveRequest,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let session_id = Uuid::new_v4();

    // Check size limit
    {
        let storage = ctx.storage.read().unwrap();
        storage.check_size_limit(req.total_size)
            .map_err(|e| format!("Archive rejected: {}", e))?;
    }

    // Create project entry
    let project = StoredProject {
        uuid: req.project_uuid,
        name: req.project_name.clone(),
        size_bytes: req.total_size,
        file_count: req.file_count,
        encrypted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    {
        let mut storage = ctx.storage.write().unwrap();
        storage.add_project(project.clone())
            .map_err(|e| format!("Cannot add project: {}", e))?;
        storage.write_meta(&req.project_uuid, &project)
            .map_err(|e| format!("Cannot write meta: {}", e))?;
    }

    *state = ConnState::Archiving(ArchiveSession {
        session_id,
        project_uuid: req.project_uuid,
        project_name: req.project_name.clone(),
        total_size: req.total_size,
        file_count: req.file_count,
        compression: req.compression,
        bytes_received: 0,
    });

    let ack = ArchiveAccept { session_id };
    send_frame(stream, &ack, MessageType::ArchiveAccept)?;

    log::info!(
        "Archive started: {} ({} bytes, {} files)",
        req.project_name,
        req.total_size,
        req.file_count
    );

    Ok(())
}

/// Handle the end of an archive transfer.
fn handle_archive_finish(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    complete: &ArchiveComplete,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let session = match state {
        ConnState::Archiving(s) => s,
        _ => return Err("Not in archiving state".into()),
    };

    if !complete.success {
        // Clean up the failed project
        let _ = ctx.storage.write().unwrap().remove_project(&session.project_uuid);
        *state = ConnState::Authenticated;
        let ack = ArchiveComplete {
            success: false,
            total_size: 0,
            archive_hash: String::new(),
            error: complete.error.clone(),
        };
        send_frame(stream, &ack, MessageType::ArchiveComplete)?;
        return Ok(());
    }

    // Update project with final size
    {
        let mut storage = ctx.storage.write().unwrap();
        if let Some(mut project) = storage.get_project(&session.project_uuid).cloned() {
            project.size_bytes = complete.total_size;
            project.updated_at = chrono::Utc::now();
            storage.update_project(project)
                .map_err(|e| format!("Cannot update project: {}", e))?;
        }
    }

    *state = ConnState::Authenticated;

    let ack = ArchiveComplete {
        success: true,
        total_size: complete.total_size,
        archive_hash: complete.archive_hash.clone(),
        error: None,
    };
    send_frame(stream, &ack, MessageType::ArchiveComplete)?;

    log::info!(
        "Archive complete: {} ({} bytes, hash: {})",
        session.project_name,
        complete.total_size,
        &complete.archive_hash[..16.min(complete.archive_hash.len())]
    );

    Ok(())
}

/// Handle the start of a restore transfer.
fn handle_restore_start(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    req: &RestoreRequest,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let storage = ctx.storage.read().unwrap();
    let project = storage
        .get_project(&req.project_uuid)
        .cloned()
        .ok_or_else(|| format!("Project not found: {}", req.project_uuid))?;

    if !storage.archive_exists(&req.project_uuid) {
        return Err(format!(
            "Archive data missing for project {}",
            req.project_uuid
        ));
    }

    let session_id = Uuid::new_v4();

    *state = ConnState::Restoring(RestoreSession {
        session_id,
        project_uuid: req.project_uuid,
        total_size: project.size_bytes,
        file_count: project.file_count,
        bytes_sent: 0,
    });

    let ack = RestoreAccept {
        session_id,
        total_size: project.size_bytes,
        file_count: project.file_count,
        archive_hash: String::new(), // Server doesn't compute hash
    };
    send_frame(stream, &ack, MessageType::RestoreAccept)?;

    log::info!(
        "Restore started: {} ({} bytes)",
        project.name,
        project.size_bytes
    );

    Ok(())
}

/// Handle a status/list query.
fn handle_status(
    stream: &mut (impl Read + Write),
    req: &StatusRequest,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let storage = ctx.storage.read().unwrap();
    let projects: Vec<ProjectInfo> = if let Some(uuid) = &req.project_uuid {
        storage
            .get_project(uuid)
            .map(|p| {
                vec![ProjectInfo {
                    uuid: p.uuid,
                    name: p.name.clone(),
                    size_bytes: p.size_bytes,
                    file_count: p.file_count,
                    created_at: p.created_at,
                    last_modified: p.updated_at,
                }]
            })
            .unwrap_or_default()
    } else {
        storage
            .list_projects()
            .iter()
            .map(|p| ProjectInfo {
                uuid: p.uuid,
                name: p.name.clone(),
                size_bytes: p.size_bytes,
                file_count: p.file_count,
                created_at: p.created_at,
                last_modified: p.updated_at,
            })
            .collect()
    };

    let response = StatusResponse { projects };
    send_frame(stream, &response, MessageType::StatusResponse)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// I/O Helpers
// ---------------------------------------------------------------------------

/// Send a framed message on a stream.
fn send_frame(
    stream: &mut (impl Write),
    msg: &impl serde::Serialize,
    msg_type: MessageType,
) -> Result<(), String> {
    let frame = pwr_core::frame::encode_frame(msg, msg_type)
        .map_err(|e| format!("encode error: {}", e))?;
    stream
        .write_all(&frame)
        .map_err(|e| format!("write error: {}", e))?;
    stream
        .flush()
        .map_err(|e| format!("flush error: {}", e))?;
    Ok(())
}
