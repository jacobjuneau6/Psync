//! Per-connection request handler for pwr-server.
//!
//! Each TCP connection progresses through a state machine:
//! AwaitingHandshake → Authenticated → (Archiving | Restoring | Idle).
//! After authentication, the handler loops reading frames and dispatching
//! to the appropriate operation handler until the client disconnects.

use pwr_core::frame::{FrameDecoder, FrameHeader};
use pwr_core::protocol::{
    self, ArchiveAccept, ArchiveComplete, ArchiveRequest, ClientMessage,
    ErrorMessage, Handshake, HandshakeAck, MessageType, ProjectInfo,
    RestoreAccept, RestoreComplete, RestoreRequest, ServerMessage,
    StatusRequest, StatusResponse,
};
use pwr_core::crypto;
use ring::rand::SecureRandom;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

use crate::storage::{ProjectStorage, StoredProject};

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ConnState {
    AwaitingHandshake,
    Authenticated,
    Archiving(ArchiveSession),
    Restoring(RestoreSession),
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

pub struct HandlerContext {
    pub storage: Arc<RwLock<ProjectStorage>>,
    pub psk: [u8; 32],
    pub peer_addr: SocketAddr,
    pub connected_at: Instant,
}

// ---------------------------------------------------------------------------
// Main dispatch loop
// ---------------------------------------------------------------------------

pub fn handle_connection(
    mut stream: impl Read + Write,
    ctx: HandlerContext,
) -> Result<(), String> {
    let mut state = ConnState::AwaitingHandshake;
    let mut decoder = FrameDecoder::new();
    let mut read_buf = vec![0u8; 8192];

    loop {
        let n = stream.read(&mut read_buf)
            .map_err(|e| format!("read error: {}", e))?;
        if n == 0 {
            break;
        }

        decoder.push_bytes(&read_buf[..n]);

        loop {
            match decoder.try_decode() {
                Ok(Some((header, payload))) => {
                    if let Err(e) = dispatch(&mut stream, &mut state, header, &payload, &ctx) {
                        send_server_msg(&mut stream, &protocol::build_error(1, &e))?;
                        return Err(e);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    send_server_msg(&mut stream, &protocol::build_error(2, &format!("Frame: {}", e)))?;
                    return Err(format!("Frame error: {}", e));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Message dispatch
// ---------------------------------------------------------------------------

fn dispatch(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    header: FrameHeader,
    payload: &[u8],
    ctx: &HandlerContext,
) -> Result<(), String> {
    // Decode the client message
    let msg = protocol::decode_client_message(header.msg_type, payload)
        .map_err(|e| format!("Decode: {}", e))?;

    match (&state, msg) {
        // --- Handshake (only valid before auth) ---
        (ConnState::AwaitingHandshake, ClientMessage::Handshake(hs)) => {
            handle_handshake(stream, state, &hs, ctx)
        }

        // --- Archive flow ---
        (ConnState::Authenticated, ClientMessage::ArchiveRequest(req)) => {
            handle_archive_start(stream, state, &req, ctx)
        }
        (ConnState::Archiving(_), ClientMessage::ArchiveComplete(complete)) => {
            handle_archive_finish(stream, state, &complete, ctx)
        }

        // --- Restore flow ---
        (ConnState::Authenticated, ClientMessage::RestoreRequest(req)) => {
            handle_restore_start(stream, state, &req, ctx)
        }

        // --- Status query ---
        (ConnState::Authenticated, ClientMessage::StatusRequest(req)) => {
            handle_status(stream, &req, ctx)
        }

        // --- Protocol violations ---
        (ConnState::AwaitingHandshake, _) => {
            Err("Handshake required before any other message".into())
        }
        (ConnState::Closed, _) => Err("Connection is closed".into()),
        (_, msg) => Err(format!(
            "Unexpected message in state {:?}",
            std::mem::discriminant(state)
        )),
    }
}

// ---------------------------------------------------------------------------
// Handshake handler
// ---------------------------------------------------------------------------

fn handle_handshake(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    hs: &Handshake,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let expected_proof = crypto::compute_client_proof(&ctx.psk, &hs.nonce);

    if expected_proof != hs.proof {
        *state = ConnState::Closed;
        send_server_msg(
            stream,
            &protocol::build_handshake_ack_failed("Authentication failed: invalid proof"),
        )?;
        return Err("Authentication failed".into());
    }

    // Generate server nonce and proof
    let mut server_nonce = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut server_nonce)
        .map_err(|_| "CSPRNG failure".to_string())?;

    let server_proof =
        crypto::compute_server_proof(&ctx.psk, &hs.nonce, &server_nonce);

    *state = ConnState::Authenticated;
    send_server_msg(
        stream,
        &protocol::build_handshake_ack_success(
            env!("CARGO_PKG_VERSION"),
            server_nonce,
            server_proof,
        ),
    )?;

    log::info!("Client '{}' authenticated from {}", hs.client_id, ctx.peer_addr);
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive handlers
// ---------------------------------------------------------------------------

fn handle_archive_start(
    stream: &mut (impl Read + Write),
    state: &mut ConnState,
    req: &ArchiveRequest,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let session_id = Uuid::new_v4();

    // Check storage limit
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

    send_server_msg(stream, &protocol::build_archive_accept(session_id))?;

    log::info!(
        "Archive started: {} ({} bytes, {} files)",
        req.project_name, req.total_size, req.file_count
    );
    Ok(())
}

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
        let _ = ctx.storage.write().unwrap().remove_project(&session.project_uuid);
        *state = ConnState::Authenticated;
        // Send the ArchiveComplete back as acknowledgment
        send_server_msg(stream, &protocol::build_error(0, "Archive cancelled by client"))?;
        return Ok(());
    }

    // Update project with final size
    {
        let mut storage = ctx.storage.write().unwrap();
        if let Some(mut project) = storage.get_project(&session.project_uuid).cloned() {
            project.size_bytes = complete.total_size;
            project.updated_at = chrono::Utc::now();
            storage.update_project(project)
                .map_err(|e| format!("Cannot update: {}", e))?;
        }
    }

    *state = ConnState::Authenticated;
    log::info!(
        "Archive complete: {} ({} bytes, hash: {})",
        session.project_name, complete.total_size,
        &complete.archive_hash[..16.min(complete.archive_hash.len())]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Restore handler
// ---------------------------------------------------------------------------

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
        return Err(format!("Archive data missing for {}", req.project_uuid));
    }
    drop(storage);

    let session_id = Uuid::new_v4();
    let total_size = project.size_bytes;
    let file_count = project.file_count;

    *state = ConnState::Restoring(RestoreSession {
        session_id,
        project_uuid: req.project_uuid,
        total_size,
        file_count,
        bytes_sent: 0,
    });

    send_server_msg(
        stream,
        &protocol::build_restore_accept(session_id, total_size, file_count, ""),
    )?;

    log::info!("Restore started: {} ({} bytes)", project.name, total_size);
    Ok(())
}

// ---------------------------------------------------------------------------
// Status handler
// ---------------------------------------------------------------------------

fn handle_status(
    stream: &mut (impl Read + Write),
    req: &StatusRequest,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let storage = ctx.storage.read().unwrap();
    let projects: Vec<ProjectInfo> = if let Some(uuid) = &req.project_uuid {
        storage
            .get_project(uuid)
            .map(|p| vec![ProjectInfo {
                uuid: p.uuid,
                name: p.name.clone(),
                size_bytes: p.size_bytes,
                file_count: p.file_count,
                created_at: p.created_at,
                last_modified: p.updated_at,
            }])
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

    send_server_msg(stream, &protocol::build_status_response(projects))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

fn send_server_msg(
    stream: &mut (impl Write),
    msg: &ServerMessage,
) -> Result<(), String> {
    let frame = pwr_core::frame::encode_frame(msg, msg.message_type())
        .map_err(|e| format!("encode: {}", e))?;
    stream.write_all(&frame).map_err(|e| format!("write: {}", e))?;
    stream.flush().map_err(|e| format!("flush: {}", e))?;
    Ok(())
}
