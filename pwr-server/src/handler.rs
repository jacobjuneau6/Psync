//! Per-connection request handler for pwr-server.
//!
//! Each TCP connection progresses through a state machine:
//! AwaitingHandshake → Authenticated → (Archiving | Restoring | Idle).
//! After authentication, the handler loops reading frames and dispatching
//! to the appropriate operation handler until the client disconnects.

use pwr_core::frame::{FrameDecoder, FrameHeader};
use pwr_core::protocol::{
    self, ArchiveComplete, ArchiveRequest, ClientMessage,
    Handshake, ProjectInfo, RestoreRequest, ServerMessage,
    StatusRequest,
};
use pwr_core::crypto;
use ring::rand::SecureRandom;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use uuid::Uuid;

use crate::auth::RateLimiter;
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
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
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
            handle_archive_start(stream, state, &req, ctx)?;
            // After accepting, receive raw chunk data for the archive blob
            handle_archive_chunks(stream, state, ctx)
        }
        (ConnState::Archiving(_), ClientMessage::ArchiveComplete(complete)) => {
            handle_archive_finish(stream, state, &complete, ctx)
        }

        // --- Restore flow ---
        (ConnState::Authenticated, ClientMessage::RestoreRequest(req)) => {
            handle_restore_start(stream, state, &req, ctx)?;
            // After accepting, stream raw chunk data back to client
            handle_restore_chunks(stream, state, ctx)
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
    // Rate limiting check
    let peer_ip = ctx.peer_addr.ip();
    {
        let mut limiter = ctx.rate_limiter.lock().unwrap();
        if !limiter.check_attempt(peer_ip) {
            *state = ConnState::Closed;
            send_server_msg(
                stream,
                &protocol::build_handshake_ack_failed("Too many authentication attempts — try again later"),
            )?;
            return Err("Rate limited".into());
        }
    }

    let expected_proof = crypto::compute_client_proof(&ctx.psk, &hs.nonce);

    if expected_proof != hs.proof {
        *state = ConnState::Closed;
        send_server_msg(
            stream,
            &protocol::build_handshake_ack_failed("Authentication failed: invalid proof"),
        )?;
        return Err("Authentication failed".into());
    }

    // Record successful auth for rate limiting
    ctx.rate_limiter.lock().unwrap().record_success(peer_ip);

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
    // Extract session data before modifying state (avoids borrow conflict)
    let (project_uuid, project_name, _total_size) = match state {
        ConnState::Archiving(s) => (s.project_uuid, s.project_name.clone(), s.total_size),
        _ => return Err("Not in archiving state".into()),
    };

    if !complete.success {
        let _ = ctx.storage.write().unwrap().remove_project(&project_uuid);
        *state = ConnState::Authenticated;
        send_server_msg(stream, &protocol::build_error(0, "Archive cancelled by client"))?;
        return Ok(());
    }

    // Update project with final size
    {
        let mut storage = ctx.storage.write().unwrap();
        if let Some(mut project) = storage.get_project(&project_uuid).cloned() {
            project.size_bytes = complete.total_size;
            project.updated_at = chrono::Utc::now();
            storage.update_project(project)
                .map_err(|e| format!("Cannot update: {}", e))?;
        }
    }

    *state = ConnState::Authenticated;
    log::info!(
        "Archive complete: {} ({} bytes, hash: {})",
        project_name, complete.total_size,
        &complete.archive_hash[..16.min(complete.archive_hash.len())]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Archive chunk streaming
// ---------------------------------------------------------------------------

/// Receive raw chunk data from the client and write it to the project's
/// archive file on disk. Chunks use the 4-byte length-prefixed format
/// with a zero-length chunk indicating EOF.
fn handle_archive_chunks(
    stream: &mut (impl Read + Write),
    state: &ConnState,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let (project_uuid, _total_size) = match state {
        ConnState::Archiving(s) => (s.project_uuid, s.total_size),
        _ => return Err("Not in archiving state".into()),
    };

    let mut total_bytes = 0u64;
    let mut header_buf = [0u8; 4];

    loop {
        // Read 4-byte chunk length
        stream
            .read_exact(&mut header_buf)
            .map_err(|e| format!("chunk header read: {}", e))?;

        let chunk_len = u32::from_be_bytes(header_buf) as usize;

        if chunk_len == 0 {
            break; // EOF
        }

        // Read chunk data into a buffer and write to archive
        let mut chunk = vec![0u8; chunk_len];
        stream
            .read_exact(&mut chunk)
            .map_err(|e| format!("chunk data read: {}", e))?;

        total_bytes += chunk_len as u64;

        // Write chunk to the archive file
        {
            let storage = ctx.storage.read().unwrap();
            let archive_path = storage.archive_path(&project_uuid);

            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&archive_path)
                .map_err(|e| format!("Cannot open archive: {}", e))?;
            file.write_all(&chunk)
                .map_err(|e| format!("Cannot write chunk: {}", e))?;
        }

        log::debug!(
            "Received chunk: {} bytes (total: {})",
            chunk_len,
            total_bytes
        );
    }

    log::info!(
        "Archive data received: {} bytes for project {}",
        total_bytes,
        project_uuid
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Restore chunk streaming
// ---------------------------------------------------------------------------

/// Stream the project's archive file back to the client in chunked format.
fn handle_restore_chunks(
    stream: &mut (impl Read + Write),
    state: &ConnState,
    ctx: &HandlerContext,
) -> Result<(), String> {
    let project_uuid = match state {
        ConnState::Restoring(s) => s.project_uuid,
        _ => return Err("Not in restoring state".into()),
    };

    // Read the archive file from disk
    let archive_data = {
        let storage = ctx.storage.read().unwrap();
        let mut reader = storage
            .read_archive(&project_uuid)
            .map_err(|e| format!("Cannot read archive: {}", e))?;
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut data)
            .map_err(|e| format!("Cannot read archive data: {}", e))?;
        data
    };

    // Stream in chunks
    let chunk_size: usize = 1024 * 1024; // 1 MiB
    let mut total_sent = 0u64;

    for chunk in archive_data.chunks(chunk_size) {
        // Write 4-byte length prefix + chunk data
        stream
            .write_all(&(chunk.len() as u32).to_be_bytes())
            .map_err(|e| format!("chunk header write: {}", e))?;
        stream
            .write_all(chunk)
            .map_err(|e| format!("chunk data write: {}", e))?;

        total_sent += chunk.len() as u64;
    }

    // Send EOF marker
    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|e| format!("eof write: {}", e))?;
    stream.flush().map_err(|e| format!("flush: {}", e))?;

    log::info!(
        "Restore data sent: {} bytes for project {}",
        total_sent,
        project_uuid
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
