//! Wire protocol message types shared between client and server.
//!
//! Control messages are serialized as JSON in framed envelopes (see `frame.rs`).
//! File data is streamed as raw bytes outside the framing layer.
//!
//! ## Message flow
//!
//! ```text
//! Client                                 Server
//!   |                                      |
//!   |--- Handshake ----------------------->|
//!   |<-- HandshakeAck ---------------------|
//!   |                                      |
//!   |--- ArchiveRequest ------------------>|
//!   |<-- ArchiveAccept --------------------|
//!   |--- [FileHeader + raw chunks]* ------>|
//!   |--- ArchiveComplete ----------------->|
//!   |                                      |
//!   |--- RestoreRequest ------------------>|
//!   |<-- RestoreAccept --------------------|
//!   |<-- [FileHeader + raw chunks]* -------|
//!   |<-- RestoreComplete ------------------|
//!   |                                      |
//!   |--- StatusRequest ------------------->|
//!   |<-- StatusResponse -------------------|
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{PwrError, Result};

/// Protocol version constant. Both client and server must agree on this.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Default chunk size for file streaming: 1 MiB.
pub const CHUNK_SIZE: usize = 1024 * 1024;

// =========================================================================
// Message type identifiers
// =========================================================================

/// Identifies the type of a protocol message in the frame header.
///
/// Each variant corresponds to a payload struct below. The discriminants
/// are assigned explicitly so they remain stable across code changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // Handshake
    Handshake = 0x01,
    HandshakeAck = 0x02,

    // Archive flow (client → server)
    ArchiveRequest = 0x10,
    ArchiveAccept = 0x11,
    ArchiveComplete = 0x12,

    // Restore flow (client → server)
    RestoreRequest = 0x20,
    RestoreAccept = 0x21,
    RestoreComplete = 0x22,

    // File streaming
    FileHeader = 0x30,
    FileEnd = 0x31,

    // Query
    StatusRequest = 0x40,
    StatusResponse = 0x41,

    // Generic
    Error = 0xFF,
}

impl MessageType {
    /// Convert from the byte stored in the frame header.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::HandshakeAck),
            0x10 => Some(Self::ArchiveRequest),
            0x11 => Some(Self::ArchiveAccept),
            0x12 => Some(Self::ArchiveComplete),
            0x20 => Some(Self::RestoreRequest),
            0x21 => Some(Self::RestoreAccept),
            0x22 => Some(Self::RestoreComplete),
            0x30 => Some(Self::FileHeader),
            0x31 => Some(Self::FileEnd),
            0x40 => Some(Self::StatusRequest),
            0x41 => Some(Self::StatusResponse),
            0xFF => Some(Self::Error),
            _ => None,
        }
    }
}

// =========================================================================
// Unified message enums — each variant wraps the corresponding payload struct
// =========================================================================

/// All messages a client can send to the server.
///
/// Serialization is delegated to the inner struct; this enum exists
/// for type-safe dispatch in the handler state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Handshake(Handshake),
    ArchiveRequest(ArchiveRequest),
    ArchiveComplete(ArchiveComplete),
    RestoreRequest(RestoreRequest),
    StatusRequest(StatusRequest),
}

impl ClientMessage {
    /// Return the MessageType discriminant for this variant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Handshake(_) => MessageType::Handshake,
            Self::ArchiveRequest(_) => MessageType::ArchiveRequest,
            Self::ArchiveComplete(_) => MessageType::ArchiveComplete,
            Self::RestoreRequest(_) => MessageType::RestoreRequest,
            Self::StatusRequest(_) => MessageType::StatusRequest,
        }
    }
}

/// All messages a server can send to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    HandshakeAck(HandshakeAck),
    ArchiveAccept(ArchiveAccept),
    RestoreAccept(RestoreAccept),
    RestoreComplete(RestoreComplete),
    StatusResponse(StatusResponse),
    Error(ErrorMessage),
}

impl ServerMessage {
    /// Return the MessageType discriminant for this variant.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::HandshakeAck(_) => MessageType::HandshakeAck,
            Self::ArchiveAccept(_) => MessageType::ArchiveAccept,
            Self::RestoreAccept(_) => MessageType::RestoreAccept,
            Self::RestoreComplete(_) => MessageType::RestoreComplete,
            Self::StatusResponse(_) => MessageType::StatusResponse,
            Self::Error(_) => MessageType::Error,
        }
    }
}

// =========================================================================
// Handshake messages
// =========================================================================

/// Sent by the client immediately after the TLS handshake completes.
///
/// Contains a random nonce and an HMAC-SHA256 proof computed over the
/// nonce and the pre-shared key, authenticating the client to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    /// Protocol version the client speaks.
    pub version: u8,
    /// Human-readable client identifier (hostname or user-supplied name).
    pub client_id: String,
    /// 32-byte random nonce generated fresh for this connection.
    pub nonce: [u8; 32],
    /// HMAC-SHA256(nonce || "pwr-auth-v1", PSK).
    pub proof: [u8; 32],
}

/// Server response to a Handshake message.
///
/// Contains its own nonce and proof so the client can mutually
/// authenticate the server (prevents impersonation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// Whether authentication succeeded.
    pub success: bool,
    /// Server version string (informational).
    pub server_version: String,
    /// 32-byte server nonce for mutual authentication.
    pub server_nonce: [u8; 32],
    /// HMAC-SHA256(client_nonce || server_nonce || "pwr-auth-v1", PSK).
    pub server_proof: [u8; 32],
    /// Human-readable reason if success is false.
    #[serde(default)]
    pub reason: Option<String>,
}

// =========================================================================
// Archive flow messages (client → server direction, server acks)
// =========================================================================

/// Client requests permission to upload a project archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRequest {
    /// UUID of the project being archived.
    pub project_uuid: Uuid,
    /// Human-readable project name.
    pub project_name: String,
    /// Total size of the encrypted archive in bytes.
    pub total_size: u64,
    /// Number of files in the project (for progress granularity).
    pub file_count: u32,
    /// Whether the archive is compressed.
    pub compression: bool,
}

/// Server accepts the archive request and assigns a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAccept {
    /// Session identifier for correlating subsequent file chunks.
    pub session_id: Uuid,
}

/// Client reports the final outcome of the archive transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveComplete {
    /// Whether the client considers the transfer successful.
    pub success: bool,
    /// Total bytes received by the server.
    pub total_size: u64,
    /// SHA-256 hash of the encrypted archive (hex-encoded).
    pub archive_hash: String,
    /// Error description if success is false.
    #[serde(default)]
    pub error: Option<String>,
}

// =========================================================================
// Restore flow messages (client requests, server streams back)
// =========================================================================

/// Client requests a project archive be sent back for restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// UUID of the project to restore.
    pub project_uuid: Uuid,
}

/// Server accepts the restore request and provides metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreAccept {
    /// Session identifier for correlating subsequent file chunks.
    pub session_id: Uuid,
    /// Total size of the encrypted archive in bytes.
    pub total_size: u64,
    /// Number of files in the archive.
    pub file_count: u32,
    /// SHA-256 hash of the archive (hex-encoded) for client-side
    /// integrity verification after download.
    pub archive_hash: String,
}

/// Server reports the restore transfer is complete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreComplete {
    /// Whether the server considers the transfer successful.
    pub success: bool,
    /// Error description if success is false.
    #[serde(default)]
    pub error: Option<String>,
}

// =========================================================================
// File streaming messages (used by both archive and restore)
// =========================================================================

/// Metadata for a single file within a project archive.
///
/// Sent before the file's raw content bytes. The receiver uses this
/// to create the correct directory structure and allocate space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    /// Relative path within the project (e.g., "src/main.rs").
    /// Uses forward slashes regardless of platform.
    pub rel_path: String,
    /// File size in bytes (0 for empty files).
    pub size: u64,
    /// Unix file mode bits (e.g., 0o644 for regular files).
    pub mode: u32,
}

/// Sent after a file's content has been fully streamed.
///
/// Carries the SHA-256 hash of the file content so the receiver
/// can verify integrity before acknowledging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEnd {
    /// SHA-256 hash of the file content (hex-encoded).
    pub checksum: String,
}

// =========================================================================
// Query messages
// =========================================================================

/// Request project information from the server.
/// An empty request returns all projects; provide a UUID to query one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    /// If set, only return information for this project.
    #[serde(default)]
    pub project_uuid: Option<Uuid>,
}

/// Server response with matching project information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// List of projects matching the request.
    pub projects: Vec<ProjectInfo>,
}

/// Summary information about a stored project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    /// Project UUID.
    pub uuid: Uuid,
    /// Human-readable name.
    pub name: String,
    /// Total size in bytes of the stored archive.
    pub size_bytes: u64,
    /// Number of files in the project.
    pub file_count: u32,
    /// When the project was first archived.
    pub created_at: DateTime<Utc>,
    /// When the project was last modified (archived or restored).
    pub last_modified: DateTime<Utc>,
}

// =========================================================================
// Error message
// =========================================================================

/// Generic error response sent by either party on protocol violations,
/// authentication failures, or storage errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Numeric error code for programmatic handling:
    /// 1 = authentication failed, 2 = framing error, 3 = not found,
    /// 4 = storage full, 5 = protocol violation.
    pub code: u32,
    /// Human-readable error description.
    pub message: String,
}

// =========================================================================
// Deserialization helpers
// =========================================================================

/// Deserialize a client message from raw frame payload bytes.
pub fn decode_client_message(msg_type: MessageType, payload: &[u8]) -> Result<ClientMessage> {
    match msg_type {
        MessageType::Handshake => {
            let m: Handshake = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad Handshake: {}", e)))?;
            Ok(ClientMessage::Handshake(m))
        }
        MessageType::ArchiveRequest => {
            let m: ArchiveRequest = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad ArchiveRequest: {}", e)))?;
            Ok(ClientMessage::ArchiveRequest(m))
        }
        MessageType::ArchiveComplete => {
            let m: ArchiveComplete = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad ArchiveComplete: {}", e)))?;
            Ok(ClientMessage::ArchiveComplete(m))
        }
        MessageType::RestoreRequest => {
            let m: RestoreRequest = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad RestoreRequest: {}", e)))?;
            Ok(ClientMessage::RestoreRequest(m))
        }
        MessageType::StatusRequest => {
            let m: StatusRequest = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad StatusRequest: {}", e)))?;
            Ok(ClientMessage::StatusRequest(m))
        }
        other => Err(PwrError::Protocol(format!(
            "Expected client message, got server message type {:?}", other
        ))),
    }
}

/// Deserialize a server message from raw frame payload bytes.
pub fn decode_server_message(msg_type: MessageType, payload: &[u8]) -> Result<ServerMessage> {
    match msg_type {
        MessageType::HandshakeAck => {
            let m: HandshakeAck = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad HandshakeAck: {}", e)))?;
            Ok(ServerMessage::HandshakeAck(m))
        }
        MessageType::ArchiveAccept => {
            let m: ArchiveAccept = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad ArchiveAccept: {}", e)))?;
            Ok(ServerMessage::ArchiveAccept(m))
        }
        MessageType::RestoreAccept => {
            let m: RestoreAccept = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad RestoreAccept: {}", e)))?;
            Ok(ServerMessage::RestoreAccept(m))
        }
        MessageType::RestoreComplete => {
            let m: RestoreComplete = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad RestoreComplete: {}", e)))?;
            Ok(ServerMessage::RestoreComplete(m))
        }
        MessageType::StatusResponse => {
            let m: StatusResponse = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad StatusResponse: {}", e)))?;
            Ok(ServerMessage::StatusResponse(m))
        }
        MessageType::Error => {
            let m: ErrorMessage = serde_json::from_slice(payload)
                .map_err(|e| PwrError::Framing(format!("bad ErrorMessage: {}", e)))?;
            Ok(ServerMessage::Error(m))
        }
        other => Err(PwrError::Protocol(format!(
            "Expected server message, got client message type {:?}", other
        ))),
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_round_trip() {
        let variants = [
            MessageType::Handshake,
            MessageType::HandshakeAck,
            MessageType::ArchiveRequest,
            MessageType::ArchiveAccept,
            MessageType::ArchiveComplete,
            MessageType::RestoreRequest,
            MessageType::RestoreAccept,
            MessageType::RestoreComplete,
            MessageType::FileHeader,
            MessageType::FileEnd,
            MessageType::StatusRequest,
            MessageType::StatusResponse,
            MessageType::Error,
        ];

        for v in &variants {
            let byte = *v as u8;
            let decoded = MessageType::from_byte(byte);
            assert_eq!(decoded, Some(*v));
        }
    }

    #[test]
    fn test_invalid_message_type() {
        assert_eq!(MessageType::from_byte(0x00), None);
        assert_eq!(MessageType::from_byte(0x99), None);
    }

    #[test]
    fn test_archive_request_serialization() {
        let req = ArchiveRequest {
            project_uuid: Uuid::new_v4(),
            project_name: "testproj".into(),
            total_size: 1_048_576,
            file_count: 42,
            compression: true,
        };

        let encoded = serde_json::to_vec(&req).unwrap();
        let decoded: ArchiveRequest = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.project_name, "testproj");
        assert_eq!(decoded.file_count, 42);
        assert!(decoded.compression);
    }

    #[test]
    fn test_client_message_round_trip() {
        let msg = ClientMessage::ArchiveRequest(ArchiveRequest {
            project_uuid: Uuid::new_v4(),
            project_name: "roundtrip".into(),
            total_size: 5000,
            file_count: 10,
            compression: false,
        });

        let encoded = serde_json::to_vec(&msg).unwrap();
        let decoded: ClientMessage = serde_json::from_slice(&encoded).unwrap();

        match decoded {
            ClientMessage::ArchiveRequest(req) => {
                assert_eq!(req.project_name, "roundtrip");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_server_message_round_trip() {
        let msg = ServerMessage::Error(ErrorMessage {
            code: 3,
            message: "project not found".into(),
        });

        let encoded = serde_json::to_vec(&msg).unwrap();
        let decoded: ServerMessage = serde_json::from_slice(&encoded).unwrap();

        match decoded {
            ServerMessage::Error(e) => {
                assert_eq!(e.code, 3);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_decode_client_message_wrong_type() {
        // Passing a server message type should error
        let payload = serde_json::to_vec(&ErrorMessage { code: 1, message: "err".into() }).unwrap();
        let result = decode_client_message(MessageType::Error, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_server_message_wrong_type() {
        let payload = serde_json::to_vec(&Handshake {
            version: 1,
            client_id: "x".into(),
            nonce: [0; 32],
            proof: [0; 32],
        }).unwrap();
        let result = decode_server_message(MessageType::Handshake, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_project_info_timestamps() {
        let info = ProjectInfo {
            uuid: Uuid::new_v4(),
            name: "test".into(),
            size_bytes: 1000,
            file_count: 10,
            created_at: Utc::now(),
            last_modified: Utc::now(),
        };

        let encoded = serde_json::to_vec(&info).unwrap();
        let decoded: ProjectInfo = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded.name, "test");
        assert_eq!(decoded.size_bytes, 1000);
    }

    #[test]
    fn test_client_message_type_mapping() {
        let msg = ClientMessage::Handshake(Handshake {
            version: 1,
            client_id: "test".into(),
            nonce: [0; 32],
            proof: [0; 32],
        });
        assert_eq!(msg.message_type(), MessageType::Handshake);

        let msg = ClientMessage::StatusRequest(StatusRequest { project_uuid: None });
        assert_eq!(msg.message_type(), MessageType::StatusRequest);
    }

    #[test]
    fn test_server_message_type_mapping() {
        let msg = ServerMessage::HandshakeAck(HandshakeAck {
            success: true,
            server_version: "0.1.0".into(),
            server_nonce: [0; 32],
            server_proof: [0; 32],
            reason: None,
        });
        assert_eq!(msg.message_type(), MessageType::HandshakeAck);

        let msg = ServerMessage::Error(ErrorMessage { code: 1, message: "oops".into() });
        assert_eq!(msg.message_type(), MessageType::Error);
    }
}
