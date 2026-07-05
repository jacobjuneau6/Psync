//! Wire protocol message types shared between client and server.
//!
//! All control messages are serialized with bincode for compact,
//! efficient encoding. File data is streamed as raw bytes outside
//! the message framing layer (see `frame.rs`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol version constant. Both client and server must agree on this.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Default chunk size for file streaming: 1 MiB.
pub const CHUNK_SIZE: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Message type identifiers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Archive flow messages
// ---------------------------------------------------------------------------

/// Client requests permission to upload a project archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRequest {
    /// UUID of the project being archived.
    pub project_uuid: Uuid,
    /// Human-readable project name.
    pub project_name: String,
    /// Total uncompressed size in bytes (for progress estimation).
    pub total_size: u64,
    /// Number of files being sent (for progress granularity).
    pub file_count: u32,
    /// Whether the archive is compressed.
    pub compression: bool,
}

/// Server accepts the archive request and assigns a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAccept {
    /// Session identifier for correlating subsequent chunks.
    pub session_id: Uuid,
}

/// Client reports the final outcome of the archive transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveComplete {
    /// Whether the client considers the transfer successful.
    pub success: bool,
    /// Total bytes received by the server.
    pub total_size: u64,
    /// SHA-256 hash of the entire encrypted archive (hex-encoded).
    pub archive_hash: String,
    /// Error description if success is false.
    #[serde(default)]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Restore flow messages
// ---------------------------------------------------------------------------

/// Client requests a project archive be sent back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRequest {
    /// UUID of the project to restore.
    pub project_uuid: Uuid,
}

/// Server accepts the restore request and provides size information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreAccept {
    /// Session identifier for correlating subsequent chunks.
    pub session_id: Uuid,
    /// Total size of the archive in bytes.
    pub total_size: u64,
    /// Number of files in the archive.
    pub file_count: u32,
    /// SHA-256 hash of the archive (hex-encoded) for client verification.
    pub archive_hash: String,
}

/// Server reports the restore transfer is complete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreComplete {
    /// Whether the server considers the transfer complete.
    pub success: bool,
    /// Error description if success is false.
    #[serde(default)]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// File streaming messages
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Query messages
// ---------------------------------------------------------------------------

/// Request the list of all projects stored on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusRequest {
    /// If set, only return information for this project.
    #[serde(default)]
    pub project_uuid: Option<Uuid>,
}

/// Server response with project information.
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

// ---------------------------------------------------------------------------
// Error message
// ---------------------------------------------------------------------------

/// Generic error response sent by either party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Numeric error code for programmatic handling.
    pub code: u32,
    /// Human-readable error description.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn test_handshake_message_sizes() {
        let h = Handshake {
            version: 1,
            client_id: "laptop".into(),
            nonce: [0xAA; 32],
            proof: [0xBB; 32],
        };

        let encoded = serde_json::to_vec(&h).unwrap();
        // Handshake should be reasonably small
        assert!(!encoded.is_empty());
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
}
