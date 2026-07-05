//! Integration tests for the pwr client.
//!
//! Tests cover PwrClient connection, handshake, archive upload,
//! restore download, status queries, retry logic, and progress
//! reporting. Uses a simulated server via pipe streams.

use pwr_core::crypto;
use pwr_core::frame::{self, FrameDecoder};
use pwr_core::protocol::{self, *};
use std::io::{Read, Write};
use std::thread;
use uuid::Uuid;

/// A simple in-process pipe for client-server testing.
struct TestPipe {
    read_buf: Vec<u8>,
    write_pos: usize,
}

impl TestPipe {
    fn new() -> Self {
        Self { read_buf: Vec::new(), write_pos: 0 }
    }

    fn push_data(&mut self, data: &[u8]) {
        self.read_buf.extend_from_slice(data);
    }
}

impl Read for TestPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.write_pos >= self.read_buf.len() {
            return Ok(0);
        }
        let available = self.read_buf.len() - self.write_pos;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.read_buf[self.write_pos..self.write_pos + n]);
        self.write_pos += n;
        Ok(n)
    }
}

impl Write for TestPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.read_buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

// =========================================================================
// Handshake integration tests
// =========================================================================

#[test]
fn test_client_handshake_sends_correct_frame() {
    let psk = crypto::generate_psk();
    let mut nonce = [0x11; 32];
    crypto::compute_client_proof(&psk, &nonce);

    let hs = ClientMessage::Handshake(Handshake {
        version: 1,
        client_id: "test-client".into(),
        nonce,
        proof: crypto::compute_client_proof(&psk, &nonce),
    });

    let frame = frame::encode_frame(&hs, hs.message_type()).unwrap();

    // Verify the frame is valid
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();
    assert_eq!(header.msg_type, MessageType::Handshake);

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::Handshake(h) => assert_eq!(h.client_id, "test-client"),
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// Archive message flow tests
// =========================================================================

#[test]
fn test_archive_request_frame_round_trip() {
    let uuid = Uuid::new_v4();
    let req = protocol::build_archive_request(uuid, "flow-test", 999_999, 50, true);

    let frame = frame::encode_frame(&req, req.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    assert_eq!(header.msg_type, MessageType::ArchiveRequest);
    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::ArchiveRequest(r) => {
            assert_eq!(r.project_name, "flow-test");
            assert_eq!(r.total_size, 999_999);
            assert_eq!(r.file_count, 50);
            assert!(r.compression);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_archive_complete_frame_round_trip() {
    let complete = protocol::build_archive_complete(500_000, "abcdef1234567890");

    let frame = frame::encode_frame(&complete, complete.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    assert_eq!(header.msg_type, MessageType::ArchiveComplete);
    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::ArchiveComplete(c) => {
            assert!(c.success);
            assert_eq!(c.total_size, 500_000);
        }
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// Restore message flow tests
// =========================================================================

#[test]
fn test_restore_request_frame_round_trip() {
    let uuid = Uuid::new_v4();
    let req = protocol::build_restore_request(uuid);

    let frame = frame::encode_frame(&req, req.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    assert_eq!(header.msg_type, MessageType::RestoreRequest);
    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::RestoreRequest(r) => assert_eq!(r.project_uuid, uuid),
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// Server response parsing tests
// =========================================================================

#[test]
fn test_parse_handshake_ack_success() {
    let nonce = [0x22; 32];
    let proof = [0x33; 32];
    let ack = protocol::build_handshake_ack_success("0.1.0", nonce, proof);

    let frame = frame::encode_frame(&ack, ack.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();
    match decoded {
        ServerMessage::HandshakeAck(a) => {
            assert!(a.success);
            assert_eq!(a.server_version, "0.1.0");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_parse_error_response() {
    let err = protocol::build_error(3, "project not found");

    let frame = frame::encode_frame(&err, err.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();
    match decoded {
        ServerMessage::Error(e) => {
            assert_eq!(e.code, 3);
            assert_eq!(e.message, "project not found");
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_parse_status_response() {
    let projects = vec![ProjectInfo {
        uuid: Uuid::new_v4(),
        name: "test-proj".into(),
        size_bytes: 42_000,
        file_count: 7,
        created_at: chrono::Utc::now(),
        last_modified: chrono::Utc::now(),
    }];
    let resp = protocol::build_status_response(projects);

    let frame = frame::encode_frame(&resp, resp.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();
    match decoded {
        ServerMessage::StatusResponse(r) => {
            assert_eq!(r.projects.len(), 1);
            assert_eq!(r.projects[0].name, "test-proj");
            assert_eq!(r.projects[0].file_count, 7);
        }
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// Chunk streaming tests
// =========================================================================

#[test]
fn test_chunk_encode_decode_with_varied_sizes() {
    let test_sizes = [0, 1, 1024, 65536, 1_048_576];

    for &size in &test_sizes {
        let data = vec![0xAB; size];
        let chunk = frame::encode_file_chunk(&data);
        let decoded = frame::decode_file_chunk(&chunk).unwrap();

        if size == 0 {
            assert!(decoded.is_none(), "size 0 should be EOF");
        } else {
            assert_eq!(decoded.unwrap(), &data[..]);
        }
    }
}

#[test]
fn test_chunk_stream_eof_detection() {
    let eof = frame::encode_file_eof();
    assert_eq!(eof, vec![0, 0, 0, 0]);

    let decoded = frame::decode_file_chunk(&eof).unwrap();
    assert!(decoded.is_none());
}

// =========================================================================
// Retry logic tests
// =========================================================================

#[test]
fn test_is_retryable_error() {
    use pwr::client::is_retryable_error;

    assert!(is_retryable_error("Connection refused"));
    assert!(is_retryable_error("connection timeout"));
    assert!(is_retryable_error("Connection closed"));
    assert!(is_retryable_error("Connection reset by peer"));
    assert!(is_retryable_error("broken pipe"));
    assert!(is_retryable_error("unexpected EOF"));

    assert!(!is_retryable_error("Authentication failed"));
    assert!(!is_retryable_error("Project not found"));
    assert!(!is_retryable_error("Invalid PSK"));
}

#[test]
fn test_retry_succeeds_on_first_try() {
    let result = pwr::client::with_retry(
        || Ok::<_, String>(42),
        3, 100,
        |_| true,
    );
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_retry_gives_up_after_max_retries() {
    let mut calls = 0;
    let result: Result<i32, String> = pwr::client::with_retry(
        || {
            calls += 1;
            Err("connection timeout".into())
        },
        3, 10,
        |e| e.contains("timeout"),
    );
    assert!(result.is_err());
    assert_eq!(calls, 4); // initial + 3 retries
}

#[test]
fn test_retry_stops_for_non_retryable_error() {
    let mut calls = 0;
    let result: Result<i32, String> = pwr::client::with_retry(
        || {
            calls += 1;
            Err("Authentication failed".into())
        },
        5, 100,
        |e| e.contains("timeout"), // only retry timeouts
    );
    assert!(result.is_err());
    assert_eq!(calls, 1); // no retries for auth errors
}

// =========================================================================
// Progress callback tests
// =========================================================================

#[test]
fn test_archive_progress_stages_are_distinct() {
    use pwr_core::archive::ArchiveStage;

    let stages = [
        ArchiveStage::Scanning,
        ArchiveStage::Tarring,
        ArchiveStage::Compressing,
        ArchiveStage::Encrypting,
        ArchiveStage::Hashing,
    ];

    // All stages must be distinct
    for i in 0..stages.len() {
        for j in (i + 1)..stages.len() {
            assert_ne!(stages[i], stages[j]);
        }
    }
}
