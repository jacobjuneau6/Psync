//! Integration tests for the pwr wire protocol.
//!
//! Tests cover the full message lifecycle: serialization, framing,
//! streaming chunk encoding, error injection, and boundary conditions.
//! No network is required — all tests operate on in-memory data.

use pwr_core::frame::{self, FrameDecoder, HEADER_SIZE};
use pwr_core::protocol::{self, *};
use uuid::Uuid;

// =========================================================================
// Frame encode/decode round-trips
// =========================================================================

#[test]
fn test_frame_round_trip_all_message_types() {
    let archive_req = protocol::build_archive_request(
        Uuid::new_v4(),
        "integration-test",
        1_000_000,
        100,
        true,
    );

    let frame = frame::encode_frame(&archive_req, archive_req.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    assert_eq!(header.version, frame::PROTOCOL_VERSION);
    assert_eq!(header.msg_type, MessageType::ArchiveRequest);

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::ArchiveRequest(req) => {
            assert_eq!(req.project_name, "integration-test");
            assert_eq!(req.total_size, 1_000_000);
            assert_eq!(req.file_count, 100);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_frame_restore_request_round_trip() {
    let uuid = Uuid::new_v4();
    let msg = protocol::build_restore_request(uuid);

    let frame = frame::encode_frame(&msg, msg.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::RestoreRequest(req) => assert_eq!(req.project_uuid, uuid),
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_frame_handshake_round_trip() {
    let hs = ClientMessage::Handshake(Handshake {
        version: 1,
        client_id: "test-laptop".into(),
        nonce: [0xAB; 32],
        proof: [0xCD; 32],
    });

    let frame = frame::encode_frame(&hs, hs.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::Handshake(h) => {
            assert_eq!(h.client_id, "test-laptop");
            assert_eq!(h.version, 1);
        }
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// FrameDecoder buffering behavior
// =========================================================================

#[test]
fn test_decoder_handles_byte_by_byte_arrival() {
    let msg = protocol::build_status_response(vec![ProjectInfo {
        uuid: Uuid::new_v4(),
        name: "byte-test".into(),
        size_bytes: 42,
        file_count: 7,
        created_at: chrono::Utc::now(),
        last_modified: chrono::Utc::now(),
    }]);

    let frame = frame::encode_frame(&msg, msg.message_type()).unwrap();
    let mut decoder = FrameDecoder::new();

    // Feed one byte at a time
    for byte in &frame {
        decoder.push_bytes(&[*byte]);
        match decoder.try_decode() {
            Ok(Some((header, payload))) => {
                let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();
                match decoded {
                    ServerMessage::StatusResponse(resp) => {
                        assert_eq!(resp.projects[0].name, "byte-test");
                        return; // success
                    }
                    _ => panic!("Wrong variant"),
                }
            }
            Ok(None) => continue, // Need more bytes
            Err(e) => panic!("Decode error: {}", e),
        }
    }

    panic!("Frame never completed");
}

#[test]
fn test_decoder_handles_two_frames_in_one_read() {
    let msg1 = protocol::build_archive_request(Uuid::new_v4(), "first", 100, 1, false);
    let msg2 = protocol::build_restore_request(Uuid::new_v4());

    let frame1 = frame::encode_frame(&msg1, msg1.message_type()).unwrap();
    let frame2 = frame::encode_frame(&msg2, msg2.message_type()).unwrap();

    // Concatenate both frames into one buffer
    let mut combined = frame1.clone();
    combined.extend_from_slice(&frame2);

    let mut decoder = FrameDecoder::new();
    decoder.push_bytes(&combined);

    // First frame
    let (h1, p1) = decoder.try_decode().unwrap().unwrap();
    let decoded1 = protocol::decode_client_message(h1.msg_type, &p1).unwrap();
    assert!(matches!(decoded1, ClientMessage::ArchiveRequest(_)));

    // Second frame
    let (h2, p2) = decoder.try_decode().unwrap().unwrap();
    let decoded2 = protocol::decode_client_message(h2.msg_type, &p2).unwrap();
    assert!(matches!(decoded2, ClientMessage::RestoreRequest(_)));

    // Buffer should be empty
    assert_eq!(decoder.buffered_len(), 0);
}

// =========================================================================
// Error injection
// =========================================================================

#[test]
fn test_bad_magic_bytes_rejected() {
    let mut data = vec![0x00; HEADER_SIZE + 10];
    data[0] = 0xBA;
    data[1] = 0xAD;

    let result = frame::decode_frame(&data);
    assert!(result.is_err());
}

#[test]
fn test_truncated_frame_header_returns_none() {
    // Only 5 bytes of a 10-byte header
    let data = vec![0x50, 0x57, 0x52, 0x46, 0x00];
    let result = frame::decode_frame(&data).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_oversized_payload_rejected() {
    let mut header = Vec::new();
    header.extend_from_slice(&frame::FRAME_MAGIC);
    // Claim a payload larger than 16 MiB
    header.extend_from_slice(&((frame::MAX_FRAME_SIZE as u32 + 1).to_be_bytes()));
    header.push(frame::PROTOCOL_VERSION);
    header.push(MessageType::Error as u8);

    let result = frame::decode_frame(&header);
    assert!(result.is_err());
}

#[test]
fn test_wrong_version_rejected() {
    let msg = protocol::build_error(1, "test");
    let mut frame = frame::encode_frame(&msg, msg.message_type()).unwrap();

    // Corrupt the version byte (offset 8)
    frame[8] = 0xFF;

    let result = frame::decode_frame(&frame);
    assert!(result.is_err());
}

#[test]
fn test_unknown_message_type_rejected() {
    let mut header = Vec::new();
    header.extend_from_slice(&frame::FRAME_MAGIC);
    header.extend_from_slice(&10u32.to_be_bytes()); // 10-byte payload
    header.push(frame::PROTOCOL_VERSION);
    header.push(0xEE); // Unknown message type byte
    header.extend_from_slice(&[0u8; 10]); // Dummy payload

    let result = frame::decode_frame(&header);
    assert!(result.is_err());
}

// =========================================================================
// File chunk streaming
// =========================================================================

#[test]
fn test_file_chunk_encode_decode_exact() {
    // Single chunk exactly 1 MiB
    let data = vec![0x42; 1024 * 1024];
    let chunk = frame::encode_file_chunk(&data);
    let decoded = frame::decode_file_chunk(&chunk).unwrap();
    assert_eq!(decoded, Some(&data[..]));
}

#[test]
fn test_file_chunk_empty_data_is_eof() {
    // An empty chunk (length 0) is indistinguishable from the EOF marker.
    // This is by design — there is no reason to send an empty file chunk.
    let chunk = frame::encode_file_chunk(&[]);
    let decoded = frame::decode_file_chunk(&chunk).unwrap();
    assert!(decoded.is_none(), "zero-length chunk is treated as EOF");
}

#[test]
fn test_file_chunk_zero_length_is_eof() {
    let eof = frame::encode_file_eof();
    let decoded = frame::decode_file_chunk(&eof).unwrap();
    assert!(decoded.is_none());
}

#[test]
fn test_multiple_chunks_reassemble_correctly() {
    let original: Vec<u8> = (0..255).cycle().take(500_000).collect();

    let mut reassembled = Vec::new();
    for chunk_data in original.chunks(4096) {
        let encoded = frame::encode_file_chunk(chunk_data);
        let decoded = frame::decode_file_chunk(&encoded).unwrap().unwrap();
        reassembled.extend_from_slice(decoded);
    }

    assert_eq!(reassembled, original);
}

// =========================================================================
// ClientMessage/ServerMessage enum serialization
// =========================================================================

#[test]
fn test_all_client_messages_serialize() {
    let uuid = Uuid::new_v4();
    let messages: Vec<ClientMessage> = vec![
        ClientMessage::Handshake(Handshake {
            version: 1,
            client_id: "test".into(),
            nonce: [0; 32],
            proof: [0; 32],
        }),
        protocol::build_archive_request(uuid, "test", 100, 1, false),
        protocol::build_archive_complete(100, "abcdef"),
        protocol::build_restore_request(uuid),
        ClientMessage::StatusRequest(StatusRequest { project_uuid: None }),
    ];

    for msg in &messages {
        let encoded = serde_json::to_vec(msg).unwrap();
        let decoded: ClientMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(msg.message_type(), decoded.message_type());
    }
}

#[test]
fn test_all_server_messages_serialize() {
    let messages: Vec<ServerMessage> = vec![
        protocol::build_handshake_ack_success("1.0", [0; 32], [0; 32]),
        protocol::build_handshake_ack_failed("bad proof"),
        protocol::build_archive_accept(Uuid::new_v4()),
        protocol::build_restore_accept(Uuid::new_v4(), 100, 5, "hash"),
        protocol::build_restore_complete(),
        protocol::build_status_response(vec![]),
        protocol::build_error(1, "test error"),
    ];

    for msg in &messages {
        let encoded = serde_json::to_vec(msg).unwrap();
        let decoded: ServerMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(msg.message_type(), decoded.message_type());
    }
}

// =========================================================================
// Boundary conditions
// =========================================================================

#[test]
fn test_empty_project_info_list() {
    let response = protocol::build_status_response(vec![]);
    let frame = frame::encode_frame(&response, response.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();
    match decoded {
        ServerMessage::StatusResponse(resp) => assert!(resp.projects.is_empty()),
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_max_size_frame() {
    // Create a payload close to but under 16 MiB
    let big_name = "x".repeat(100_000);
    let response = protocol::build_status_response(vec![ProjectInfo {
        uuid: Uuid::new_v4(),
        name: big_name,
        size_bytes: u64::MAX,
        file_count: u32::MAX,
        created_at: chrono::Utc::now(),
        last_modified: chrono::Utc::now(),
    }]);

    let frame = frame::encode_frame(&response, response.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();
    let decoded = protocol::decode_server_message(header.msg_type, &payload).unwrap();

    match decoded {
        ServerMessage::StatusResponse(resp) => {
            assert_eq!(resp.projects[0].size_bytes, u64::MAX);
            assert_eq!(resp.projects[0].file_count, u32::MAX);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_decode_client_message_rejects_server_type() {
    // A server Error message should not decode as a client message
    let err = protocol::build_error(5, "protocol violation");
    let encoded = serde_json::to_vec(&err).unwrap();

    let result = protocol::decode_client_message(MessageType::Error, &encoded);
    assert!(result.is_err());
}

#[test]
fn test_decode_server_message_rejects_client_type() {
    let hs = ClientMessage::Handshake(Handshake {
        version: 1,
        client_id: "bad".into(),
        nonce: [0; 32],
        proof: [0; 32],
    });
    let encoded = serde_json::to_vec(&hs).unwrap();

    let result = protocol::decode_server_message(MessageType::Handshake, &encoded);
    assert!(result.is_err());
}
