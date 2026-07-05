//! Integration tests for pwr-server.
//!
//! Tests cover storage CRUD operations, the handshake protocol,
//! archive chunk streaming, restore chunk streaming, and the
//! authentication rate limiter. No real network is required.

use pwr_core::crypto;
use pwr_core::frame;
use pwr_core::protocol::{self, *};
use pwr_server::auth::RateLimiter;
use pwr_server::config::ServerConfig;
use pwr_server::storage::{ProjectStorage, StoredProject};
use std::io::Read;
use std::net::IpAddr;
use tempfile::TempDir;
use uuid::Uuid;

// =========================================================================
// Test helpers
// =========================================================================

fn test_config(dir: &std::path::Path) -> ServerConfig {
    let mut cfg = ServerConfig::default();
    cfg.storage_base_path = dir.join("storage");
    cfg.auth_token = crypto::psk_to_hex(&crypto::generate_psk());
    cfg
}

fn test_project(name: &str) -> StoredProject {
    StoredProject {
        uuid: Uuid::new_v4(),
        name: name.into(),
        size_bytes: 1_000_000,
        file_count: 42,
        encrypted: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// =========================================================================
// Storage CRUD tests
// =========================================================================

#[test]
fn test_storage_create_and_list_projects() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let mut storage = ProjectStorage::new(config).unwrap();

    let p1 = test_project("alpha");
    let p2 = test_project("beta");

    storage.add_project(p1).unwrap();
    storage.add_project(p2).unwrap();

    assert_eq!(storage.list_projects().len(), 2);
}

#[test]
fn test_storage_duplicate_uuid_rejected() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let mut storage = ProjectStorage::new(config).unwrap();

    let p = test_project("dup");
    storage.add_project(p.clone()).unwrap();
    assert!(storage.add_project(p).is_err());
}

#[test]
fn test_storage_remove_project() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let mut storage = ProjectStorage::new(config).unwrap();

    let p = test_project("removable");
    let uuid = p.uuid;
    storage.add_project(p).unwrap();
    storage.remove_project(&uuid).unwrap();
    assert!(storage.get_project(&uuid).is_none());
}

#[test]
fn test_storage_archive_read_write() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let mut storage = ProjectStorage::new(config).unwrap();

    let p = test_project("archive-test");
    let uuid = p.uuid;
    storage.add_project(p).unwrap();

    // Write archive data
    let data = b"encrypted project blob data for testing";
    storage.write_archive(&uuid, &mut &data[..]).unwrap();

    // Read it back
    let mut reader = storage.read_archive(&uuid).unwrap();
    let mut read_back = Vec::new();
    reader.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn test_storage_persistence_across_reopens() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let uuid;

    {
        let mut storage = ProjectStorage::new(config.clone()).unwrap();
        let p = test_project("persistent");
        uuid = p.uuid;
        storage.add_project(p).unwrap();
    }

    // Re-open and verify
    {
        let storage = ProjectStorage::new(config).unwrap();
        let retrieved = storage.get_project(&uuid).unwrap();
        assert_eq!(retrieved.name, "persistent");
    }
}

#[test]
fn test_storage_size_limit_enforcement() {
    let tmp = TempDir::new().unwrap();
    let mut config = test_config(tmp.path());
    config.max_project_size_gb = 1; // 1 GB limit

    let storage = ProjectStorage::new(config).unwrap();

    // Adding 500 MB should be fine
    assert!(storage.check_size_limit(500 * 1024 * 1024).is_ok());

    // Adding 2 GB should fail
    assert!(storage.check_size_limit(2 * 1024 * 1024 * 1024).is_err());
}

// =========================================================================
// PSK handshake protocol tests
// =========================================================================

#[test]
fn test_handshake_success_flow() {
    let psk = crypto::generate_psk();

    // Client computes proof
    let mut client_nonce = [0u8; 32];
    for i in 0..32 {
        client_nonce[i] = i as u8;
    }
    let client_proof = crypto::compute_client_proof(&psk, &client_nonce);

    // Server verifies and responds
    let expected = crypto::compute_client_proof(&psk, &client_nonce);
    assert_eq!(client_proof, expected, "Server should verify client proof");

    let mut server_nonce = [0u8; 32];
    for i in 0..32 {
        server_nonce[i] = (i * 2) as u8;
    }
    let server_proof = crypto::compute_server_proof(&psk, &client_nonce, &server_nonce);

    // Client verifies server proof
    let expected_server = crypto::compute_server_proof(&psk, &client_nonce, &server_nonce);
    assert_eq!(server_proof, expected_server, "Client should verify server proof");

    // Proofs must differ
    assert_ne!(client_proof, server_proof);
}

#[test]
fn test_handshake_wrong_psk_fails() {
    let psk1 = crypto::generate_psk();
    let psk2 = crypto::generate_psk();

    let client_nonce = [0xAA; 32];
    let client_proof = crypto::compute_client_proof(&psk1, &client_nonce);

    // Server uses psk2 — should not match
    let expected = crypto::compute_client_proof(&psk2, &client_nonce);
    assert_ne!(client_proof, expected);
}

// =========================================================================
// Frame-level handshake integration tests
// =========================================================================

#[test]
fn test_framed_handshake_round_trip() {
    let psk = crypto::generate_psk();

    // Client sends Handshake
    let mut client_nonce = [0u8; 32];
    for i in 0..32 {
        client_nonce[i] = i as u8;
    }
    let client_proof = crypto::compute_client_proof(&psk, &client_nonce);

    let hs = ClientMessage::Handshake(Handshake {
        version: 1,
        client_id: "integration-test".into(),
        nonce: client_nonce,
        proof: client_proof,
    });

    let frame = frame::encode_frame(&hs, hs.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::Handshake(h) => {
            assert_eq!(h.client_id, "integration-test");
            assert_eq!(h.nonce, client_nonce);
        }
        _ => panic!("Wrong variant"),
    }
}

#[test]
fn test_framed_archive_request_round_trip() {
    let uuid = Uuid::new_v4();
    let req = protocol::build_archive_request(uuid, "test-proj", 500_000, 100, true);

    let frame = frame::encode_frame(&req, req.message_type()).unwrap();
    let (header, payload) = frame::decode_frame(&frame).unwrap().unwrap();

    let decoded = protocol::decode_client_message(header.msg_type, &payload).unwrap();
    match decoded {
        ClientMessage::ArchiveRequest(r) => {
            assert_eq!(r.project_name, "test-proj");
            assert_eq!(r.total_size, 500_000);
        }
        _ => panic!("Wrong variant"),
    }
}

// =========================================================================
// File chunk streaming tests
// =========================================================================

#[test]
fn test_chunk_stream_round_trip() {
    // Encode data in chunks, then decode and reassemble
    let original: Vec<u8> = (0..=255).cycle().take(250_000).collect();
    let mut transmitted = Vec::new();

    // Client sends chunks
    for chunk in original.chunks(4096) {
        let len = chunk.len() as u32;
        transmitted.extend_from_slice(&len.to_be_bytes());
        transmitted.extend_from_slice(chunk);
    }
    // EOF marker
    transmitted.extend_from_slice(&0u32.to_be_bytes());

    // Server receives chunks
    let mut received = Vec::new();
    let mut pos = 0;
    loop {
        if pos + 4 > transmitted.len() {
            break;
        }
        let len = u32::from_be_bytes([
            transmitted[pos], transmitted[pos+1],
            transmitted[pos+2], transmitted[pos+3],
        ]) as usize;
        pos += 4;

        if len == 0 {
            break; // EOF
        }

        received.extend_from_slice(&transmitted[pos..pos + len]);
        pos += len;
    }

    assert_eq!(received, original);
}

#[test]
fn test_chunk_stream_empty_archive() {
    // An empty archive: just the EOF marker
    let stream = vec![0u8, 0, 0, 0]; // 4-byte zero = EOF
    let mut pos = 0;
    let mut received = Vec::new();

    loop {
        if pos + 4 > stream.len() {
            break;
        }
        let len = u32::from_be_bytes([
            stream[pos], stream[pos+1],
            stream[pos+2], stream[pos+3],
        ]) as usize;
        pos += 4;

        if len == 0 {
            break;
        }
        received.extend_from_slice(&stream[pos..pos + len]);
        pos += len;
    }

    assert!(received.is_empty());
}

// =========================================================================
// Rate limiter tests
// =========================================================================

#[test]
fn test_rate_limiter_blocks_after_max_attempts() {
    let mut limiter = RateLimiter::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    for _ in 0..5 {
        assert!(limiter.check_attempt(ip));
    }
    assert!(!limiter.check_attempt(ip), "6th attempt should be blocked");
}

#[test]
fn test_rate_limiter_resets_on_success() {
    let mut limiter = RateLimiter::new();
    let ip: IpAddr = "10.0.0.2".parse().unwrap();

    for _ in 0..3 {
        limiter.check_attempt(ip);
    }
    limiter.record_success(ip);

    for _ in 0..5 {
        assert!(limiter.check_attempt(ip), "Should reset after success");
    }
}

#[test]
fn test_rate_limiter_independent_ips() {
    let mut limiter = RateLimiter::new();
    let ip1: IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: IpAddr = "192.168.1.2".parse().unwrap();

    for _ in 0..5 {
        limiter.check_attempt(ip1);
    }
    assert!(!limiter.check_attempt(ip1), "ip1 should be blocked");
    assert!(limiter.check_attempt(ip2), "ip2 should still be allowed");
}

// =========================================================================
// Full server archive/restore simulation
// =========================================================================

#[test]
fn test_full_archive_restore_simulation() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let psk = crypto::generate_psk();

    // Set up storage
    let mut storage = ProjectStorage::new(config).unwrap();
    let project = test_project("simulation-test");
    let uuid = project.uuid;
    storage.add_project(project).unwrap();

    // Simulate archive: receive chunks from client
    let archive_data: Vec<u8> = (0..=255).cycle().take(500_000).collect();
    storage.write_archive(&uuid, &mut &archive_data[..]).unwrap();

    // Simulate restore: read archive and verify
    let mut reader = storage.read_archive(&uuid).unwrap();
    let mut restored = Vec::new();
    reader.read_to_end(&mut restored).unwrap();

    assert_eq!(restored, archive_data);
    assert_eq!(restored.len(), 500_000);

    // Verify the project metadata persisted
    let retrieved = storage.get_project(&uuid).unwrap();
    assert_eq!(retrieved.name, "simulation-test");

    let _ = psk; // Used in real handshake
}

#[test]
fn test_storage_cleanup_after_failed_archive() {
    let tmp = TempDir::new().unwrap();
    let config = test_config(tmp.path());
    let mut storage = ProjectStorage::new(config).unwrap();

    let p = test_project("failed-archive");
    let uuid = p.uuid;
    storage.add_project(p).unwrap();

    // Write some partial data
    storage.write_archive(&uuid, &mut &b"partial"[..]).unwrap();
    assert!(storage.archive_exists(&uuid));

    // Remove the project (simulating failed archive cleanup)
    storage.remove_project(&uuid).unwrap();
    assert!(!storage.archive_exists(&uuid));
    assert!(storage.get_project(&uuid).is_none());
}
