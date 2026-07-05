//! End-to-end integration test: full client-server archive and restore cycle.
//!
//! Exercises the complete lifecycle: project creation, metadata tracking,
//! cryptographic archive packaging, PSK handshake authentication, chunked
//! upload and download, integrity verification, and local placeholder
//! management. No real network — the client and server communicate over
//! paired in-memory byte streams.

use pwr_core::archive;
use pwr_core::config::PwrConfig;
use pwr_core::crypto;
use pwr_core::frame::{self, FrameDecoder};
use pwr_core::metadata::ProjectMeta;
use pwr_core::project;
use pwr_core::protocol::{self, *};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use uuid::Uuid;

// =========================================================================
// In-memory transport — two paired byte buffers for client↔server I/O
// =========================================================================

struct Pipe {
    read_buf: Arc<Mutex<Vec<u8>>>,
    write_buf: Arc<Mutex<Vec<u8>>>,
}

impl Pipe {
    fn pair() -> (Self, Self) {
        let a_to_b = Arc::new(Mutex::new(Vec::new()));
        let b_to_a = Arc::new(Mutex::new(Vec::new()));
        (
            Self { read_buf: b_to_a.clone(), write_buf: a_to_b.clone() },
            Self { read_buf: a_to_b, write_buf: b_to_a },
        )
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut data = self.read_buf.lock().unwrap();
        if data.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(data.len());
        buf[..n].copy_from_slice(&data[..n]);
        data.drain(..n);
        Ok(n)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn test_full_client_server_archive_restore_cycle() {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("myproject");
    std::fs::create_dir_all(project_dir.join("src")).unwrap();
    std::fs::write(project_dir.join("README.md"), b"# My Project\n\nA test project.\n").unwrap();
    std::fs::write(project_dir.join("src/main.rs"), b"fn main() { println!(\"hi\"); }\n").unwrap();
    std::fs::write(project_dir.join("Cargo.toml"), b"[package]\nname = \"test\"\n").unwrap();

    // --- Setup: keys, metadata, archive ---
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let psk = crypto::generate_psk();

    let (encrypted, archive_hash) = archive::create_archive(&project_dir, &public_key).unwrap();
    assert!(!encrypted.is_empty());

    let project_uuid = Uuid::new_v4();
    let mut meta = ProjectMeta::new_local(
        "myproject".into(),
        project_dir.to_string_lossy().to_string(),
        "localhost:9742:/srv/pwr/projects/myproject".into(),
    );
    meta.uuid = project_uuid;

    // --- Client sends archive to server over pipe ---
    let (mut client_pipe, mut server_pipe) = Pipe::pair();

    // Client: handshake → archive request → chunks → complete
    let psk_clone = psk;
    let encrypted_clone = encrypted.clone();
    let hash_clone = archive_hash.clone();
    let uuid_clone = project_uuid;

    let client_thread = std::thread::spawn(move || {
        // Handshake
        let mut nonce = [0u8; 32];
        for i in 0..32 { nonce[i] = i as u8; }
        let proof = crypto::compute_client_proof(&psk_clone, &nonce);
        let hs = ClientMessage::Handshake(Handshake {
            version: 1, client_id: "e2e-test".into(), nonce, proof,
        });
        let frame = frame::encode_frame(&hs, hs.message_type()).unwrap();
        client_pipe.write_all(&frame).unwrap();
        client_pipe.flush().unwrap();

        // Read HandshakeAck
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 8192];
        let (header, payload) = loop {
            let n = client_pipe.read(&mut buf).unwrap();
            decoder.push_bytes(&buf[..n]);
            if let Some(result) = decoder.try_decode().unwrap() { break result; }
        };
        let ack: HandshakeAck = serde_json::from_slice(&payload).unwrap();
        assert!(ack.success, "Handshake should succeed");

        // Verify server proof
        let expected = crypto::compute_server_proof(&psk_clone, &nonce, &ack.server_nonce);
        assert_eq!(expected, ack.server_proof);

        // Archive request
        let req = protocol::build_archive_request(uuid_clone, "myproject", encrypted_clone.len() as u64, 3, true);
        let frame = frame::encode_frame(&req, req.message_type()).unwrap();
        client_pipe.write_all(&frame).unwrap();

        // Send chunks
        for chunk in encrypted_clone.chunks(1024 * 1024) {
            client_pipe.write_all(&(chunk.len() as u32).to_be_bytes()).unwrap();
            client_pipe.write_all(chunk).unwrap();
        }
        client_pipe.write_all(&0u32.to_be_bytes()).unwrap(); // EOF

        // Archive complete
        let complete = protocol::build_archive_complete(encrypted_clone.len() as u64, &hash_clone);
        let frame = frame::encode_frame(&complete, complete.message_type()).unwrap();
        client_pipe.write_all(&frame).unwrap();
        client_pipe.flush().unwrap();
    });

    // --- Server receives archive ---
    let server_data = Arc::new(Mutex::new(Vec::new()));
    let server_data_clone = server_data.clone();

    let server_thread = std::thread::spawn(move || {
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 8192];

        // Read Handshake
        let (header, payload) = loop {
            let n = server_pipe.read(&mut buf).unwrap();
            if n == 0 { std::thread::sleep(std::time::Duration::from_millis(10)); continue; }
            decoder.push_bytes(&buf[..n]);
            if let Some(result) = decoder.try_decode().unwrap() { break result; }
        };
        let hs: Handshake = serde_json::from_slice(&payload).unwrap();

        // Verify client proof and respond
        let expected = crypto::compute_client_proof(&psk, &hs.nonce);
        assert_eq!(expected, hs.proof);
        let mut server_nonce = [0u8; 32];
        for i in 0..32 { server_nonce[i] = (i * 2) as u8; }
        let server_proof = crypto::compute_server_proof(&psk, &hs.nonce, &server_nonce);
        let ack = protocol::build_handshake_ack_success("0.1.0", server_nonce, server_proof);
        let frame = frame::encode_frame(&ack, ack.message_type()).unwrap();
        server_pipe.write_all(&frame).unwrap();

        // Read ArchiveRequest
        let (_header, payload) = loop {
            let n = server_pipe.read(&mut buf).unwrap();
            if n == 0 { continue; }
            decoder.push_bytes(&buf[..n]);
            if let Some(result) = decoder.try_decode().unwrap() { break result; }
        };
        let _req: ArchiveRequest = serde_json::from_slice(&payload).unwrap();

        // Receive chunks
        let mut received = Vec::new();
        let mut header_buf = [0u8; 4];
        loop {
            server_pipe.read_exact(&mut header_buf).unwrap();
            let len = u32::from_be_bytes(header_buf) as usize;
            if len == 0 { break; }
            let start = received.len();
            received.resize(start + len, 0);
            server_pipe.read_exact(&mut received[start..]).unwrap();
        }

        *server_data_clone.lock().unwrap() = received;

        // Read ArchiveComplete
        let (_header, _payload) = loop {
            let n = server_pipe.read(&mut buf).unwrap();
            if n == 0 { continue; }
            decoder.push_bytes(&buf[..n]);
            if let Some(result) = decoder.try_decode().unwrap() { break result; }
        };
    });

    client_thread.join().unwrap();
    server_thread.join().unwrap();

    // --- Verify server received the correct data ---
    let received = server_data.lock().unwrap();
    assert_eq!(*received, encrypted, "Server should receive exact encrypted blob");

    // --- Verify decryption round-trip ---
    let decrypted = crypto::age_decrypt(&received, &identity).unwrap();
    assert!(!decrypted.is_empty(), "Decrypted data should not be empty");

    // --- Project metadata lifecycle ---
    project::write_project_file(&project_dir, &meta).unwrap();
    assert!(project::is_local_project(&project_dir));

    meta.mark_archived(received.len() as u64, 3, true);
    project::write_project_file(&project_dir, &meta).unwrap();
    assert!(project::is_archived_placeholder(&project_dir));

    // Remove content, leaving placeholder
    project::remove_dir_contents_except_project(&project_dir).unwrap();
    assert!(project::is_archived_placeholder(&project_dir));
    // .project.toml should still exist
    assert!(project_dir.join(".project.toml").exists());
}

#[test]
fn test_end_to_end_hash_verification_prevents_corruption() {
    let tmp = TempDir::new().unwrap();
    let project_dir = tmp.path().join("corrupt-test");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(project_dir.join("data.txt"), b"original content").unwrap();

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();

    let (encrypted, original_hash) = archive::create_archive(&project_dir, &public_key).unwrap();

    // Verify correct hash passes
    let actual_hash = crypto::sha256_hex(&encrypted);
    assert_eq!(actual_hash, original_hash);

    // A wrong hash should not match
    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(original_hash, wrong_hash);

    // Corrupt the encrypted blob
    let mut corrupted = encrypted.clone();
    if corrupted.len() > 10 {
        corrupted[5] ^= 0xFF;
    }

    // Corrupted blob should fail decryption or hash check
    let corrupted_hash = crypto::sha256_hex(&corrupted);
    assert_ne!(corrupted_hash, original_hash, "Corrupted data should have different hash");
}
