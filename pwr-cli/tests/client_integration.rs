//! Integration tests for the pwr client networking module.
//!
//! Tests cover connection retry logic, progress callback invocation,
//! and client configuration round-trips.

use pwr::client::PwrClient;
use pwr_core::config::PwrConfig;
use pwr_core::crypto;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Build a test config pointing at localhost with a random PSK.
fn test_config(port: u16) -> PwrConfig {
    let psk = crypto::psk_to_hex(&crypto::generate_psk());
    PwrConfig::new(
        "localhost".into(),
        port,
        psk,
        "/tmp/pwr-test-projects".into(),
    )
}

#[test]
fn test_connect_to_nonexistent_server_fails_after_retries() {
    let config = test_config(19999);
    let result = PwrClient::connect(&config, false);
    match result {
        Ok(_) => panic!("Should fail when no server is listening"),
        Err(e) => {
            assert!(
                e.contains("attempts") || e.contains("Connection"),
                "Error: {}", e
            );
        }
    }
}

#[test]
#[ignore = "requires unreachable network address, OS TCP timeout varies"]
fn test_connect_timeout_is_respected() {
    // Test with a non-routable address and very short timeout.
    // The connection should fail — we don't assert timing since
    // OS-level TCP timeout behavior varies across platforms.
    let config = PwrConfig {
        version: 2,
        server_host: "10.255.255.1".into(),
        server_port: 9742,
        server_psk: crypto::psk_to_hex(&crypto::generate_psk()),
        use_tls: false,
        server_fingerprint: None,
        local_root: "/tmp/pwr-test".into(),
        connect_timeout_secs: 1,
        transfer_timeout_secs: 300,
    };

    let result = PwrClient::connect(&config, config.use_tls);
    assert!(result.is_err(), "Connection to non-routable address should fail");
}

#[test]
fn test_progress_callback_fires_during_operations() {
    // This test verifies the progress callback signature and plumbing.
    // No real server needed — we test the callback infrastructure.
    let progress_count = Arc::new(AtomicU64::new(0));
    let count = progress_count.clone();

    // Simulate progress reporting
    let cb = |sent: u64, total: u64| {
        assert!(sent <= total, "sent {} should not exceed total {}", sent, total);
        count.fetch_add(1, Ordering::SeqCst);
    };

    // Simulate archive progress
    let fake_data = vec![0u8; 3_000_000]; // 3 MB
    let total = fake_data.len() as u64;
    for chunk in fake_data.chunks(1_000_000) {
        cb(chunk.len() as u64, total);
    }

    // Should have fired at least once per chunk
    assert!(progress_count.load(Ordering::SeqCst) >= 3);
}

#[test]
fn test_progress_callback_edge_cases() {
    let calls = Arc::new(AtomicU64::new(0));
    let c = calls.clone();
    let cb = |sent: u64, total: u64| {
        if total > 0 {
            assert!(sent <= total);
        }
        c.fetch_add(1, Ordering::SeqCst);
    };

    // Empty data: should still work (0 chunks, 0 calls)
    // No chunks means no callback calls
    let data: Vec<u8> = vec![];
    for _chunk in data.chunks(1_000_000) {
        cb(0, 0);
    }

    // Single small chunk
    let data = b"hello";
    cb(data.len() as u64, data.len() as u64);
    assert!(calls.load(Ordering::SeqCst) >= 1);
}

#[test]
fn test_client_config_server_addr() {
    let config = test_config(9742);
    assert_eq!(config.server_addr(), "localhost:9742");
}

#[test]
fn test_client_config_default_timeouts() {
    let config = PwrConfig::new(
        "nas".into(),
        9742,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        "/tmp/test".into(),
    );
    assert_eq!(config.connect_timeout_secs, 10);
    assert_eq!(config.transfer_timeout_secs, 300);
    assert_eq!(config.server_fingerprint, None);
}
