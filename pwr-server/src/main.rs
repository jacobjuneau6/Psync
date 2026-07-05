//! pwr-server — NAS-side daemon for the pwr lazy project archiver.
//!
//! Handles project storage, retrieval, and listing over a TLS-encrypted
//! TCP connection. Client authentication is via pre-shared key.

mod config;

fn main() {
    println!("pwr-server v{}", env!("CARGO_PKG_VERSION"));
    println!("Configuration paths checked:");
    if let Some(path) = config::find_config(None) {
        println!("  Found: {}", path.display());
    } else {
        println!("  No config found. Run 'pwr-server init' to create one.");
    }
}
