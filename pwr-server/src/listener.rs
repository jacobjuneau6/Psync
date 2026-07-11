//! TLS listener and connection accept loop for pwr-server.
//!
//! Uses synchronous I/O wrapped in tokio::task::spawn_blocking to
//! keep the handler code simple (Read + Write traits) while still
//! running in the tokio async runtime.

use std::fs;
use std::io::BufReader;
use std::net::{TcpListener, SocketAddr};
use std::sync::Arc;

use rustls::ServerConfig as TlsServerConfig;
use rustls::pki_types::CertificateDer;

use crate::auth::RateLimiter;
use crate::config::ServerConfig;
use crate::handler::{self, HandlerContext};
use crate::storage::ProjectStorage;

/// Build a rustls TLS server configuration from the cert and key files.
fn build_tls_config(config: &ServerConfig) -> Result<TlsServerConfig, String> {
    let cert_file = fs::File::open(&config.tls_cert_path)
        .map_err(|e| format!("Cannot open TLS cert {}: {}", config.tls_cert_path.display(), e))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Cannot parse TLS cert: {}", e))?;

    if certs.is_empty() {
        return Err("No certificates found in cert file".into());
    }

    let key_file = fs::File::open(&config.tls_key_path)
        .map_err(|e| format!("Cannot open TLS key {}: {}", config.tls_key_path.display(), e))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Cannot parse TLS key: {}", e))?
        .ok_or_else(|| "No private key found in key file".to_string())?;

    let tls_config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Cannot build TLS config: {}", e))?;

    Ok(tls_config)
}

/// Run the server main loop. Blocks until shutdown.
///
/// Spawns one OS thread per connection (via spawn_blocking) to keep
/// handler code synchronous while the tokio runtime drives I/O.
pub fn run(config: ServerConfig) -> Result<(), String> {
    let psk = pwr_core::crypto::psk_from_hex(&config.auth_token)
        .map_err(|e| format!("Invalid auth token: {}", e))?;

    let storage = ProjectStorage::new(config.clone())?;
    let storage = Arc::new(std::sync::RwLock::new(storage));
    let rate_limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new()));

    let tls_config = Arc::new(build_tls_config(&config)?);

    let bind_addr = config.bind_addr();
    let listener = bind_dual_stack(&bind_addr)?;

    log::info!("pwr-server listening on {} (TLS 1.3)", bind_addr);
    log::info!("Storage: {}", config.storage_base_path.display());

    // Accept connections in a loop
    for stream_result in listener.incoming() {
        let stream = stream_result.map_err(|e| format!("Accept error: {}", e))?;
        let peer_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| "unknown".parse().unwrap());

        let psk = psk;
        let storage = storage.clone();
        let rate_limiter = rate_limiter.clone();
        let tls_config = tls_config.clone();

        // Handle each connection on a dedicated thread
        std::thread::spawn(move || {
            log::debug!("Connection from {}", peer_addr);

            // Perform TLS handshake
            let conn = match rustls::ServerConnection::new(tls_config.clone()) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Cannot create TLS connection: {}", e);
                    return;
                }
            };
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);

            let ctx = HandlerContext {
                storage: storage.clone(),
                rate_limiter: rate_limiter.clone(),
                psk,
                peer_addr,
                connected_at: std::time::Instant::now(),
            };

            if let Err(e) = handler::handle_connection(&mut tls_stream, ctx) {
                log::error!("Handler error for {}: {}", peer_addr, e);
            }
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Dual-stack binding
// ---------------------------------------------------------------------------

/// Bind to `addr`, preferring IPv6 dual-stack with IPv4 fallback.
///
/// On Linux, binding to `[::]:port` with `IPV6_V6ONLY=0` (the default)
/// accepts both IPv4 and IPv6 connections. If the configured address
/// fails to bind, we try `0.0.0.0:port` as a fallback for systems
/// without IPv6.
///
/// Also explicitly sets `SO_REUSEADDR` so rapid restarts don't fail
/// with "address already in use".
fn bind_dual_stack(bind_addr: &str) -> Result<TcpListener, String> {
    // Try the configured address first
    if let Ok(addr) = bind_addr.parse::<SocketAddr>() {
        match bind_with_reuse(addr) {
            Ok(listener) => return Ok(listener),
            Err(e) => log::warn!("Cannot bind to {}: {} (trying fallback)", addr, e),
        }
    } else {
        // Hostname bind — let the OS resolve it
        match TcpListener::bind(bind_addr) {
            Ok(listener) => return Ok(listener),
            Err(e) => log::warn!("Cannot bind to {}: {} (trying fallback)", bind_addr, e),
        }
    }

    // Fallback: if the configured address was [::], try 0.0.0.0
    // (system may not have IPv6 available)
    if bind_addr.starts_with('[') || bind_addr == "[::]" {
        let port = bind_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.trim_end_matches(']').parse::<u16>().ok())
            .unwrap_or(9742);
        let fallback = SocketAddr::from(([0, 0, 0, 0], port));
        log::info!("Falling back to IPv4: {}", fallback);
        return bind_with_reuse(fallback)
            .map_err(|e| format!("Cannot bind to {} or fallback {}: {}", bind_addr, fallback, e));
    }

    Err(format!("Cannot bind to {}", bind_addr))
}

/// Bind a TcpListener with SO_REUSEADDR set.
fn bind_with_reuse(addr: SocketAddr) -> std::io::Result<TcpListener> {
    use std::os::unix::io::FromRawFd;

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };

    let sock = unsafe {
        let fd = libc::socket(domain, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // SO_REUSEADDR: allow rebinding to the same port quickly after restart
        let opt: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &opt as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as u32,
        ) < 0
        {
            libc::close(fd);
            return Err(std::io::Error::last_os_error());
        }

        // For IPv6: clear IPV6_V6ONLY so the socket accepts IPv4 connections too
        if domain == libc::AF_INET6 {
            let opt: libc::c_int = 0;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &opt as *const _ as *const _,
                std::mem::size_of::<libc::c_int>() as u32,
            ) < 0
            {
                // Non-fatal: IPv4-mapped addresses might not work but IPv6 still will
                log::warn!("Cannot clear IPV6_V6ONLY: {}", std::io::Error::last_os_error());
            }
        }

        fd
    };

    // Bind the socket
    let sockaddr = socket_addr_to_raw(&addr);
    let sockaddr_len = if addr.is_ipv4() {
        std::mem::size_of::<libc::sockaddr_in>()
    } else {
        std::mem::size_of::<libc::sockaddr_in6>()
    };

    let ret = unsafe {
        libc::bind(
            sock,
            &sockaddr as *const _ as *const libc::sockaddr,
            sockaddr_len as u32,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }

    // Listen
    let ret = unsafe { libc::listen(sock, 128) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        return Err(err);
    }

    // Wrap in TcpListener. SAFETY: we created this socket ourselves and
    // it's in a valid listening state.
    Ok(unsafe { TcpListener::from_raw_fd(sock) })
}

/// Convert a SocketAddr to a libc sockaddr_storage.
fn socket_addr_to_raw(addr: &SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let raw: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            raw.sin_family = libc::AF_INET as u16;
            raw.sin_port = v4.port().to_be();
            raw.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
        }
        SocketAddr::V6(v6) => {
            let raw: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            raw.sin6_family = libc::AF_INET6 as u16;
            raw.sin6_port = v6.port().to_be();
            raw.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            raw.sin6_flowinfo = v6.flowinfo();
            raw.sin6_scope_id = v6.scope_id();
        }
    }
    storage
}
