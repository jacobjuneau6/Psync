//! pwr-server — NAS-side daemon for the pwr lazy project archiver.
//!
//! Handles project storage, retrieval, and listing over a TLS-encrypted
//! TCP connection. Client authentication is via pre-shared key.
//!
//! ## Subcommands
//!
//! - `init` — Generate config, TLS cert, and PSK for first-time setup
//! - `start` — Run the daemon (bind, accept, serve)
//! - `status` — Check whether a server is reachable on the configured port

mod cert;
mod config;
mod handler;
mod listener;
mod storage;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// pwr-server — NAS-side daemon for the pwr lazy project archiver
#[derive(Parser)]
#[command(name = "pwr-server", version, about, long_about = None)]
struct Cli {
    /// Path to the server config file
    #[arg(short, long, default_value = "/etc/pwr/server.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new server configuration with TLS certificate and PSK
    Init {
        /// Hostname for the TLS certificate (default: system hostname)
        #[arg(long)]
        hostname: Option<String>,
    },

    /// Start the pwr-server daemon
    Start {
        /// Run in the foreground (do not daemonize)
        #[arg(long, short = 'f')]
        foreground: bool,
    },

    /// Show server status and configuration summary
    Status,
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pwr_server=info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { hostname } => cmd_init(&cli.config, hostname),
        Commands::Start { foreground } => cmd_start(&cli.config, foreground),
        Commands::Status => cmd_status(&cli.config),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmd_init(config_path: &PathBuf, hostname: Option<String>) -> Result<(), String> {
    let hostname = hostname.unwrap_or_else(|| {
        // Try to get the system hostname, fall back to a default
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "pwr-server".into())
    });

    println!("Initializing pwr-server on '{}'...", hostname);
    cert::init_server(config_path, &hostname)?;

    println!();
    println!("To start the server:");
    println!("  pwr-server --config {} start", config_path.display());

    Ok(())
}

fn cmd_start(config_path: &PathBuf, foreground: bool) -> Result<(), String> {
    // Find and load config
    let path = config::find_config(Some(config_path))
        .ok_or_else(|| format!("Config not found at {}", config_path.display()))?;

    let server_config = config::load_config(&path)?;

    tracing::info!("Starting pwr-server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Config: {}", path.display());
    tracing::info!(
        "Storage: {}",
        server_config.storage_base_path.display()
    );
    tracing::info!("Bind: {}", server_config.bind_addr());

    if !foreground {
        tracing::info!("Daemonizing is not yet implemented — running in foreground");
    }

    // Run the listener (blocks until shutdown signal)
    listener::run(server_config)?;

    tracing::info!("Server stopped");
    Ok(())
}

fn cmd_status(config_path: &PathBuf) -> Result<(), String> {
    let path = config::find_config(Some(config_path))
        .ok_or_else(|| format!("No config found at {}", config_path.display()))?;

    let cfg = config::load_config(&path)?;

    println!("pwr-server configuration:");
    println!("  Config file:  {}", path.display());
    println!("  Listen:       {}", cfg.bind_addr());
    println!("  Storage:      {}", cfg.storage_base_path.display());
    println!("  Max size:     {} GB", cfg.max_project_size_gb);
    println!("  Max conns:    {}", cfg.max_connections);
    println!("  Idle timeout: {}s", cfg.idle_timeout_secs);
    println!("  TLS cert:     {}", cfg.tls_cert_path.display());
    println!("  TLS key:      {}", cfg.tls_key_path.display());

    // Check if cert files exist
    if cfg.tls_cert_path.exists() {
        println!("  TLS:          certificate present");
    } else {
        println!("  TLS:          certificate MISSING — run 'init' first");
    }

    // Try to connect to check if server is running
    match std::net::TcpStream::connect_timeout(
        &cfg.bind_addr().parse().unwrap(),
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => println!("  Server:       RUNNING (port {})", cfg.listen_port),
        Err(_) => println!("  Server:       not reachable"),
    }

    Ok(())
}
