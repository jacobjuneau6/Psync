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

// Module declarations for the binary target
mod auth;
mod cert;
mod config;
mod daemon;
mod handler;
mod listener;
mod storage;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

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

        /// Also install and enable the systemd service
        /// (user service if unprivileged, system service if root)
        #[arg(long)]
        with_service: bool,
    },

    /// Start the pwr-server daemon
    Start {
        /// Run in the foreground (do not daemonize)
        #[arg(long, short = 'f')]
        foreground: bool,
    },

    /// Stop a running pwr-server daemon
    Stop,

    /// Show server status and configuration summary
    Status,
}

fn main() {
    // Explicitly install the ring crypto provider before any TLS code runs.
    // This is necessary because some transitive dependencies (rcgen,
    // rustls-webpki) pull in aws-lc-rs alongside ring, which prevents
    // rustls from auto-detecting which provider to use.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring crypto provider");

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
        Commands::Init { hostname, with_service } => cmd_init(&cli.config, hostname, with_service),
        Commands::Start { foreground } => cmd_start(&cli.config, foreground),
        Commands::Stop => cmd_stop(),
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

fn cmd_init(cli_config: &PathBuf, hostname: Option<String>, with_service: bool) -> Result<(), String> {
    let hostname = hostname.unwrap_or_else(|| {
        // Try to get the system hostname, fall back to a default
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "pwr-server".into())
    });

    // Determine where to place config files. If the CLI explicitly passed
    // a non-default --config path, respect it (and derive the config-dir
    // from it). Otherwise, auto-detect: prefer system dirs, fall back to
    // per-user XDG dirs when not writable.
    let (config_dir, storage_dir) = if cli_config.as_os_str() != "/etc/pwr/server.toml" {
        // User gave an explicit config path — place everything alongside it.
        let dir = cli_config
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let storage = config::user_data_dir();
        (dir, storage)
    } else {
        // Auto-detect: use system paths if writable, else XDG user paths.
        let base = config::resolve_config_base();
        let is_system = base == config::system_config_dir();
        let storage = if is_system {
            config::system_data_dir()
        } else {
            config::user_data_dir()
        };
        (base, storage)
    };

    println!("Initializing pwr-server on '{}'...", hostname);
    if !config::is_path_writable(&config_dir) {
        println!("  (using {} — system paths not writable)", config_dir.display());
    }
    cert::init_server(&config_dir, &storage_dir, &hostname)?;

    if with_service {
        install_service(&config_dir)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Systemd service installation
// ---------------------------------------------------------------------------

/// Install the systemd service file and reload the daemon.
///
/// Detects whether we're running as root:
/// - root → installs a system service to /etc/systemd/system/
/// - unprivileged → installs a user service to ~/.config/systemd/user/
///
/// The installed unit file uses the current binary path so it works
/// regardless of where pwr-server was built from.
fn install_service(config_dir: &Path) -> Result<(), String> {
    let is_root = unsafe { libc::geteuid() == 0 };
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Cannot determine binary path: {}", e))?;
    let exe_path = current_exe.to_string_lossy();
    let config_path = config_dir.join("server.toml");
    let config_str = config_path.to_string_lossy();

    // Substitute placeholders in the template.
    // We can't use format!() with a runtime format string, so use .replace().
    let substitute = |template: &str| -> String {
        template
            .replace("{exe}", &exe_path)
            .replace("{config}", &config_str)
    };

    if is_root {
        // --- System service ---
        let unit = substitute(SYSTEM_SERVICE_TEMPLATE);

        let dest = PathBuf::from("/etc/systemd/system/pwr-server.service");
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
        }
        std::fs::write(&dest, &unit)
            .map_err(|e| format!("write {}: {}", dest.display(), e))?;

        println!();
        println!("System service installed to {}", dest.display());

        // Reload systemd
        run_cmd("systemctl", &["daemon-reload"])?;

        println!();
        println!("Enable and start the service:");
        println!("  sudo systemctl enable --now pwr-server");
    } else {
        // --- User service ---
        let unit = substitute(USER_SERVICE_TEMPLATE);

        let dest = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("systemd/user/pwr-server.service");

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
        }
        std::fs::write(&dest, &unit)
            .map_err(|e| format!("write {}: {}", dest.display(), e))?;

        println!();
        println!("User service installed to {}", dest.display());

        // Reload systemd --user
        run_cmd("systemctl", &["--user", "daemon-reload"])?;

        println!();
        println!("Enable and start the service:");
        println!("  systemctl --user enable --now pwr-server");
        println!();
        println!("To have the service survive logout:");
        println!("  sudo loginctl enable-linger $USER");
    }

    Ok(())
}

/// Thin wrapper around Command::spawn + wait for systemctl calls.
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Cannot run {}: {}", cmd, e))?;

    if !status.success() {
        // Non-fatal: systemctl might not be available or user isn't
        // running systemd. Just warn and continue.
        println!("  (warning: {} {:?} returned exit code {:?})",
            cmd, args, status.code());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded service templates
// ---------------------------------------------------------------------------

/// Template for the system-wide service.
/// {exe} = path to the current pwr-server binary
/// {config} = path to server.toml
const SYSTEM_SERVICE_TEMPLATE: &str = r#"[Unit]
Description=pwr-server — Lazy Project Archiver daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} --config {config} start --foreground
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pwr-server

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Resource limits
LimitNOFILE=4096
MemoryMax=512M

[Install]
WantedBy=multi-user.target
"#;

/// Template for the per-user service.
/// {exe} = path to the current pwr-server binary
/// {config} = path to server.toml
const USER_SERVICE_TEMPLATE: &str = r#"[Unit]
Description=pwr-server — Lazy Project Archiver daemon (user)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} --config {config} start --foreground
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pwr-server

# Security hardening (user-level)
NoNewPrivileges=yes
PrivateTmp=yes

# Resource limits
LimitNOFILE=4096
MemoryMax=512M

[Install]
WantedBy=default.target
"#;

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
        // Pick the right PID file: system vs. user-local, based on where
        // the config file lives.
        let pid_file = daemon::pid_file_for_config(&path);
        daemon::daemonize(&pid_file)?;
        tracing::info!("Daemonized successfully (PID file: {})", pid_file.display());
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

    // Try to connect to check if server is running (use localhost
    // since the bind address might be [::] or 0.0.0.0)
    let check_addr = format!("localhost:{}", cfg.listen_port);
    match std::net::TcpStream::connect_timeout(
        &check_addr.parse().unwrap(),
        std::time::Duration::from_secs(2),
    ) {
        Ok(_) => println!("  Server:       RUNNING (port {})", cfg.listen_port),
        Err(_) => println!("  Server:       not reachable"),
    }

    Ok(())
}

fn cmd_stop() -> Result<(), String> {
    // Try system PID file first, then user PID file.
    let candidates = [
        std::path::PathBuf::from(daemon::SYSTEM_PID_FILE),
        daemon::user_pid_file(),
    ];

    let mut errors = Vec::new();
    for pid_file in &candidates {
        match daemon::stop_daemon(pid_file) {
            Ok(summary) => {
                println!("{}", summary);
                return Ok(());
            }
            Err(e) => errors.push(e),
        }
    }

    // Both failed — report and exit cleanly
    for e in &errors {
        eprintln!("{}", e);
    }
    Ok(())
}
