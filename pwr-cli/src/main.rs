//! pwr — Lazy Project Archiver (client CLI).
//!
//! Archives projects to a pwr-server daemon on a NAS and restores
//! them on demand. Supports CLI mode and an optional TUI.

mod client;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// pwr — Lazy Project Archiver
///
/// Move projects between your local machine and a NAS running pwr-server.
/// Archives projects you're not using and restores them on demand, with
/// transparent encryption and integrity verification.
#[derive(Parser)]
#[command(name = "pwr", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize pwr configuration
    Init {
        /// Server hostname or IP
        #[arg(long)]
        server_host: Option<String>,

        /// Server port (default: 9742)
        #[arg(long)]
        server_port: Option<u16>,

        /// Hex-encoded pre-shared key
        #[arg(long)]
        psk: Option<String>,

        /// Local root directory for projects
        #[arg(long)]
        local_root: Option<String>,
    },

    /// Create a .project.toml to start tracking a project
    Create {
        /// Path to the project directory (defaults to current directory)
        path: Option<PathBuf>,

        /// Project name (defaults to directory name)
        #[arg(long)]
        name: Option<String>,
    },

    /// Archive a project to the server
    Archive {
        /// Path to the project directory
        path: PathBuf,

        /// Dry run — show what would happen without doing it
        #[arg(long, short = 'n')]
        dry_run: bool,
    },

    /// Restore a project from the server
    Restore {
        /// Path to the project directory (or placeholder)
        path: PathBuf,

        /// Dry run — show what would happen without doing it
        #[arg(long, short = 'n')]
        dry_run: bool,
    },

    /// Ensure a project is local (for shell wrapper integration)
    Ensure {
        /// Path to the project directory
        path: PathBuf,

        /// Suppress output
        #[arg(long, short = 'q')]
        quiet: bool,
    },

    /// Show status of all tracked projects
    Status {
        /// Search recursively for projects
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// List all tracked projects with paths
    List {
        /// Search recursively for projects
        #[arg(long, short = 'r')]
        recursive: bool,
    },

    /// Generate shell integration script
    Shell {
        /// Shell: bash, zsh, or fish
        #[arg(default_value = "bash")]
        shell: String,

        /// Print initialization instructions
        #[arg(long)]
        init: bool,
    },

    /// Show transaction history
    Log {
        /// Filter by project name
        project: Option<String>,

        /// Show error details
        #[arg(long, short = 'e')]
        errors: bool,
    },

    /// Launch the terminal UI for interactive project management
    #[cfg(feature = "tui")]
    Tui,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init {
            server_host,
            server_port,
            psk,
            local_root,
        } => cmd_init(server_host, server_port, psk, local_root),

        Commands::Create { path, name } => cmd_create(path, name),

        Commands::Archive { path, dry_run } => cmd_archive(path, dry_run),

        Commands::Restore { path, dry_run } => cmd_restore(path, dry_run),

        Commands::Ensure { path, quiet } => cmd_ensure(path, quiet),

        Commands::Status { recursive } => cmd_status(recursive),

        Commands::List { recursive } => cmd_list(recursive),

        Commands::Shell { shell, init } => {
            if init {
                cmd_shell_init(&shell)
            } else {
                cmd_shell(&shell)
            }
        }

        Commands::Log { project, errors } => cmd_log(project, errors),

        #[cfg(feature = "tui")]
        Commands::Tui => cmd_tui(),
    };

    if let Err(err) = result {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// TUI entry point
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod tui;

#[cfg(feature = "tui")]
fn cmd_tui() -> Result<(), String> {
    tui::run()
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn cmd_init(
    server_host: Option<String>,
    server_port: Option<u16>,
    psk: Option<String>,
    local_root: Option<String>,
) -> Result<(), String> {
    use pwr_core::config::{self, PwrConfig};

    if config::config_exists() {
        println!("Config already exists at {}", config::config_path().display());
        return Ok(());
    }

    let host = server_host.unwrap_or_else(|| "nas".to_string());
    let port = server_port.unwrap_or(9742);
    let key = psk.unwrap_or_else(|| {
        let psk = pwr_core::crypto::generate_psk();
        pwr_core::crypto::psk_to_hex(&psk)
    });
    let root = local_root.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/jacob".to_string());
        format!("{}/Projects", home)
    });

    let config = PwrConfig::new(host.clone(), port, key.clone(), root.clone());
    config::save_config(&config).map_err(|e| format!("{}", e))?;

    println!("Configuration saved to {}", config::config_path().display());
    println!("  Server: {}:{}", host, port);
    println!("  PSK: {} (save this for the server config)", key);
    println!("  Local root: {}", root);

    // Try to generate age identity
    match pwr_core::crypto::generate_age_identity() {
        Ok((_, pk)) => println!("  Age public key: {}", pk),
        Err(e) => println!("  Warning: could not generate age identity: {}", e),
    }

    Ok(())
}

fn cmd_create(path: Option<PathBuf>, name: Option<String>) -> Result<(), String> {
    use pwr_core::config::load_config;
    use pwr_core::project;

    let config = load_config().map_err(|e| format!("Load config: {}", e))?;

    // Determine the project directory
    let abs_path = if let Some(p) = path {
        p.canonicalize().map_err(|e| format!("Cannot resolve path: {}", e))?
    } else {
        std::env::current_dir().map_err(|e| format!("Current dir: {}", e))?
    };

    if !abs_path.is_dir() {
        return Err(format!("Not a directory: {}", abs_path.display()));
    }

    // Check if already tracked
    if project::is_tracked(&abs_path) {
        println!(
            "Project is already tracked: {}",
            abs_path.join(project::PROJECT_FILE).display()
        );
        return Ok(());
    }

    // Determine project name
    let project_name = name.unwrap_or_else(|| {
        abs_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed")
            .to_string()
    });

    let remote_path = format!(
        "{}:{}/{}",
        config.server_addr(),
        config.server_host,
        project_name
    );

    let meta = pwr_core::metadata::ProjectMeta::new_local(
        project_name.clone(),
        abs_path.to_string_lossy().to_string(),
        remote_path,
    );

    project::write_project_file(&abs_path, &meta)
        .map_err(|e| format!("{}", e))?;

    println!("Created project '{}'", project_name);
    println!("  Path:  {}", abs_path.display());
    println!("  UUID:  {}", meta.uuid);
    println!("  State: local");
    println!();
    println!("To archive this project:");
    println!("  pwr archive {}", abs_path.display());

    Ok(())
}

fn cmd_archive(path: PathBuf, dry_run: bool) -> Result<(), String> {
    use pwr_core::config::load_config;
    use pwr_core::project;

    let config = load_config().map_err(|e| format!("{}", e))?;

    let abs_path = path
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    if !abs_path.is_dir() {
        return Err(format!("Not a directory: {}", abs_path.display()));
    }

    let project_name = abs_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Cannot determine project name")?;

    let mut meta = if let Some(existing) =
        project::read_project_file(&abs_path).map_err(|e| format!("{}", e))?
    {
        println!("Found existing project: {}", existing.name);
        existing
    } else {
        let remote_path = format!(
            "{}:{}/{}",
            config.server_addr(),
            config.server_host,
            project_name
        );
        pwr_core::metadata::ProjectMeta::new_local(
            project_name.to_string(),
            abs_path.to_string_lossy().to_string(),
            remote_path,
        )
    };

    let size = project::dir_size(&abs_path).map_err(|e| format!("{}", e))?;
    println!(
        "Archiving '{}' ({} bytes)",
        project_name,
        pwr_core::metadata::human_size(size)
    );

    if dry_run {
        println!("[DRY RUN] Would upload then remove local files");
        return Ok(());
    }

    // Load age identity for encryption
    let identity = pwr_core::crypto::load_age_identity()
        .map_err(|e| format!("Cannot load age identity: {}", e))?;
    let public_key = identity.to_public().to_string();

    // Create encrypted archive
    println!("Creating encrypted archive...");
    let (encrypted, hash) =
        pwr_core::archive::create_archive(&abs_path, &public_key)
            .map_err(|e| format!("Archive creation failed: {}", e))?;

    println!(
        "Encrypted archive: {} bytes (SHA-256: {})",
        pwr_core::metadata::human_size(encrypted.len() as u64),
        &hash[..16]
    );

    // Connect to server and upload with progress bar
    println!("Connecting to {}...", config.server_addr());
    let mut client = client::PwrClient::connect(&config, false)
        .map_err(|e| format!("Connection failed: {}", e))?;

    let total = encrypted.len() as u64;
    let pb = indicatif::ProgressBar::new(total);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("Uploading {spinner:.green} [{bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let pb_ref = &pb;
    client
        .archive_project_with_progress(
            &meta.uuid, project_name, &encrypted, &hash,
            Some(&|sent, _total| { pb_ref.set_position(sent); }),
        )
        .map_err(|e| format!("Archive failed: {}", e))?;
    pb.finish_and_clear();

    // Update local metadata and clean up
    let file_count = project::file_count(&abs_path).map_err(|e| format!("{}", e))?;
    meta.mark_archived(encrypted.len() as u64, file_count, true);
    project::write_project_file(&abs_path, &meta).map_err(|e| format!("{}", e))?;
    project::remove_dir_contents_except_project(&abs_path)
        .map_err(|e| format!("{}", e))?;

    println!("Archived '{}' successfully", project_name);
    println!(
        "  {} freed locally",
        pwr_core::metadata::human_size(size)
    );

    Ok(())
}

fn cmd_restore(path: PathBuf, dry_run: bool) -> Result<(), String> {
    use pwr_core::config::load_config;
    use pwr_core::project;

    let config = load_config().map_err(|e| format!("{}", e))?;

    let abs_path = path
        .canonicalize()
        .unwrap_or_else(|_| path.clone());

    if !project::is_archived_placeholder(&abs_path) {
        if abs_path.is_dir() && project::is_local_project(&abs_path) {
            println!("'{}' is already local", abs_path.display());
            return Ok(());
        }
        return Err(format!(
            "Not an archived project: {}",
            abs_path.display()
        ));
    }

    let meta = project::read_project_file(&abs_path)
        .map_err(|e| format!("{}", e))?
        .ok_or("No .project.toml found")?;

    println!("Restoring '{}' ({} bytes)...", meta.name, meta.size_human());

    if dry_run {
        println!("[DRY RUN] Would download and extract");
        return Ok(());
    }

    // Connect and download with progress bar
    let mut client = client::PwrClient::connect(&config, false)
        .map_err(|e| format!("Connection failed: {}", e))?;

    let pb = indicatif::ProgressBar::new(meta.size_bytes);
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("Downloading {spinner:.green} [{bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let pb_ref = &pb;
    let encrypted = client
        .restore_project_with_progress(
            &meta.uuid,
            Some(&|received, _total| { pb_ref.set_position(received); }),
        )
        .map_err(|e| format!("Restore failed: {}", e))?;
    pb.finish_and_clear();

    // Decrypt and extract
    println!("Decrypting and extracting...");
    let identity = pwr_core::crypto::load_age_identity()
        .map_err(|e| format!("Cannot load age identity: {}", e))?;

    let hash = pwr_core::crypto::sha256_hex(&encrypted);
    pwr_core::archive::extract_archive(&encrypted, &identity, &abs_path, &hash)
        .map_err(|e| format!("Extraction failed: {}", e))?;

    // Update metadata
    let mut updated = meta.clone();
    let new_size = project::dir_size(&abs_path).map_err(|e| format!("{}", e))?;
    let new_count = project::file_count(&abs_path).map_err(|e| format!("{}", e))?;
    updated.mark_local(new_size, new_count);
    project::write_project_file(&abs_path, &updated)
        .map_err(|e| format!("{}", e))?;

    println!("Restored '{}' successfully", meta.name);
    Ok(())
}

fn cmd_ensure(path: PathBuf, quiet: bool) -> Result<(), String> {
    use pwr_core::project;

    let abs_path = if path.is_absolute() {
        path.clone()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("{}", e))?
            .join(&path)
    };

    if abs_path.is_dir() && !project::is_archived_placeholder(&abs_path) {
        return Ok(()); // Already local
    }

    if project::is_archived_placeholder(&abs_path) {
        if !quiet {
            println!("Project archived. Restoring...");
        }
        return cmd_restore(abs_path, false);
    }

    Err(format!("No such project: {}", path.display()))
}

fn cmd_status(recursive: bool) -> Result<(), String> {
    use pwr_core::config::load_config;
    use pwr_core::project;

    let config = load_config().map_err(|e| format!("{}", e))?;
    let root = PathBuf::from(&config.local_root);

    if !root.is_dir() {
        println!("Local root '{}' does not exist.", root.display());
        return Ok(());
    }

    let projects = if recursive {
        project::find_projects_recursive(&root)
    } else {
        project::find_projects(&root)
    }
    .map_err(|e| format!("{}", e))?;

    if projects.is_empty() {
        println!("No tracked projects found.");
        return Ok(());
    }

    println!("{:<10} {:<20} {:<12} {:<12}", "STATUS", "NAME", "SIZE", "LAST SYNC");
    println!("{}", "-".repeat(60));

    for (_path, meta) in &projects {
        let status = if meta.is_archived() { "archived" } else { "local" };
        let last_sync = meta.last_sync.format("%Y-%m-%d").to_string();
        println!(
            "{:<10} {:<20} {:<12} {:<12}",
            status,
            meta.name,
            meta.size_human(),
            last_sync,
        );
    }

    let local = projects.iter().filter(|(_, m)| m.is_local()).count();
    let archived = projects.iter().filter(|(_, m)| m.is_archived()).count();
    println!(
        "\n{} local, {} archived ({} total)",
        local, archived, projects.len()
    );

    Ok(())
}

fn cmd_list(recursive: bool) -> Result<(), String> {
    cmd_status(recursive) // Same output format
}

fn cmd_shell(shell: &str) -> Result<(), String> {
    let script = match shell {
        "bash" => include_str!("../shell/pwr.bash"),
        "zsh" => include_str!("../shell/pwr.zsh"),
        "fish" => include_str!("../shell/pwr.fish"),
        _ => return Err(format!("Unsupported shell: {}", shell)),
    };
    println!("{}", script);
    Ok(())
}

fn cmd_shell_init(shell: &str) -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let rc_file = match shell {
        "bash" => format!("{}/.bashrc", home),
        "zsh" => format!("{}/.zshrc", home),
        "fish" => format!("{}/.config/fish/config.fish", home),
        _ => return Err(format!("Unsupported shell: {}", shell)),
    };
    println!("Add this to {}:\n", rc_file);
    println!("eval \"$(pwr shell {})\"", shell);
    Ok(())
}

fn cmd_log(project: Option<String>, show_errors: bool) -> Result<(), String> {
    use pwr_core::transaction;

    let transactions = transaction::read_transactions()
        .map_err(|e| format!("{}", e))?;

    let filtered: Vec<_> = if let Some(ref name) = project {
        transactions.into_iter().filter(|t| t.project_name == *name).collect()
    } else {
        transactions
    };

    if filtered.is_empty() {
        println!("No transactions found.");
        return Ok(());
    }

    for tx in &filtered {
        let status = match tx.status {
            pwr_core::transaction::TransactionStatus::Completed => "OK",
            pwr_core::transaction::TransactionStatus::Failed => "FAILED",
            pwr_core::transaction::TransactionStatus::Started => "INCOMPLETE",
        };
        println!(
            "{} {:8} {:20} {:>10} {:>8}",
            tx.timestamp.format("%Y-%m-%d %H:%M"),
            format!("{:?}", tx.operation).to_lowercase(),
            tx.project_name,
            pwr_core::metadata::human_size(tx.size_bytes),
            status,
        );
        if show_errors {
            if let Some(ref err) = tx.error {
                println!("  Error: {}", err);
            }
        }
    }

    Ok(())
}
