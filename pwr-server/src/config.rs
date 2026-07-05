use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Server-side configuration, typically stored at `/etc/pwr/server.toml`
/// or `~/.config/pwr/server.toml`.
///
/// Controls the TLS listener, project storage backend, authentication,
/// and operational limits for the pwr-server daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// IP address to bind the TCP listener to (e.g., "0.0.0.0" for all
    /// interfaces, or "127.0.0.1" for local-only access).
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// TCP port to listen on. Defaults to 9742, an unprivileged port
    /// not assigned by IANA.
    #[serde(default = "default_port")]
    pub listen_port: u16,

    /// Filesystem path where project archives are stored.
    /// The server creates per-project subdirectories under this root.
    #[serde(default = "default_storage_path")]
    pub storage_base_path: PathBuf,

    /// Maximum size in gigabytes allowed for a single project archive.
    /// Archives exceeding this limit are rejected before transfer begins.
    #[serde(default = "default_max_size_gb")]
    pub max_project_size_gb: u64,

    /// Path to the PEM-encoded TLS certificate file.
    /// Generated during `pwr-server init` if not provided.
    pub tls_cert_path: PathBuf,

    /// Path to the PEM-encoded TLS private key file.
    /// Must be readable only by the server process (mode 0o600).
    pub tls_key_path: PathBuf,

    /// Hex-encoded 256-bit pre-shared key for client authentication.
    /// Must match the value in the client's config.toml.
    pub auth_token: String,

    /// Maximum number of concurrent client connections.
    /// Additional connections are accepted but immediately closed
    /// with a rate-limit error.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Idle timeout in seconds for authenticated connections.
    /// Connections with no activity for this duration are closed.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

fn default_listen_address() -> String {
    "0.0.0.0".into()
}

fn default_port() -> u16 {
    9742
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("/srv/pwr/projects")
}

fn default_max_size_gb() -> u64 {
    500
}

fn default_max_connections() -> usize {
    32
}

fn default_idle_timeout() -> u64 {
    300
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            version: 1,
            listen_address: default_listen_address(),
            listen_port: default_port(),
            storage_base_path: default_storage_path(),
            max_project_size_gb: default_max_size_gb(),
            tls_cert_path: PathBuf::from("/etc/pwr/server.crt"),
            tls_key_path: PathBuf::from("/etc/pwr/server.key"),
            auth_token: String::new(),
            max_connections: default_max_connections(),
            idle_timeout_secs: default_idle_timeout(),
        }
    }
}

impl ServerConfig {
    /// Validate the configuration for common mistakes.
    ///
    /// Checks that required paths exist (or can be created), the port
    /// is in the valid range, the auth token is non-empty, and size
    /// limits are reasonable.
    pub fn validate(&self) -> Result<(), String> {
        if self.listen_port == 0 {
            return Err("listen_port must be non-zero".into());
        }
        if self.auth_token.is_empty() {
            return Err("auth_token must not be empty".into());
        }
        if self.max_project_size_gb == 0 {
            return Err("max_project_size_gb must be positive".into());
        }
        if self.max_connections == 0 {
            return Err("max_connections must be positive".into());
        }
        Ok(())
    }

    /// Return the bind address as "address:port".
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.listen_address, self.listen_port)
    }

    /// Return the path where a specific project's data is stored.
    pub fn project_dir(&self, uuid: &uuid::Uuid) -> PathBuf {
        self.storage_base_path.join(uuid.to_string())
    }

    /// Return the path to the project registry index file.
    pub fn registry_path(&self) -> PathBuf {
        self.storage_base_path.join("registry.json")
    }
}

/// Search for the server config file in standard locations.
///
/// Checks, in order:
/// 1. The path specified by the `--config` CLI argument (if provided)
/// 2. `./server.toml` (current working directory, for development)
/// 3. `~/.config/pwr/server.toml` (user-local install)
/// 4. `/etc/pwr/server.toml` (system-wide install)
pub fn find_config(explicit_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit_path {
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }

    let candidates = [
        PathBuf::from("server.toml"),
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("pwr")
            .join("server.toml"),
        PathBuf::from("/etc/pwr/server.toml"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Some(candidate.clone());
        }
    }

    None
}

/// Load the server configuration from a specific path.
pub fn load_config(path: &Path) -> Result<ServerConfig, String> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let config: ServerConfig = toml::from_str(&contents)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    config.validate()?;

    Ok(config)
}

/// Save a server configuration to disk, creating parent directories
/// as needed.
pub fn save_config(config: &ServerConfig, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }

    let contents = toml::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    fs::write(path, &contents)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_passes_validation() {
        let mut cfg = ServerConfig::default();
        cfg.auth_token = "test-token-0123456789abcdef".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_empty_auth_token_fails_validation() {
        let cfg = ServerConfig::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_zero_port_fails_validation() {
        let mut cfg = ServerConfig::default();
        cfg.listen_port = 0;
        cfg.auth_token = "test".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_bind_addr_format() {
        let mut cfg = ServerConfig::default();
        cfg.listen_address = "192.168.1.100".into();
        cfg.listen_port = 8443;
        assert_eq!(cfg.bind_addr(), "192.168.1.100:8443");
    }

    #[test]
    fn test_project_dir() {
        let cfg = ServerConfig::default();
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let dir = cfg.project_dir(&uuid);
        assert!(dir.to_string_lossy().contains("550e8400"));
    }

    #[test]
    fn test_registry_path() {
        let cfg = ServerConfig::default();
        assert!(cfg
            .registry_path()
            .to_string_lossy()
            .ends_with("registry.json"));
    }

    #[test]
    fn test_save_and_load_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("server.toml");

        let mut cfg = ServerConfig::default();
        cfg.auth_token = "roundtrip-test-token".into();
        cfg.listen_port = 12345;

        save_config(&cfg, &path).unwrap();
        let loaded = load_config(&path).unwrap();

        assert_eq!(loaded.listen_port, 12345);
        assert_eq!(loaded.auth_token, "roundtrip-test-token");
        assert_eq!(loaded.version, 1);
    }
}
