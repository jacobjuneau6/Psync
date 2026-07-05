use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::error::{PwrError, Result};

/// Client configuration stored at `~/.config/pwr/config.toml`.
///
/// Contains the connection details for reaching the pwr-server daemon
/// and the local directory root where projects are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PwrConfig {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Hostname or IP address of the NAS running pwr-server.
    pub server_host: String,

    /// Port the server listens on (default: 9742).
    #[serde(default = "default_port")]
    pub server_port: u16,

    /// Hex-encoded 256-bit pre-shared key for authentication.
    pub server_psk: String,

    /// SHA-256 fingerprint of the server's TLS certificate (hex).
    /// Used for certificate pinning.
    #[serde(default)]
    pub server_fingerprint: Option<String>,

    /// Local root directory where projects live, e.g. "/home/jacob/Projects".
    pub local_root: String,

    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub connect_timeout_secs: u64,

    /// Transfer timeout in seconds.
    #[serde(default = "default_transfer_timeout")]
    pub transfer_timeout_secs: u64,
}

fn default_port() -> u16 {
    9742
}

fn default_timeout() -> u64 {
    10
}

fn default_transfer_timeout() -> u64 {
    300
}

impl PwrConfig {
    /// Create a new client configuration.
    pub fn new(
        server_host: String,
        server_port: u16,
        server_psk: String,
        local_root: String,
    ) -> Self {
        Self {
            version: 2,
            server_host,
            server_port,
            server_psk,
            server_fingerprint: None,
            local_root,
            connect_timeout_secs: 10,
            transfer_timeout_secs: 300,
        }
    }

    /// Return the server address as "host:port".
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}

/// Determine the config directory: `~/.config/pwr/`.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("pwr")
}

/// Path to the main client config file.
pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Path to the age identity file (client-side encryption key).
pub fn identity_path() -> PathBuf {
    config_dir().join("identity")
}

/// Path to the transaction log.
pub fn transaction_log_path() -> PathBuf {
    config_dir().join("transactions.log")
}

/// Check whether a config file exists without loading it.
pub fn config_exists() -> bool {
    config_path().exists()
}

/// Load the client config from disk, or return NoConfig if it doesn't exist.
pub fn load_config() -> Result<PwrConfig> {
    let path = config_path();
    if !path.exists() {
        return Err(PwrError::NoConfig);
    }
    let contents = fs::read_to_string(&path)?;
    let config: PwrConfig =
        toml::from_str(&contents).map_err(|e| PwrError::TomlParse {
            path: path.to_string_lossy().to_string(),
            source: e,
        })?;
    Ok(config)
}

/// Save the client config to disk.
pub fn save_config(config: &PwrConfig) -> Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;
    let contents = toml::to_string_pretty(config)?;
    fs::write(config_path(), contents)?;
    log::info!("Config saved to {}", config_path().display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_addr() {
        let config = PwrConfig::new(
            "nas.local".into(),
            9742,
            "abcdef0123456789".into(),
            "/home/jacob/Projects".into(),
        );
        assert_eq!(config.server_addr(), "nas.local:9742");
    }

    #[test]
    fn test_config_path() {
        let path = config_path();
        assert!(path.ends_with("pwr/config.toml"));
    }

    #[test]
    fn test_default_port() {
        assert_eq!(default_port(), 9742);
    }
}
