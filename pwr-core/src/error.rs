use thiserror::Error;

/// Unified error type for all pwr operations.
///
/// Covers I/O failures, serialization errors, protocol violations,
/// cryptographic failures, authentication problems, network issues,
/// and storage-layer errors on the server side.
#[derive(Error, Debug)]
pub enum PwrError {
    /// File or directory I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML configuration file could not be parsed.
    #[error("TOML parse error in {path}: {source}")]
    TomlParse {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    /// TOML serialization failed.
    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Bincode serialization or deserialization failed (wire protocol).
    #[error("Bincode error: {0}")]
    Bincode(#[from] bincode::error::EncodeError),

    /// Client or server configuration is missing or invalid.
    #[error("Config error: {0}")]
    Config(String),

    /// No configuration found — user must run init first.
    #[error("No config found — run `pwr init` first")]
    NoConfig,

    /// Protocol framing error: magic bytes mismatch, truncated frame,
    /// or message exceeding size limit.
    #[error("Protocol framing error: {0}")]
    Framing(String),

    /// Received an unexpected or invalid protocol message.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Cryptographic operation failed (key generation, encryption,
    /// decryption, or hash computation).
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Authentication with the server failed (wrong token, expired
    /// credentials, or too many attempts).
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Network connection could not be established or was lost.
    #[error("Network error: {0}")]
    Network(String),

    /// Operation timed out.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Requested project does not exist on the server.
    #[error("Project not found: {0}")]
    NotFound(String),

    /// Project already exists (cannot overwrite without explicit flag).
    #[error("Project already exists: {0}")]
    AlreadyExists(String),

    /// Stored project data is corrupted or unreadable.
    #[error("Corrupted project data: {0}")]
    Corrupted(String),

    /// UUID parsing or formatting failed.
    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),
}

/// Convenience result type used throughout the codebase.
pub type Result<T> = std::result::Result<T, PwrError>;
