use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents the state of a tracked project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    /// Project files are present on local disk.
    Local,
    /// Project is stored on the server; local directory is a placeholder.
    Archived,
}

/// Core metadata for a tracked project.
///
/// Serialized as `.project.toml` inside the project directory.
/// This file persists locally regardless of whether the project
/// content is present (Local state) or stored on the server
/// (Archived state), providing stable identity and reconnection
/// information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Unique identifier for this project, generated at creation time.
    /// Survives renames and moves.
    pub uuid: Uuid,

    /// Human-readable project name, derived from the directory name
    /// at the time of first archive.
    pub name: String,

    /// Absolute path to the project directory on the local machine.
    pub local_path: String,

    /// Server-side storage reference in the format
    /// "host:port:/base/path/project-name".
    pub remote_path: String,

    /// Total size in bytes at the time of the last successful sync.
    pub size_bytes: u64,

    /// Number of files in the project at the time of the last sync.
    #[serde(default)]
    pub file_count: u32,

    /// Timestamp of the last successful sync (upload or download).
    pub last_sync: DateTime<Utc>,

    /// Whether compression was used during the last transfer.
    pub compression: bool,

    /// Whether at-rest encryption was enabled for this project.
    #[serde(default)]
    pub encryption_enabled: bool,

    /// The age public key used for encrypting this project's archive,
    /// stored as a Bech32-encoded string. Only set if encryption is
    /// enabled.
    #[serde(default)]
    pub public_key: Option<String>,

    /// Current state of the project.
    pub state: ProjectState,
}

impl ProjectMeta {
    /// Create metadata for a new project that is currently local.
    ///
    /// Generates a fresh UUIDv4 and sets the last_sync timestamp
    /// to the current time. The project starts in the Local state
    /// with zero size and no compression or encryption.
    pub fn new_local(name: String, local_path: String, remote_path: String) -> Self {
        Self {
            version: 1,
            uuid: Uuid::new_v4(),
            name,
            local_path,
            remote_path,
            size_bytes: 0,
            file_count: 0,
            last_sync: Utc::now(),
            compression: false,
            encryption_enabled: false,
            public_key: None,
            state: ProjectState::Local,
        }
    }

    /// Create metadata with encryption enabled.
    ///
    /// Generates a fresh UUIDv4 and stores the age public key
    /// that will be used to encrypt the project archive before
    /// uploading to the server.
    pub fn new_local_encrypted(
        name: String,
        local_path: String,
        remote_path: String,
        public_key: String,
    ) -> Self {
        Self {
            version: 1,
            uuid: Uuid::new_v4(),
            name,
            local_path,
            remote_path,
            size_bytes: 0,
            file_count: 0,
            last_sync: Utc::now(),
            compression: false,
            encryption_enabled: true,
            public_key: Some(public_key),
            state: ProjectState::Local,
        }
    }

    /// Mark the project as archived after a successful upload to the server.
    ///
    /// Updates the state, records the transferred size and file count,
    /// and sets the last_sync timestamp to now.
    pub fn mark_archived(&mut self, size_bytes: u64, file_count: u32, compression: bool) {
        self.state = ProjectState::Archived;
        self.size_bytes = size_bytes;
        self.file_count = file_count;
        self.compression = compression;
        self.last_sync = Utc::now();
    }

    /// Mark the project as local after a successful download from the server.
    ///
    /// Updates the state, records the restored size, and sets the
    /// last_sync timestamp to now.
    pub fn mark_local(&mut self, size_bytes: u64, file_count: u32) {
        self.state = ProjectState::Local;
        self.size_bytes = size_bytes;
        self.file_count = file_count;
        self.last_sync = Utc::now();
    }

    /// Returns `true` if the project is currently archived (stored on
    /// the server, local directory is a placeholder).
    pub fn is_archived(&self) -> bool {
        self.state == ProjectState::Archived
    }

    /// Returns `true` if the project is currently local.
    pub fn is_local(&self) -> bool {
        self.state == ProjectState::Local
    }

    /// Return the number of days since the last sync.
    ///
    /// Useful for identifying stale projects that might be candidates
    /// for automatic archival.
    pub fn days_since_sync(&self) -> f64 {
        let duration = Utc::now() - self.last_sync;
        duration.num_milliseconds() as f64 / (1000.0 * 60.0 * 60.0 * 24.0)
    }

    /// Format the project size in a human-readable way (e.g., "1.5 GB").
    pub fn size_human(&self) -> String {
        human_size(self.size_bytes)
    }
}

/// Format a byte count as a human-readable string.
///
/// Uses binary prefixes (1024-based): B, KB, MB, GB, TB.
/// Values below 1024 are displayed as plain bytes.
pub fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} B", bytes)
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1_048_576), "1.0 MB");
        assert_eq!(human_size(1_073_741_824), "1.0 GB");
        assert_eq!(human_size(2_199_023_255_552), "2.0 TB");
    }

    #[test]
    fn test_project_state_serialization() {
        let meta = ProjectMeta::new_local(
            "testproj".into(),
            "/home/jacob/Projects/testproj".into(),
            "nas.local:9742:/srv/pwr/projects/testproj".into(),
        );
        assert_eq!(meta.state, ProjectState::Local);
        assert_eq!(meta.version, 1);
        assert!(!meta.is_archived());
        assert!(meta.is_local());
    }

    #[test]
    fn test_state_transitions() {
        let mut meta = ProjectMeta::new_local(
            "testproj".into(),
            "/home/jacob/Projects/testproj".into(),
            "nas.local:9742:/srv/pwr/projects/testproj".into(),
        );
        assert!(meta.is_local());

        // Archive
        meta.mark_archived(1_048_576, 42, true);
        assert!(meta.is_archived());
        assert_eq!(meta.size_bytes, 1_048_576);
        assert_eq!(meta.file_count, 42);
        assert!(meta.compression);

        // Restore
        meta.mark_local(1_048_576, 42);
        assert!(meta.is_local());
        assert!(!meta.is_archived());
    }

    #[test]
    fn test_encrypted_project() {
        let meta = ProjectMeta::new_local_encrypted(
            "secretproj".into(),
            "/home/jacob/Projects/secretproj".into(),
            "nas.local:9742:/srv/pwr/projects/secretproj".into(),
            "age1qx0...".into(),
        );
        assert!(meta.encryption_enabled);
        assert!(meta.public_key.is_some());
    }

    #[test]
    fn test_days_since_sync() {
        let meta = ProjectMeta::new_local(
            "recent".into(),
            "/tmp/recent".into(),
            "nas.local:9742:/srv/pwr/projects/recent".into(),
        );
        // Just created, should be nearly zero
        assert!(meta.days_since_sync() < 0.01);
    }

    #[test]
    fn test_serialization_round_trip() {
        let meta = ProjectMeta::new_local_encrypted(
            "roundtrip".into(),
            "/tmp/roundtrip".into(),
            "server:9742:/srv/roundtrip".into(),
            "age1test".into(),
        );

        let toml_str = toml::to_string_pretty(&meta).unwrap();
        let parsed: ProjectMeta = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.uuid, meta.uuid);
        assert_eq!(parsed.name, "roundtrip");
        assert_eq!(parsed.encryption_enabled, true);
        assert_eq!(parsed.public_key, Some("age1test".into()));
        assert_eq!(parsed.state, ProjectState::Local);
    }
}
