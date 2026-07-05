use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents the state of a tracked project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    Local,
    Archived,
}

/// Core metadata for a tracked project.
/// Serialized as `.project.toml` inside the project directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    /// Schema version for forward compatibility.
    pub version: u32,

    /// Unique identifier for this project.
    pub uuid: Uuid,

    /// Human-readable project name (derived from directory name).
    pub name: String,

    /// Absolute path to the project on the local machine.
    pub local_path: String,

    /// Remote path on the NAS, e.g. "nas:/srv/projects/myproject"
    pub remote_path: String,

    /// Total size in bytes at the time of last sync.
    pub size_bytes: u64,

    /// Timestamp of the last successful sync (upload or download).
    pub last_sync: DateTime<Utc>,

    /// Whether compression was used during the last transfer.
    pub compression: bool,

    /// Current state of the project.
    pub state: ProjectState,
}

impl ProjectMeta {
    /// Create metadata for a new project that is currently local.
    pub fn new_local(name: String, local_path: String, remote_path: String) -> Self {
        Self {
            version: 1,
            uuid: Uuid::new_v4(),
            name,
            local_path,
            remote_path,
            size_bytes: 0,
            last_sync: Utc::now(),
            compression: false,
            state: ProjectState::Local,
        }
    }

    /// Mark the project as archived (after successful upload).
    pub fn mark_archived(&mut self, size_bytes: u64, compression: bool) {
        self.state = ProjectState::Archived;
        self.size_bytes = size_bytes;
        self.compression = compression;
        self.last_sync = Utc::now();
    }

    /// Mark the project as local (after successful download).
    pub fn mark_local(&mut self, size_bytes: u64) {
        self.state = ProjectState::Local;
        self.size_bytes = size_bytes;
        self.last_sync = Utc::now();
    }

    /// Returns true if the project is currently archived.
    pub fn is_archived(&self) -> bool {
        self.state == ProjectState::Archived
    }

    /// Format the size in a human-readable way.
    pub fn size_human(&self) -> String {
        human_size(self.size_bytes)
    }
}

/// Format a byte count as a human-readable string.
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
    }

    #[test]
    fn test_project_state_serialization() {
        let meta = ProjectMeta::new_local(
            "testproj".into(),
            "/home/jacob/Projects/testproj".into(),
            "nas:/srv/projects/testproj".into(),
        );
        assert_eq!(meta.state, ProjectState::Local);
        assert_eq!(meta.version, 1);
        assert!(!meta.is_archived());
    }
}
