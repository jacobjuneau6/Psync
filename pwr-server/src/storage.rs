//! Project storage backend for pwr-server.
//!
//! Manages the on-disk project registry (a JSON index file) and the
//! per-project directories containing encrypted archive blobs and
//! metadata. All operations are synchronous (the caller wraps them
//! in tokio::task::spawn_blocking for async contexts).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::config::ServerConfig;

/// Represents a project stored on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProject {
    pub uuid: Uuid,
    pub name: String,
    pub size_bytes: u64,
    pub file_count: u32,
    pub encrypted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The project registry, persisted as a JSON file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Registry {
    version: u32,
    projects: HashMap<Uuid, StoredProject>,
}

impl Registry {
    fn new() -> Self {
        Self {
            version: 1,
            projects: HashMap::new(),
        }
    }
}

/// Handle to the project storage subsystem.
///
/// Wraps the registry and the filesystem root where project data
/// is stored. Methods that modify the registry save it to disk
/// atomically after each mutation.
pub struct ProjectStorage {
    config: ServerConfig,
    registry: Registry,
}

impl ProjectStorage {
    /// Create or load the project storage.
    ///
    /// If the storage directory does not exist, it is created along
    /// with an empty registry. If it exists, the registry is loaded
    /// and validated.
    pub fn new(config: ServerConfig) -> Result<Self, String> {
        fs::create_dir_all(&config.storage_base_path)
            .map_err(|e| format!("Cannot create storage dir: {}", e))?;

        let registry_path = config.registry_path();
        let registry = if registry_path.exists() {
            Self::load_registry(&registry_path)?
        } else {
            let reg = Registry::new();
            Self::save_registry(&registry_path, &reg)?;
            reg
        };

        Ok(Self { config, registry })
    }

    /// Add a new project to the registry.
    ///
    /// Returns an error if a project with the same UUID already exists.
    pub fn add_project(&mut self, project: StoredProject) -> Result<(), String> {
        if self.registry.projects.contains_key(&project.uuid) {
            return Err(format!(
                "Project {} ({}) already exists",
                project.name, project.uuid
            ));
        }

        // Ensure the project storage directory exists
        let project_dir = self.config.project_dir(&project.uuid);
        fs::create_dir_all(&project_dir)
            .map_err(|e| format!("Cannot create project dir: {}", e))?;

        self.registry
            .projects
            .insert(project.uuid, project);
        self.flush()
    }

    /// Remove a project from the registry and delete its files.
    pub fn remove_project(&mut self, uuid: &Uuid) -> Result<(), String> {
        if self.registry.projects.remove(uuid).is_none() {
            return Err(format!("Project {} not found", uuid));
        }

        // Delete project directory
        let project_dir = self.config.project_dir(uuid);
        if project_dir.exists() {
            fs::remove_dir_all(&project_dir)
                .map_err(|e| format!("Cannot delete project dir: {}", e))?;
        }

        self.flush()
    }

    /// Get a project by UUID.
    pub fn get_project(&self, uuid: &Uuid) -> Option<&StoredProject> {
        self.registry.projects.get(uuid)
    }

    /// List all projects in the registry.
    pub fn list_projects(&self) -> Vec<&StoredProject> {
        self.registry.projects.values().collect()
    }

    /// Update a project's metadata in the registry.
    pub fn update_project(&mut self, project: StoredProject) -> Result<(), String> {
        if !self.registry.projects.contains_key(&project.uuid) {
            return Err(format!("Project {} not found", project.uuid));
        }
        self.registry
            .projects
            .insert(project.uuid, project);
        self.flush()
    }

    /// Return the path where a project's archive blob is stored.
    pub fn archive_path(&self, uuid: &Uuid) -> PathBuf {
        self.config.project_dir(uuid).join("data.enc")
    }

    /// Return the path where a project's metadata TOML is stored.
    pub fn meta_path(&self, uuid: &Uuid) -> PathBuf {
        self.config.project_dir(uuid).join("meta.toml")
    }

    /// Write a project's archive blob to disk using streaming I/O.
    ///
    /// Data is read from the provided reader and written to the
    /// archive path. The caller is responsible for encryption —
    /// the server stores whatever bytes it receives.
    pub fn write_archive(
        &self,
        uuid: &Uuid,
        reader: &mut impl Read,
    ) -> Result<u64, String> {
        let path = self.archive_path(uuid);
        let file = fs::File::create(&path)
            .map_err(|e| format!("Cannot create archive file: {}", e))?;
        let mut writer = BufWriter::new(file);

        let bytes_written = std::io::copy(reader, &mut writer)
            .map_err(|e| format!("Cannot write archive data: {}", e))?;

        writer
            .flush()
            .map_err(|e| format!("Cannot flush archive: {}", e))?;

        Ok(bytes_written)
    }

    /// Open a project's archive blob for reading.
    ///
    /// Returns a buffered reader positioned at the start of the file.
    pub fn read_archive(&self, uuid: &Uuid) -> Result<BufReader<fs::File>, String> {
        let path = self.archive_path(uuid);
        if !path.exists() {
            return Err(format!(
                "Archive file not found for project {}",
                uuid
            ));
        }
        let file = fs::File::open(&path)
            .map_err(|e| format!("Cannot open archive: {}", e))?;
        Ok(BufReader::new(file))
    }

    /// Check whether an archive blob exists for a project.
    pub fn archive_exists(&self, uuid: &Uuid) -> bool {
        self.archive_path(uuid).exists()
    }

    /// Write a project's per-project metadata TOML file.
    pub fn write_meta(&self, uuid: &Uuid, project: &StoredProject) -> Result<(), String> {
        let path = self.meta_path(uuid);
        let contents = toml::to_string_pretty(project)
            .map_err(|e| format!("Cannot serialize meta: {}", e))?;
        fs::write(&path, contents)
            .map_err(|e| format!("Cannot write meta file: {}", e))?;
        Ok(())
    }

    /// Check that the total stored size does not exceed the configured limit.
    pub fn check_size_limit(&self, additional_bytes: u64) -> Result<(), String> {
        let current_total: u64 = self
            .registry
            .projects
            .values()
            .map(|p| p.size_bytes)
            .sum();
        let max_bytes = self.config.max_project_size_gb * 1024 * 1024 * 1024;
        let new_total = current_total + additional_bytes;

        if new_total > max_bytes {
            return Err(format!(
                "Storage limit exceeded: would use {} GB (limit {} GB)",
                new_total / (1024 * 1024 * 1024),
                self.config.max_project_size_gb
            ));
        }
        Ok(())
    }

    // Private helpers

    fn load_registry(path: &Path) -> Result<Registry, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Cannot read registry: {}", e))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("Cannot parse registry: {}", e))
    }

    fn save_registry(path: &Path, registry: &Registry) -> Result<(), String> {
        let tmp_path = path.with_extension("tmp");
        let contents = serde_json::to_string_pretty(registry)
            .map_err(|e| format!("Cannot serialize registry: {}", e))?;

        // Atomic write
        fs::write(&tmp_path, contents)
            .map_err(|e| format!("Cannot write registry tmp: {}", e))?;
        fs::rename(&tmp_path, path)
            .map_err(|e| format!("Cannot rename registry: {}", e))?;

        Ok(())
    }

    fn flush(&self) -> Result<(), String> {
        Self::save_registry(&self.config.registry_path(), &self.registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_config(dir: &Path) -> ServerConfig {
        let mut cfg = ServerConfig::default();
        cfg.storage_base_path = dir.join("storage");
        cfg.auth_token = "test-token".into();
        cfg
    }

    fn make_project(name: &str) -> StoredProject {
        StoredProject {
            uuid: Uuid::new_v4(),
            name: name.into(),
            size_bytes: 1_000_000,
            file_count: 42,
            encrypted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_create_and_list() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut storage = ProjectStorage::new(config).unwrap();

        let p1 = make_project("alpha");
        let p2 = make_project("beta");

        storage.add_project(p1.clone()).unwrap();
        storage.add_project(p2.clone()).unwrap();

        let list = storage.list_projects();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_duplicate_rejected() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut storage = ProjectStorage::new(config).unwrap();

        let p = make_project("test");
        storage.add_project(p.clone()).unwrap();
        assert!(storage.add_project(p).is_err());
    }

    #[test]
    fn test_remove_project() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut storage = ProjectStorage::new(config).unwrap();

        let p = make_project("removable");
        let uuid = p.uuid;
        storage.add_project(p).unwrap();
        assert!(storage.get_project(&uuid).is_some());

        storage.remove_project(&uuid).unwrap();
        assert!(storage.get_project(&uuid).is_none());
    }

    #[test]
    fn test_write_and_read_archive() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let mut storage = ProjectStorage::new(config).unwrap();

        let p = make_project("data-test");
        let uuid = p.uuid;
        storage.add_project(p).unwrap();

        let data = b"encrypted project archive contents here";
        let written = storage
            .write_archive(&uuid, &mut &data[..])
            .unwrap();
        assert_eq!(written as usize, data.len());

        let mut reader = storage.read_archive(&uuid).unwrap();
        let mut read_back = Vec::new();
        reader.read_to_end(&mut read_back).unwrap();
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_persistence() {
        let tmp = TempDir::new().unwrap();
        let config = make_config(tmp.path());
        let uuid;

        {
            let mut storage = ProjectStorage::new(config.clone()).unwrap();
            let p = make_project("persistent");
            uuid = p.uuid;
            storage.add_project(p).unwrap();
        }

        // Re-open
        {
            let storage = ProjectStorage::new(config).unwrap();
            let retrieved = storage.get_project(&uuid).unwrap();
            assert_eq!(retrieved.name, "persistent");
        }
    }
}
