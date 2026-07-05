use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{PwrError, Result};
use crate::metadata::ProjectMeta;

/// The filename for project metadata stored inside a project directory.
pub const PROJECT_FILE: &str = ".project.toml";

/// Read a `.project.toml` from a directory.
/// Returns `None` if the file doesn't exist.
pub fn read_project_file(dir: &Path) -> Result<Option<ProjectMeta>> {
    let file_path = dir.join(PROJECT_FILE);
    if !file_path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&file_path)?;
    let meta: ProjectMeta = toml::from_str(&contents).map_err(|e| PwrError::TomlParse {
        path: file_path.to_string_lossy().to_string(),
        source: e,
    })?;
    Ok(Some(meta))
}

/// Write a `.project.toml` into a directory.
/// Creates the directory if it doesn't exist.
pub fn write_project_file(dir: &Path, meta: &ProjectMeta) -> Result<()> {
    fs::create_dir_all(dir)?;
    let contents = toml::to_string_pretty(meta)?;
    let file_path = dir.join(PROJECT_FILE);
    fs::write(&file_path, contents)?;
    log::info!("Wrote project file: {}", file_path.display());
    Ok(())
}

/// Remove the `.project.toml` from a directory, indicating the project is
/// fully local and no longer tracked as archived.
pub fn remove_project_file(dir: &Path) -> Result<()> {
    let file_path = dir.join(PROJECT_FILE);
    if file_path.exists() {
        fs::remove_file(&file_path)?;
        log::info!("Removed project file: {}", file_path.display());
    }
    Ok(())
}

/// Check if a directory is an archived project placeholder
/// (directory exists, contains ONLY a .project.toml, and that file says
/// the project is archived).
pub fn is_archived_placeholder(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let project_file = dir.join(PROJECT_FILE);
    if !project_file.exists() {
        return false;
    }
    // Read it and check state
    match read_project_file(dir) {
        Ok(Some(meta)) => meta.is_archived(),
        _ => false,
    }
}

/// Check if a project file exists and the project is local.
pub fn is_local_project(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    match read_project_file(dir) {
        Ok(Some(meta)) => !meta.is_archived(),
        _ => false,
    }
}

/// Find all `.project.toml` files under a root directory (non-recursive).
pub fn find_projects(root: &Path) -> Result<Vec<(PathBuf, ProjectMeta)>> {
    let mut projects = Vec::new();
    if !root.is_dir() {
        return Ok(projects);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(meta) = read_project_file(&path)? {
                projects.push((path, meta));
            }
        }
    }
    Ok(projects)
}

/// Find all `.project.toml` files recursively under a root directory.
pub fn find_projects_recursive(root: &Path) -> Result<Vec<(PathBuf, ProjectMeta)>> {
    let mut projects = Vec::new();
    if !root.is_dir() {
        return Ok(projects);
    }
    find_projects_recursive_inner(root, &mut projects)?;
    Ok(projects)
}

fn find_projects_recursive_inner(
    dir: &Path,
    projects: &mut Vec<(PathBuf, ProjectMeta)>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(meta) = read_project_file(&path)? {
                projects.push((path.clone(), meta));
            }
            // Still recurse — a project might have nested projects
            find_projects_recursive_inner(&path, projects)?;
        }
    }
    Ok(())
}

/// Compute the total size of a directory (excluding the .project.toml itself).
pub fn dir_size(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    compute_dir_size(dir, &mut total)?;
    Ok(total)
}

fn compute_dir_size(dir: &Path, total: &mut u64) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Skip the project file itself for size calculation
        if path.file_name().map_or(false, |n| n == PROJECT_FILE) {
            continue;
        }
        if path.is_dir() {
            compute_dir_size(&path, total)?;
        } else {
            *total += entry.metadata()?.len();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_read_write_round_trip() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("testproj");

        let meta = ProjectMeta::new_local(
            "testproj".into(),
            proj_dir.to_string_lossy().to_string(),
            "server:9742:/srv/pwr/projects/testproj".into(),
        );

        write_project_file(&proj_dir, &meta)?;
        let read_back = read_project_file(&proj_dir)?;
        assert!(read_back.is_some());
        assert_eq!(read_back.unwrap().name, "testproj");

        Ok(())
    }
}
