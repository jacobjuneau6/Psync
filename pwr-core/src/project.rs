use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{PwrError, Result};
use crate::metadata::ProjectMeta;

/// The filename for project metadata stored inside a project directory.
pub const PROJECT_FILE: &str = ".project.toml";

/// Read a `.project.toml` from a directory.
///
/// Returns `None` if the file doesn't exist, allowing callers to
/// distinguish between an untracked directory and a tracked project
/// with no metadata file.
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
///
/// Creates the directory and all parent directories if they don't
/// exist. The file is written atomically by first writing to a
/// temporary name and then renaming, preventing readers from seeing
/// a partially-written file.
pub fn write_project_file(dir: &Path, meta: &ProjectMeta) -> Result<()> {
    fs::create_dir_all(dir)?;
    let contents = toml::to_string_pretty(meta)?;
    let file_path = dir.join(PROJECT_FILE);
    let tmp_path = dir.join(format!(".project.toml.tmp"));

    // Write to temp file first, then rename for atomicity
    fs::write(&tmp_path, &contents)?;
    fs::rename(&tmp_path, &file_path)?;

    log::info!("Wrote project file: {}", file_path.display());
    Ok(())
}

/// Remove the `.project.toml` from a directory.
///
/// This indicates the project is no longer tracked. The directory
/// contents are not modified.
pub fn remove_project_file(dir: &Path) -> Result<()> {
    let file_path = dir.join(PROJECT_FILE);
    if file_path.exists() {
        fs::remove_file(&file_path)?;
        log::info!("Removed project file: {}", file_path.display());
    }
    Ok(())
}

/// Check if a directory is an archived project placeholder.
///
/// Returns `true` only when all conditions are met:
/// 1. The path exists and is a directory
/// 2. A `.project.toml` file exists inside it
/// 3. The metadata inside has `state = "archived"`
pub fn is_archived_placeholder(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let project_file = dir.join(PROJECT_FILE);
    if !project_file.exists() {
        return false;
    }
    match read_project_file(dir) {
        Ok(Some(meta)) => meta.is_archived(),
        _ => false,
    }
}

/// Check if a project file exists in the directory and the project is local.
pub fn is_local_project(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    match read_project_file(dir) {
        Ok(Some(meta)) => meta.is_local(),
        _ => false,
    }
}

/// Determine whether a path is tracked by pwr (has a .project.toml).
pub fn is_tracked(dir: &Path) -> bool {
    dir.is_dir() && dir.join(PROJECT_FILE).exists()
}

/// Find all `.project.toml` files under a root directory (non-recursive).
///
/// Only checks direct children of the root. Use `find_projects_recursive`
/// for nested project structures.
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
///
/// Performs a depth-first traversal. A directory that itself is a
/// tracked project may still contain nested tracked projects; both
/// the parent and children are included in the results.
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
            // Recurse into subdirectories — a project may contain
            // nested tracked projects (e.g., a monorepo with
            // independently archivable subprojects).
            find_projects_recursive_inner(&path, projects)?;
        }
    }
    Ok(())
}

/// Compute the total size of files in a directory, excluding the
/// `.project.toml` metadata file itself.
///
/// Walks the directory tree recursively. Symlinks are not followed;
/// their size is reported as the link target path length.
pub fn dir_size(dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    compute_dir_size(dir, &mut total)?;
    Ok(total)
}

fn compute_dir_size(dir: &Path, total: &mut u64) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().map_or(false, |n| n == PROJECT_FILE) {
            continue;
        }
        if path.is_dir() {
            compute_dir_size(&path, total)?;
        } else if path.is_symlink() {
            // Count the symlink itself, not the target
            *total += fs::read_link(&path)
                .map(|p| p.as_os_str().len() as u64)
                .unwrap_or(0);
        } else {
            *total += entry.metadata()?.len();
        }
    }
    Ok(())
}

/// Count files in a directory recursively, excluding `.project.toml`.
pub fn file_count(dir: &Path) -> Result<u32> {
    let mut count = 0u32;
    count_files(dir, &mut count)?;
    Ok(count)
}

fn count_files(dir: &Path, count: &mut u32) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().map_or(false, |n| n == PROJECT_FILE) {
            continue;
        }
        if path.is_dir() {
            count_files(&path, count)?;
        } else {
            *count += 1;
        }
    }
    Ok(())
}

/// Remove all files and subdirectories in a directory except the
/// `.project.toml` file, leaving an archived placeholder.
///
/// This is called after a successful archive to the server to free
/// local disk space while preserving project identity.
pub fn remove_dir_contents_except_project(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str());

        if file_name == Some(PROJECT_FILE) {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_project(dir: &Path, name: &str) -> ProjectMeta {
        ProjectMeta::new_local(
            name.into(),
            dir.to_string_lossy().to_string(),
            format!("server:9742:/srv/pwr/projects/{}", name),
        )
    }

    #[test]
    fn test_read_write_round_trip() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("testproj");
        let meta = make_test_project(&proj_dir, "testproj");

        write_project_file(&proj_dir, &meta)?;
        let read_back = read_project_file(&proj_dir)?;
        assert!(read_back.is_some());
        assert_eq!(read_back.unwrap().name, "testproj");

        Ok(())
    }

    #[test]
    fn test_atomic_write_no_partial_read() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("atomic");
        let meta = make_test_project(&proj_dir, "atomic");

        // Before write, no .project.toml and no .tmp file
        assert!(!proj_dir.join(PROJECT_FILE).exists());

        write_project_file(&proj_dir, &meta)?;

        // After write, .project.toml exists and .tmp does not
        assert!(proj_dir.join(PROJECT_FILE).exists());
        assert!(!proj_dir.join(".project.toml.tmp").exists());

        Ok(())
    }

    #[test]
    fn test_remove_project_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("remove-test");
        let meta = make_test_project(&proj_dir, "remove-test");

        write_project_file(&proj_dir, &meta)?;
        assert!(is_tracked(&proj_dir));

        remove_project_file(&proj_dir)?;
        assert!(!is_tracked(&proj_dir));

        Ok(())
    }

    #[test]
    fn test_is_archived_placeholder() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("archived-proj");
        let mut meta = make_test_project(&proj_dir, "archived-proj");
        meta.mark_archived(1024, 3, false);

        write_project_file(&proj_dir, &meta)?;
        assert!(is_archived_placeholder(&proj_dir));
        assert!(!is_local_project(&proj_dir));

        Ok(())
    }

    #[test]
    fn test_is_local_project() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("local-proj");
        let meta = make_test_project(&proj_dir, "local-proj");

        write_project_file(&proj_dir, &meta)?;
        assert!(is_local_project(&proj_dir));
        assert!(!is_archived_placeholder(&proj_dir));

        Ok(())
    }

    #[test]
    fn test_is_tracked() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("tracked");

        assert!(!is_tracked(&proj_dir));

        let meta = make_test_project(&proj_dir, "tracked");
        write_project_file(&proj_dir, &meta)?;

        assert!(is_tracked(&proj_dir));

        Ok(())
    }

    #[test]
    fn test_dir_size() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("sized");
        fs::create_dir_all(proj_dir.join("src"))?;
        fs::write(proj_dir.join("src").join("main.rs"), b"fn main() {}")?;
        fs::write(proj_dir.join("README.md"), b"# Hello")?;

        let size = dir_size(&proj_dir)?;
        assert!(size > 0);
        // "fn main() {}" is 12 bytes, "# Hello\n" is 7 bytes
        assert_eq!(size, 19);

        Ok(())
    }

    #[test]
    fn test_file_count() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("counted");
        fs::create_dir_all(proj_dir.join("subdir"))?;
        fs::write(proj_dir.join("a.txt"), b"a")?;
        fs::write(proj_dir.join("b.txt"), b"b")?;
        fs::write(proj_dir.join("subdir").join("c.txt"), b"c")?;

        // Write a .project.toml — should be excluded from count
        let meta = make_test_project(&proj_dir, "counted");
        write_project_file(&proj_dir, &meta)?;

        assert_eq!(file_count(&proj_dir)?, 3);

        Ok(())
    }

    #[test]
    fn test_remove_dir_contents_except_project() -> Result<()> {
        let tmp = TempDir::new()?;
        let proj_dir = tmp.path().join("stripped");
        fs::create_dir_all(proj_dir.join("src"))?;
        fs::write(proj_dir.join("src").join("lib.rs"), b"pub fn foo() {}")?;
        fs::write(proj_dir.join("Cargo.toml"), b"[package]")?;

        let meta = make_test_project(&proj_dir, "stripped");
        write_project_file(&proj_dir, &meta)?;

        remove_dir_contents_except_project(&proj_dir)?;

        // Only .project.toml should remain
        let entries: Vec<_> = fs::read_dir(&proj_dir)?
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec![PROJECT_FILE.to_string()]);

        Ok(())
    }

    #[test]
    fn test_find_projects() -> Result<()> {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("projects");
        fs::create_dir_all(&root)?;

        // Create two tracked projects
        for name in &["alpha", "beta"] {
            let dir = root.join(name);
            fs::create_dir(&dir)?;
            let meta = make_test_project(&dir, name);
            write_project_file(&dir, &meta)?;
        }

        // Create an untracked directory
        fs::create_dir(root.join("random"))?;

        let found = find_projects(&root)?;
        assert_eq!(found.len(), 2);

        let names: Vec<String> = found.iter().map(|(_, m)| m.name.clone()).collect();
        assert!(names.contains(&"alpha".into()));
        assert!(names.contains(&"beta".into()));

        Ok(())
    }

    #[test]
    fn test_find_projects_recursive() -> Result<()> {
        let tmp = TempDir::new()?;
        let root = tmp.path().join("nested");
        fs::create_dir_all(root.join("outer").join("inner"))?;

        let outer_meta = make_test_project(&root.join("outer"), "outer");
        write_project_file(&root.join("outer"), &outer_meta)?;

        let inner_meta = make_test_project(&root.join("outer").join("inner"), "inner");
        write_project_file(&root.join("outer").join("inner"), &inner_meta)?;

        let found = find_projects_recursive(&root)?;
        assert_eq!(found.len(), 2);

        Ok(())
    }
}
