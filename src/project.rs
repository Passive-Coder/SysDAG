//! Deterministic project discovery and staging for local source dependencies.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

const MAX_FILES: usize = 50_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ProjectFile {
    pub relative: PathBuf,
    pub source: PathBuf,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ProjectSnapshot {
    pub root: PathBuf,
    pub files: Vec<ProjectFile>,
    pub digest: String,
}

pub fn project_root_for_file(source: &Path) -> Result<PathBuf> {
    let source = source
        .canonicalize()
        .with_context(|| format!("resolve {}", source.display()))?;
    if !source.is_file() {
        bail!("{} is not a regular project file", source.display());
    }
    let parent = source.parent().context("source has no parent directory")?;
    for dir in parent.ancestors() {
        if project_marker(dir) {
            return Ok(dir.to_path_buf());
        }
    }
    Ok(parent.to_path_buf())
}

fn project_marker(dir: &Path) -> bool {
    [
        ".git",
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "Makefile",
        "CMakeLists.txt",
        "Cargo.toml",
        "package.json",
    ]
    .iter()
    .any(|name| dir.join(name).exists())
}

fn ignored_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".sysdag"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".tox"
    )
}

pub fn contains_program(folder: &Path) -> Result<bool> {
    let root = folder
        .canonicalize()
        .with_context(|| format!("resolve {}", folder.display()))?;
    if !root.is_dir() {
        bail!("{} is not a project directory", folder.display());
    }
    contains_program_under(&root, &root, &mut BTreeSet::new())
}

fn contains_program_under(
    root: &Path,
    dir: &Path,
    visited: &mut BTreeSet<PathBuf>,
) -> Result<bool> {
    let canonical = dir.canonicalize()?;
    if !visited.insert(canonical.clone()) {
        return Ok(false);
    }
    for entry in
        fs::read_dir(&canonical).with_context(|| format!("scan {}", canonical.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            let resolved = path
                .canonicalize()
                .with_context(|| format!("resolve symlink {}", path.display()))?;
            if !resolved.starts_with(root) {
                continue;
            }
            if resolved.is_dir() && contains_program_under(root, &resolved, visited)? {
                return Ok(true);
            }
            if resolved.is_file() && is_program_file(&resolved)? {
                return Ok(true);
            }
            continue;
        }
        if file_type.is_dir() {
            if ignored_directory(&entry.file_name().to_string_lossy()) {
                continue;
            }
            if contains_program_under(root, &path, visited)? {
                return Ok(true);
            }
        } else if file_type.is_file() && is_program_file(&path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn is_program_file(path: &Path) -> Result<bool> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(extension.as_str(), "c" | "py" | "sh" | "bash") {
        return Ok(true);
    }
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut magic = [0u8; 128];
    let count = file.read(&mut magic)?;
    Ok(magic[..count].starts_with(b"\x7fELF") || magic[..count].starts_with(b"#!"))
}

pub fn snapshot(root: &Path, excluded_run_dir: Option<&Path>) -> Result<ProjectSnapshot> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolve {}", root.display()))?;
    if !root.is_dir() {
        bail!("{} is not a project directory", root.display());
    }
    let excluded = excluded_run_dir.and_then(|dir| dir.canonicalize().ok());
    let mut sources = BTreeMap::new();
    let mut stack = Vec::new();
    collect(
        &root,
        &root,
        &root,
        excluded.as_deref(),
        &mut stack,
        &mut sources,
    )?;
    let mut files = Vec::new();
    let mut bytes_total = 0u64;
    let mut hasher = Sha256::new();
    for (relative, source) in sources {
        let bytes = fs::read(&source).with_context(|| format!("read {}", source.display()))?;
        bytes_total = bytes_total.saturating_add(bytes.len() as u64);
        if bytes_total > MAX_BYTES {
            bail!(
                "project exceeds the {} MiB staging limit",
                MAX_BYTES / (1024 * 1024)
            );
        }
        let name = relative.to_string_lossy();
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        files.push(ProjectFile {
            relative,
            source,
            size: bytes.len() as u64,
        });
    }
    Ok(ProjectSnapshot {
        root,
        files,
        digest: hex::encode(hasher.finalize()),
    })
}

fn collect(
    root: &Path,
    logical: &Path,
    physical: &Path,
    excluded: Option<&Path>,
    stack: &mut Vec<PathBuf>,
    sources: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<()> {
    let canonical = physical
        .canonicalize()
        .with_context(|| format!("resolve {}", physical.display()))?;
    if !canonical.starts_with(root) {
        bail!(
            "project symlink escapes project root: {}",
            logical.display()
        );
    }
    if excluded.is_some_and(|dir| canonical.starts_with(dir)) {
        return Ok(());
    }
    if stack.contains(&canonical) {
        bail!("project directory symlink cycle at {}", logical.display());
    }
    stack.push(canonical.clone());
    for entry in
        fs::read_dir(&canonical).with_context(|| format!("scan {}", canonical.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let logical_child = logical.join(&name);
        let physical_child = entry.path();
        let resolved = physical_child
            .canonicalize()
            .with_context(|| format!("resolve {}", logical_child.display()))?;
        if !resolved.starts_with(root) {
            bail!(
                "project symlink escapes project root: {}",
                logical_child.display()
            );
        }
        if excluded.is_some_and(|dir| resolved.starts_with(dir)) {
            continue;
        }
        if resolved.is_dir() {
            if ignored_directory(&name.to_string_lossy()) {
                continue;
            }
            collect(root, &logical_child, &resolved, excluded, stack, sources)?;
        } else if resolved.is_file() {
            let relative = logical_child
                .strip_prefix(root)
                .context("project path escaped root")?
                .to_path_buf();
            sources.insert(relative, resolved);
            if sources.len() > MAX_FILES {
                bail!("project exceeds the {MAX_FILES} file staging limit");
            }
        }
    }
    stack.pop();
    Ok(())
}

pub fn stage(snapshot: &ProjectSnapshot, run_dir: &Path) -> Result<PathBuf> {
    let destination = run_dir.join("target/project");
    for file in &snapshot.files {
        let output = destination.join(&file.relative);
        fs::create_dir_all(output.parent().context("staged file has no parent")?)?;
        fs::copy(&file.source, &output)
            .with_context(|| format!("stage {}", file.source.display()))?;
    }
    Ok(destination)
}

pub fn select_entry(snapshot: &ProjectSnapshot, requested: Option<&Path>) -> Result<PathBuf> {
    if let Some(requested) = requested {
        let requested = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            snapshot.root.join(requested)
        };
        let absolute = requested
            .canonicalize()
            .with_context(|| format!("resolve entrypoint {}", requested.display()))?;
        let relative = absolute
            .strip_prefix(&snapshot.root)
            .with_context(|| format!("entrypoint {} is outside the project", absolute.display()))?
            .to_path_buf();
        if !snapshot.files.iter().any(|file| file.relative == relative) {
            bail!("entrypoint {} was not staged", relative.display());
        }
        if !is_program_file(&absolute)? {
            bail!(
                "{} is not a supported C, Python, shell, or Linux ELF entrypoint",
                relative.display()
            );
        }
        return Ok(relative);
    }

    let mut candidates = Vec::new();
    for file in &snapshot.files {
        if !is_program_file(&file.source)? {
            continue;
        }
        let name = file
            .relative
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("");
        if name == "__init__.py"
            || name == "setup.py"
            || name.starts_with("test_")
            || name.ends_with("_test.c")
        {
            continue;
        }
        let priority = match file.relative.to_string_lossy().as_ref() {
            "main.py" | "main.c" | "main.sh" | "main.bash" => 0,
            "src/main.py" | "src/main.c" | "src/main.sh" | "src/main.bash" => 1,
            "app.py" | "run.py" | "run.sh" | "run.bash" => 2,
            _ if name.starts_with("main.") => 3,
            _ => 4,
        };
        candidates.push((priority, file.relative.clone()));
    }
    candidates.sort();
    let Some((best, entry)) = candidates.first() else {
        bail!("project contains no supported C, Python, shell, or Linux ELF entrypoint");
    };
    if candidates.len() > 1 && candidates[1].0 == *best {
        let options = candidates
            .iter()
            .take(8)
            .map(|(_, path)| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("project has multiple possible entrypoints ({options}); pass --entry <path>");
    }
    Ok(entry.clone())
}
