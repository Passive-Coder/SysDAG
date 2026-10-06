//! Disposable Linux guest for tracing a target.
//!
//! On macOS the guest is an isolated Alpine container inside Docker Desktop's
//! lightweight VM (Apple Virtualization): 256 MiB, 1 CPU, loopback-only,
//! SYS_PTRACE, torn down after the run. That is the practical micro-VM host
//! when Firecracker/KVM is unavailable.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::canonical::digest_bytes;
use crate::config::Config;
use crate::project;
use crate::tracer::STRACE_FILTER;

#[derive(Debug)]
pub struct SandboxRun {
    pub run_dir: PathBuf,
    pub traces_dir: PathBuf,
    pub target_sha256: String,
    pub command: Vec<String>,
    pub target_exit_code: Option<i32>,
}

pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn doctor() -> Result<()> {
    println!("sysdag doctor");
    println!(
        "  host: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let docker = Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .output();
    match docker {
        Ok(o) if o.status.success() => {
            println!("  docker: {}", String::from_utf8_lossy(&o.stdout).trim());
        }
        _ => {
            println!("  docker: not available (required to trace programs on macOS)");
            println!("           install Docker Desktop, then rerun `sysdag doctor`");
        }
    }
    Ok(())
}

pub fn ensure_image(cfg: &Config) -> Result<()> {
    let image = &cfg.sandbox.image;
    let exists = Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if exists {
        return Ok(());
    }
    eprintln!("building micro-VM guest image {image} (first run only)...");
    let dockerfile = workspace_dockerfile()?;
    let status = Command::new("docker")
        .args(["build", "-t", image, "-f"])
        .arg(&dockerfile)
        .arg(dockerfile.parent().unwrap_or(Path::new(".")))
        .status()
        .context("docker build")?;
    if !status.success() {
        bail!("failed to build guest image {image}");
    }
    Ok(())
}

fn workspace_dockerfile() -> Result<PathBuf> {
    let candidates = [
        PathBuf::from("guest/Dockerfile"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("guest/Dockerfile"),
    ];
    for p in candidates {
        if p.is_file() {
            return Ok(p);
        }
    }
    // Write a fallback Dockerfile into the run-time work dir later if needed.
    let fallback = PathBuf::from("guest/Dockerfile");
    if let Some(dir) = fallback.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(
        &fallback,
        "FROM alpine:3.20\nRUN apk add --no-cache strace build-base python3 bash coreutils\nWORKDIR /guest\n",
    )?;
    Ok(fallback)
}

pub fn prepare_run_dir(root: &Path, run_id: &str) -> Result<PathBuf> {
    let dir = root.join("runs").join(run_id);
    fs::create_dir_all(dir.join("target"))?;
    fs::create_dir_all(dir.join("www"))?;
    fs::create_dir_all(dir.join("decoy"))?;
    fs::create_dir_all(dir.join("traces"))?;
    fs::create_dir_all(dir.join("work"))?;
    Ok(dir)
}

pub fn stage_target(run_dir: &Path, source: &Path) -> Result<(PathBuf, String)> {
    stage_target_with_entry(run_dir, source, None)
}

pub fn stage_target_with_entry(
    run_dir: &Path,
    source: &Path,
    requested_entry: Option<&Path>,
) -> Result<(PathBuf, String)> {
    let root = if source.is_dir() {
        source
            .canonicalize()
            .with_context(|| format!("resolve {}", source.display()))?
    } else {
        if requested_entry.is_some() {
            bail!("--entry applies to a project folder, not a file");
        }
        project::project_root_for_file(source)?
    };
    let snapshot = project::snapshot(&root, Some(run_dir))?;
    let relative = if source.is_dir() {
        project::select_entry(&snapshot, requested_entry)?
    } else {
        source
            .canonicalize()?
            .strip_prefix(&snapshot.root)
            .context("entrypoint is outside its project root")?
            .to_path_buf()
    };
    let dest = project::stage(&snapshot, run_dir)?.join(relative);
    Ok((dest, snapshot.digest))
}

pub fn run_in_microvm(
    cfg: &Config,
    run_dir: &Path,
    guest_rel: &str,
    target_args: &[String],
    retain_trace_on_error: bool,
) -> Result<SandboxRun> {
    if !docker_available() {
        bail!(
            "Docker is required to trace a program on this host.\n\
             Install Docker Desktop, or pass a recorded strace log instead."
        );
    }
    ensure_image(cfg)?;

    let traces = run_dir.join("traces");
    let script = build_guest_script(run_dir, guest_rel, target_args)?;
    fs::write(run_dir.join("work/run.sh"), script)?;

    let mount = run_dir
        .canonicalize()
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    let image = &cfg.sandbox.image;
    let mem = format!("{}m", cfg.sandbox.memory_mb);
    let cpus = cfg.sandbox.cpus.to_string();
    let mount_hash = digest_bytes(mount.to_string_lossy().as_bytes());
    let name = format!(
        "sysdag-{}-{}",
        run_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("run"),
        &mount_hash[..12]
    );

    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--name",
        &name,
        "--memory",
        &mem,
        "--cpus",
        &cpus,
        "--network",
        "none",
        "--cap-add=SYS_PTRACE",
        "--security-opt",
        "seccomp=unconfined",
        "-v",
    ]);
    cmd.arg(format!("{}:/guest", mount.display()));
    cmd.arg(image);
    cmd.args(["sh", "/guest/work/run.sh"]);

    let timeout = Duration::from_secs(cfg.sandbox.timeout_sec);
    let started = Instant::now();
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn docker micro-VM")?;
    let mut target_exit_code = None;

    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                let out = child.wait_with_output()?;
                let has_trace = fs::read_dir(&traces)
                    .map(|entries| entries.flatten().any(|entry| entry.path().is_file()))
                    .unwrap_or(false);
                if !retain_trace_on_error || !has_trace {
                    bail!(
                        "micro-VM run failed (exit {status}):\n{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                target_exit_code = status.code();
            }
            break;
        }
        if started.elapsed() > timeout {
            let _ = Command::new("docker").args(["kill", &name]).status();
            let _ = child.kill();
            bail!("micro-VM timed out after {}s", cfg.sandbox.timeout_sec);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let sha = digest_bytes(&fs::read(run_dir.join(guest_rel))?);

    Ok(SandboxRun {
        run_dir: run_dir.to_path_buf(),
        traces_dir: traces,
        target_sha256: sha,
        command: vec![guest_rel.to_string()],
        target_exit_code,
    })
}

fn build_guest_script(run_dir: &Path, guest_rel: &str, target_args: &[String]) -> Result<String> {
    let args = shell_join(target_args);
    let path = sh_single(&format!("/guest/{guest_rel}"));
    let ext = Path::new(guest_rel)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let (prepare, command) = if ext == "c" {
        (
            c_compile_command(run_dir, guest_rel)?,
            format!("/guest/work/a.out {args}"),
        )
    } else if ext == "py" {
        (String::new(), format!("python3 {path} {args}"))
    } else if ext == "sh" || guest_rel.ends_with(".bash") {
        (String::new(), format!("sh {path} {args}"))
    } else {
        (
            format!("chmod +x {path} 2>/dev/null || true"),
            format!("{path} {args}"),
        )
    };

    Ok(format!(
        r#"#!/bin/sh
set -eu
cd /guest/target/project
{prepare}
export APP_ROOT=/guest/www
export PYTHONPATH=/guest/target/project:/guest/target/project/src${{PYTHONPATH:+:$PYTHONPATH}}
exec strace -ff -ttt -T -yy -s 256 \
  -e trace={filter} \
  -o /guest/traces/trace -- \
  {command}
"#,
        prepare = prepare,
        filter = STRACE_FILTER,
        command = command.trim(),
    ))
}

fn c_compile_command(run_dir: &Path, guest_rel: &str) -> Result<String> {
    let root = run_dir.join("target/project");
    let entry = Path::new(guest_rel)
        .strip_prefix("target/project")
        .context("C entrypoint is outside the staged project")?
        .to_path_buf();
    let snapshot = project::snapshot(&root, None)?;
    let mut sources = BTreeSet::from([entry.clone()]);
    let mut headers = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::from([entry]);

    while let Some(relative) = queue.pop_front() {
        if !visited.insert(relative.clone()) {
            continue;
        }
        let text = fs::read_to_string(root.join(&relative))
            .with_context(|| format!("read C dependency {}", relative.display()))?;
        for line in text.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("#include") else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            let Some((name, _)) = rest.split_once('"') else {
                continue;
            };
            let Some(header) = resolve_local_include(&snapshot, &relative, name)? else {
                continue;
            };
            headers.insert(header.clone());
            queue.push_back(header.clone());
            if header.extension().and_then(|ext| ext.to_str()) == Some("h") {
                let stem = header
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("");
                let matches = snapshot
                    .files
                    .iter()
                    .filter(|file| {
                        file.relative.extension().and_then(|ext| ext.to_str()) == Some("c")
                            && file.relative.file_stem().and_then(|part| part.to_str())
                                == Some(stem)
                    })
                    .map(|file| file.relative.clone())
                    .collect::<Vec<_>>();
                if matches.len() == 1 {
                    let module = matches[0].clone();
                    if sources.insert(module.clone()) {
                        queue.push_back(module);
                    }
                }
            }
        }
    }

    let mut include_dirs = BTreeSet::from([PathBuf::new()]);
    for header in headers {
        if let Some(parent) = header.parent() {
            include_dirs.insert(parent.to_path_buf());
        }
    }
    let includes = include_dirs
        .iter()
        .map(|dir| {
            let guest = Path::new("/guest/target/project").join(dir);
            format!("-I{}", sh_single(&guest.to_string_lossy()))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let source_args = sources
        .iter()
        .map(|source| {
            sh_single(
                &Path::new("/guest/target/project")
                    .join(source)
                    .to_string_lossy(),
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        "gcc -O1 {includes} -o /guest/work/a.out {source_args}"
    ))
}

fn resolve_local_include(
    snapshot: &project::ProjectSnapshot,
    including: &Path,
    name: &str,
) -> Result<Option<PathBuf>> {
    let root = &snapshot.root;
    let candidates = [
        including.parent().unwrap_or(Path::new("")).join(name),
        PathBuf::from(name),
    ];
    for candidate in candidates {
        let path = root.join(&candidate);
        if path.is_file() {
            let canonical = path.canonicalize()?;
            let relative = canonical
                .strip_prefix(root)
                .with_context(|| format!("local include {} escapes project", name))?;
            return Ok(Some(relative.to_path_buf()));
        }
    }
    let matches = snapshot
        .files
        .iter()
        .filter(|file| file.relative.file_name() == Some(std::ffi::OsStr::new(name)))
        .map(|file| file.relative.clone())
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        bail!(
            "C include {name} matches multiple local headers; use a project-relative include path"
        );
    }
    Ok(matches.into_iter().next())
}

fn sh_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', r#"'"'"'"#))
}

fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| sh_single(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn file_sha256(path: &Path) -> Result<String> {
    Ok(digest_bytes(&fs::read(path)?))
}
