//! Disposable Linux guest for tracing a target.
//!
//! On macOS the guest is an isolated Alpine container inside Docker Desktop's
//! lightweight VM (Apple Virtualization): 256 MiB, 1 CPU, loopback-only,
//! SYS_PTRACE, torn down after the run. That is the practical micro-VM host
//! when Firecracker/KVM is unavailable.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::canonical::digest_bytes;
use crate::config::Config;
use crate::tracer::STRACE_FILTER;

#[derive(Debug)]
pub struct SandboxRun {
    pub run_dir: PathBuf,
    pub traces_dir: PathBuf,
    pub target_sha256: String,
    pub command: Vec<String>,
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
    let bytes = fs::read(source).with_context(|| format!("read {}", source.display()))?;
    let sha = digest_bytes(&bytes);
    let dest = run_dir
        .join("target")
        .join(source.file_name().unwrap_or_default());
    fs::write(&dest, &bytes)?;
    Ok((dest, sha))
}

pub fn run_in_microvm(
    cfg: &Config,
    run_dir: &Path,
    guest_rel: &str,
    target_args: &[String],
) -> Result<SandboxRun> {
    if !docker_available() {
        bail!(
            "Docker is required to trace a program on this host.\n\
             Install Docker Desktop, or pass a recorded strace log instead."
        );
    }
    ensure_image(cfg)?;

    let traces = run_dir.join("traces");
    let script = build_guest_script(guest_rel, target_args)?;
    fs::write(run_dir.join("work/run.sh"), script)?;

    let mount = run_dir
        .canonicalize()
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    let image = &cfg.sandbox.image;
    let mem = format!("{}m", cfg.sandbox.memory_mb);
    let cpus = cfg.sandbox.cpus.to_string();
    let name = format!(
        "sysdag-{}",
        run_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("run")
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

    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                let out = child.wait_with_output()?;
                bail!(
                    "micro-VM run failed (exit {status}):\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
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

    let sha = if let Some(name) = Path::new(guest_rel).file_name() {
        let p = run_dir.join("target").join(name);
        digest_bytes(&fs::read(p).unwrap_or_default())
    } else {
        digest_bytes(b"unknown")
    };

    Ok(SandboxRun {
        run_dir: run_dir.to_path_buf(),
        traces_dir: traces,
        target_sha256: sha,
        command: vec![guest_rel.to_string()],
    })
}

fn build_guest_script(guest_rel: &str, target_args: &[String]) -> Result<String> {
    let args = shell_join(target_args);
    let path = format!("/guest/{guest_rel}");
    let ext = Path::new(guest_rel)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let (prepare, command) = if ext == "c" {
        (
            format!("gcc -O1 -o /guest/work/a.out {path}"),
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
cd /guest
{prepare}
export APP_ROOT=/guest/www
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
