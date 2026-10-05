use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::canonical::digest_bytes;
use crate::config::Config;
use crate::detector::{
    find_baseline, load_baseline, save_baseline, score, train_baseline_with_provenance,
    BaselineManifest, DecisionRecord,
};
use crate::event::{ParseStats, TraceEvent};
use crate::features::{encode, EncodedGraph};
use crate::graph::{build_windows, validate_graph, GraphQuality, GraphRecord};
use crate::sandbox::{file_sha256, prepare_run_dir, run_in_microvm, stage_target};
use crate::streaming::WindowBuilder;
use crate::tracer::{looks_like_strace, parse_strace_path_with_privacy_map};
use crate::visualizer::{format_decision, write_graph_artifacts};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Auto,
    Train,
    Monitor,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub mode: Mode,
    pub target_sha256: String,
    pub events: usize,
    /// Aggregate capture-quality stats from parsing (Phase 1.3).
    pub parse_stats: Option<ParseStats>,
    pub graphs: Vec<GraphRecord>,
    pub encoded: Vec<EncodedGraph>,
    pub decisions: Vec<DecisionRecord>,
    pub baseline_path: Option<PathBuf>,
    pub run_dir: PathBuf,
}

pub enum InputKind {
    Strace,
    EventJsonl,
    Program,
}

pub fn classify_input(path: &Path) -> Result<InputKind> {
    if path.is_dir() {
        return Ok(InputKind::Strace);
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "c" | "py" | "sh" | "bash") {
        return Ok(InputKind::Program);
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.starts_with(b"\x7fELF") {
        return Ok(InputKind::Program);
    }
    // Mach-O cannot run in the Linux guest.
    if bytes.len() >= 4
        && matches!(
            &bytes[..4],
            b"\xcf\xfa\xed\xfe" | b"\xce\xfa\xed\xfe" | b"\xca\xfe\xba\xbe" | b"\xfe\xed\xfa\xce"
        )
    {
        bail!(
            "{} is a macOS binary and cannot run inside the Linux micro-VM.\n\
             Pass a .c / .py / .sh source file, a Linux ELF, or a strace log.",
            path.display()
        );
    }
    let text = String::from_utf8_lossy(&bytes);
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first.starts_with('{') && first.contains("schema_version") {
        return Ok(InputKind::EventJsonl);
    }
    if looks_like_strace(&text) {
        return Ok(InputKind::Strace);
    }
    Ok(InputKind::Program)
}

fn write_private_path_map(
    run_dir: &Path,
    map: BTreeMap<String, String>,
    cfg: &Config,
) -> Result<()> {
    if cfg.privacy.is_redact_enabled() && !map.is_empty() {
        fs::write(
            run_dir.join("path-map.json"),
            serde_json::to_string_pretty(&map)?,
        )?;
    }
    Ok(())
}
type IngestResult = (
    Vec<TraceEvent>,
    String,
    PathBuf,
    GraphQuality,
    Option<ParseStats>,
);

fn ingest(
    path: &Path,
    cfg: &Config,
    work_root: &Path,
    run_id: &str,
    target_args: &[String],
    app_root_override: Option<&str>,
) -> Result<IngestResult> {
    let mut cfg = cfg.clone();
    if let Some(root) = app_root_override {
        cfg.labels.app_root = root.to_string();
    }
    match classify_input(path)? {
        InputKind::Strace => {
            let sha = if path.is_file() {
                file_sha256(path)?
            } else {
                digest_bytes(path.to_string_lossy().as_bytes())
            };
            let (events, stats, path_map) = parse_strace_path_with_privacy_map(path, &cfg)?;
            let anchor_fraction = if events.is_empty() {
                0.0
            } else {
                let anchored = events
                    .iter()
                    .filter(|e| e.enter_ns > 0 && e.exit_ns >= e.enter_ns)
                    .count();
                anchored as f64 / events.len() as f64
            };
            let quality = GraphQuality {
                capture_loss: stats.lost_events_estimate,
                unknown_calls: stats.unknown_syscalls,
                anchor_fraction,
                rejected_lines: stats.rejected,
            };
            let run_dir = prepare_run_dir(work_root, run_id)?;
            write_private_path_map(&run_dir, path_map, &cfg)?;
            Ok((events, sha, run_dir, quality, Some(stats)))
        }
        InputKind::EventJsonl => {
            let sha = file_sha256(path)?;
            let text = fs::read_to_string(path)?;
            let mut events = Vec::new();
            for (i, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let ev: TraceEvent = serde_json::from_str(line)
                    .with_context(|| format!("{}:{}", path.display(), i + 1))?;
                events.push(ev);
            }
            let run_dir = prepare_run_dir(work_root, run_id)?;
            Ok((events, sha, run_dir, GraphQuality::default(), None))
        }
        InputKind::Program => {
            cfg.labels.app_root = "/guest/www".into();
            let run_dir = prepare_run_dir(work_root, run_id)?;
            let (_dest, sha) = stage_target(&run_dir, path)?;
            let rel = format!(
                "target/{}",
                path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("program")
            );
            let sandbox = run_in_microvm(&cfg, &run_dir, &rel, target_args)?;
            let (events, stats, path_map) =
                parse_strace_path_with_privacy_map(&sandbox.traces_dir, &cfg)?;
            let quality = GraphQuality {
                capture_loss: stats.lost_events_estimate,
                unknown_calls: stats.unknown_syscalls,
                rejected_lines: stats.rejected,
                ..GraphQuality::default()
            };
            write_private_path_map(&run_dir, path_map, &cfg)?;
            Ok((events, sha, run_dir, quality, Some(stats)))
        }
    }
}

fn encode_all(
    events: &[TraceEvent],
    cfg: &Config,
    run_id: &str,
    key: &str,
    q: GraphQuality,
) -> Result<Vec<EncodedGraph>> {
    if events.is_empty() {
        bail!("no tracked syscall events (file/network/descriptor/process) were captured");
    }
    let graphs = build_windows(events, cfg, run_id, key, q);
    let mut encoded = Vec::new();
    for g in graphs {
        validate_graph(&g).map_err(|e| anyhow::anyhow!("graph invariant: {e}"))?;
        encoded.push(encode(g, cfg));
    }
    Ok(encoded)
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_path(
    path: &Path,
    mode: Mode,
    cfg: &Config,
    work_root: &Path,
    baseline_dir: &Path,
    target_args: &[String],
    write_artifacts: bool,
    identity: Option<&str>,
) -> Result<RunReport> {
    analyze_path_opts(
        path,
        mode,
        cfg,
        work_root,
        baseline_dir,
        target_args,
        write_artifacts,
        identity,
        AnalyzeOpts::default(),
    )
}

/// Extra switches for `analyze_path` (kept additive so existing callers are stable).
#[derive(Debug, Clone, Default)]
pub struct AnalyzeOpts {
    /// Permit monitoring with a baseline that has hard compatibility mismatches.
    pub allow_mismatch: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn analyze_path_opts(
    path: &Path,
    mode: Mode,
    cfg: &Config,
    work_root: &Path,
    baseline_dir: &Path,
    target_args: &[String],
    write_artifacts: bool,
    identity: Option<&str>,
    opts: AnalyzeOpts,
) -> Result<RunReport> {
    let run_id = new_run_id();
    let (events, file_sha, run_dir, quality, parse_stats) =
        ingest(path, cfg, work_root, &run_id, target_args, None)?;
    let target_sha =
        identity
            .map(|s| s.to_string())
            .unwrap_or_else(|| match classify_input(path) {
                Ok(InputKind::Program) => file_sha.clone(),
                _ => "strace-anonymous".into(),
            });
    let encoded = encode_all(&events, cfg, &run_id, &target_sha, quality)?;

    if write_artifacts {
        for (i, enc) in encoded.iter().enumerate() {
            write_graph_artifacts(&run_dir.join("graphs").join(format!("w{i:04}")), &enc.graph)?;
        }
        let jsonl: Vec<String> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect();
        fs::write(run_dir.join("events.jsonl"), jsonl.join("\n"))?;
    }

    let existing = find_baseline(baseline_dir, &target_sha);
    let resolved = match mode {
        Mode::Train => Mode::Train,
        Mode::Monitor => Mode::Monitor,
        Mode::Auto => {
            if existing.is_some() {
                Mode::Monitor
            } else {
                Mode::Train
            }
        }
    };

    match resolved {
        Mode::Train => {
            let provenance = crate::detector::TrainingProvenance {
                run_ids: vec![run_id.clone()],
                total_events: events.len() as u64,
                window_count: encoded.len() as u64,
                input_digests: BTreeMap::from([("input".into(), file_sha.clone())]),
                trained_with_config_sha256: cfg.digest(),
            };
            let baseline = train_baseline_with_provenance(
                &encoded,
                &events,
                cfg,
                &target_sha,
                &target_sha,
                Some(provenance),
            );
            let path = save_baseline(baseline_dir, &baseline)?;
            if write_artifacts {
                fs::copy(&path, run_dir.join("baseline.json"))?;
                write_run_manifest(
                    &run_dir,
                    &run_id,
                    "Train",
                    &file_sha,
                    cfg,
                    &encoded,
                    Some("baseline.json"),
                    &["baseline.json", "events.jsonl"],
                )?;
            }
            Ok(RunReport {
                mode: Mode::Train,
                target_sha256: target_sha,
                events: events.len(),
                parse_stats,
                graphs: encoded.iter().map(|e| e.graph.clone()).collect(),
                encoded,
                decisions: vec![],
                baseline_path: Some(path),
                run_dir,
            })
        }
        Mode::Monitor => {
            let bp = existing.ok_or_else(|| {
                anyhow::anyhow!(
                    "no baseline for this file; run `sysdag train {}` first",
                    path.display()
                )
            })?;
            let baseline = load_baseline(&bp)?;
            let compat = baseline.compatibility(cfg, &target_sha);
            if !compat.compatible {
                if !opts.allow_mismatch {
                    bail!(
                        "baseline is incompatible with this run: {}\
                         \nre-train (`sysdag train`) or pass --allow-mismatch to proceed anyway",
                        compat.mismatches.join("; ")
                    );
                }
                eprintln!(
                    "warning: proceeding with incompatible baseline: {}",
                    compat.mismatches.join("; ")
                );
            }
            for w in &compat.warnings {
                eprintln!("note: {w}");
            }
            let decisions: Vec<_> = encoded.iter().map(|e| score(e, &baseline, cfg)).collect();
            if write_artifacts {
                fs::write(
                    run_dir.join("decisions.json"),
                    serde_json::to_string_pretty(&decisions)?,
                )?;
                let base_file = bp.file_name().and_then(|s| s.to_str()).map(str::to_string);
                write_run_manifest(
                    &run_dir,
                    &run_id,
                    "Monitor",
                    &file_sha,
                    cfg,
                    &encoded,
                    base_file.as_deref(),
                    &["decisions.json", "events.jsonl"],
                )?;
            }
            Ok(RunReport {
                mode: Mode::Monitor,
                target_sha256: target_sha,
                events: events.len(),
                parse_stats,
                graphs: encoded.iter().map(|e| e.graph.clone()).collect(),
                encoded,
                decisions,
                baseline_path: Some(bp),
                run_dir,
            })
        }
        Mode::Auto => unreachable!(),
    }
}

pub fn print_report(report: &RunReport, json: bool) -> Result<i32> {
    if json {
        let v = serde_json::json!({
            "mode": format!("{:?}", report.mode),
            "target_sha256": report.target_sha256,
            "events": report.events,
            "windows": report.encoded.len(),
            "capture_quality": capture_quality_summary(report),
            "baseline": report.baseline_path,
            "run_dir": report.run_dir,
            "decisions": report.decisions,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        if let Some(q) = capture_quality_summary(report) {
            println!("capture-quality: {q}");
        }
        match report.mode {
            Mode::Train => {
                println!(
                    "trained baseline from {} events / {} windows",
                    report.events,
                    report.encoded.len()
                );
                if let Some(p) = &report.baseline_path {
                    println!("wrote {}", p.display());
                }
                println!("re-run `sysdag <file>` on a new workload to monitor");
            }
            Mode::Monitor => {
                println!(
                    "monitored {} events / {} windows",
                    report.events,
                    report.encoded.len()
                );
                for d in &report.decisions {
                    println!("  {}  {}", d.window_id, format_decision(d));
                }
            }
            Mode::Auto => {}
        }
        println!("artifacts {}", report.run_dir.display());
    }
    let anomalous = report.decisions.iter().any(|d| d.decision == "ANOMALOUS");
    Ok(if anomalous { 2 } else { 0 })
}

/// One-line capture-quality summary for reports (Phase 1.3); None when no stats.
fn capture_quality_summary(report: &RunReport) -> Option<String> {
    let stats = report.parse_stats.as_ref()?;
    if stats.quality_loss() == 0 {
        return Some("clean".into());
    }
    let rate = if stats.lines > 0 {
        format!(
            " ({:.2}% of {} lines)",
            stats.quality_loss() as f64 / stats.lines as f64 * 100.0,
            stats.lines
        )
    } else {
        String::new()
    };
    Some(format!(
        "unknown={} malformed={} lost={}{}",
        stats.unknown_syscalls, stats.malformed_records, stats.lost_events_estimate, rate
    ))
}

fn new_run_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("run-{ns}")
}

/// Write `manifest.json` into `run_dir`, checksumming every artifact present.
/// Files in `required` that are missing cause an error; others are skipped.
#[allow(clippy::too_many_arguments)]
pub fn write_run_manifest(
    run_dir: &Path,
    run_id: &str,
    mode_name: &str,
    input_sha: &str,
    cfg: &Config,
    encoded: &[EncodedGraph],
    baseline_file: Option<&str>,
    required: &[&str],
) -> Result<()> {
    use crate::canonical::digest_bytes;
    use crate::detector::RunManifest;

    let mut checksums = BTreeMap::new();
    for rel in ["events.jsonl", "decisions.json", "baseline.json"] {
        let p = run_dir.join(rel);
        if let Ok(bytes) = fs::read(&p) {
            checksums.insert(rel.to_string(), digest_bytes(&bytes));
        } else if required.contains(&rel) {
            bail!("expected artifact {rel} missing from {}", run_dir.display());
        }
    }
    let graphs_dir = run_dir.join("graphs");
    if let Ok(entries) = fs::read_dir(&graphs_dir) {
        let mut names: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for name in names {
            let rel = format!("graphs/{name}");
            // Directory entries hold graph.dot / graph.json; flatten to files.
            let p = graphs_dir.join(&name);
            if p.is_dir() {
                for f in ["graph.json", "graph.dot"] {
                    let fp = p.join(f);
                    if let Ok(bytes) = fs::read(&fp) {
                        checksums.insert(format!("{rel}/{f}"), digest_bytes(&bytes));
                    }
                }
            }
        }
    }

    let manifest = RunManifest {
        manifest_schema: crate::MANIFEST_SCHEMA.into(),
        run_id: run_id.to_string(),
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        sysdag_version: crate::detector::crate_version(),
        mode: mode_name.into(),
        input_sha256: input_sha.into(),
        config_sha256: cfg.digest(),
        event_count: 0,
        graph_digests: encoded
            .iter()
            .map(|e| e.graph.graph_digest_before_wl.clone())
            .collect(),
        baseline_file: baseline_file.map(str::to_string),
        artifact_checksums: checksums,
        artifact_checksum: String::new(),
    };
    let mut manifest = manifest;
    manifest.event_count = match fs::read_to_string(run_dir.join("events.jsonl")) {
        Ok(text) => text.lines().filter(|l| !l.trim().is_empty()).count() as u64,
        Err(_) => 0,
    };
    manifest.artifact_checksum = manifest.checksum();
    fs::write(
        run_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(())
}

pub fn load_run_manifest(run_dir: &Path) -> Result<crate::detector::RunManifest> {
    let text = fs::read_to_string(run_dir.join("manifest.json"))
        .with_context(|| format!("read manifest in {}", run_dir.display()))?;
    serde_json::from_str(&text).with_context(|| "parse manifest.json")
}

pub fn monitor_events(
    events: Vec<TraceEvent>,
    cfg: &Config,
    baseline: &BaselineManifest,
    run_id: &str,
) -> Result<Vec<DecisionRecord>> {
    let sha = baseline.target_sha256.clone();
    let encoded = encode_all(&events, cfg, run_id, &sha, GraphQuality::default())?;
    Ok(encoded.iter().map(|e| score(e, baseline, cfg)).collect())
}

/// Incremental counterpart to `monitor_events`. Decisions are returned as each
/// complete window closes; `evicted` feeds the existing DEGRADED_CAPTURE rule.
pub fn monitor_event_stream<I: IntoIterator<Item = TraceEvent>>(
    events: I,
    cfg: &Config,
    baseline: &BaselineManifest,
    run_id: &str,
    max_in_flight: usize,
) -> Vec<DecisionRecord> {
    let mut builder =
        WindowBuilder::new(cfg.clone(), run_id, &baseline.target_sha256, max_in_flight);
    events
        .into_iter()
        .filter_map(|e| builder.push(e))
        .map(|g| score(&g, baseline, cfg))
        .collect()
}
