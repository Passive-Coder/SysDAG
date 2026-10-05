//! Phase 2 reproducible datasets, calibration, and evaluation.
use crate::{
    canonical::digest_bytes,
    config::Config,
    detector::{
        load_baseline, save_baseline, score, train_baseline_with_provenance, CalibrationProvenance,
        TrainingProvenance,
    },
    ebpf::EbpfEnvelope,
    event::TraceEvent,
    features::{encode, EncodedGraph},
    graph::{build_windows, GraphQuality},
    tracer::parse_strace_path,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRun {
    pub id: String,
    pub trace: String,
    pub partition: String,
    pub label: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManifest {
    pub schema: String,
    pub id: String,
    pub created_unix: u64,
    pub source: String,
    pub host: BTreeMap<String, String>,
    pub runs: Vec<DatasetRun>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub dataset_id: String,
    pub baseline: String,
    pub runs: usize,
    pub windows: usize,
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    pub fn_: u64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub fpr: f64,
    pub precision_wilson_95: [f64; 2],
    pub recall_wilson_95: [f64; 2],
    pub fpr_wilson_95: [f64; 2],
    pub latency_ms_p50: f64,
    pub latency_ms_p95: f64,
    pub latency_ms_p99: f64,
    pub cpu_time_ms: f64,
    pub peak_rss_bytes: Option<u64>,
    pub capture_quality_loss: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentManifest {
    pub schema: String,
    pub created_unix: u64,
    pub dataset_id: String,
    pub dataset_manifest_sha256: String,
    pub baseline_sha256: String,
    pub config_sha256: String,
    pub software_version: String,
    pub hardware: BTreeMap<String, String>,
    pub seed: u64,
    pub artifacts: BTreeMap<String, String>,
    pub checksum: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct AblationGrid {
    #[serde(rename = "run")]
    pub runs: Vec<AblationRun>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct AblationRun {
    pub name: String,
    pub window_size: Option<usize>,
    pub window_overlap: Option<usize>,
    pub wl_iterations: Option<u32>,
    pub directed: Option<bool>,
    pub edge_typed: Option<bool>,
    pub buffer_flow: Option<bool>,
    pub representation: Option<String>,
    pub edge_set: Option<String>,
    pub exact_only: Option<bool>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AblationResult {
    pub name: String,
    pub config_sha256: String,
    pub result_dir: String,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn walk(p: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in fs::read_dir(p)? {
        let x = e?.path();
        if x.is_dir() {
            walk(&x, out)?
        } else {
            out.push(x)
        }
    }
    Ok(())
}
fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    if v.is_empty() {
        1.5
    } else {
        v[((v.len() - 1) as f64 * p).ceil() as usize]
    }
}
fn wilson(success: u64, total: u64) -> [f64; 2] {
    if total == 0 {
        return [0.0, 1.0];
    };
    let z = 1.959963984540054;
    let n = total as f64;
    let p = success as f64 / n;
    let d = 1.0 + z * z / n;
    let c = (p + z * z / (2.0 * n)) / d;
    let r = z * ((p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt()) / d;
    [(c - r).max(0.0), (c + r).min(1.0)]
}
fn peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = fs::read_to_string("/proc/self/status").ok()?;
        let line = s.lines().find(|x| x.starts_with("VmHWM:"))?;
        return line
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
            .map(|x| x * 1024);
    }
    #[cfg(not(target_os = "linux"))]
    None
}

pub fn import_dataset(source: &Path, work: &Path, requested: Option<&str>) -> Result<PathBuf> {
    if !source.is_dir() {
        bail!("dataset import source must be a directory")
    };
    let raw = requested
        .or_else(|| source.file_name().and_then(|x| x.to_str()))
        .unwrap_or("dataset");
    let id: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let root = work.join("datasets").join(&id);
    if root.exists() {
        bail!("dataset already exists: {}", root.display())
    };
    fs::create_dir_all(&root)?;
    let mut source_files = Vec::new();
    walk(source, &mut source_files)?;
    for f in source_files {
        let rel = f.strip_prefix(source).unwrap();
        let dst = root.join(rel);
        fs::create_dir_all(dst.parent().unwrap())?;
        fs::copy(f, dst)?;
    }
    let labels: BTreeMap<String, String> =
        match fs::read_to_string(source.join("ground_truth.json")) {
            Ok(t) => serde_json::from_str(&t).context("parse ground_truth.json")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
    let mut files = Vec::new();
    walk(&root, &mut files)?;
    let mut clean = 0;
    let mut runs = Vec::new();
    for f in files {
        if f.extension().and_then(|x| x.to_str()) != Some("strace") {
            continue;
        };
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let label = labels.get(&rel).cloned().unwrap_or_else(|| {
            if rel.split('/').any(|x| x == "attacks") {
                "attack".into()
            } else {
                "clean".into()
            }
        });
        let partition = if label == "attack" {
            "test"
        } else {
            let x = match clean % 5 {
                3 => "validation",
                4 => "test",
                _ => "train",
            };
            clean += 1;
            x
        };
        let run_id = Path::new(&rel)
            .parent()
            .and_then(|x| x.file_name())
            .and_then(|x| x.to_str())
            .unwrap_or("run")
            .to_string();
        runs.push(DatasetRun {
            id: run_id,
            trace: rel,
            partition: partition.into(),
            label,
            sha256: digest_bytes(&fs::read(f)?),
        })
    }
    if runs.is_empty() {
        bail!("no .strace files found")
    };
    runs.sort_by(|a, b| a.trace.cmp(&b.trace));
    let m = DatasetManifest {
        schema: "1.0".into(),
        id,
        created_unix: now(),
        source: source.display().to_string(),
        host: BTreeMap::from([
            ("arch".into(), std::env::consts::ARCH.into()),
            ("os".into(), std::env::consts::OS.into()),
        ]),
        runs,
    };
    let p = root.join("manifest.json");
    fs::write(&p, serde_json::to_string_pretty(&m)?)?;
    Ok(p)
}
pub fn load_dataset(work: &Path, id: &str) -> Result<(PathBuf, DatasetManifest)> {
    let root = work.join("datasets").join(id);
    let t = fs::read_to_string(root.join("manifest.json"))
        .with_context(|| format!("load dataset {id}"))?;
    Ok((root, serde_json::from_str(&t)?))
}
fn encoded(trace: &Path, cfg: &Config, id: &str, key: &str) -> Result<(Vec<EncodedGraph>, u64)> {
    let (e, quality_loss) = capture_events(trace, cfg)?;
    if e.is_empty() {
        bail!("{} has no tracked events", trace.display())
    };
    let q = GraphQuality {
        capture_loss: quality_loss,
        ..Default::default()
    };
    Ok((
        build_windows(&e, cfg, id, key, q)
            .into_iter()
            .map(|g| encode(g, cfg))
            .collect(),
        quality_loss,
    ))
}

/// Read either the strace reference format or JSONL emitted by `collect-ebpf`.
/// This keeps the evaluation/calibration path identical across capture backends.
fn capture_events(trace: &Path, cfg: &Config) -> Result<(Vec<TraceEvent>, u64)> {
    if trace.extension().and_then(|x| x.to_str()) != Some("jsonl") {
        let (events, stats) = parse_strace_path(trace, cfg)?;
        return Ok((events, stats.quality_loss()));
    }
    let mut events = Vec::new();
    let mut loss: u64 = 0;
    for (line_no, line) in fs::read_to_string(trace)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match EbpfEnvelope::parse_jsonl(line)
            .or_else(|_| {
                serde_json::from_str::<TraceEvent>(line).map(|event| EbpfEnvelope::Event { event })
            })
            .with_context(|| format!("decode {}:{}", trace.display(), line_no + 1))?
        {
            EbpfEnvelope::Event { event } => events.push(event),
            EbpfEnvelope::Lost { count } => loss = loss.saturating_add(count),
        }
    }
    Ok((events, loss))
}
pub fn calibrate(work: &Path, id: &str, cfg: &Config) -> Result<PathBuf> {
    let (root, d) = load_dataset(work, id)?;
    let key = format!("dataset-{id}");
    let (mut train, mut digests, mut ids) = (Vec::new(), BTreeMap::new(), Vec::new());
    for r in d
        .runs
        .iter()
        .filter(|r| r.label == "clean" && r.partition == "train")
    {
        let (x, _) = encoded(&root.join(&r.trace), cfg, &r.id, &key)?;
        train.extend(x);
        digests.insert(r.id.clone(), r.sha256.clone());
        ids.push(r.id.clone())
    }
    if train.is_empty() {
        bail!("dataset needs a clean train run")
    };
    let prov = TrainingProvenance {
        run_ids: ids,
        total_events: 0,
        window_count: train.len() as u64,
        input_digests: digests,
        trained_with_config_sha256: cfg.digest(),
    };
    let mut b = train_baseline_with_provenance(&train, &[], cfg, &key, &key, Some(prov));
    let (mut scores, mut validation) = (Vec::new(), Vec::new());
    for r in d
        .runs
        .iter()
        .filter(|r| r.label == "clean" && r.partition == "validation")
    {
        let (x, _) = encoded(&root.join(&r.trace), cfg, &r.id, &key)?;
        scores.extend(x.iter().map(|e| score(e, &b, cfg).score));
        validation.push(r.id.clone())
    }
    if scores.is_empty() {
        bail!("dataset needs a clean validation run")
    };
    let review = pct(scores.clone(), 0.99) + 0.01;
    let alert = (pct(scores.clone(), 0.999) + 0.01).max(review);
    b.thresholds.insert("review".into(), review);
    b.thresholds.insert("alert".into(), alert);
    b.calibration=Some(CalibrationProvenance{validation_run_ids:validation,validation_windows:scores.len()as u64,review_fpr_target:0.01,alert_fpr_target:0.001,rationale:"Empirical clean-validation score quantiles with a strict-comparison margin; monitor uses frozen thresholds.".into()});
    b.refresh_checksum();
    save_baseline(&work.join("baselines"), &b)
}
pub fn evaluate(work: &Path, id: &str, baseline_path: &Path, cfg: &Config) -> Result<PathBuf> {
    let (root, d) = load_dataset(work, id)?;
    let b = load_baseline(baseline_path)?;
    let all = Instant::now();
    let (mut tp, mut fp, mut tn, mut fn_, mut windows, mut loss) = (0, 0, 0, 0, 0, 0);
    let mut times = Vec::new();
    for r in d.runs.iter().filter(|r| r.partition == "test") {
        let t = Instant::now();
        let (x, l) = encoded(&root.join(&r.trace), cfg, &r.id, &b.target_sha256)?;
        loss += l;
        let found = x.iter().any(|e| {
            windows += 1;
            let z = score(e, &b, cfg);
            z.decision == "REVIEW" || z.decision == "ANOMALOUS"
        });
        times.push(t.elapsed().as_secs_f64() * 1000.0);
        match (r.label == "attack", found) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
    }
    if tp + fp + tn + fn_ == 0 {
        bail!("dataset has no test runs")
    };
    let precision = tp as f64 / (tp + fp).max(1) as f64;
    let recall = tp as f64 / (tp + fn_).max(1) as f64;
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };
    let report = EvaluationReport {
        dataset_id: id.into(),
        baseline: baseline_path.display().to_string(),
        runs: (tp + fp + tn + fn_) as usize,
        windows,
        tp,
        fp,
        tn,
        fn_,
        precision,
        recall,
        f1,
        fpr: fp as f64 / (fp + tn).max(1) as f64,
        precision_wilson_95: wilson(tp, tp + fp),
        recall_wilson_95: wilson(tp, tp + fn_),
        fpr_wilson_95: wilson(fp, fp + tn),
        latency_ms_p50: pct(times.clone(), 0.5),
        latency_ms_p95: pct(times.clone(), 0.95),
        latency_ms_p99: pct(times, 0.99),
        cpu_time_ms: all.elapsed().as_secs_f64() * 1000.0,
        peak_rss_bytes: peak_rss_bytes(),
        capture_quality_loss: loss,
    };
    let out = work.join("results").join(format!("{}-{}", id, now()));
    fs::create_dir_all(&out)?;
    fs::write(
        out.join("report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    fs::write(out.join("summary.md"),format!("# Evaluation {id}\n\nPrecision: {:.4} ({:.4}–{:.4})\n\nRecall: {:.4} ({:.4}–{:.4})\n\nF1: {:.4}\n\nFPR: {:.4} ({:.4}–{:.4})\n\nPipeline CPU/wall time: {:.2} ms\n",report.precision,report.precision_wilson_95[0],report.precision_wilson_95[1],report.recall,report.recall_wilson_95[0],report.recall_wilson_95[1],report.f1,report.fpr,report.fpr_wilson_95[0],report.fpr_wilson_95[1],report.cpu_time_ms))?;
    Ok(out)
}

pub fn measure(work: &Path, id: &str, baseline_path: &Path, cfg: &Config) -> Result<PathBuf> {
    let (root, d) = load_dataset(work, id)?;
    let b = load_baseline(baseline_path)?;
    if b.config_sha256 != cfg.digest() {
        bail!("measurement config differs from baseline; pass the training --config to keep the experiment reproducible")
    }
    for r in d
        .runs
        .iter()
        .filter(|r| r.partition == "test" && r.label == "clean")
    {
        let (x, _) = encoded(&root.join(&r.trace), cfg, &r.id, &b.target_sha256)?;
        let scores: Vec<_> = x.iter().map(|e| score(e, &b, cfg)).collect();
        if scores.iter().any(|d| d.decision != "NORMAL") {
            bail!(
                "known-clean test run {} did not score NORMAL: {:?}",
                r.id,
                scores
                    .iter()
                    .map(|d| (&d.decision, d.score, d.threshold_review))
                    .collect::<Vec<_>>()
            )
        }
    }
    let result = evaluate(work, id, baseline_path, cfg)?;
    let mut artifacts = BTreeMap::new();
    for name in ["report.json", "summary.md"] {
        artifacts.insert(name.into(), digest_bytes(&fs::read(result.join(name))?));
    }
    let mut m = ExperimentManifest {
        schema: "1.0".into(),
        created_unix: now(),
        dataset_id: id.into(),
        dataset_manifest_sha256: digest_bytes(&fs::read(root.join("manifest.json"))?),
        baseline_sha256: digest_bytes(&fs::read(baseline_path)?),
        config_sha256: cfg.digest(),
        software_version: crate::VERSION.into(),
        hardware: BTreeMap::from([
            ("arch".into(), std::env::consts::ARCH.into()),
            ("os".into(), std::env::consts::OS.into()),
        ]),
        seed: 0,
        artifacts,
        checksum: String::new(),
    };
    m.checksum = digest_bytes(&serde_json::to_vec(&m)?);
    fs::write(
        result.join("experiment-manifest.json"),
        serde_json::to_string_pretty(&m)?,
    )?;
    Ok(result)
}

/// Execute representation/window/WL sweeps described by `[[run]]` TOML entries.
pub fn ablate(work: &Path, dataset: &str, grid_path: &Path, base: &Config) -> Result<PathBuf> {
    let grid: AblationGrid =
        toml::from_str(&fs::read_to_string(grid_path)?).context("parse ablation grid")?;
    if grid.runs.is_empty() {
        bail!("ablation grid has no [[run]] entries")
    };
    let mut results = Vec::new();
    for run in grid.runs {
        let mut cfg = base.clone();
        if let Some(x) = run.window_size {
            cfg.window.size = x
        };
        if let Some(x) = run.window_overlap {
            cfg.window.overlap = x
        };
        if let Some(x) = run.wl_iterations {
            cfg.wl.iterations = x
        };
        if let Some(x) = run.directed {
            cfg.wl.directed = x
        };
        if let Some(x) = run.edge_typed {
            cfg.wl.edge_typed = x
        };
        if let Some(x) = run.buffer_flow {
            cfg.graph.buffer_flow = x
        };
        if let Some(x) = run.representation {
            cfg.graph.representation = x
        };
        if let Some(x) = run.edge_set {
            cfg.graph.edge_set = x
        };
        if run.exact_only.unwrap_or(false) {
            cfg.detector.exact_weight = 1.0;
            cfg.detector.similarity_weight = 0.0;
            cfg.detector.size_weight = 0.0;
            cfg.detector.risk_weight = 0.0
        };
        let baseline = calibrate(work, dataset, &cfg)?;
        let result = evaluate(work, dataset, &baseline, &cfg)?;
        results.push(AblationResult {
            name: run.name,
            config_sha256: cfg.digest(),
            result_dir: result.display().to_string(),
        });
    }
    let out = work
        .join("ablations")
        .join(format!("{}-{}", dataset, now()));
    fs::create_dir_all(&out)?;
    fs::write(
        out.join("summary.json"),
        serde_json::to_string_pretty(&results)?,
    )?;
    Ok(out)
}

/// Evaluate the sequence baseline over the same run-level dataset split as the DAG.
pub fn evaluate_ngram(work: &Path, id: &str, cfg: &Config) -> Result<PathBuf> {
    use crate::baselines::ngram;
    let (root, d) = load_dataset(work, id)?;
    let mut train = Vec::new();
    for r in d
        .runs
        .iter()
        .filter(|r| r.partition == "train" && r.label == "clean")
    {
        train.extend(parse_strace_path(&root.join(&r.trace), cfg)?.0)
    }
    if train.is_empty() {
        bail!("dataset needs clean train traces")
    };
    let mut b = ngram::train(&train, vec![1, 2, 3], 0.0, 0.0);
    let mut validation = Vec::new();
    for r in d
        .runs
        .iter()
        .filter(|r| r.partition == "validation" && r.label == "clean")
    {
        let ev = parse_strace_path(&root.join(&r.trace), cfg)?.0;
        validation
            .push(1.0 - ngram::similarity(&ngram::window_ngrams(&ev, &b.n_values), &b.profile))
    }
    if validation.is_empty() {
        bail!("dataset needs clean validation traces")
    };
    b.threshold_review = pct(validation.clone(), 0.99) + 0.01;
    b.threshold_alert = (pct(validation, 0.999) + 0.01).max(b.threshold_review);
    let (mut tp, mut fp, mut tn, mut fn_) = (0, 0, 0, 0);
    for r in d.runs.iter().filter(|r| r.partition == "test") {
        let ev = parse_strace_path(&root.join(&r.trace), cfg)?.0;
        let found = ngram::score(&ev, &b, &r.id, GraphQuality::default()).decision != "NORMAL";
        match (r.label == "attack", found) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
    }
    let precision = tp as f64 / (tp + fp).max(1) as f64;
    let recall = tp as f64 / (tp + fn_).max(1) as f64;
    let report = EvaluationReport {
        dataset_id: id.into(),
        baseline: "ngram-1-3".into(),
        runs: (tp + fp + tn + fn_) as usize,
        windows: (tp + fp + tn + fn_) as usize,
        tp,
        fp,
        tn,
        fn_,
        precision,
        recall,
        f1: if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        },
        fpr: fp as f64 / (fp + tn).max(1) as f64,
        precision_wilson_95: wilson(tp, tp + fp),
        recall_wilson_95: wilson(tp, tp + fn_),
        fpr_wilson_95: wilson(fp, fp + tn),
        latency_ms_p50: 0.0,
        latency_ms_p95: 0.0,
        latency_ms_p99: 0.0,
        cpu_time_ms: 0.0,
        peak_rss_bytes: peak_rss_bytes(),
        capture_quality_loss: 0,
    };
    let out = work.join("results").join(format!("ngram-{}-{}", id, now()));
    fs::create_dir_all(&out)?;
    fs::write(
        out.join("report.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    Ok(out)
}
