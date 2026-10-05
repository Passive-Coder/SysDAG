//! Baseline learning, hybrid scoring, and explainable decisions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::canonical::{digest, digest_bytes};
use crate::config::Config;
use crate::event::TraceEvent;
use crate::features::{weighted_jaccard, EncodedGraph};
use crate::graph::GraphQuality;
use crate::DECISION_SCHEMA;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prototype {
    pub id: String,
    pub fingerprint: String,
    pub features: BTreeMap<String, u64>,
    pub n_nodes: usize,
    pub n_edges: usize,
    pub label_ops: BTreeSet<String>,
    pub edge_types: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManifest {
    pub baseline_id: String,
    pub created_unix: u64,
    pub target_sha256: String,
    pub config_sha256: String,
    pub platform: BTreeMap<String, String>,
    pub pipeline: BTreeMap<String, String>,
    pub exact_fingerprints: BTreeMap<String, u64>,
    pub prototypes: Vec<Prototype>,
    pub score_weights: BTreeMap<String, f64>,
    pub thresholds: BTreeMap<String, f64>,
    pub artifact_checksum: String,
    /// Full effective config at training time (for human inspection; the digest gates).
    #[serde(default)]
    pub resolved_config: Option<serde_json::Value>,
    /// sysdag version that produced this baseline.
    #[serde(default)]
    pub software_version: String,
    /// Provenance of the training inputs (runs, event counts, digests).
    #[serde(default)]
    pub training: Option<TrainingProvenance>,
    #[serde(default)]
    pub calibration: Option<CalibrationProvenance>,
    pub notes: String,
}

/// Immutable record of what went into a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingProvenance {
    pub run_ids: Vec<String>,
    pub total_events: u64,
    pub window_count: u64,
    pub input_digests: BTreeMap<String, String>,
    pub trained_with_config_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationProvenance {
    pub validation_run_ids: Vec<String>,
    pub validation_windows: u64,
    pub review_fpr_target: f64,
    pub alert_fpr_target: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub manifest_schema: String,
    pub run_id: String,
    pub created_unix: u64,
    pub sysdag_version: String,
    pub mode: String,
    /// sha256 of the target program / trace file ("strace-anonymous" when n/a).
    pub input_sha256: String,
    pub config_sha256: String,
    pub event_count: u64,
    /// Per-window graph digests in order.
    pub graph_digests: Vec<String>,
    /// Baseline used (monitor) or written (train), by filename.
    pub baseline_file: Option<String>,
    /// sha256 over every file listed in `files`, keyed by relative path.
    pub artifact_checksums: BTreeMap<String, String>,
    pub artifact_checksum: String,
}

impl RunManifest {
    pub fn checksum(&self) -> String {
        let mut copy = self.clone();
        copy.artifact_checksum.clear();
        let v = serde_json::to_value(&copy).unwrap_or_default();
        digest(&crate::config::json_to_canon(&v))
    }

    /// Recompute artifact checksums and the manifest checksum against on-disk state.
    pub fn verify_against(&self, dir: &Path) -> Result<()> {
        if self.artifact_checksum != self.checksum() {
            bail!("manifest checksum mismatch; metadata may be corrupted");
        }
        for (rel, want) in &self.artifact_checksums {
            let p = dir.join(rel);
            let got = match fs::read(&p) {
                Ok(bytes) => digest_bytes(&bytes),
                Err(_) => bail!("missing artifact {rel}"),
            };
            if got != *want {
                bail!("artifact {rel} modified since run (sha256 mismatch)");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearestNormal {
    pub prototype: String,
    pub weighted_jaccard: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub motif: String,
    pub events: Vec<u64>,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision_schema: String,
    pub window_id: String,
    pub baseline_id: String,
    pub decision: String,
    pub score: f64,
    pub threshold_review: f64,
    pub threshold_alert: f64,
    pub exact_known: bool,
    pub nearest_normal: Option<NearestNormal>,
    pub evidence: Vec<EvidenceItem>,
    pub quality: GraphQuality,
    pub fingerprint: String,
    pub n_nodes: usize,
    pub n_edges: usize,
    #[serde(default)]
    pub note: String,
}

impl BaselineManifest {
    /// Compare this baseline against the current run environment.
    ///
    /// Hard invariants (schema, pipeline shape) always fail. Soft facts (config
    /// digest, platform) are reported so callers can warn or require an override.
    pub fn compatibility(&self, cfg: &Config, target_sha: &str) -> CompatibilityReport {
        let mut hard: Vec<String> = Vec::new();
        let mut soft: Vec<String> = Vec::new();

        if self.target_sha256 != target_sha {
            hard.push(format!(
                "target digest mismatch (baseline {}, input {})",
                short(&self.target_sha256),
                short(target_sha)
            ));
        }
        if self.config_sha256 != cfg.digest() {
            // Window/WL shape must still match even when only detector knobs changed.
            let w = self.pipeline.get("W").map(|s| s.as_str());
            let h = self.pipeline.get("h").map(|s| s.as_str());
            if w != Some(&cfg.window.size.to_string()) || h != Some(&cfg.wl.iterations.to_string())
            {
                hard.push("pipeline (W/h) incompatible with current config".into());
            } else {
                soft.push("config digest differs but window/WL shape matches".into());
            }
        }

        let event_schema = self.pipeline.get("event_schema").map(|s| s.as_str());
        if let Some(v) = event_schema {
            if v != crate::SCHEMA_VERSION {
                hard.push(format!(
                    "event schema mismatch (baseline {v}, current {})",
                    crate::SCHEMA_VERSION
                ));
            }
        }
        let label_schema = self.pipeline.get("label_schema").map(|s| s.as_str());
        if let Some(v) = label_schema {
            if v != crate::LABEL_SCHEMA_VERSION {
                hard.push(format!(
                    "label schema mismatch (baseline {v}, current {})",
                    crate::LABEL_SCHEMA_VERSION
                ));
            }
        }
        let edge_policy = self.pipeline.get("edge_policy").map(|s| s.as_str());
        if let Some(v) = edge_policy {
            if v != cfg.graph.fd_policy {
                hard.push(format!(
                    "edge policy mismatch (baseline {v}, current {})",
                    cfg.graph.fd_policy
                ));
            }
        }
        let tracer = self.platform.get("tracer").map(|s| s.as_str());
        if let Some(v) = tracer {
            if v != cfg.tracer {
                hard.push(format!(
                    "tracer mismatch (baseline {v}, current {})",
                    cfg.tracer
                ));
            }
        }
        let arch = self.platform.get("arch").map(|s| s.as_str());
        if let Some(v) = arch {
            if v != std::env::consts::ARCH {
                soft.push(format!(
                    "arch differs (baseline {v}, current {})",
                    std::env::consts::ARCH
                ));
            }
        }
        let kernel = self.platform.get("kernel").map(|s| s.as_str());
        if let Some(v) = kernel {
            match current_kernel() {
                Some(cur) if cur != *v => {
                    soft.push(format!("kernel differs (baseline {v}, current {cur})"));
                }
                None => soft.push("current kernel unknown".into()),
                _ => {}
            }
        }
        if self.software_version != crate_version() {
            soft.push(format!(
                "sysdag version differs (baseline {}, current {})",
                self.software_version,
                crate_version()
            ));
        }

        CompatibilityReport {
            compatible: hard.is_empty(),
            mismatches: hard,
            warnings: soft,
        }
    }

    /// Backwards-compatible gate used by monitor paths: fails on any hard mismatch.
    pub fn compatibility_ok(&self, cfg: &Config, target_sha: &str) -> Result<()> {
        let report = self.compatibility(cfg, target_sha);
        if report.compatible {
            Ok(())
        } else {
            bail!("{}", report.mismatches.join("; "))
        }
    }
}

/// Result of comparing a baseline against the current environment.
#[derive(Debug, Clone)]
pub struct CompatibilityReport {
    pub compatible: bool,
    /// Hard failures; monitoring must refuse unless explicitly overridden.
    pub mismatches: Vec<String>,
    /// Soft divergences recorded for provenance and surfaced as warnings.
    pub warnings: Vec<String>,
}

pub(crate) fn short(s: &str) -> &str {
    &s[..12.min(s.len())]
}

fn current_kernel() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(mut u) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            while u.ends_with(['\n', '\r']) {
                u.pop();
            }
            return Some(u);
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Host kernel is irrelevant off-Linux (traces come from the guest VM),
        // but record something stable for provenance.
        Some("non-linux-host".into())
    }
}

pub fn crate_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

pub fn train_baseline(
    encoded: &[EncodedGraph],
    events: &[TraceEvent],
    cfg: &Config,
    target_sha: &str,
    baseline_id: &str,
) -> BaselineManifest {
    train_baseline_with_provenance(encoded, events, cfg, target_sha, baseline_id, None)
}

/// Same as `train_baseline` but records training-input provenance in the manifest.
pub fn train_baseline_with_provenance(
    encoded: &[EncodedGraph],
    events: &[TraceEvent],
    cfg: &Config,
    target_sha: &str,
    baseline_id: &str,
    provenance: Option<TrainingProvenance>,
) -> BaselineManifest {
    let _ = events;
    let mut exact: BTreeMap<String, u64> = BTreeMap::new();
    let mut prototypes = Vec::new();
    for (i, enc) in encoded.iter().enumerate() {
        *exact.entry(enc.fingerprint.clone()).or_insert(0) += 1;
        if prototypes.len() < cfg.detector.max_prototypes
            && !prototypes
                .iter()
                .any(|p: &Prototype| p.fingerprint == enc.fingerprint)
        {
            prototypes.push(make_prototype(i, enc));
        }
    }
    let mut weights = BTreeMap::new();
    weights.insert("alpha".into(), cfg.detector.exact_weight);
    weights.insert("beta".into(), cfg.detector.similarity_weight);
    weights.insert("gamma".into(), cfg.detector.size_weight);
    weights.insert("delta".into(), cfg.detector.risk_weight);
    let mut thresholds = BTreeMap::new();
    thresholds.insert("review".into(), cfg.detector.threshold_review);
    thresholds.insert("alert".into(), cfg.detector.threshold_alert);
    let mut pipeline = BTreeMap::new();
    pipeline.insert("event_schema".into(), crate::SCHEMA_VERSION.into());
    pipeline.insert("label_schema".into(), crate::LABEL_SCHEMA_VERSION.into());
    pipeline.insert("W".into(), cfg.window.size.to_string());
    pipeline.insert("O".into(), cfg.window.overlap.to_string());
    pipeline.insert("h".into(), cfg.wl.iterations.to_string());
    pipeline.insert("edge_policy".into(), cfg.graph.fd_policy.clone());
    let mut platform = BTreeMap::new();
    platform.insert("tracer".into(), cfg.tracer.clone());
    platform.insert("arch".into(), std::env::consts::ARCH.into());
    if let Some(kernel) = current_kernel() {
        platform.insert("kernel".into(), kernel);
    }
    let mut manifest = BaselineManifest {
        baseline_id: baseline_id.into(),
        created_unix: unix_now(),
        target_sha256: target_sha.into(),
        config_sha256: cfg.digest(),
        platform,
        pipeline,
        exact_fingerprints: exact,
        prototypes,
        score_weights: weights,
        thresholds,
        artifact_checksum: String::new(),
        resolved_config: Some(serde_json::to_value(cfg).unwrap_or_default()),
        software_version: crate_version(),
        training: provenance,
        calibration: None,
        notes: "Trained from known-clean windows. An unseen fingerprint is evidence, not proof of an attack.".into(),
    };
    manifest.artifact_checksum = checksum_manifest(&manifest);
    manifest
}

impl BaselineManifest {
    pub fn refresh_checksum(&mut self) {
        self.artifact_checksum = checksum_manifest(self);
    }
}

fn make_prototype(i: usize, enc: &EncodedGraph) -> Prototype {
    let mut label_ops = BTreeSet::new();
    for n in &enc.graph.nodes {
        let op = n.label_fields.get("op").cloned().unwrap_or_default();
        let pc = n
            .label_fields
            .get("path_class")
            .cloned()
            .unwrap_or_default();
        label_ops.insert(format!("{op}:{pc}"));
    }
    let edge_types = enc
        .graph
        .edges
        .iter()
        .map(|e| e.edge_type.clone())
        .collect();
    Prototype {
        id: format!("p{i:04}"),
        fingerprint: enc.fingerprint.clone(),
        features: flatten_features(&enc.features),
        n_nodes: enc.n_nodes,
        n_edges: enc.n_edges,
        label_ops,
        edge_types,
    }
}

fn flatten_features(feat: &BTreeMap<(u32, String), u64>) -> BTreeMap<String, u64> {
    feat.iter()
        .map(|((r, c), n)| (format!("{r}:{c}"), *n))
        .collect()
}

fn unflatten_features(feat: &BTreeMap<String, u64>) -> BTreeMap<(u32, String), u64> {
    let mut out = BTreeMap::new();
    for (k, n) in feat {
        if let Some((r, c)) = k.split_once(':') {
            if let Ok(round) = r.parse::<u32>() {
                out.insert((round, c.to_string()), *n);
            }
        }
    }
    out
}

fn checksum_manifest(m: &BaselineManifest) -> String {
    let mut copy = m.clone();
    copy.artifact_checksum.clear();
    let v = serde_json::to_value(&copy).unwrap_or_default();
    digest(&crate::config::json_to_canon(&v))
}

pub fn save_baseline(dir: &Path, manifest: &BaselineManifest) -> Result<PathBuf> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", manifest.baseline_id));
    let text = serde_json::to_string_pretty(manifest)?;
    fs::write(&path, text)?;
    Ok(path)
}

pub fn load_baseline(path: &Path) -> Result<BaselineManifest> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let m: BaselineManifest = serde_json::from_str(&text)?;
    let expect = checksum_manifest(&m);
    if m.artifact_checksum != expect {
        bail!("baseline checksum mismatch; file may be corrupted");
    }
    Ok(m)
}

pub fn find_baseline(dir: &Path, target_sha: &str) -> Option<PathBuf> {
    let p = dir.join(format!("{target_sha}.json"));
    if p.is_file() {
        return Some(p);
    }
    if !dir.is_dir() {
        return None;
    }
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(m) = load_baseline(&path) {
            if m.target_sha256 == target_sha {
                return Some(path);
            }
        }
    }
    None
}

pub struct ScoreBreakdown {
    pub alpha: f64,
    pub beta: f64,
    pub gamma: f64,
    pub delta: f64,
    pub total: f64,
}

pub fn score_breakdown(
    enc: &EncodedGraph,
    baseline: &BaselineManifest,
    cfg: &Config,
) -> ScoreBreakdown {
    let exact_known = baseline.exact_fingerprints.contains_key(&enc.fingerprint);
    let mut best_sim = 0.0;
    for p in &baseline.prototypes {
        let sim = weighted_jaccard(&enc.features, &unflatten_features(&p.features));
        if sim > best_sim {
            best_sim = sim;
        }
    }
    let size_dev = robust_size_dev(enc, baseline);
    let (risk, _evidence) = risk_and_evidence(enc, baseline.prototypes.first(), cfg);
    let alpha = cfg.detector.exact_weight * (if exact_known { 0.0 } else { 1.0 });
    let beta = cfg.detector.similarity_weight * (1.0 - best_sim);
    let gamma = cfg.detector.size_weight * size_dev;
    let delta = cfg.detector.risk_weight * risk;
    let total = (alpha + beta + gamma + delta).clamp(0.0, 1.5);
    ScoreBreakdown {
        alpha,
        beta,
        gamma,
        delta,
        total,
    }
}

pub fn score(enc: &EncodedGraph, baseline: &BaselineManifest, cfg: &Config) -> DecisionRecord {
    // Thresholds are part of the frozen baseline.  This prevents a monitor CLI
    // config from silently changing the calibrated decision boundary.
    let threshold_review = baseline
        .thresholds
        .get("review")
        .copied()
        .unwrap_or(cfg.detector.threshold_review);
    let threshold_alert = baseline
        .thresholds
        .get("alert")
        .copied()
        .unwrap_or(cfg.detector.threshold_alert);
    if enc.graph.quality.capture_loss > 0 && enc.n_nodes == 0 {
        return DecisionRecord {
            decision_schema: DECISION_SCHEMA.into(),
            window_id: enc.graph.window.window_id.clone(),
            baseline_id: baseline.baseline_id.clone(),
            decision: "UNKNOWN".into(),
            score: 0.0,
            threshold_review,
            threshold_alert,
            exact_known: false,
            nearest_normal: None,
            evidence: vec![EvidenceItem {
                motif: "CAPTURE_DEGRADED".into(),
                events: vec![],
                detail: "event loss prevents a confident decision".into(),
            }],
            quality: enc.graph.quality.clone(),
            fingerprint: enc.fingerprint.clone(),
            n_nodes: enc.n_nodes,
            n_edges: enc.n_edges,
            note: "Degraded capture".into(),
        };
    }

    let exact_known = baseline.exact_fingerprints.contains_key(&enc.fingerprint);
    let mut best = None;
    let mut best_sim = 0.0;
    for p in &baseline.prototypes {
        let sim = weighted_jaccard(&enc.features, &unflatten_features(&p.features));
        if best.is_none() || sim > best_sim {
            best_sim = sim;
            best = Some(p);
        }
    }
    let size_dev = robust_size_dev(enc, baseline);
    let (risk, mut evidence) = risk_and_evidence(enc, best, cfg);
    if let Some(p) = best {
        let cur_ops: BTreeSet<_> = enc
            .graph
            .nodes
            .iter()
            .map(|n| {
                format!(
                    "{}:{}",
                    n.label_fields.get("op").cloned().unwrap_or_default(),
                    n.label_fields
                        .get("path_class")
                        .cloned()
                        .unwrap_or_default()
                )
            })
            .collect();
        let new: Vec<_> = cur_ops.difference(&p.label_ops).take(3).cloned().collect();
        let missing: Vec<_> = p.label_ops.difference(&cur_ops).take(3).cloned().collect();
        for m in new {
            evidence.push(EvidenceItem {
                motif: format!("new {m}"),
                events: vec![],
                detail: "label pair absent from nearest normal prototype".into(),
            });
        }
        for m in missing {
            evidence.push(EvidenceItem {
                motif: format!("missing {m}"),
                events: vec![],
                detail: "normal motif not observed in this window".into(),
            });
        }
    }

    let alpha = cfg.detector.exact_weight;
    let beta = cfg.detector.similarity_weight;
    let gamma = cfg.detector.size_weight;
    let delta = cfg.detector.risk_weight;
    let score = alpha * (if exact_known { 0.0 } else { 1.0 })
        + beta * (1.0 - best_sim)
        + gamma * size_dev
        + delta * risk;
    let score = score.clamp(0.0, 1.5);

    let mut decision = if score < threshold_review {
        "NORMAL"
    } else if score < threshold_alert {
        "REVIEW"
    } else {
        "ANOMALOUS"
    };
    let mut note = if exact_known {
        "Exact fingerprint present in the clean baseline".into()
    } else {
        "Exact fingerprint unseen; score uses similarity, size, and risk motifs".into()
    };

    // DEGRADED_CAPTURE (Phase 1.3): when capture quality loss exceeds the
    // configured rate, decisions cannot be trusted above REVIEW.
    if let Some(reason) = degraded_capture_reason(enc, cfg) {
        if decision == "ANOMALOUS" {
            decision = "REVIEW";
        }
        note = format!("DEGRADED_CAPTURE: {reason}; decision capped at REVIEW. {note}");
        evidence.push(EvidenceItem {
            motif: "DEGRADED_CAPTURE".into(),
            events: vec![],
            detail: reason,
        });
    }

    DecisionRecord {
        decision_schema: DECISION_SCHEMA.into(),
        window_id: enc.graph.window.window_id.clone(),
        baseline_id: baseline.baseline_id.clone(),
        decision: decision.into(),
        score,
        threshold_review,
        threshold_alert,
        exact_known,
        nearest_normal: best.map(|p| NearestNormal {
            prototype: p.id.clone(),
            weighted_jaccard: best_sim,
        }),
        evidence,
        quality: enc.graph.quality.clone(),
        fingerprint: enc.fingerprint.clone(),
        n_nodes: enc.n_nodes,
        n_edges: enc.n_edges,
        note,
    }
}

/// Returns Some(reason) when this window's capture quality is degraded beyond the
/// configured rate threshold (Phase 1.3 DEGRADED_CAPTURE).
fn degraded_capture_reason(enc: &EncodedGraph, cfg: &Config) -> Option<String> {
    let q = &enc.graph.quality;
    let loss_total = q.capture_loss + q.unknown_calls + q.rejected_lines;
    if loss_total == 0 {
        return None;
    }
    // Rate denominator: window events, falling back to node count.
    let denom = enc.graph.window.event_count.max(enc.n_nodes);
    if denom == 0 {
        return Some(format!(
            "window has no usable events but {} recorded capture losses",
            loss_total
        ));
    }
    let rate_pct = loss_total as f64 / denom as f64 * 100.0;
    if rate_pct > cfg.detector.max_degraded_rate_pct {
        Some(format!(
            "capture loss rate {:.1}% > max_degraded_rate_pct {:.1}%",
            rate_pct, cfg.detector.max_degraded_rate_pct
        ))
    } else {
        None
    }
}

fn robust_size_dev(enc: &EncodedGraph, baseline: &BaselineManifest) -> f64 {
    if baseline.prototypes.is_empty() {
        return 0.0;
    }
    let mut sizes: Vec<f64> = baseline
        .prototypes
        .iter()
        .map(|p| p.n_nodes as f64)
        .collect();
    sizes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = sizes[sizes.len() / 2];
    let dev = (enc.n_nodes as f64 - med).abs() / (med + 1.0);
    (dev / 2.0).min(1.0)
}

fn risk_and_evidence(
    enc: &EncodedGraph,
    nearest: Option<&Prototype>,
    cfg: &Config,
) -> (f64, Vec<EvidenceItem>) {
    let _ = nearest;
    let mut risk: f64 = 0.0;
    let mut ev = Vec::new();

    // Node-based risk motifs
    for n in &enc.graph.nodes {
        let op = n.label_fields.get("op").map(|s| s.as_str()).unwrap_or("");
        let pc = n
            .label_fields
            .get("path_class")
            .map(|s| s.as_str())
            .unwrap_or("");

        // sensitive opens
        if op == "FILE_OPEN" && matches!(pc, "SYSTEM_CONFIG" | "DECOY" | "HOME") {
            risk += 0.35;
            ev.push(EvidenceItem {
                motif: format!("FILE_OPEN({})", pc),
                events: n.source_seq.into_iter().collect(),
                detail: "sensitive or out-of-root path class".into(),
            });
        }

        // sensitive reads (e.g., /etc/passwd, secrets, home files)
        if op == "FILE_READ" && matches!(pc, "SYSTEM_CONFIG" | "DECOY" | "HOME") {
            risk += 0.35;
            ev.push(EvidenceItem {
                motif: format!("FILE_READ({})", pc),
                events: n.source_seq.into_iter().collect(),
                detail: "sensitive file read detected".into(),
            });
        }

        // file writes that create or truncate files (possible staging)
        let flags = n
            .label_fields
            .get("flags")
            .map(|s| s.as_str())
            .unwrap_or("");
        if op == "FILE_WRITE" && flags == "CREATE_WRITE" {
            risk += 0.25;
            ev.push(EvidenceItem {
                motif: "FILE_CREATE_WRITE".into(),
                events: n.source_seq.into_iter().collect(),
                detail: "file created or truncated for writing".into(),
            });
        }

        // network connect attempts
        if op.starts_with("NET_CONNECT") || op == "NET_CONNECT" {
            risk += 0.30;
            ev.push(EvidenceItem {
                motif: "NET_CONNECT".into(),
                events: n.source_seq.into_iter().collect(),
                detail: "network connection attempt".into(),
            });
        }

        // direct net sends (without explicit buffer flow) are suspicious
        if op == "NET_SEND" {
            risk += 0.20;
            ev.push(EvidenceItem {
                motif: "NET_SEND".into(),
                events: n.source_seq.into_iter().collect(),
                detail: "direct network send observed".into(),
            });
        }

        // shell exec remains high risk
        if op == "PROCESS_EXEC" && matches!(pc, "SHELL") {
            risk += 0.4;
            ev.push(EvidenceItem {
                motif: "PROCESS_EXEC(SHELL)".into(),
                events: n.source_seq.into_iter().collect(),
                detail: "shell image transition".into(),
            });
        }
    }

    // Edge-based: buffer flow consumed by a network send (exfil pattern)
    let buffer_confidence = enc
        .graph
        .edges
        .iter()
        .filter(|e| e.edge_type == "BUFFER_FLOW")
        .map(|e| e.confidence as f64 / 100.0)
        .fold(0.0, f64::max);
    let has_buf_to_net = enc.graph.edges.iter().any(|e| {
        e.edge_type == "BUFFER_FLOW"
            && enc.graph.nodes.iter().any(|n| {
                n.id == e.dst && n.label_fields.get("op").map(|s| s.as_str()) == Some("NET_SEND")
            })
    });
    if has_buf_to_net {
        let weight = if buffer_confidence < 1.0 {
            cfg.graph.low_confidence_buffer_weight
        } else {
            1.0
        };
        risk += 0.45 * weight;
        let events: Vec<u64> = enc
            .graph
            .edges
            .iter()
            .filter(|e| e.edge_type == "BUFFER_FLOW")
            .flat_map(|e| {
                enc.graph
                    .nodes
                    .iter()
                    .filter(|n| n.id == e.src || n.id == e.dst)
                    .filter_map(|n| n.source_seq)
            })
            .collect();
        ev.push(EvidenceItem {
            motif: "BUFFER_FLOW -> NET_SEND".into(),
            events,
            detail: format!(
                "read/recv buffer consumed by a network send (confidence {:.0}%)",
                buffer_confidence * 100.0
            ),
        });
    }

    (risk.min(1.0), ev)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::digest;
    use crate::config::Config;
    use crate::features::encode;
    use crate::graph::{GraphEdge, GraphNode, GraphQuality, GraphRecord, WindowMeta};

    #[test]
    fn thresholds_split_decisions() {
        let detector = Config::default().detector;
        assert!(detector.threshold_review < detector.threshold_alert);
    }

    #[test]
    fn risk_motifs_detected() {
        let cfg = Config::default();
        // create two nodes: a FILE_READ on SYSTEM_CONFIG and a NET_CONNECT
        let n0 = GraphNode {
            id: "n0000".into(),
            source_seq: Some(1),
            label_fields: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("op".into(), "FILE_READ".into());
                m.insert("path_class".into(), "SYSTEM_CONFIG".into());
                m.insert("flags".into(), "NONE".into());
                m.insert("bytes".into(), "NONE".into());
                m.insert("family".into(), "file".into());
                m.insert("resource_kind".into(), "FILE".into());
                m
            },
            label_digest: digest(&crate::canonical::Canon::str("x")),
            kind: "event".into(),
        };
        let n1 = GraphNode {
            id: "n0001".into(),
            source_seq: Some(2),
            label_fields: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("op".into(), "NET_CONNECT".into());
                m.insert("path_class".into(), "NONE".into());
                m.insert("flags".into(), "NONE".into());
                m.insert("bytes".into(), "NONE".into());
                m.insert("family".into(), "network".into());
                m.insert("resource_kind".into(), "SOCKET".into());
                m
            },
            label_digest: digest(&crate::canonical::Canon::str("y")),
            kind: "event".into(),
        };
        let e = GraphEdge {
            src: "n0000".into(),
            dst: "n0001".into(),
            edge_type: "FD_FLOW".into(),
            resource_class: "SOCKET".into(),
            confidence: 100,
        };
        let g = GraphRecord {
            graph_schema: "1.0".into(),
            label_schema: "1.0".into(),
            graph_id: "g".into(),
            baseline_key: "k".into(),
            window: WindowMeta {
                start_seq: 1,
                end_seq: 2,
                w: 2,
                overlap: 0,
                complete: true,
                window_id: "g".into(),
                event_count: 2,
            },
            nodes: vec![n0.clone(), n1.clone()],
            edges: vec![e],
            quality: GraphQuality::default(),
            graph_digest_before_wl: "x".into(),
        };
        let enc = encode(g.clone(), &cfg);
        let (risk, evidence) = risk_and_evidence(&enc, None, &Config::default());
        assert!(risk > 0.0, "expected risk > 0 from motifs, got {}", risk);
        assert!(!evidence.is_empty());
        // ensure at least one motif mentions FILE_READ or NET_CONNECT
        let motifs: Vec<_> = evidence.iter().map(|e| e.motif.as_str()).collect();
        assert!(motifs
            .iter()
            .any(|m| m.contains("FILE_READ") || m.contains("NET_CONNECT") || *m == "NET_SEND"));
    }
}
