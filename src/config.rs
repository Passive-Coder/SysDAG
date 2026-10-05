use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::canonical::{digest, Canon};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowConfig {
    pub size: usize,
    pub overlap: usize,
    pub flush_on_exec: bool,
    pub include_incomplete_tail: bool,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            size: 100,
            overlap: 20,
            flush_on_exec: true,
            include_incomplete_tail: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphConfig {
    pub fd_policy: String,
    pub buffer_flow: bool,
    pub buffer_heuristic: String,
    pub external_anchors: bool,
    pub seed_stdio: bool,
    /// `full` keeps typed edges; `node_only` removes every edge before WL.
    pub representation: String,
    /// `fd_only` removes buffer-flow edges; `fd_buffer` keeps both.
    pub edge_set: String,
    /// Multiplier applied to risk evidence that relies on heuristic buffer flow.
    pub low_confidence_buffer_weight: f64,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            fd_policy: "last_event_chain".into(),
            buffer_flow: true,
            buffer_heuristic: "address_or_last_writer".into(),
            external_anchors: true,
            seed_stdio: true,
            representation: "full".into(),
            edge_set: "fd_buffer".into(),
            low_confidence_buffer_weight: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LabelConfig {
    pub include_exact_path: bool,
    pub include_path_class: bool,
    pub include_fd_number: bool,
    pub app_root: String,
}

impl Default for LabelConfig {
    fn default() -> Self {
        Self {
            include_exact_path: false,
            include_path_class: true,
            include_fd_number: false,
            app_root: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WlConfig {
    pub iterations: u32,
    pub directed: bool,
    pub edge_typed: bool,
    pub digest: String,
}

impl Default for WlConfig {
    fn default() -> Self {
        Self {
            iterations: 3,
            directed: true,
            edge_typed: true,
            digest: "sha256".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectorConfig {
    pub exact_weight: f64,
    pub similarity_weight: f64,
    pub size_weight: f64,
    pub risk_weight: f64,
    pub threshold_review: f64,
    pub threshold_alert: f64,
    pub max_prototypes: usize,
    /// Capture-quality loss rate (percent of trace lines) above which windows are
    /// flagged DEGRADED_CAPTURE and decisions are capped at REVIEW (Phase 1.3).
    pub max_degraded_rate_pct: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            exact_weight: 0.15,
            similarity_weight: 0.65,
            size_weight: 0.10,
            risk_weight: 0.10,
            threshold_review: 0.35,
            threshold_alert: 0.45,
            max_prototypes: 4000,
            max_degraded_rate_pct: 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    pub backend: String,
    pub memory_mb: u32,
    pub cpus: f64,
    pub timeout_sec: u64,
    pub network: String,
    pub image: String,
    pub guest_arch: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: "auto".into(),
            memory_mb: 256,
            cpus: 1.0,
            timeout_sec: 90,
            network: "none".into(),
            image: "sysdag-microvm:1.0".into(),
            guest_arch: "auto".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Path redaction mode: "token" (F1, F2...), "hash" (SHA-256), or "off"
    pub redact_paths: String,
    /// Persist raw strace lines in events (default: false)
    pub persist_raw_lines: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            redact_paths: "token".into(),
            persist_raw_lines: false,
        }
    }
}

impl PrivacyConfig {
    pub fn is_redact_enabled(&self) -> bool {
        self.redact_paths != "off"
    }

    pub fn use_hash(&self) -> bool {
        self.redact_paths == "hash"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema_version: String,
    pub tracer: String,
    pub process_scope: String,
    pub window: WindowConfig,
    pub graph: GraphConfig,
    pub labels: LabelConfig,
    pub wl: WlConfig,
    pub detector: DetectorConfig,
    pub sandbox: SandboxConfig,
    pub privacy: PrivacyConfig,
    pub syscall_classes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: "1.0".into(),
            tracer: "strace".into(),
            process_scope: "process_tree".into(),
            window: WindowConfig::default(),
            graph: GraphConfig::default(),
            labels: LabelConfig::default(),
            wl: WlConfig::default(),
            detector: DetectorConfig::default(),
            sandbox: SandboxConfig::default(),
            privacy: PrivacyConfig::default(),
            syscall_classes: vec![
                "file".into(),
                "descriptor".into(),
                "network".into(),
                "process".into(),
            ],
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            None => Ok(Self::default()),
            Some(p) => {
                let text = fs::read_to_string(p)
                    .with_context(|| format!("read config {}", p.display()))?;
                let cfg: Self = toml::from_str(&text)
                    .with_context(|| format!("parse config {}", p.display()))?;
                Ok(cfg)
            }
        }
    }

    pub fn digest(&self) -> String {
        let json = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        digest(&json_to_canon(&json))
    }
}

pub fn json_to_canon(value: &serde_json::Value) -> Canon {
    match value {
        serde_json::Value::Null => Canon::Null,
        serde_json::Value::Bool(b) => Canon::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Canon::Int(i)
            } else if let Some(u) = n.as_u64() {
                Canon::Int(u as i64)
            } else {
                Canon::str(n.to_string())
            }
        }
        serde_json::Value::String(s) => Canon::str(s),
        serde_json::Value::Array(xs) => Canon::List(xs.iter().map(json_to_canon).collect()),
        serde_json::Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(crate::canonical::nfc(k), json_to_canon(v));
            }
            Canon::Map(out)
        }
    }
}

use std::collections::BTreeMap;
