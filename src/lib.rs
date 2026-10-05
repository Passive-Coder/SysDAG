//! SysCall-DAG: process-scoped syscall dependency graphs and WL fingerprints.

pub mod baselines;
pub mod canonical;
pub mod config;
pub mod detector;
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod ebpf_native;
pub mod event;
pub mod experiments;
pub mod features;
pub mod graph;
pub mod help;
pub mod labels;
pub mod pipeline;
pub mod sandbox;
pub mod streaming;
pub mod tracer;
pub mod tui;
pub mod visualizer;

pub use config::Config;
pub use pipeline::{
    analyze_path, analyze_path_opts, load_run_manifest, write_run_manifest, Mode, RunReport,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: &str = "1.0";
pub const LABEL_SCHEMA_VERSION: &str = "1.0";
pub const DECISION_SCHEMA: &str = "1.0";
pub const MANIFEST_SCHEMA: &str = "1.0";
pub const WL_VERSION: &str = "wl-directed-edge-typed-1";
