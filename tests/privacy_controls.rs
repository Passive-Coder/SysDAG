//! Phase 1.4 acceptance: exported artifacts contain no plaintext paths.

mod fixtures;
use fixtures::{synthetic_trace, CLEAN_TRACE};
use std::path::PathBuf;

use sysdag::config::Config;
use sysdag::pipeline::{analyze_path, Mode};

#[test]
fn redaction_keeps_plaintext_out_of_exported_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-privacy");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut cfg = Config::default();
    cfg.window.size = 16;
    cfg.window.overlap = 4;
    cfg.privacy.redact_paths = "token".into();
    cfg.privacy.persist_raw_lines = false;

    let report = analyze_path(
        &synthetic_trace(&root.join("input"), "clean.strace", CLEAN_TRACE),
        Mode::Train,
        &cfg,
        &root,
        &root.join("baselines"),
        &[],
        true,
        Some("privacy-fixture"),
    )
    .unwrap();

    let plaintext = "/guest/www";
    for artifact in [
        report.run_dir.join("events.jsonl"),
        report.run_dir.join("baseline.json"),
        report.run_dir.join("graphs/w0000/graph.json"),
        report.run_dir.join("graphs/w0000/graph.dot"),
    ] {
        let body = std::fs::read_to_string(&artifact).unwrap();
        assert!(
            !body.contains(plaintext),
            "plaintext path leaked into {}",
            artifact.display()
        );
    }

    // The reversible token map is intentionally local to the run directory and
    // is not included in run-manifest exported artifacts.
    let map = std::fs::read_to_string(report.run_dir.join("path-map.json")).unwrap();
    assert!(map.contains(plaintext));
    let manifest = sysdag::load_run_manifest(&report.run_dir).unwrap();
    assert!(!manifest.artifact_checksums.contains_key("path-map.json"));
}
