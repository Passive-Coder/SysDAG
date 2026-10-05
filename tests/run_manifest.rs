mod fixtures;
use fixtures::{synthetic_trace, CLEAN_TRACE};
use std::path::PathBuf;

use sysdag::config::Config;
use sysdag::pipeline::{analyze_path, load_run_manifest, Mode};

fn cfg() -> Config {
    let mut c = Config::default();
    c.window.size = 16;
    c.window.overlap = 4;
    c.labels.app_root = "/guest/www".into();
    c
}

#[test]
fn run_manifest_roundtrip_and_tamper() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-manifest");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let cfg = cfg();
    let baselines = tmp.join("baselines");

    let train = analyze_path(
        &synthetic_trace(&tmp.join("input"), "clean.strace", CLEAN_TRACE),
        Mode::Train,
        &cfg,
        &tmp,
        &baselines,
        &[],
        true,
        Some("fixture-manifest"),
    )
    .unwrap();

    // Train mode writes baseline.json + events.jsonl and a manifest.
    let run_dir = train.run_dir.clone();
    let m = load_run_manifest(&run_dir).expect("manifest present");
    assert_eq!(m.mode, "Train");
    assert!(m.artifact_checksums.contains_key("baseline.json"));
    assert!(m.artifact_checksums.contains_key("events.jsonl"));
    assert!(m.baseline_file.as_deref() == Some("baseline.json"));

    // Provenance recorded on the baseline manifest itself.
    let base = sysdag::detector::load_baseline(train.baseline_path.as_ref().unwrap()).unwrap();
    let prov = base
        .training
        .as_ref()
        .expect("training provenance recorded");
    assert!(!prov.input_digests.is_empty());
    assert!(
        prov.input_digests.values().all(|d| d.len() == 64),
        "input digests must be sha256 hex"
    );
    assert!(prov.trained_with_config_sha256 == m.config_sha256);

    m.verify_against(&run_dir)
        .expect("clean verification passes");

    // Tampering with an artifact must fail verification.
    let events = run_dir.join("events.jsonl");
    let mut body = std::fs::read_to_string(&events).unwrap();
    body.push_str("{\"tampered\":true}\n");
    std::fs::write(&events, body).unwrap();
    let err = m
        .verify_against(&run_dir)
        .expect_err("modified artifact must be detected");
    assert!(
        err.to_string().contains("sha256 mismatch"),
        "unexpected error: {err}"
    );
}
