mod fixtures;
use fixtures::{synthetic_trace, ATTACK_TRACE, CLEAN_TRACE};
use std::path::PathBuf;

use sysdag::config::Config;
use sysdag::pipeline::{analyze_path, Mode};

fn cfg() -> Config {
    let mut c = Config::default();
    c.window.size = 16;
    c.window.overlap = 4;
    c.labels.app_root = "/guest/www".into();
    c
}

#[test]
fn train_then_monitor_flags_exfiltration() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-it");
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
        false,
        Some("fixture-web"),
    )
    .unwrap();
    assert!(train.baseline_path.is_some());
    assert!(!train.encoded.is_empty());

    let clean = analyze_path(
        &synthetic_trace(&tmp.join("input"), "clean.strace", CLEAN_TRACE),
        Mode::Monitor,
        &cfg,
        &tmp,
        &baselines,
        &[],
        false,
        Some("fixture-web"),
    )
    .unwrap();
    assert!(clean
        .decisions
        .iter()
        .all(|d| d.decision == "NORMAL" || d.decision == "REVIEW"));
    assert!(clean.decisions.iter().any(|d| d.exact_known));

    let attack = analyze_path(
        &synthetic_trace(&tmp.join("input"), "attack.strace", ATTACK_TRACE),
        Mode::Monitor,
        &cfg,
        &tmp,
        &baselines,
        &[],
        false,
        Some("fixture-web"),
    )
    .unwrap();
    assert!(
        attack
            .decisions
            .iter()
            .any(|d| d.decision == "ANOMALOUS" || d.decision == "REVIEW"),
        "expected attack windows to diverge, got {:?}",
        attack
            .decisions
            .iter()
            .map(|d| (d.decision.as_str(), d.score))
            .collect::<Vec<_>>()
    );
    assert!(attack.decisions.iter().any(|d| !d.exact_known));
}

#[test]
fn incremental_monitor_emits_a_closed_window() {
    let mut cfg = cfg();
    cfg.window.size = 4;
    cfg.window.overlap = 1;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-stream");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let train = analyze_path(
        &synthetic_trace(&root.join("input"), "clean.strace", CLEAN_TRACE),
        Mode::Train,
        &cfg,
        &root,
        &root.join("baselines"),
        &[],
        false,
        Some("stream"),
    )
    .unwrap();
    let baseline = sysdag::detector::load_baseline(train.baseline_path.as_ref().unwrap()).unwrap();
    let (events, _) = sysdag::tracer::parse_strace_path(
        &synthetic_trace(&root.join("input"), "attack.strace", ATTACK_TRACE),
        &cfg,
    )
    .unwrap();
    let decisions = sysdag::pipeline::monitor_event_stream(events, &cfg, &baseline, "live", 32);
    assert!(!decisions.is_empty());
}

#[test]
fn graphs_are_dags() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-dag");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let report = analyze_path(
        &synthetic_trace(&tmp.join("input"), "attack.strace", ATTACK_TRACE),
        Mode::Train,
        &cfg(),
        &tmp,
        &tmp.join("baselines"),
        &[],
        false,
        Some("fixture-web-dag"),
    )
    .unwrap();
    for g in &report.graphs {
        sysdag::graph::validate_graph(g).unwrap();
        assert!(g.edges.iter().any(|e| e.edge_type == "FD_FLOW"));
        assert!(g.edges.iter().any(|e| e.edge_type == "BUFFER_FLOW"));
    }
}
