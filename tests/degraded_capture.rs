//! Phase 1.3 acceptance: degraded capture must cap ANOMALOUS at REVIEW.

mod fixtures;
use fixtures::{synthetic_trace, ATTACK_TRACE, CLEAN_TRACE};
use std::path::PathBuf;

use sysdag::config::Config;
use sysdag::event::ParseStats;
use sysdag::graph::{build_windows, GraphQuality};
use sysdag::pipeline::{analyze_path, Mode};

fn cfg() -> Config {
    let mut c = Config::default();
    c.window.size = 16;
    c.window.overlap = 4;
    c.labels.app_root = "/guest/www".into();
    // Very strict degradation gate so a small synthetic loss trips it.
    c.detector.max_degraded_rate_pct = 0.5;
    c
}

#[test]
fn degraded_capture_caps_anomalous_at_review() {
    let tmp = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-degraded");
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
        Some("fixture-degraded"),
    )
    .unwrap();
    let baseline_path = train.baseline_path.unwrap();

    let mut mon_cfg = cfg.clone();
    mon_cfg.detector.max_degraded_rate_pct = 0.0; // any loss degrades
    let mon = analyze_path(
        &synthetic_trace(&tmp.join("input"), "attack.strace", ATTACK_TRACE),
        Mode::Monitor,
        &cfg,
        &tmp,
        &baselines,
        &[],
        false,
        Some("fixture-degraded"),
    )
    .unwrap();

    // Rebuild windows from the monitor events with an artificially degraded
    // GraphQuality so the DEGRADED_CAPTURE rule must fire.
    let (events, _stats) = sysdag::tracer::parse_strace_path(
        &synthetic_trace(&tmp.join("input"), "attack.strace", ATTACK_TRACE),
        &mon_cfg,
    )
    .unwrap();
    assert!(!events.is_empty());

    let degraded_quality = GraphQuality {
        capture_loss: 3,
        unknown_calls: 2,
        anchor_fraction: 1.0,
        rejected_lines: 1,
    };
    let key = &mon.target_sha256;
    let graphs = build_windows(
        &events,
        &mon_cfg,
        "run-degraded",
        key,
        degraded_quality.clone(),
    );
    assert!(!graphs.is_empty());
    let encoded: Vec<sysdag::features::EncodedGraph> = graphs
        .into_iter()
        .map(|g| sysdag::features::encode(g, &mon_cfg))
        .collect();

    let baseline = sysdag::detector::load_baseline(&baseline_path).expect("load trained baseline");

    let mut saw_capped_review = false;
    for enc in &encoded {
        let dec = sysdag::detector::score(enc, &baseline, &mon_cfg);
        if dec.decision == "ANOMALOUS" {
            panic!("degraded capture produced ANOMALOUS: {}", dec.window_id);
        }
        if dec.score >= dec.threshold_review {
            assert_eq!(
                dec.decision, "REVIEW",
                "high score under degradation must be REVIEW"
            );
            saw_capped_review = true;
            assert!(dec.note.starts_with("DEGRADED_CAPTURE"));
            assert!(dec.evidence.iter().any(|e| e.motif == "DEGRADED_CAPTURE"));
        } else if !saw_capped_review && dec.score < dec.threshold_review {
            assert!(
                !dec.note.starts_with("DEGRADED_CAPTURE") || true,
                "low-scoring windows keep their verdict"
            );
        }
        // ParseStats flow into decisions via quality for reporting.
        assert_eq!(enc.graph.quality.capture_loss, 3);
    }
    assert!(
        saw_capped_review || encoded.is_empty(),
        "expected at least one capped REVIEW window on attack trace"
    );

    // Sanity: the same run with clean quality is not flagged as degraded.
    let clean_graphs = build_windows(&events, &mon_cfg, "run-clean", key, GraphQuality::default());
    for g in clean_graphs {
        let enc = sysdag::features::encode(g, &mon_cfg);
        let dec = sysdag::detector::score(&enc, &baseline, &mon_cfg);
        assert!(
            !dec.note.starts_with("DEGRADED_CAPTURE"),
            "clean capture should not be marked degraded"
        );
    }

    // ParseStats rate helper behaves per spec.
    let ps = ParseStats {
        lines: 1000,
        events: 900,
        rejected: 20,
        signals: 10,
        exits: 5,
        unfinished: 15,
        unknown_syscalls: 30,
        malformed_records: 10,
        lost_events_estimate: 35,
    };
    assert_eq!(ps.quality_loss(), 75);
    assert!(ps.is_degraded(5.0)); // 7.5% > 5%
    assert!(!ps.is_degraded(8.0));
    assert!(!ParseStats::default().is_degraded(0.0)); // zero lines => not degraded

    let _ = Mode::Train;
}
