mod fixtures;
use fixtures::{synthetic_trace, ATTACK_TRACE, CLEAN_TRACE};
use std::path::PathBuf;

use sysdag::{
    config::Config,
    experiments::{
        ablate, calibrate, evaluate, evaluate_ngram, import_dataset, load_dataset, measure,
    },
};

#[test]
fn imports_by_run_calibrates_and_evaluates() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-experiments");
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("source");
    for i in 0..5 {
        let p = source.join(format!("clean/run-{i}/trace.strace"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::copy(
            synthetic_trace(&root.join("templates"), "clean.strace", CLEAN_TRACE),
            p,
        )
        .unwrap();
    }
    let attack = source.join("attacks/exfil/trace.strace");
    std::fs::create_dir_all(attack.parent().unwrap()).unwrap();
    std::fs::copy(
        synthetic_trace(&root.join("templates"), "attack.strace", ATTACK_TRACE),
        &attack,
    )
    .unwrap();

    let mut cfg = Config::default();
    cfg.window.size = 4;
    cfg.window.overlap = 1;
    let manifest = import_dataset(&source, &root, Some("fixture")).unwrap();
    assert!(manifest.is_file());
    let (_, data) = load_dataset(&root, "fixture").unwrap();
    assert_eq!(
        data.runs.iter().filter(|r| r.partition == "train").count(),
        3
    );
    assert_eq!(
        data.runs
            .iter()
            .filter(|r| r.partition == "validation")
            .count(),
        1
    );
    assert_eq!(
        data.runs.iter().filter(|r| r.partition == "test").count(),
        2
    );

    let baseline = calibrate(&root, "fixture", &cfg).unwrap();
    let b = sysdag::detector::load_baseline(&baseline).unwrap();
    assert!(b.calibration.is_some());
    let results = evaluate(&root, "fixture", &baseline, &cfg).unwrap();
    assert!(results.join("report.json").is_file());
    assert!(results.join("summary.md").is_file());
    let measured = measure(&root, "fixture", &baseline, &cfg).unwrap();
    let manifest: sysdag::experiments::ExperimentManifest = serde_json::from_str(
        &std::fs::read_to_string(measured.join("experiment-manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.dataset_id, "fixture");
    assert!(manifest.artifacts.contains_key("report.json"));
    assert!(!manifest.checksum.is_empty());

    let grid = root.join("grid.toml");
    std::fs::write(&grid, "[[run]]\nname = 'node-only'\nrepresentation = 'node_only'\nwl_iterations = 1\n\n[[run]]\nname = 'exact-only'\nexact_only = true\n").unwrap();
    let ablations = ablate(&root, "fixture", &grid, &cfg).unwrap();
    let summary = std::fs::read_to_string(ablations.join("summary.json")).unwrap();
    assert!(summary.contains("node-only"));
    assert!(evaluate_ngram(&root, "fixture", &cfg)
        .unwrap()
        .join("report.json")
        .is_file());
}
