mod fixtures;

use fixtures::{synthetic_trace, CLEAN_TRACE};
use std::path::PathBuf;
use sysdag::baselines::ngram;

#[test]
fn sequence_similarity_drops_when_dummy_calls_are_inserted() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/sysdag-ngram");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let input = synthetic_trace(&root.join("input"), "clean.strace", CLEAN_TRACE);
    let cfg = sysdag::Config::default();
    let (clean, _) = sysdag::tracer::parse_strace_path(&input, &cfg).unwrap();
    let profile = ngram::train(&clean, vec![1, 2, 3], 0.1, 0.2);
    let mut altered = clean.clone();
    altered.insert(1, altered[0].clone());
    assert!(
        ngram::similarity(
            &ngram::window_ngrams(&altered, &[1, 2, 3]),
            &profile.profile
        ) < 1.0
    );
}
