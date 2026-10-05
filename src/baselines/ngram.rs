//! Sequence n-gram reference baseline for graph-vs-sequence experiments.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::detector::{DecisionRecord, EvidenceItem};
use crate::event::TraceEvent;
use crate::graph::GraphQuality;
use crate::DECISION_SCHEMA;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgramBaseline {
    pub n_values: Vec<usize>,
    pub profile: BTreeMap<String, u64>,
    pub threshold_review: f64,
    pub threshold_alert: f64,
}

pub fn window_ngrams(events: &[TraceEvent], n_values: &[usize]) -> BTreeMap<String, u64> {
    let names: Vec<_> = events.iter().map(|e| e.syscall.name.as_str()).collect();
    let mut out = BTreeMap::new();
    for &n in n_values {
        if n == 0 || names.len() < n {
            continue;
        }
        for slice in names.windows(n) {
            let key = format!("{n}:{}", slice.join("\u{1f}"));
            *out.entry(key).or_insert(0) += 1;
        }
    }
    out
}

pub fn train(
    events: &[TraceEvent],
    n_values: Vec<usize>,
    review: f64,
    alert: f64,
) -> NgramBaseline {
    NgramBaseline {
        profile: window_ngrams(events, &n_values),
        n_values,
        threshold_review: review,
        threshold_alert: alert,
    }
}

pub fn similarity(a: &BTreeMap<String, u64>, b: &BTreeMap<String, u64>) -> f64 {
    let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
    let (mut min, mut max) = (0u64, 0u64);
    for key in keys {
        min += a
            .get(key)
            .copied()
            .unwrap_or(0)
            .min(b.get(key).copied().unwrap_or(0));
        max += a
            .get(key)
            .copied()
            .unwrap_or(0)
            .max(b.get(key).copied().unwrap_or(0));
    }
    if max == 0 {
        1.0
    } else {
        min as f64 / max as f64
    }
}

/// Sequence baseline result uses `DecisionRecord`, allowing the metrics harness
/// to consume graph and sequence outputs uniformly.
pub fn score(
    events: &[TraceEvent],
    baseline: &NgramBaseline,
    window_id: &str,
    quality: GraphQuality,
) -> DecisionRecord {
    let grams = window_ngrams(events, &baseline.n_values);
    let sim = similarity(&grams, &baseline.profile);
    let score = 1.0 - sim;
    let decision = if score < baseline.threshold_review {
        "NORMAL"
    } else if score < baseline.threshold_alert {
        "REVIEW"
    } else {
        "ANOMALOUS"
    };
    DecisionRecord {
        decision_schema: DECISION_SCHEMA.into(),
        window_id: window_id.into(),
        baseline_id: "ngram".into(),
        decision: decision.into(),
        score,
        threshold_review: baseline.threshold_review,
        threshold_alert: baseline.threshold_alert,
        exact_known: score == 0.0,
        nearest_normal: None,
        evidence: vec![EvidenceItem {
            motif: "NGRAM_SEQUENCE".into(),
            events: vec![],
            detail: format!("n-gram multiset similarity {sim:.4}"),
        }],
        quality,
        fingerprint: String::new(),
        n_nodes: events.len(),
        n_edges: 0,
        note: "Sequence n-gram reference baseline".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef, TraceEvent},
        labels::NodeLabels,
    };
    fn ev(name: &str) -> TraceEvent {
        TraceEvent::new(
            ProcessRef {
                pid: 1,
                tid: 1,
                start_ns: 0,
                image_gen: 0,
                comm: String::new(),
            },
            1,
            0,
            0,
            SyscallRef {
                nr: 0,
                name: name.into(),
                arch: "linux".into(),
            },
            EventArgs::default(),
            Some(0),
            None,
            NodeLabels {
                family: String::new(),
                op: String::new(),
                result: String::new(),
                resource_kind: String::new(),
                flags: String::new(),
                bytes: String::new(),
                path_class: String::new(),
            },
            CaptureInfo::default(),
        )
    }
    #[test]
    fn detects_sequence_change() {
        let clean = vec![ev("openat"), ev("read"), ev("close")];
        let b = train(&clean, vec![1, 2, 3], 0.2, 0.4);
        assert_eq!(
            score(&clean, &b, "w", GraphQuality::default()).decision,
            "NORMAL"
        );
        let changed = vec![ev("execve"), ev("send")];
        assert_eq!(
            score(&changed, &b, "w", GraphQuality::default()).decision,
            "ANOMALOUS"
        );
    }
}
