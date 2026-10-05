//! Directed, edge-typed Weisfeiler–Lehman refinement and graph fingerprints.

use std::collections::{BTreeMap, HashMap};

use crate::canonical::{canonical_multiset, digest, digest_bytes, Canon};
use crate::config::Config;
use crate::graph::GraphRecord;
use crate::WL_VERSION;

#[derive(Debug, Clone)]
pub struct EncodedGraph {
    pub fingerprint: String,
    pub features: BTreeMap<(u32, String), u64>,
    pub n_nodes: usize,
    pub n_edges: usize,
    pub graph: GraphRecord,
    pub wl_depth: u32,
}

pub fn encode(graph: GraphRecord, cfg: &Config) -> EncodedGraph {
    let h = cfg.wl.iterations;
    let mut colors: HashMap<String, String> = HashMap::new();
    for n in &graph.nodes {
        colors.insert(n.id.clone(), n.label_digest.clone());
    }

    let mut features: BTreeMap<(u32, String), u64> = BTreeMap::new();
    for c in colors.values() {
        *features.entry((0, c.clone())).or_insert(0) += 1;
    }

    let mut incoming: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut outgoing: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for e in &graph.edges {
        if cfg.graph.representation == "node_only" {
            continue;
        }
        if cfg.graph.edge_set == "fd_only" && e.edge_type == "BUFFER_FLOW" {
            continue;
        }
        let etype = if cfg.wl.edge_typed {
            e.edge_type.clone()
        } else {
            "EDGE".into()
        };
        incoming
            .entry(e.dst.clone())
            .or_default()
            .push((etype.clone(), e.src.clone()));
        outgoing
            .entry(e.src.clone())
            .or_default()
            .push((etype, e.dst.clone()));
        if !cfg.wl.directed {
            incoming
                .entry(e.src.clone())
                .or_default()
                .push(("EDGE".into(), e.dst.clone()));
            outgoing
                .entry(e.dst.clone())
                .or_default()
                .push(("EDGE".into(), e.src.clone()));
        }
    }

    for i in 1..=h {
        let mut next = HashMap::new();
        for n in &graph.nodes {
            let mut in_toks = Vec::new();
            if let Some(nbrs) = incoming.get(&n.id) {
                for (etype, src) in nbrs {
                    let color = colors.get(src).cloned().unwrap_or_default();
                    in_toks.push(Canon::List(vec![
                        Canon::str("IN"),
                        Canon::str(etype),
                        Canon::str(color),
                    ]));
                }
            }
            let mut out_toks = Vec::new();
            if let Some(nbrs) = outgoing.get(&n.id) {
                for (etype, dst) in nbrs {
                    let color = colors.get(dst).cloned().unwrap_or_default();
                    out_toks.push(Canon::List(vec![
                        Canon::str("OUT"),
                        Canon::str(etype),
                        Canon::str(color),
                    ]));
                }
            }
            let prev = colors.get(&n.id).cloned().unwrap_or_default();
            let mut full = Vec::from(b"WL");
            full.extend(crate::canonical::dumps(&Canon::str(&prev)));
            full.extend(canonical_multiset(&in_toks));
            full.extend(canonical_multiset(&out_toks));
            let new_color = digest_bytes(&full);
            next.insert(n.id.clone(), new_color);
        }
        colors = next;
        for c in colors.values() {
            *features.entry((i, c.clone())).or_insert(0) += 1;
        }
    }

    let hist: Vec<Canon> = features
        .iter()
        .map(|((round, color), count)| {
            Canon::List(vec![
                Canon::Int(*round as i64),
                Canon::str(color),
                Canon::Int(*count as i64),
            ])
        })
        .collect();
    let fingerprint = digest(&Canon::List(vec![
        Canon::str(WL_VERSION),
        Canon::Int(graph.nodes.len() as i64),
        Canon::Int(graph.edges.len() as i64),
        Canon::List(hist),
    ]));

    EncodedGraph {
        n_nodes: graph.nodes.len(),
        n_edges: graph.edges.len(),
        wl_depth: h,
        fingerprint,
        features,
        graph,
    }
}

pub fn weighted_jaccard(a: &BTreeMap<(u32, String), u64>, b: &BTreeMap<(u32, String), u64>) -> f64 {
    let mut keys = std::collections::BTreeSet::new();
    keys.extend(a.keys());
    keys.extend(b.keys());
    let mut min = 0.0;
    let mut max = 0.0;
    for k in keys {
        let va = a.get(k).copied().unwrap_or(0) as f64;
        let vb = b.get(k).copied().unwrap_or(0) as f64;
        min += va.min(vb);
        max += va.max(vb);
    }
    if max == 0.0 {
        1.0
    } else {
        min / max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, GraphQuality, WindowMeta};

    fn tiny(flip: bool) -> GraphRecord {
        let n = |id: &str, lab: &str| GraphNode {
            id: id.into(),
            source_seq: Some(if id == "n0000" { 1 } else { 2 }),
            label_fields: BTreeMap::from([("op".into(), lab.into())]),
            label_digest: digest(&Canon::str(lab)),
            kind: "event".into(),
        };
        let (src, dst) = if flip {
            ("n0001", "n0000")
        } else {
            ("n0000", "n0001")
        };
        GraphRecord {
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
            nodes: vec![n("n0000", "FILE_OPEN"), n("n0001", "FILE_READ")],
            edges: vec![GraphEdge {
                src: src.into(),
                dst: dst.into(),
                edge_type: "FD_FLOW".into(),
                resource_class: "FILE".into(),
                confidence: 100,
            }],
            quality: GraphQuality::default(),
            graph_digest_before_wl: "x".into(),
        }
    }

    #[test]
    fn permutation_of_node_order_is_stable() {
        let cfg = Config::default();
        let mut g = tiny(false);
        let a = encode(g.clone(), &cfg).fingerprint;
        g.nodes.reverse();
        let b = encode(g, &cfg).fingerprint;
        assert_eq!(a, b);
    }

    #[test]
    fn direction_changes_fingerprint() {
        let cfg = Config::default();
        let a = encode(tiny(false), &cfg).fingerprint;
        let b = encode(tiny(true), &cfg).fingerprint;
        assert_ne!(a, b);
    }

    #[test]
    fn jaccard_identical_is_one() {
        let mut m = BTreeMap::new();
        m.insert((0, "a".into()), 2);
        assert!((weighted_jaccard(&m, &m) - 1.0).abs() < 1e-12);
    }
}
