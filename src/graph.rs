//! Resource-state machine and windowed typed event DAG construction.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::canonical::{digest, Canon};
use crate::config::Config;
use crate::event::TraceEvent;
use crate::labels::{is_fd_allocator, is_shell_path, label_digest, syscall_class};
use crate::{LABEL_SCHEMA_VERSION, SCHEMA_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub source_seq: Option<u64>,
    pub label_fields: BTreeMap<String, String>,
    pub label_digest: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphEdge {
    pub src: String,
    pub dst: String,
    #[serde(rename = "type")]
    pub edge_type: String,
    pub resource_class: String,
    /// 100 is address-proven; 50 is a last-writer heuristic fallback.
    #[serde(default = "default_edge_confidence")]
    pub confidence: u8,
}

fn default_edge_confidence() -> u8 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowMeta {
    pub start_seq: u64,
    pub end_seq: u64,
    pub w: usize,
    pub overlap: usize,
    pub complete: bool,
    pub window_id: String,
    pub event_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphQuality {
    pub capture_loss: u64,
    pub unknown_calls: u64,
    pub anchor_fraction: f64,
    pub rejected_lines: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRecord {
    pub graph_schema: String,
    pub label_schema: String,
    pub graph_id: String,
    pub baseline_key: String,
    pub window: WindowMeta,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub quality: GraphQuality,
    pub graph_digest_before_wl: String,
}

#[derive(Clone)]
struct FdRes {
    generation: u64,
    kind: String,
    last_seq: u64,
}

#[derive(Clone, Default)]
struct BufferWriter {
    seq: u64,
    start: Option<u64>,
    end: Option<u64>,
}

struct ProcessState {
    fd: HashMap<i32, FdRes>,
    fd_gen: HashMap<i32, u64>,
    last_writer: Option<Vec<BufferWriter>>,
    image_gen: u64,
    seeded: bool,
}

impl ProcessState {
    fn new() -> Self {
        Self {
            fd: HashMap::new(),
            fd_gen: HashMap::new(),
            last_writer: None,
            image_gen: 0,
            seeded: false,
        }
    }
}

pub fn build_windows(
    events: &[TraceEvent],
    cfg: &Config,
    run_id: &str,
    baseline_key: &str,
    quality: GraphQuality,
) -> Vec<GraphRecord> {
    // strace -ff commonly reports thread IDs.  Normalize each event to its
    // thread-group/process key before building resource state. Child threads
    // (`CLONE_THREAD`) share the parent's key; forked children get their own.
    let mut groups: HashMap<i32, i32> = HashMap::new();
    let mut normalized = Vec::with_capacity(events.len());
    for event in events {
        let mut event = event.clone();
        let tid = event.process.tid;
        let group = *groups.entry(tid).or_insert(event.process.pid);
        event.process.pid = group;
        if event.success() && matches!(event.syscall.name.as_str(), "clone" | "clone3") {
            if let Some(child) = event.args.child_pid {
                let child_group = if event
                    .args
                    .flags
                    .as_deref()
                    .map(|f| f.contains("CLONE_THREAD"))
                    .unwrap_or(false)
                {
                    group
                } else {
                    child
                };
                groups.insert(child, child_group);
            }
        }
        normalized.push(event);
    }
    let events = &normalized;
    let w = cfg.window.size.max(1);
    let o = cfg.window.overlap.min(w.saturating_sub(1));
    let mut buf: VecDeque<&TraceEvent> = VecDeque::new();
    let mut state: HashMap<i32, ProcessState> = HashMap::new();
    let mut out = Vec::new();
    let mut win_idx = 0u32;

    for ev in events {
        if cfg.window.flush_on_exec && ev.syscall.name.starts_with("execve") && ev.success() {
            if !buf.is_empty() {
                out.push(emit_window(
                    buf.make_contiguous(),
                    &state,
                    cfg,
                    run_id,
                    baseline_key,
                    win_idx,
                    false,
                    quality.clone(),
                ));
                win_idx += 1;
                buf.clear();
            }
            if let Some(ps) = state.get_mut(&ev.process.pid) {
                ps.image_gen += 1;
                ps.last_writer = None;
            }
        }

        buf.push_back(ev);
        apply_state(&mut state, ev, cfg);

        if buf.len() >= w {
            let slice: Vec<&TraceEvent> = buf.iter().copied().collect();
            out.push(emit_window(
                &slice,
                &state,
                cfg,
                run_id,
                baseline_key,
                win_idx,
                true,
                quality.clone(),
            ));
            win_idx += 1;
            let keep = o;
            while buf.len() > keep {
                buf.pop_front();
            }
        }
    }

    if cfg.window.include_incomplete_tail && !buf.is_empty() {
        let slice: Vec<&TraceEvent> = buf.iter().copied().collect();
        out.push(emit_window(
            &slice,
            &state,
            cfg,
            run_id,
            baseline_key,
            win_idx,
            slice.len() >= w,
            quality,
        ));
    }
    out
}

fn apply_state(state: &mut HashMap<i32, ProcessState>, ev: &TraceEvent, cfg: &Config) {
    let pid = ev.process.pid;
    let ps = state.entry(pid).or_insert_with(ProcessState::new);
    if cfg.graph.seed_stdio && !ps.seeded {
        for fd in 0..3 {
            ps.fd.insert(
                fd,
                FdRes {
                    generation: 0,
                    kind: "FILE".into(),
                    last_seq: 0,
                },
            );
        }
        ps.seeded = true;
    }

    let name = ev.syscall.name.as_str();
    if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
        if let Some(child) = ev.args.child_pid {
            let snapshot = clone_state(ps);
            state.insert(child, snapshot);
        }
    }

    let ps = state.entry(pid).or_insert_with(ProcessState::new);

    if ev.success() && is_fd_allocator(name) {
        let dup_like = matches!(name, "dup" | "dup2" | "dup3")
            || (name == "fcntl"
                && ev
                    .args
                    .flags
                    .as_deref()
                    .map(|f| f.contains("DUP"))
                    .unwrap_or(false));
        if dup_like {
            if let (Some(old), Some(newfd)) = (ev.args.fd, ev.args.newfd) {
                if let Some(res) = ps.fd.get(&old).cloned() {
                    ps.fd.insert(
                        newfd,
                        FdRes {
                            generation: res.generation,
                            kind: res.kind,
                            last_seq: ev.seq,
                        },
                    );
                }
            }
        } else if let Some(fd) = ev.args.fd {
            let gen = ps.fd_gen.entry(fd).or_insert(0);
            *gen += 1;
            let kind = if syscall_class(name) == "network" || ev.labels.resource_kind == "SOCKET" {
                "SOCKET"
            } else {
                "FILE"
            };
            ps.fd.insert(
                fd,
                FdRes {
                    generation: *gen,
                    kind: kind.into(),
                    last_seq: ev.seq,
                },
            );
        }
    }

    if ev.success() && matches!(name, "pipe" | "pipe2") {
        if let Some((r, w)) = ev.args.pipe_fds {
            for fd in [r, w] {
                let gen = ps.fd_gen.entry(fd).or_insert(0);
                *gen += 1;
                ps.fd.insert(
                    fd,
                    FdRes {
                        generation: *gen,
                        kind: "PIPE".into(),
                        last_seq: ev.seq,
                    },
                );
            }
        }
    }

    // Unix-domain descriptor passing: resource identity is not observable on
    // receive, so seed passed descriptors conservatively as external FILEs.
    if ev.success() && name == "recvmsg" {
        for fd in &ev.args.received_fds {
            let generation = ps.fd_gen.entry(*fd).or_insert(0);
            *generation += 1;
            ps.fd.insert(
                *fd,
                FdRes {
                    generation: *generation,
                    kind: "FILE".into(),
                    last_seq: ev.seq,
                },
            );
        }
    }

    if ev.success() && matches!(name, "mmap" | "mmap2" | "munmap") {
        // Address ranges can be reused after map changes; do not join a later
        // sink to a stale producer through the last-writer fallback.
        ps.last_writer = None;
    }

    if ev.success() {
        if let Some(fd) = ev.args.fd {
            if let Some(res) = ps.fd.get_mut(&fd) {
                if !is_fd_allocator(name) || matches!(name, "dup" | "dup2" | "dup3" | "fcntl") {
                    // last-event-chain update for consumers
                    if !matches!(
                        name,
                        "dup" | "dup2" | "dup3" | "fcntl" | "open" | "openat" | "socket"
                    ) {
                        res.last_seq = ev.seq;
                    }
                }
            }
        }
    }

    if ev.success() && name == "close" {
        if let Some(fd) = ev.args.fd {
            if let Some(res) = ps.fd.get_mut(&fd) {
                res.last_seq = ev.seq;
            }
            ps.fd.remove(&fd);
        }
    }

    if cfg.graph.buffer_flow && ev.success() {
        let is_prod = matches!(
            name,
            "read" | "pread64" | "readv" | "recvfrom" | "recv" | "recvmsg"
        );
        let is_cons = matches!(
            name,
            "write" | "pwrite64" | "writev" | "sendto" | "send" | "sendmsg"
        );
        if is_prod {
            let n = ev.ret.filter(|v| *v > 0).unwrap_or(0) as u64;
            ps.last_writer = Some(buffer_writers(ev, n));
        } else if is_cons {
            // consumer observed later when building edges
        }
    }
}

fn clone_state(ps: &ProcessState) -> ProcessState {
    ProcessState {
        fd: ps.fd.clone(),
        fd_gen: ps.fd_gen.clone(),
        last_writer: None,
        image_gen: ps.image_gen,
        seeded: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_window(
    events: &[&TraceEvent],
    live: &HashMap<i32, ProcessState>,
    cfg: &Config,
    run_id: &str,
    baseline_key: &str,
    idx: u32,
    complete: bool,
    mut quality: GraphQuality,
) -> GraphRecord {
    let _ = live;
    let window_id = format!("{run_id}:w{idx:04}");
    let start_seq = events.first().map(|e| e.seq).unwrap_or(0);
    let end_seq = events.last().map(|e| e.seq).unwrap_or(0);
    let in_window: BTreeSet<u64> = events.iter().map(|e| e.seq).collect();

    let mut seq_to_id: HashMap<u64, String> = HashMap::new();
    let mut nodes = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        let id = format!("n{i:04}");
        seq_to_id.insert(ev.seq, id.clone());
        let mut fields = BTreeMap::new();
        fields.insert("family".into(), ev.labels.family.clone());
        fields.insert("op".into(), ev.labels.op.clone());
        fields.insert("result".into(), ev.labels.result.clone());
        fields.insert("resource_kind".into(), ev.labels.resource_kind.clone());
        fields.insert("flags".into(), ev.labels.flags.clone());
        fields.insert("bytes".into(), ev.labels.bytes.clone());
        fields.insert("path_class".into(), ev.labels.path_class.clone());
        nodes.push(GraphNode {
            id,
            source_seq: Some(ev.seq),
            label_digest: label_digest(&ev.labels),
            label_fields: fields,
            kind: "event".into(),
        });
    }

    let mut anchors: HashMap<String, String> = HashMap::new();
    let mut edges: BTreeSet<GraphEdge> = BTreeSet::new();
    let mut replay: HashMap<i32, ProcessState> = HashMap::new();
    let mut last_writer: HashMap<i32, Vec<BufferWriter>> = HashMap::new();

    let add_edge = |src_seq: Option<u64>,
                    dst_seq: u64,
                    etype: &str,
                    class: &str,
                    anchors: &mut HashMap<String, String>,
                    nodes: &mut Vec<GraphNode>,
                    edges: &mut BTreeSet<GraphEdge>,
                    seq_to_id: &HashMap<u64, String>| {
        let dst = match seq_to_id.get(&dst_seq) {
            Some(id) => id.clone(),
            None => return,
        };
        let src = match src_seq {
            Some(s) if in_window.contains(&s) => seq_to_id.get(&s).cloned(),
            Some(_) | None if cfg.graph.external_anchors => {
                let key = match class {
                    "SOCKET" => "EXTERNAL_SOCKET",
                    "PROCESS" => "EXTERNAL_PROCESS",
                    "FILE" | "PIPE" => "EXTERNAL_FILE",
                    _ => "UNKNOWN_PRODUCER",
                };
                Some(
                    anchors
                        .entry(key.into())
                        .or_insert_with(|| {
                            let id = format!("a:{key}");
                            let mut fields = BTreeMap::new();
                            fields.insert("family".into(), "anchor".into());
                            fields.insert("op".into(), key.into());
                            fields.insert("result".into(), "SUCCESS".into());
                            fields.insert("resource_kind".into(), class.into());
                            fields.insert("flags".into(), "NONE".into());
                            fields.insert("bytes".into(), "NONE".into());
                            fields.insert("path_class".into(), "NONE".into());
                            nodes.push(GraphNode {
                                id: id.clone(),
                                source_seq: None,
                                label_digest: digest(&Canon::str(key)),
                                label_fields: fields,
                                kind: "anchor".into(),
                            });
                            id
                        })
                        .clone(),
                )
            }
            _ => None,
        };
        let Some(src) = src else { return };
        if src == dst {
            return;
        }
        if let (Some(ss), _) = (src_seq, dst_seq) {
            if ss >= dst_seq {
                return;
            }
        }
        edges.insert(GraphEdge {
            src,
            dst,
            edge_type: etype.into(),
            resource_class: class.into(),
            confidence: if etype == "BUFFER_FLOW" { 50 } else { 100 },
        });
    };

    for ev in events {
        let pid = ev.process.pid;
        let name = ev.syscall.name.as_str();
        let child_snapshot = {
            let ps = replay.entry(pid).or_insert_with(ProcessState::new);
            if cfg.graph.seed_stdio && !ps.seeded {
                for fd in 0..3 {
                    ps.fd.insert(
                        fd,
                        FdRes {
                            generation: 0,
                            kind: "FILE".into(),
                            last_seq: 0,
                        },
                    );
                }
                ps.seeded = true;
            }

            if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
                add_edge(
                    None,
                    ev.seq,
                    "PROCESS_FLOW",
                    "PROCESS",
                    &mut anchors,
                    &mut nodes,
                    &mut edges,
                    &seq_to_id,
                );
            }

            if ev.success() && matches!(name, "execve" | "execveat") {
                add_edge(
                    None,
                    ev.seq,
                    "PROCESS_FLOW",
                    "PROCESS",
                    &mut anchors,
                    &mut nodes,
                    &mut edges,
                    &seq_to_id,
                );
                let _ = is_shell_path(ev.args.path.as_deref().unwrap_or(""));
            }

            if let Some(fd) = ev.args.fd {
                let prior = ps.fd.get(&fd).cloned();
                if let Some(res) = prior {
                    if res.last_seq != ev.seq {
                        add_edge(
                            if res.last_seq == 0 {
                                None
                            } else {
                                Some(res.last_seq)
                            },
                            ev.seq,
                            "FD_FLOW",
                            &res.kind,
                            &mut anchors,
                            &mut nodes,
                            &mut edges,
                            &seq_to_id,
                        );
                    }
                } else if !is_fd_allocator(name) {
                    add_edge(
                        None,
                        ev.seq,
                        "FD_FLOW",
                        &ev.labels.resource_kind,
                        &mut anchors,
                        &mut nodes,
                        &mut edges,
                        &seq_to_id,
                    );
                }
            }

            if ev.success() && is_fd_allocator(name) {
                let dup_like = matches!(name, "dup" | "dup2" | "dup3")
                    || (name == "fcntl"
                        && ev
                            .args
                            .flags
                            .as_deref()
                            .map(|f| f.contains("DUP"))
                            .unwrap_or(false));
                if dup_like {
                    if let (Some(old), Some(newfd)) = (ev.args.fd, ev.args.newfd) {
                        if let Some(res) = ps.fd.get(&old).cloned() {
                            ps.fd.insert(
                                newfd,
                                FdRes {
                                    generation: res.generation,
                                    kind: res.kind,
                                    last_seq: ev.seq,
                                },
                            );
                        }
                    }
                } else if let Some(fd) = ev.args.fd {
                    let gen = ps.fd_gen.entry(fd).or_insert(0);
                    *gen += 1;
                    ps.fd.insert(
                        fd,
                        FdRes {
                            generation: *gen,
                            kind: ev.labels.resource_kind.clone(),
                            last_seq: ev.seq,
                        },
                    );
                }
            } else if ev.success() {
                if let Some(fd) = ev.args.fd {
                    if let Some(res) = ps.fd.get_mut(&fd) {
                        res.last_seq = ev.seq;
                    }
                }
            }

            if ev.success() && name == "close" {
                if let Some(fd) = ev.args.fd {
                    ps.fd.remove(&fd);
                }
            }

            if ev.success() && matches!(name, "pipe" | "pipe2") {
                if let Some((r, wfd)) = ev.args.pipe_fds {
                    for fd in [r, wfd] {
                        let gen = ps.fd_gen.entry(fd).or_insert(0);
                        *gen += 1;
                        ps.fd.insert(
                            fd,
                            FdRes {
                                generation: *gen,
                                kind: "PIPE".into(),
                                last_seq: ev.seq,
                            },
                        );
                    }
                }
            }

            if ev.success() && name == "recvmsg" {
                for fd in &ev.args.received_fds {
                    let generation = ps.fd_gen.entry(*fd).or_insert(0);
                    *generation += 1;
                    ps.fd.insert(
                        *fd,
                        FdRes {
                            generation: *generation,
                            kind: "FILE".into(),
                            last_seq: ev.seq,
                        },
                    );
                }
            }

            if ev.success() && matches!(name, "clone" | "clone3" | "fork" | "vfork") {
                ev.args.child_pid.map(|child| (child, clone_state(ps)))
            } else {
                None
            }
        };
        if let Some((child, snap)) = child_snapshot {
            replay.insert(child, snap);
        }

        if cfg.graph.buffer_flow && ev.success() {
            let is_prod = matches!(
                name,
                "read" | "pread64" | "readv" | "recvfrom" | "recv" | "recvmsg"
            ) && ev.ret.unwrap_or(0) > 0;
            let is_cons = matches!(
                name,
                "write" | "pwrite64" | "writev" | "sendto" | "send" | "sendmsg"
            );
            if is_prod {
                let n = ev.ret.unwrap_or(0) as u64;
                last_writer.insert(pid, buffer_writers(ev, n));
            } else if is_cons {
                if let Some(writers) = last_writer.get(&pid).cloned() {
                    for w in writers {
                        for consumer in buffer_consumers(ev) {
                            let overlap = match (w.start, w.end, consumer.start, consumer.end) {
                                (Some(a0), Some(a1), Some(b0), Some(b1)) => a0 < b1 && b0 < a1,
                                _ => cfg.graph.buffer_heuristic == "address_or_last_writer",
                            };
                            if overlap && w.seq < ev.seq {
                                add_edge(
                                    Some(w.seq),
                                    ev.seq,
                                    "BUFFER_FLOW",
                                    "BUFFER",
                                    &mut anchors,
                                    &mut nodes,
                                    &mut edges,
                                    &seq_to_id,
                                );
                            }
                        }
                    }
                }
            }
            if matches!(name, "mmap" | "mmap2" | "munmap") {
                last_writer.remove(&pid);
            }
        }
    }

    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    let edge_list: Vec<GraphEdge> = edges.into_iter().collect();
    let anchor_count = nodes.iter().filter(|n| n.kind == "anchor").count();
    quality.anchor_fraction = if nodes.is_empty() {
        0.0
    } else {
        anchor_count as f64 / nodes.len() as f64
    };

    let digest_src = Canon::map_from([
        (
            "nodes",
            Canon::List(
                nodes
                    .iter()
                    .map(|n| {
                        Canon::map_from([
                            ("id", Canon::str(&n.id)),
                            ("label", Canon::str(&n.label_digest)),
                            ("kind", Canon::str(&n.kind)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "edges",
            Canon::List(
                edge_list
                    .iter()
                    .map(|e| {
                        Canon::map_from([
                            ("src", Canon::str(&e.src)),
                            ("dst", Canon::str(&e.dst)),
                            ("type", Canon::str(&e.edge_type)),
                            ("class", Canon::str(&e.resource_class)),
                            ("confidence", Canon::Int(e.confidence as i64)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);

    GraphRecord {
        graph_schema: SCHEMA_VERSION.into(),
        label_schema: LABEL_SCHEMA_VERSION.into(),
        graph_id: window_id.clone(),
        baseline_key: baseline_key.into(),
        window: WindowMeta {
            start_seq,
            end_seq,
            w: cfg.window.size,
            overlap: cfg.window.overlap,
            complete,
            window_id: window_id.clone(),
            event_count: events.len(),
        },
        graph_digest_before_wl: digest(&digest_src),
        nodes,
        edges: edge_list,
        quality,
    }
}

pub fn validate_graph(g: &GraphRecord) -> Result<(), String> {
    let ids: BTreeSet<_> = g.nodes.iter().map(|n| n.id.as_str()).collect();
    if ids.len() != g.nodes.len() {
        return Err("duplicate node ids".into());
    }
    let seqs: HashMap<_, _> = g
        .nodes
        .iter()
        .filter_map(|n| n.source_seq.map(|s| (n.id.as_str(), s)))
        .collect();
    for e in &g.edges {
        if e.confidence > 100 {
            return Err("edge confidence exceeds 100".into());
        }
        if !ids.contains(e.src.as_str()) || !ids.contains(e.dst.as_str()) {
            return Err("edge endpoint missing".into());
        }
        if let (Some(a), Some(b)) = (seqs.get(e.src.as_str()), seqs.get(e.dst.as_str())) {
            if a >= b {
                return Err("backward edge".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef};
    use crate::labels::build_labels;

    fn ev(seq: u64, name: &str, path: &str, fd: Option<i32>, ret: i64) -> TraceEvent {
        let args = EventArgs {
            fd,
            path: if path.is_empty() {
                None
            } else {
                Some(path.into())
            },
            ..Default::default()
        };
        let labels = build_labels(name, path, "", "", "", Some(ret), None, Some(ret), "/app");
        TraceEvent::new(
            ProcessRef {
                pid: 1,
                tid: 1,
                start_ns: 0,
                image_gen: 0,
                comm: "t".into(),
            },
            seq,
            seq * 10,
            seq * 10 + 1,
            SyscallRef {
                nr: 0,
                name: name.into(),
                arch: "test".into(),
            },
            args,
            Some(ret),
            None,
            labels,
            CaptureInfo::default(),
        )
    }

    #[test]
    fn fd_chain_and_reuse() {
        let mut cfg = Config::default();
        cfg.window.size = 10;
        cfg.window.overlap = 0;
        cfg.labels.app_root = "/app".into();
        let events = vec![
            ev(1, "openat", "/app/a", Some(3), 3),
            ev(2, "read", "/app/a", Some(3), 8),
            ev(3, "close", "", Some(3), 0),
            ev(4, "openat", "/app/b", Some(3), 3),
            ev(5, "read", "/app/b", Some(3), 4),
        ];
        let graphs = build_windows(&events, &cfg, "t", "k", GraphQuality::default());
        assert_eq!(graphs.len(), 1);
        validate_graph(&graphs[0]).unwrap();
        assert!(graphs[0].edges.iter().any(|e| e.edge_type == "FD_FLOW"));
    }

    #[test]
    fn clone_thread_shares_buffer_state_with_parent() {
        let mut cfg = Config::default();
        cfg.window.size = 10;
        cfg.window.overlap = 0;
        let mut read = ev(1, "read", "/app/a", Some(3), 4);
        read.args.buffer_addr = Some(0x1000);
        read.args.count = Some(4);
        let mut clone = ev(2, "clone", "", None, 2);
        clone.args.child_pid = Some(2);
        clone.args.flags = Some("CLONE_THREAD".into());
        let mut send = ev(3, "send", "", Some(4), 4);
        send.process.pid = 2;
        send.process.tid = 2;
        send.args.buffer_addr = Some(0x1000);
        send.args.count = Some(4);
        send.labels.op = "NET_SEND".into();
        send.labels.resource_kind = "SOCKET".into();
        let g = build_windows(
            &[read, clone, send],
            &cfg,
            "t",
            "k",
            GraphQuality::default(),
        );
        assert!(g[0].edges.iter().any(|e| e.edge_type == "BUFFER_FLOW"));
    }

    #[test]
    fn vectored_io_matches_later_iovec_not_just_first() {
        let mut cfg = Config::default();
        cfg.window.size = 10;
        cfg.window.overlap = 0;
        let mut read = ev(1, "readv", "/app/a", Some(3), 8);
        read.args.iovecs = vec![
            crate::event::Iovec {
                addr: 0x1000,
                len: 4,
            },
            crate::event::Iovec {
                addr: 0x2000,
                len: 4,
            },
        ];
        let mut write = ev(2, "writev", "", Some(4), 4);
        write.args.iovecs = vec![crate::event::Iovec {
            addr: 0x2000,
            len: 4,
        }];
        let g = build_windows(&[read, write], &cfg, "t", "k", GraphQuality::default());
        assert!(g[0].edges.iter().any(|e| e.edge_type == "BUFFER_FLOW"));
    }
}

fn buffer_writers(ev: &TraceEvent, mut bytes: u64) -> Vec<BufferWriter> {
    if !ev.args.iovecs.is_empty() {
        return ev
            .args
            .iovecs
            .iter()
            .filter_map(|iov| {
                let used = bytes.min(iov.len);
                bytes = bytes.saturating_sub(used);
                (used > 0).then_some(BufferWriter {
                    seq: ev.seq,
                    start: Some(iov.addr),
                    end: Some(iov.addr.saturating_add(used)),
                })
            })
            .collect();
    }
    vec![BufferWriter {
        seq: ev.seq,
        start: ev.args.buffer_addr,
        end: ev.args.buffer_addr.map(|a| a.saturating_add(bytes)),
    }]
}

fn buffer_consumers(ev: &TraceEvent) -> Vec<BufferWriter> {
    if !ev.args.iovecs.is_empty() {
        return ev
            .args
            .iovecs
            .iter()
            .map(|iov| BufferWriter {
                seq: ev.seq,
                start: Some(iov.addr),
                end: Some(iov.addr.saturating_add(iov.len)),
            })
            .collect();
    }
    vec![BufferWriter {
        seq: ev.seq,
        start: ev.args.buffer_addr,
        end: ev
            .args
            .buffer_addr
            .zip(ev.args.count)
            .map(|(a, n)| a.saturating_add(n.max(0) as u64)),
    }]
}
