SysCall-DAG — Pipeline Flow

Overview

This document explains the end-to-end runtime and offline flow implemented by SysCall‑DAG so a developer can follow data from input to final decision.

1) Input & classification
- Supported inputs: program source (C/Python/shell), Linux ELF, a recorded strace log, or a directory of `strace -ff` files.
- classify_input (pipeline::classify_input) decides: Program, Strace, or EventJsonl.

2) Ingestion (pipeline::ingest)
- For Program: stage target into a disposable micro-VM (sandbox::run_in_microvm), run tracer inside guest, collect traces.
- For Strace/EventJsonl: parsed directly on host.
- parse_strace_path (tracer.rs) converts raw strace text(s) → RawEvent → TraceEvent (labels attached).
- prepare_run_dir writes artifacts under working dir (.sysdag by default).

3) Windowing & Graph construction (graph::build_windows)
- Sliding windows: window.size (W) with window.overlap (O). Optionally flush on exec.
- Stateful process model: track process image/version, FD generations, last-writer buffers, seeded stdio, clones/forks.
- For each window emit a GraphRecord (nodes, edges, WindowMeta, pre-WL digest).
- Edge types: FD_FLOW, BUFFER_FLOW, PROCESS_FLOW; anchors created for external producers when configured.

4) Feature encoding (features::encode)
- Directed, edge-typed Weisfeiler–Lehman refinement (cfg.wl.iterations rounds).
- Node colors start from label_digest and are refined with incoming/outgoing typed neighbor colors.
- Features: histogram of (round, color) counts; fingerprint = digest([WL_VERSION, n_nodes, n_edges, hist]).
- EncodedGraph holds fingerprint, features, sizes, and original GraphRecord.

5) Baseline training & manifest (detector::train_baseline)
- Exact fingerprint counts are collected; prototypes (unique fingerprints up to max_prototypes) are made.
- BaselineManifest records pipeline parameters, config digest, prototypes, exact index, score weights/thresholds.
- save_baseline writes JSON under baseline dir.

6) Monitoring / Scoring (detector::score)
- Exact-match short-circuits (exact_known).
- Similarity computed via weighted_jaccard(features, prototype.features).
- Size deviation (robust median-based deviation) and risk motifs (sensitive file opens, shell execs, buffer→net sends) add to score.
- Final score = alpha*(exact?) + beta*(1-sim) + gamma*size_dev + delta*risk; clamped and compared against thresholds to produce NORMAL/REVIEW/ANOMALOUS.
- DecisionRecord includes evidence motifs and nearest prototype info.

7) Artifacts & visualization (visualizer.rs)
- GraphRecord → JSON and Graphviz DOT (visualizer::write_graph_artifacts, to_dot).
- Reports and decisions are written into the run directory; print_report formats JSON/plain output.

CLI entrypoints (src/main.rs)
- sysdag run/train/monitor, sysdag doctor, sysdag viz
- TUI (ratatui + crossterm) used for interactive runs; plain/json modes skip TUI.

Where artifacts land
- Default workdir: .sysdag
  - baselines/
  - runs/<id>/events.jsonl
  - runs/<id>/graphs/wXXXX/graph.json/.dot
  - runs/<id>/decisions.json

Notes
- An unseen fingerprint is treated as evidence, not an absolute verdict; the scoring is intentionally hybrid and explainable.
- Configs live in configs/default.toml; most behaviors are configurable there.
