SysCall-DAG — Architecture Overview

Purpose

High-level summary of major modules, data models, and core algorithms so contributors can quickly find responsibility boundaries.

Module map (src/)
- canonical: Stable canonicalization and digest helpers (used by WL + fingerprinting).
- config: Config structs + load/digest helpers (configs/default.toml).
- tracer: Robust, stateful strace parser → TraceEvent (handles unfinished/resumed syscalls, timestamps, pid prefixes).
- event: TraceEvent and associated argument/label structures (labels built from syscall metadata).
- labels: Label-building helpers (path classes, resource kinds, op names).
- graph: Stateful resource model and windowed DAG builder (build_windows, validate_graph).
- features: Directed, edge-typed Weisfeiler–Lehman refinement and fingerprint / feature histogram creation (encode, weighted_jaccard).
- detector: Baseline training, prototypes, scoring, and decision records (train_baseline, score, BaselineManifest, DecisionRecord).
- pipeline: High-level orchestration (ingest, encode_all, analyze_path).
- sandbox: Guest micro-VM staging/execution for programs; file staging and trace capture helpers.
- visualizer: Graph JSON/DOT writers and human-friendly decision formatting.
- tui: Terminal UI (landing and session) used for interactive runs.

Key data models
- TraceEvent (tracer/event): single syscall event with labels and capture info.
- GraphRecord (graph.rs): nodes, edges, meta; canonical digest before WL.
- EncodedGraph (features.rs): fingerprint, features (round,color counts), original GraphRecord.
- BaselineManifest (detector.rs): baseline metadata, exact fingerprint map, prototypes, pipeline/config checksums, thresholds.
- DecisionRecord (detector.rs): explainable decision output with evidence items and nearest prototype.

Core algorithms & invariants
- Strace parsing: collects enter/exit timestamps, handles unfinished/resumed lines; filters by syscall classes.
- Windowing: sliding window with optional exec-flush. Each window emits a GraphRecord; include_incomplete_tail controls tail emission.
- Graph construction: precise FD generation tracking, last-writer buffer flow, external anchors for out-of-window producers, and strict validation (no backward edges, unique node IDs).
- WL encoding: iterative color refinement of node labels using typed incoming/outgoing neighbor colors; features = histogram((round,color) -> count).
- Fingerprint: canonical digest of WL histogram and structural counts; used for exact matching in detector.
- Scoring: hybrid linear combination of exact-match flag, 1 - similarity (weighted Jaccard), size deviation, and risk motifs. Thresholds choose NORMAL/REVIEW/ANOMALOUS.

Configuration & reproducibility
- Config controls window size/overlap, WL iterations, graph heuristics, detector weights, sandbox settings, and which syscall classes are tracked.
- Baseline compatibility checks pipeline (W/h) and config digest to prevent silent mismatches.

Testing & examples
- tests/ contains golden strace fixtures and a pipeline unit test.
- Runtime synthetic traces in integration tests exercise the full pipeline without bundled training data.

Where to dig deeper
- graph.rs: FD/buffer state machine and emit_window logic (complex but central).
- features.rs: WL implementation and fingerprint composition.
- detector.rs: how prototypes are created and scored; read risk_and_evidence and robust_size_dev for heuristics.

Contact points
- CLI entry (main.rs) delegates to pipeline, sandbox, or TUI depending on flags; printing and artifact writing are centralized in pipeline::print_report and visualizer.
