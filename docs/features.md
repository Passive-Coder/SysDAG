SysCall-DAG — Features & How to use

Quick feature list

- Traces -> typed syscall dependency DAGs (FD_FLOW, BUFFER_FLOW, PROCESS_FLOW) with anchors for external producers.
- Directed, edge-typed WL fingerprinting (configurable iterations) producing compact fingerprints and feature histograms.
- Baseline training (exact fingerprint index + prototype set) and hybrid scoring with explainable evidence motifs.
- Micro-VM sandbox runner for executing and tracing programs (network-disabled, memory-limited guest).
- Interactive terminal viewer (TUI) with simple per-graph filters (All/NETWORK/FILES/HOT) and plain/json output modes.
- Graphviz DOT export for graph inspection.
- Configurable via configs/default.toml (window, graph, WL, detector, sandbox).

Running the tool
- Install: cargo install --path .
- TUI (interactive): sysdag
- Train baseline from a trace or program: sysdag train <file>
- Monitor: sysdag monitor <file>
- One-shot (auto train/monitor): sysdag run <file>
- Bring-your-own traces and targets; no bundled training data or attack samples.
- Doctor checks prerequisites (Docker image etc): sysdag doctor
- Export DOT: sysdag viz <path/to/graph.json>
- Explain score breakdown: sysdag explain <baseline.json> <path/to/graph.json>  # prints alpha/beta/gamma/delta contributions

Configuration highlights (configs/default.toml)
- window.size, window.overlap, flush_on_exec
- graph.buffer_flow, graph.fd_policy, graph.external_anchors
- wl.iterations, wl.edge_typed
- detector.* weights and thresholds
- sandbox.memory_mb, timeout_sec, network (default none)

Extending or debugging
- To change WL or add new motifs, update features.rs and detector::risk_and_evidence.
- To adapt parsing for a tracer variant, modify tracer.rs parse_completed and interpret_args.
- Tests: tests/pipeline.rs exercises pipeline against runtime synthetic strace text.

Artifacts & inspection
- Look under .sysdag/runs/<id>/graphs/wXXXX for graph.json and graph.dot.
- Baselines: .sysdag/baselines/<target_sha>.json
- Decisions: runs/<id>/decisions.json (monitor mode)

Security & safety
- The sandbox guest uses network=none by default, and the tool emphasizes safe defaults.

Where to contribute
- Small changes: add unit tests in the module's tests sections or in tests/*.rs.
- Larger algorithm changes: add a short design doc under docs/ and update architecture.md.

Contact
- See top-level README for usage examples and installation.
