# SysDAG

SysDAG builds typed dependency DAGs from a process's Linux system calls,
fingerprints each window with directed Weisfeiler–Lehman refinement, and scores
it against a clean baseline. It is a research prototype: use `strace` as the
reference capture path, and treat eBPF performance claims as unverified until
the included measurement workflow has been run on a privileged Linux host.

## Highlights

- **Typed syscall graphs** with descriptor lifecycles, process relationships,
  vectored-I/O buffer flow, and Unix `SCM_RIGHTS` descriptor transfer.
- **`NORMAL`, `REVIEW`, and `ANOMALOUS`** decisions with score breakdowns and
  source-window evidence.
- **Browser graph visualizer** — interactive D3-based SVG viewer with:
  - Suspicious node highlighting (red glow, risk markers) matching the TUI
  - Edge typing and coloring (FD flow, buffer flow, process flow)
  - Multiple layouts (hierarchy, force-directed, radial)
  - Inspector panel, minimap, search, and SVG export
- **Capture-quality accounting**: parser/kernel loss and bounded-stream eviction
  flow into the degraded-capture safeguard rather than being silently ignored.
- **Reproducible evaluation**: dataset import, calibration, evaluation,
  measurement, ablation, and a 1/2/3-gram sequence reference.
- **Interactive TUI** plus plain-text and JSON command-line modes.
- **Incremental live monitoring** from JSONL, strace, FIFO/file, TCP, or an
  eBPF relay stream.

## Requirements

- Rust stable.
- Docker Desktop / Docker for running programs inside the disposable Linux
  guest. Recorded traces do not need Docker.
- Linux or WSL2 for live `strace` and eBPF collection.

Install and validate:

```sh
cargo install --path .
cargo test
sysdag doctor
```

## Quick start

Open the TUI on a terminal:

```sh
sysdag
```

Enter a program or trace path and press Enter. Matching files and directories
appear below the input as you type; suggestions include partial name matches
and files in nearby project folders. Use ↑/↓ to choose a suggestion and Tab to
complete it. The first run trains a baseline; subsequent runs monitor against
that baseline. Use `--plain` for a text-only report or `--json` for
machine-readable output.

### Train a baseline

```sh
sysdag --id <name> train <source-file> [target-args...]
```

### Monitor against a baseline

```sh
sysdag --id <name> monitor <source-file> [target-args...]
```

### Auto-detect mode (train if no baseline, else monitor)

```sh
sysdag --id <name> run <source-file> [target-args...]
```

### Shorthand (defaults to `run`)

```sh
sysdag --id <name> <source-file> [target-args...]
```

### Examples

```sh
sysdag --id file-reader train examples/clean_file_reader.c
sysdag --id file-reader monitor examples/anomaly_file_exfil.c
```

### Inspect a graph or its score breakdown

```sh
sysdag viz .sysdag/runs/<run-id>/graphs/w0000/graph.json
sysdag explain --baseline .sysdag/baselines/<name>.json \
  --graph .sysdag/runs/<run-id>/graphs/w0000/graph.json
```

Artifacts are written below `.sysdag/`: baselines, manifests, event streams,
graphs, decisions, and private path maps when redaction is enabled.

## Browser graph visualizer

When you run `sysdag` in TUI mode and select a graph window, pressing `b` (or
the equivalent action) opens the interactive browser visualizer. It provides:

- **Suspicious node detection** — NET_SOCKET, NET_SEND, SHELL, DECOY,
  SYSTEM_CONFIG, and FILE_WRITE nodes are highlighted in red with pulsing glow
  and risk markers, matching the TUI's red highlighting.
- **Edge typing** — FD flow, buffer flow, process flow, SCM rights, and pipe
  flow edges are color-coded. Buffer flow edges (potential data exfiltration)
  are highlighted in red.
- **Layouts** — hierarchy (default), force-directed, and radial.
- **Inspector panel** — click any node to see its fields, risk reasons,
  outgoing/incoming relationships.
- **Search** — filter nodes by operation, path, or ID.
- **Legend and filters** — toggle node categories and relationship types.
- **SVG export** — download the current view as an SVG file.
- **Minimap** — overview panel for navigation.

## Evaluation workflow

Import a corpus of traces you provide, calibrate only from clean training runs,
then evaluate the frozen baseline on the test partition:

```sh
sysdag dataset import /path/to/corpus --id my-corpus
sysdag calibrate --dataset my-corpus
sysdag evaluate --dataset my-corpus \
  --baseline .sysdag/baselines/dataset-my-corpus.json
sysdag measure --dataset my-corpus \
  --baseline .sysdag/baselines/dataset-my-corpus.json
sysdag evaluate-ngram --dataset my-corpus
```

`ablate --dataset <id> --grid <grid.toml>` runs configured representation and
window comparisons.

## Live monitoring

`monitor-live` scores a completed window as soon as enough events arrive. It
accepts JSONL events or stateful strace lines from a file, FIFO, or TCP source:

```sh
sysdag monitor-live --format strace --input /tmp/sysdag.strace \
  --baseline .sysdag/baselines/<name>.json

sysdag monitor-live --format jsonl --input tcp://127.0.0.1:9000 \
  --baseline .sysdag/baselines/<name>.json
```

## Native eBPF collection (Linux/WSL2)

The repository includes a raw-syscall eBPF program and Aya loader. Build the
object, collect its ring-buffer relay, then monitor or evaluate its JSONL:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c ebpf/sysdag.bpf.c -o ebpf/sysdag.bpf.o
cargo build --release

sudo target/release/sysdag collect-ebpf --object ebpf/sysdag.bpf.o \
  --output /tmp/sysdag.ebpf.jsonl --duration-secs 30
target/release/sysdag monitor-ebpf --input /tmp/sysdag.ebpf.jsonl \
  --baseline .sysdag/baselines/<name>.json
```

Native attachment requires a BPF-capable kernel, Clang BPF toolchain, and
`CAP_BPF` plus `CAP_PERFMON` (normally `sudo`). Run the overhead comparison
before making low-overhead claims:

```sh
SYSDAG_BIN=target/release/sysdag scripts/measure_capture_overhead.sh \
  ebpf/sysdag.bpf.o -- /path/to/workload arg1
```

Detailed instructions: [docs/EBPF_BUILD_AND_MEASURE.md](docs/EBPF_BUILD_AND_MEASURE.md)
and [docs/EBPF_RELAY_PROTOCOL.md](docs/EBPF_RELAY_PROTOCOL.md).

## Command reference

| Command | Description |
|---------|-------------|
| `sysdag` | Open interactive TUI |
| `sysdag run <file>` | Auto-train or monitor a target |
| `sysdag train <file>` | Force baseline training |
| `sysdag monitor <file>` | Score against existing baseline |
| `sysdag doctor` | Check prerequisites (Docker, guest image) |
| `sysdag viz <graph.json>` | Print Graphviz DOT for a saved graph |
| `sysdag explain --baseline <b> --graph <g>` | Score breakdown for a graph |
| `sysdag verify <run-dir>` | Verify run manifest and checksums |
| `sysdag monitor-live --input <src> --baseline <b>` | Live scoring from FIFO/TCP/JSONL |
| `sysdag monitor-ebpf --input <src> --baseline <b>` | Live scoring from eBPF relay |
| `sysdag collect-ebpf --object <o> --output <f>` | Attach eBPF collector |
| `sysdag dataset import <dir> --id <name>` | Import trace corpus |
| `sysdag calibrate --dataset <id>` | Calibrate thresholds from clean data |
| `sysdag evaluate --dataset <id> --baseline <b>` | Full evaluation suite |
| `sysdag ablate --dataset <id> --grid <toml>` | Representation/window ablations |
| `sysdag evaluate-ngram --dataset <id>` | 1/2/3-gram baseline evaluation |

### Global flags

| Flag | Description |
|------|-------------|
| `--id <name>` | Baseline identity (required for train/monitor/run) |
| `--plain` | Skip TUI, print plain text report |
| `--json` | Output as JSON |
| `--config <path>` | Custom config file |
| `--workdir <path>` | Working directory (default: `.sysdag`) |
| `--allow-mismatch` | Skip baseline compatibility checks |

## Safety and privacy

The program-execution path runs in a loopback-only guest. No training data or
attack samples are bundled. Configure path redaction before exporting artifacts;
the local token-to-path map is kept separate from exported events and graphs.

## Project map

```text
src/          Core implementation (parser, graph, detector, experiments, TUI, streaming)
tools/        Browser graph visualizer (viewer.html + d3.min.js)
ebpf/         Raw-syscall BPF program (sysdag.bpf.c)
tests/        Unit and acceptance tests using synthetic traces
examples/     Sample C, Python, and shell programs for train/monitor
docs/         Architecture, pipeline flow, features, and eBPF documentation
configs/      Default configuration (default.toml)
scripts/      Overhead measurement harness
```
