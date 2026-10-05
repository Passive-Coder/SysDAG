# SysDAG Documentation

| File | Description |
|------|-------------|
| `flow.md` | End-to-end pipeline flow (trace → graph → fingerprint → decision) |
| `architecture.md` | Module responsibilities, data models, and algorithm overview |
| `features.md` | User-facing feature list and quickstart commands |
| `EBPF_BUILD_AND_MEASURE.md` | How to build, load, and measure the eBPF collector |
| `EBPF_RELAY_PROTOCOL.md` | JSONL envelope spec for the eBPF ring-buffer relay |

## Repository layout

```text
src/          Core implementation (parser, graph, detector, experiments, TUI, streaming)
tools/        Browser graph visualizer (viewer.html + d3.min.js)
ebpf/         Raw-syscall BPF program (sysdag.bpf.c)
tests/        Unit and acceptance tests using synthetic traces
examples/     Sample C, Python, and shell programs for train/monitor
docs/         This documentation
configs/      Default configuration (default.toml)
scripts/      Overhead measurement harness
```
