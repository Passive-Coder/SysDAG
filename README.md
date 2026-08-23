# SysDAG

**Show the causal shape of a process.**

SysDAG traces a program inside a disposable Linux guest, turns its syscalls into a typed dependency graph, fingerprints that graph, and tells you whether the run still looks like the clean baseline.

On a terminal it is a full-screen app: a landing screen, then a viewer with the score, the DAG, the events, and why it decided `NORMAL`, `REVIEW`, or `ANOMALOUS`.

```bash
sysdag              # landing
sysdag test.c       # train the first run
sysdag test.c attack
```

---

## What you need

| | macOS | Linux |
|---|---|---|
| **Rust** | [rustup](https://rustup.rs) (stable) | [rustup](https://rustup.rs) (stable) |
| **Docker** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Docker Engine (`docker` on your `PATH`) |
| **Why Docker?** | Programs run in an Alpine guest (256 MiB, loopback only). macOS cannot `strace` them natively. | Same guest, so traces match across machines. |

You can still **score a recorded strace log** without Docker.

`~/.cargo/bin` must be on your `PATH` (rustup does this by default).

---

## Download and install

### 1. Install Rust

**macOS and Linux**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
```

On macOS, if the installer asks for a compiler, install the Xcode command-line tools when prompted:

```bash
xcode-select --install
```

### 2. Install Docker

**macOS** — install [Docker Desktop](https://www.docker.com/products/docker-desktop/), open it, and wait until it says Docker is running.

**Linux** (Debian / Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y docker.io
sudo usermod -aG docker "$USER"
# log out and back in so the group applies
docker info
```

Other distros: install the engine from your package manager or [Docker’s docs](https://docs.docker.com/engine/install/), then confirm `docker info` works without errors.

### 3. Install SysDAG from GitHub

This builds the `sysdag` binary and puts it in `~/.cargo/bin`:

```bash
cargo install --git https://github.com/Passive-Coder/SysDAG.git --locked
```

Or clone and install from a local checkout (same result, easier if you want `test.c` and the examples next to you):

```bash
git clone https://github.com/Passive-Coder/SysDAG.git
cd SysDAG
cargo install --path . --locked
```

The first program you trace will build the guest image `sysdag-microvm:1.0` (once).

### 4. Check the host

```bash
sysdag doctor
```

You should see your OS and a Docker version. If Docker is missing, you can still open the app and analyze `.strace` files; running `.c` / `.py` / `.sh` / ELF programs needs the guest.

---

## Use it

```bash
sysdag
```

On a TTY that opens the landing. Type a path and press enter, `d` for the bundled demo, `?` for commands, `q` to quit.

```bash
# sample in this repo — first run trains, second compares
sysdag test.c
sysdag test.c attack

# explicit modes
sysdag train test.c
sysdag monitor test.c attack

# recorded traces (no Docker)
sysdag train tests/fixtures/clean.strace
sysdag monitor tests/fixtures/attack.strace

# text instead of the viewer
sysdag --plain test.c attack
sysdag --help
```

`<file>` can be C, Python, or shell (compiled or interpreted in the guest), a Linux ELF, or an strace log (or a directory of `strace -ff` files).

Artifacts go in `.sysdag/` (baselines, traces, JSON graphs, DOT).

`--plain` / `--json` (or a non-TTY) skip the app and print a report.

### Landing

| key | action |
|---|---|
| path + enter | run |
| `d` | clean vs decoy demo |
| `?` | commands |
| `q` | quit |

### Viewer

| key | action |
|---|---|
| `tab` / `1`–`4` | overview / graph / events / inspect |
| `j` `k` | move |
| `[` `]` | window |
| `q` | quit |

---

## How it decides

1. Capture completed file, descriptor, network, and process syscalls with `strace` in the guest.
2. Build a DAG: FD generations, last-event chains, buffer flow, external anchors.
3. Slice a sliding window (default W=100, overlap=20).
4. Fingerprint each window with 3-round directed, edge-typed Weisfeiler–Lehman + SHA-256.
5. Score against the baseline: exact match, weighted Jaccard, size, and risk motifs.

Verdicts are `NORMAL`, `REVIEW`, or `ANOMALOUS`. An unseen hash is evidence, not proof. Alerts point at window node IDs and source sequence numbers.

---

## Safety

The guest has **no external network** (`--network=none`). The demo reads only a **harmless decoy** created for the experiment, never real credentials.

---

## Repository

```text
src/           CLI, parser, DAG, WL, detector, TUI, micro-VM runner
examples/      bundled demo workload
guest/         Alpine Dockerfile
tests/         golden traces and pipeline tests
configs/       window / WL / score weights
test.c         small clean-vs-attack sample
```

MIT licensed. Issues and clones: [github.com/Passive-Coder/SysDAG](https://github.com/Passive-Coder/SysDAG).
