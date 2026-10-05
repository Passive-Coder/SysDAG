# Native eBPF build and measurement

The kernel collector uses aya for loading and attachment, and the source program
is [sysdag.bpf.c](../ebpf/sysdag.bpf.c). Build the object on an x86_64 Linux
host with a BPF-capable Clang toolchain:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c ebpf/sysdag.bpf.c -o ebpf/sysdag.bpf.o
cargo build --release
```

Collect for a bounded duration (this needs `CAP_BPF` and `CAP_PERFMON`, usually
through `sudo`):

```sh
sudo target/release/sysdag collect-ebpf \
  --object ebpf/sysdag.bpf.o --output /tmp/sysdag.ebpf.jsonl --duration-secs 30
```

`/tmp/sysdag.ebpf.jsonl` can be streamed to `monitor-ebpf`, imported into a
dataset, and evaluated with the normal Phase 3 commands. Loss envelopes from
the kernel map are preserved in the JSONL output.

To generate an overhead result for one identical workload:

```sh
SYSDAG_BIN=target/release/sysdag scripts/measure_capture_overhead.sh \
  ebpf/sysdag.bpf.o -- /path/to/workload arg1
```

This writes an immutable input record (`report.json`) plus both raw trace
artifacts. Only publish the low-overhead claim after the generated eBPF dataset
has passed the measurement/evaluation gates.
