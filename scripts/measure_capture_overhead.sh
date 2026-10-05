#!/usr/bin/env bash
# Compare one identical workload under no tracing, strace, and SysDAG eBPF.
# Usage: scripts/measure_capture_overhead.sh /path/to/sysdag.bpf.o -- command args...
set -euo pipefail

if [[ $# -lt 3 || "$2" != "--" ]]; then
  echo "usage: $0 BPF_OBJECT -- COMMAND [ARG...]" >&2
  exit 64
fi

object=$1
shift 2
sysdag_bin=${SYSDAG_BIN:-sysdag}
strace_bin=${STRACE_BIN:-strace}
out_dir=${SYSDAG_BENCH_OUT:-"./sysdag-capture-bench-$(date +%s)"}
mkdir -p "$out_dir"

elapsed_ns() {
  local start end
  start=$(date +%s%N)
  "$@"
  end=$(date +%s%N)
  echo $((end - start))
}

none=$(elapsed_ns "$@")
strace=$(elapsed_ns "$strace_bin" -f -qq -o "$out_dir/strace.log" "$@")

# The collector is intentionally started before the workload. Its ring-buffer
# relay is retained as an evaluation input and is stopped immediately after the
# workload. CAP_BPF/CAP_PERFMON (normally sudo) is required for this command.
sudo "$sysdag_bin" collect-ebpf --object "$object" --output "$out_dir/ebpf.jsonl" --duration-secs 3600 &
collector_pid=$!
trap 'kill "$collector_pid" 2>/dev/null || true' EXIT
sleep 0.2
start=$(date +%s%N)
"$@"
end=$(date +%s%N)
ebpf=$((end - start))
kill "$collector_pid" 2>/dev/null || true
wait "$collector_pid" 2>/dev/null || true
trap - EXIT

printf '{"schema":"sysdag.capture-overhead.v1","no_trace_ns":%s,"strace_ns":%s,"ebpf_ns":%s,"strace_log":"%s","ebpf_log":"%s"}\n' \
  "$none" "$strace" "$ebpf" "$out_dir/strace.log" "$out_dir/ebpf.jsonl" > "$out_dir/report.json"
echo "wrote $out_dir/report.json"
