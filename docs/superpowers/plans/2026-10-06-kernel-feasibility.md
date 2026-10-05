# Native loss certification feasibility, 2026-10-06

## Result

`UNAVAILABLE(target_kernel_not_verified)` for the planned Linux x86_64 version-2 collector on this workspace. The native host is macOS arm64. Docker uses an OrbStack Linux 7.0.14 arm64 kernel. Running an amd64 image changes the container's reported userspace architecture to x86_64 through emulation; it does not provide an x86_64 kernel or x86_64 syscall tracepoints. No native x86_64 load, attachment, verifier, or fault-injection result can be inferred from that container.

The arm64 guest exposes `/sys/kernel/btf/vmlinux` and both `raw_syscalls` tracepoint IDs from a privileged arm64 container. Homebrew LLVM 21.1.3 can compile BPF objects, and the unchanged legacy `ebpf/sysdag.bpf.c` compiled successfully with that toolchain. Apple Clang 21.0.0 does not include a BPF target. These checks establish a plausible *arm64* development environment, not the x86_64 acceptance gate in the plan. The eBPF verifier has not loaded a version-2 object, and no native event/checkpoint ordering has been demonstrated.

## Required kernel contract before a version-2 ABI exists

1. Obtain a kernel-backed process incarnation that changes across PID reuse. A task-local-storage identifier allocated from a monotonic kernel counter is one candidate, but its allocation, counter overflow, and storage failures must all invalidate certification. A PID/TID or timestamp alone is insufficient. The collector must reject a thread group with multiple threads and inherited or shared FD tables until those relationships are modeled.
2. Use a bounded, non-evicting FD map keyed by incarnation and descriptor. Successful allocation, replacement, and removal must advance a generation before ring publication. Failed updates, missed enter/exit correlation, map saturation, generation wrap, and task cleanup failure must invalidate the relevant incarnation or a global health epoch. A failed map insertion cannot be represented as a healthy absent FD.
3. Classify every syscall number with a positive architecture-specific allowlist. Every number outside it invalidates certification before its event could be published. In particular, descriptor passing, `fcntl`, `close_range`, process creation, `exec`, and `io_uring` cannot be treated as harmless. Arm64 and x86_64 syscall numbers differ; an amd64 container on the arm64 guest cannot validate an x86_64 table.
4. Assign the per-thread ordinal before any ring reservation. Store high-water ordinals and generation state in independently readable maps. A missing ring record may then be detected as an ordinal gap, but a global drop count cannot locate the missing syscall.
5. Establish a checkpoint boundary that orders the map snapshot with both cited events. Draining a ring buffer and then reading maps does not alone make an atomic boundary: a concurrent syscall can advance maps before its ring record is visible. Until a boundary or a stricter verifier rule is demonstrated on a real kernel, cross-gap certificates remain unavailable.
6. Compare the C object record size, alignment, offsets, map types, and protocol version with the Rust decoder before loading. No version-2 C ABI is frozen while the collector is unavailable.

## Next native gate

On a real Linux x86_64 host with BTF, raw syscall tracepoints, a BPF-capable Clang, and sufficient BPF/tracing privileges, first implement and load a minimal task-incarnation and checkpoint probe. Prove that PID reuse, multi-threading, ring loss, map saturation, and unsupported syscalls all fail closed. Only then freeze the ABI and implement the complete `ebpf/sysdag_cert.bpf.c` collector. The default version-1 collector remains independent of this gate.
