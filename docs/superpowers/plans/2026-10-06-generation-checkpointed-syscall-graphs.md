# Generation-Checkpointed Syscall Graphs Implementation Plan

> **For implementation:** Work through the numbered tasks in order. The checkboxes are acceptance gates. This document is a plan; it contains no implementation code.

**Goal:** Add an opt-in Linux eBPF mode that can certify a limited set of file-descriptor relationships across dropped detailed events, while preserving all existing SysDAG behavior by default.

**Architecture:** A new native collector mode updates compact descriptor-generation state independently of publishing detailed events to the ring buffer. A versioned relay carries event ordinals, descriptor versions, loss records, and state checkpoints. A pure Rust verifier produces a sidecar certificate for a relationship only when process identity, descriptor identity, state health, and stream ordering are all established. Existing graph construction, WL fingerprints, baseline files, detector decisions, TUI, browser viewer, strace capture, and version-1 eBPF relay continue unchanged.

**Tech stack:** Rust 2021, serde JSONL, aya 0.14, Linux eBPF C, existing cargo integration tests. Native certification targets Linux x86_64 first; other platforms retain the current behavior.

**Spec:** This document, especially “Meaning of a certificate,” “Safety invariants,” and “Protocol contract” below. It implements the invention candidate discussed with the user on 2026-10-06.

## Meaning of a certificate

A certificate establishes one narrow fact: two observed syscalls used the same file-descriptor binding within one process incarnation, or that an observed descriptor use refers to a specifically observed allocation. It does **not** prove byte-level data flow, maliciousness, or that no other syscalls occurred. A certificate may be attached to graph evidence; the existing anomaly score and decision remain authoritative and unchanged. No relationship is certified when its required information is absent or ambiguous.

For version 1 of this feature, certify only single-process, single-thread, successful `open`, `openat`, `socket`, `accept`, `accept4`, `close`, `dup`, `dup2`, `dup3`, `read`, `write`, `sendto`, and `recvfrom` cases whose descriptor semantics the native collector can establish. Use a positive syscall allowlist: any operation whose effects are not explicitly modeled as safe invalidates certification for the affected process, including unknown syscall numbers. This covers, for example, `fcntl` duplication, `close_range`, `openat2`, `pipe`, `pipe2`, `socketpair`, `recvmsg` descriptor passing, `pidfd_getfd`, `fork`, `clone`, `vfork`, `exec`, and `io_uring` descriptor operations. Certification resumes only after a fresh observed allocation establishes a new binding and no invalidating operation intervenes. If the kernel cannot reliably identify process reincarnation or detect such invalidating operations, native certification remains unavailable on that host. Existing tracing continues.

## Safety invariants

1. A dropped detailed event must never create a positive certificate by itself. Unknown state produces `UNRESOLVED` with a reason.
2. A descriptor generation increments for every successful binding replacement or removal, including close then reuse and `dup2` replacement. Counter wrap, map eviction, failed map update, verifier disagreement, and ambiguous ordering invalidate the affected state.
3. A process identifier alone is insufficient; certification requires a kernel-established process-incarnation identifier. Thread sharing, fork inheritance, and exec transitions are unresolved in the first version.
4. A global drop count cannot localize a gap. The version-2 event carries a kernel-side per-thread ordinal assigned before ring-buffer publication; gaps between observed ordinals localize loss. A checkpoint from a separate map confirms state health. If a checkpoint cannot be ordered against the relevant events, certification is unresolved.
5. Certificates refer to existing event sequence IDs and descriptor binding generations. No raw paths, user buffers, or private syscall arguments are copied into certificates.
6. Legacy event JSON, graph digests, WL features, baseline checksums, and `DecisionRecord.decision` must remain byte-for-byte equivalent when certification is disabled. Certification is never inferred for imported, strace, version-1 relay, or historical traces.
7. If the version-2 collector and consumer disagree on protocol version or kernel object layout, stop certification with a clear error; do not reinterpret records as version 1.

## Protocol contract

Keep the existing `event` and `lost` JSONL envelopes unchanged. Add version-2 envelopes only when the new collector option is selected. A version-2 stream starts with a header identifying protocol version 2, collector build and kernel capability state. Each version-2 event contains the unmodified `TraceEvent` plus separate proof metadata: process-incarnation ID, kernel per-thread ordinal, referenced descriptor number and generation, and state-valid flag. Checkpoint envelopes carry per-process high-water ordinals, relevant descriptor generations, invalidation flags, and a monotonically increasing checkpoint ID. The consumer rejects missing header, mixed versions, duplicate or decreasing ordinals, checkpoint regressions, and unsupported metadata rather than issuing a certificate. The old relay consumer must never be silently fed a version-2 stream.

## File ownership and compatibility map

| Area | Planned files | Responsibility |
| --- | --- | --- |
| Kernel capture | New `ebpf/sysdag_cert.bpf.c`; retain `ebpf/sysdag.bpf.c` | Isolate version-2 instrumentation so the working collector is not replaced. |
| Native relay | `src/ebpf_native.rs`, `src/main.rs` | Open version-2 maps, drain events, take ordered checkpoints, emit version-2 JSONL. Preserve version-1 path. |
| Wire format | New `src/loss_cert_protocol.rs`, `src/lib.rs`, `docs/EBPF_RELAY_PROTOCOL.md` | Parse, validate and version proof envelopes without changing `TraceEvent`. |
| Pure verifier | New `src/loss_cert.rs` | Maintain bounded proof state and produce `CERTIFIED`, `UNRESOLVED`, or `NOT_APPLICABLE` records. |
| Window integration | `src/streaming.rs`, `src/main.rs` | Associate proof metadata with the same events and closed windows as graph output; do not change graph encoding. |
| Reporting | `src/main.rs`, `docs/EBPF_BUILD_AND_MEASURE.md`, README | Opt-in sidecar certificate output and truthful limitations. |
| Acceptance evidence | New `tests/loss_cert_protocol.rs`, `tests/loss_cert_verifier.rs`, `tests/loss_cert_stream.rs`; Linux capture fixture and benchmark instructions | Reproducible safety, compatibility and overhead evidence. |

## Review focus

- Descriptor closes and reopens to the same numeric FD during a gap: no false same-binding certificate.
- PID/TID reuse, fork, threads and exec: no certificate crosses an unproven process incarnation or shared FD table.
- Missing or reordered checkpoints and ring-buffer losses: `UNRESOLVED`, never a positive certificate.
- Legacy strace, default eBPF and saved baseline artifacts: exact legacy decisions and fingerprints remain unchanged.
- Kernel map exhaustion, unsupported syscalls, verifier failure, and source shutdown: certification fails closed while ordinary monitoring remains usable.

---

### Task 1: Freeze the current contract and establish the feasibility gate

**Files:** Read `src/ebpf_native.rs`, `ebpf/sysdag.bpf.c`, `src/streaming.rs`, `src/graph.rs`, `src/detector.rs`, `src/main.rs`; add focused fixture descriptions to `tests/loss_cert_stream.rs` during implementation.

**Interface produced:** A documented capability check with a binary result, `AVAILABLE` or `UNAVAILABLE(reason)`, for version-2 certification. Version-1 capture does not depend on it.

- [ ] Record exact output fixtures for default `collect-ebpf`, `monitor-ebpf`, strace monitoring, graph digest, WL fingerprint, baseline checksum and decision JSON before changing any implementation.
- [ ] Confirm on the target Linux kernel that eBPF can establish process incarnation, maintain per-descriptor state independently of ring publication, and expose map update/overflow failures; record minimum kernel and privilege requirements rather than assuming them.
- [ ] Define the positive syscall-number allowlist for Linux x86_64. Every other syscall, including an unknown number or unsupported architecture, must invalidate certification rather than be assumed harmless. Check descriptor allocation, duplication, close, process creation and `io_uring` against the list.
- [ ] Specify how event and checkpoint ordering is established. If no reliable ordering is implementable, narrow the certificate to same-event facts and do not claim across-gap certification.
- [ ] Gate: if any of these properties cannot be shown on a real kernel, stop after a working `UNAVAILABLE` capability path and revise the invention disclosure before proceeding.

### Task 2: Define and validate the version-2 relay format

**Files:** Create `src/loss_cert_protocol.rs`; modify `src/lib.rs`, `docs/EBPF_RELAY_PROTOCOL.md`; create `tests/loss_cert_protocol.rs`.

**Interface produced:** `LossCertEnvelopeV2` with header, event, checkpoint and loss variants; a parser that returns either a validated envelope or a typed protocol error. The embedded event remains a normal `TraceEvent`.

- [ ] Write parser tests for a valid stream, version-1 compatibility, mixed versions, missing header, duplicate ordinals, decreasing checkpoint IDs, zero loss count, malformed metadata, and unknown fields. Expected result: malformed proof data never reaches the verifier.
- [ ] Define the JSON fields and integer ranges in the protocol document, including the exact meaning of `process_incarnation`, `kernel_ordinal`, `fd_generation`, `state_valid`, checkpoint high-water mark and invalidation reason.
- [ ] Implement the parser and serializer without changing existing `EbpfEnvelope::Event` and `EbpfEnvelope::Lost` encoding.
- [ ] Run the protocol tests and existing eBPF relay parser tests. Gate: all old fixture encodings remain identical.

### Task 3: Implement a pure, fail-closed certificate verifier

**Files:** Create `src/loss_cert.rs`; create `tests/loss_cert_verifier.rs`.

**Interface produced:** `LossCertVerifier` consumes validated version-2 envelopes in order and returns a `CertificateRecord` containing status, event IDs, process-incarnation ID, descriptor generation, relevant checkpoint IDs, and a reason. An explicit capacity limit bounds retained state.

- [ ] Write table-driven tests for no loss, unrelated lost events, close/reopen reuse, `dup2` replacement, failed allocation, unsupported mutation, fork/exec/thread sharing, PID reuse, map failure, checkpoint regression, ordinal gap, counter wrap and state eviction. Positive cases must establish only descriptor-binding identity; all ambiguity cases must return `UNRESOLVED`.
- [ ] Define the verifier's state transition table and invariant for every supported descriptor operation. Keep ring-buffer transport loss separate from kernel-state invalidation.
- [ ] Implement the verifier as a pure Rust unit that needs no Linux kernel, baseline or UI. Its state must be bounded and eviction must invalidate certificates involving evicted state.
- [ ] Add a second verifier that reads a saved certificate and its cited version-2 envelopes and independently checks every cited fact. Gate: changing one cited generation, ordinal or checkpoint makes verification fail.
- [ ] Run verifier tests, including randomized small event sequences compared against a simple exhaustive reference model. Gate: no false `CERTIFIED` result in the test corpus.

### Task 4: Add independent kernel-side generation tracking

**Files:** Create `ebpf/sysdag_cert.bpf.c`; update `docs/EBPF_BUILD_AND_MEASURE.md`.

**Interface consumed:** The version-2 wire fields and verifier invariants from Tasks 2–3.

- [ ] Add a kernel-side per-process incarnation and per-thread ordinal that are assigned before attempting ring-buffer publication; prove PID reuse cannot preserve an old incarnation. If the host lacks the required hook or BTF capability, return `UNAVAILABLE`.
- [ ] Add a bounded per-descriptor map keyed by process incarnation and FD. Increment generations on all supported successful binding operations. Mark affected state invalid on every non-allowlisted operation, map update failure, ambiguous thread/child relationship, or counter overflow. Apply invalidation before attempting to publish that syscall's detailed event.
- [ ] Put the current descriptor generation and kernel ordinal into each detailed event. Preserve the independently readable state and high-water counters even when event ring reservation fails.
- [ ] Add kernel-level fault counters for missed enter/exit correlation and state update errors. Explicitly clean up task and descriptor entries; a cleanup failure invalidates the incarnation.
- [ ] Build and load this object on the target Linux x86_64 kernel; inspect verifier and attach diagnostics. Gate: the legacy object and default collector still build and attach independently.

### Task 5: Add a separate native version-2 collection path

**Files:** Modify `src/ebpf_native.rs`, `src/main.rs`; add Linux-only capture fixtures.

**Interface produced:** An opt-in `collect-ebpf` version-2 mode that emits a header, event/loss records and ordered checkpoints; the existing command without the option emits only its current version-1 records.

- [ ] Write host-side decoding tests that compare C record size, alignment, field order and version against Rust. Reject mismatch before collection begins.
- [ ] Open the version-2 maps without disturbing the version-1 loader. Define an ordered drain/checkpoint boundary and emit any final loss and checkpoint at shutdown.
- [ ] On map read failure, checkpoint inconsistency or unsupported kernel capability, stop version-2 certification with a diagnostic; do not convert the failure to “zero losses.”
- [ ] Force ring-buffer pressure on Linux and confirm that detailed records disappear while kernel ordinals and descriptor generations continue advancing. Gate: the version-1 command and its JSONL fixture remain unchanged.

### Task 6: Associate proof records with graph windows without changing fingerprints

**Files:** Modify `src/streaming.rs`, `src/main.rs`; create `tests/loss_cert_stream.rs`.

**Interface produced:** An additive window-emission method that returns the existing encoded graph together with its original event sequence IDs. Existing `WindowBuilder::push` and all existing callers retain their behavior.

- [ ] Write tests for overlapping windows, capacity eviction, two interleaved processes, a loss just before a window boundary, and a checkpoint just after it. Each certificate must cite only records valid for that window.
- [ ] Add the new emission method and a bounded sidecar lookup keyed by event sequence ID. Keep proof metadata out of `GraphRecord`, `GraphEdge`, node labels, WL features and baseline training input.
- [ ] When proof data is absent or too old, return `NOT_APPLICABLE` or `UNRESOLVED`; do not manufacture graph edges.
- [ ] Compare graph digests, fingerprints and detector decisions against Task 1 fixtures for the same events. Gate: they match exactly with certification off and with certification on.

### Task 7: Expose opt-in certificates without changing anomaly decisions

**Files:** Modify `src/main.rs`; update `README.md` and `docs/EBPF_RELAY_PROTOCOL.md`; extend `tests/loss_cert_stream.rs`.

**Interface produced:** `monitor-ebpf` accepts a version-2 stream only with the new opt-in option. Each emitted decision JSON gains a separate `certification` object; `decision`, `score`, and `evidence` retain their existing meanings. Version-1 output is unchanged.

- [ ] Test version-2 opt-in, version-2 without opt-in, version-1 with opt-in, corrupted proof data, unsupported Linux host, and stream ending mid-checkpoint. Version mismatch is an explicit error; uncertain evidence never appears as certified.
- [ ] Keep `ANOMALOUS`/`REVIEW`/`NORMAL` unchanged. The certificate is evidence about descriptor identity, not a new threat verdict or an override of `DEGRADED_CAPTURE`.
- [ ] Document the certificate fields and show one positive and one unresolved example. Explicitly state that raw eBPF syscalls currently lack path labels and cannot prove exfiltration or buffer flow.
- [ ] Gate: existing TUI/browser graph rendering and baseline loading require no changes and produce their old outputs.

### Task 8: Complete regression, fault-injection and measurement gates

**Files:** Add Linux acceptance fixtures under `tests/`; update `docs/EBPF_BUILD_AND_MEASURE.md` with the measured method and results after running it.

- [ ] Run formatting, static checks, all Rust unit/integration tests, release build, and the separate version-1 and version-2 BPF builds on their supported platforms. Record exact toolchain, kernel, architecture and object versions.
- [ ] Run Linux scenarios covering `open`→drop→`write`, `open`→dropped `close`/reopen→`write`, `dup2`, fork, exec, thread creation, process exit/reuse, map saturation and bursty ring loss. For each, compare certificates with a complete ground-truth trace.
- [ ] Demonstrate zero false positive certificates in the defined acceptance scenarios. If any false positive occurs, block release; do not weaken the expected result.
- [ ] Measure throughput, CPU, peak resident memory, ring loss, and added syscall latency on identical workloads for no collector, legacy eBPF and version-2 eBPF. Report raw results and variance; do not claim “low overhead” from a single run.
- [ ] Verify that default CLI output, saved run/baseline artifacts, version-1 JSONL, macOS/Docker flows, n-gram evaluation and degraded-capture decisions still match Task 1 fixtures.
- [ ] Perform an independent review of the certificate's exact claim, unsupported-operation list, failure behavior and threat model. Ship only if the review can explain why a dropped event cannot invalidate a positive certificate.

## Delivery order and stop conditions

Tasks 1–3 establish a testable proof model without kernel privileges. Task 4 is the decisive feasibility gate: if kernel identity or state reliability is unavailable, stop rather than represent a simulation as a deployed guarantee. Tasks 5–7 integrate the mechanism behind an explicit opt-in. Task 8 produces the evidence needed for a technical disclosure. A course demonstration may use synthetic fault injection, but the patent disclosure must clearly distinguish that demonstration from verified native Linux behavior.

No patentability or performance claim follows automatically from implementing this plan. Before filing, have the final mechanism and any earlier public disclosure reviewed against prior art; do not publish the new design or results before that review if filing options matter.
