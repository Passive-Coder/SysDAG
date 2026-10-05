# eBPF relay protocol

`sysdag monitor-ebpf` consumes a UTF-8 JSONL stream from a file, FIFO, or
`tcp://host:port`. A Linux eBPF ring-buffer relay must write exactly one of
these envelopes per line:

```json
{"kind":"event","event": {"schema_version":"1.0", "process": {"pid":123,"tid":123}, "seq":1, "enter_ns":0, "exit_ns":0, "syscall":{"nr":0,"name":"read","arch":"x86_64"}, "args":{}, "ret":1, "errno":null, "labels":{"family":"file","op":"FILE_READ","result":"SUCCESS","resource_kind":"FILE","flags":"NONE","bytes":"TINY","path_class":"APP"}, "capture":{"source":"ebpf"}}}
```

```json
{"kind":"lost","count":17}
```

Loss envelopes are mandatory whenever the ring buffer reports dropped records.
They are applied to the next closed graph window and can cap an alert at
`REVIEW` through the existing degraded-capture policy.

Run from Linux/WSL2 after training a compatible baseline:

```sh
sysdag monitor-ebpf --input /run/sysdag-ebpf.jsonl --baseline .sysdag/baselines/TARGET.json
```

The current implementation is a relay consumer. It does not attach an eBPF
program by itself; that loader remains the Phase 7 prerequisite before claiming
native eBPF collection or low overhead.

## Version 2 proof stream (opt-in)

Version 2 is a separate JSONL format for descriptor-binding certification. It
begins with exactly one header, followed by any number of `event`, `lost`, and
`checkpoint` records. The version-1 `event` and `lost` encodings above remain
unchanged. A version-2 event has an additional `proof` object; it must not be
passed to the version-1 consumer. `TraceEvent` inside `event` retains its
existing schema and meaning. In particular, `event.seq` is the ordinary relay
event ID, while `proof.kernel_ordinal` is assigned by the kernel before ring
publication. They are distinct counters.

The format and pure verifier are currently a synthetic proof model. No native
version-2 collector has passed the required x86_64 kernel checks, and the CLI
will return `UNAVAILABLE(...)` if native certification is requested. The
verifier accepts `synthetic-test` as its only producer identity; its positive
result is conditional on the supplied proof stream, not evidence that a real
kernel collector upheld these fields.

```json
{"kind":"header","protocol_version":2,"collector_build":"synthetic-test","capability":"available"}
{"kind":"event","event":{"schema_version":"1.0","process":{"pid":123,"tid":123},"seq":1,"enter_ns":10,"exit_ns":20,"syscall":{"nr":0,"name":"read","arch":"x86_64"},"args":{"fd":3},"ret":12,"errno":null,"labels":{"family":"file","op":"FILE_READ","result":"SUCCESS","resource_kind":"FILE","flags":"NONE","bytes":"TINY","path_class":"APP"},"capture":{"source":"ebpf"}},"proof":{"process_incarnation":42,"kernel_ordinal":7,"fd":3,"fd_generation":5,"state_valid":true}}
{"kind":"lost","count":2}
{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[{"tid":123,"kernel_ordinal":9}],"descriptors":[{"fd":3,"generation":5,"state_valid":true}]}]}
```

All integers are JSON integers, not strings or floating-point numbers. Unsigned
fields fit in `u64`; `protocol_version` fits in `u8`. The parser enforces these
ranges and the additional constraints below:

| Field | Meaning and valid range |
| --- | --- |
| `protocol_version` | Exactly `2`. Any other version is an error. |
| `collector_build` | Nonempty identifier of the native collector and object layout. A consumer must additionally check its supported layout before certifying. |
| `capability` | `available` or `unavailable`, the collector's kernel capability state. An `unavailable` stream cannot contain proof events or checkpoints. |
| `process_incarnation` | Positive `u64` kernel-established identity for a process lifetime. PID alone is insufficient. Zero means unknown and is rejected. |
| `kernel_ordinal` in `proof` | Positive `u64` per-thread syscall ordinal, assigned before detailed-event ring publication. It increases strictly for each `(process_incarnation, event.process.tid)` pair. A gap can indicate unpublished detailed events. |
| `fd` and `fd_generation` in `proof` | Both present or both `null`. `fd` is a nonnegative signed 32-bit descriptor number; generation is positive `u64` binding version after the modeled syscall transition. A matching number without a matching generation is not binding identity. |
| `state_valid` | Boolean reporting whether kernel state for that event or descriptor was valid. `false` precludes a positive certificate. |
| `invalidation_reason` | Optional known reason code when state is invalid. It must be absent for a valid event. |
| `count` | Positive `u64` number of lost detailed records. It does not locate a gap or prove state health. |
| `checkpoint_id` | Positive `u64`, strictly increasing for the entire stream. |
| `high_water[].kernel_ordinal` | Positive `u64` per-thread kernel ordinal at the checkpoint boundary. It may equal the last observed event ordinal, must not be lower than an already observed event or earlier checkpoint for that thread, and must precede any subsequently received event for that thread. |
| `descriptors[].generation` | Positive `u64` current descriptor binding version at the checkpoint boundary. Each descriptor number appears at most once per process checkpoint. |

`checkpoint.processes` is a list of process snapshots; incarnation IDs are
unique within one checkpoint. Each process snapshot contains `high_water`
entries with unique positive TIDs, `descriptors` with unique nonnegative FDs,
and optionally `invalidation_reason`. An empty list is permitted when no
relevant state is available. `high_water` is kernel state read separately from
the detailed-event ring; it is not derived from the events received by the
consumer. A checkpoint can support a claim only for the process, thread, and
descriptor entries it includes, and only when the collector can establish an
ordered drain/checkpoint boundary. The parser checks numeric ordering; the
verifier must also check state health and whether a particular checkpoint is
relevant to the events it certifies.

Known invalidation reasons are `unsupported_syscall`, `unknown_syscall`,
`shared_fd_table`, `fork`, `exec`, `map_failure`, `counter_wrap`,
`state_evicted`, `ordering_ambiguous`, `process_identity_unavailable`,
`state_update_failure`, `correlation_failure`, and `checkpoint_failure`.
Unknown reason codes, unsupported metadata fields, zero IDs or counts,
duplicate/decreasing ordinals or checkpoint IDs, missing or duplicate headers,
and mixed-version records are protocol errors. The consumer must stop
certification rather than reinterpret a bad version-2 line as version 1.
