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
