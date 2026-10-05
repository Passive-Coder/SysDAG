//! Linux aya loader for `ebpf/sysdag.bpf.c`.
//!
//! The BPF object traces raw syscall enter/exit tracepoints, uses a bounded
//! per-thread correlation map in-kernel, and delivers completed records through
//! `EVENTS`. This module deliberately owns the loaded `Ebpf` value so links stay
//! attached for the collector's lifetime.

use std::{mem::size_of, path::Path};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{HashMap, RingBuf},
    programs::TracePoint,
    Ebpf,
};

use crate::{
    event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef, TraceEvent},
    labels::build_labels,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSyscallEvent {
    tid: u32,
    tgid: u32,
    enter_ns: u64,
    exit_ns: u64,
    nr: i64,
    ret: i64,
    args: [u64; 3],
}

/// Owns the aya programs/maps. Dropping it detaches both tracepoints.
pub struct AyaCollector {
    _ebpf: Ebpf,
    events: RingBuf<aya::maps::MapData>,
    drops: HashMap<aya::maps::MapData, u32, u64>,
    sequence: u64,
    reported_drops: u64,
}

impl AyaCollector {
    /// Load an ELF compiled from `ebpf/sysdag.bpf.c` and attach its raw syscall
    /// tracepoints. The caller needs CAP_BPF+CAP_PERFMON (normally root).
    pub fn open(object: &Path) -> Result<Self> {
        let mut ebpf = Ebpf::load_file(object)
            .with_context(|| format!("load eBPF object {}", object.display()))?;
        for (program_name, event) in [("sysdag_enter", "sys_enter"), ("sysdag_exit", "sys_exit")] {
            let program: &mut TracePoint = ebpf
                .program_mut(program_name)
                .with_context(|| format!("find eBPF program {program_name}"))?
                .try_into()
                .context("convert eBPF program to tracepoint")?;
            program
                .load()
                .with_context(|| format!("load {program_name}"))?;
            program
                .attach("raw_syscalls", event)
                .with_context(|| format!("attach raw_syscalls:{event}"))?;
        }
        let events = RingBuf::try_from(ebpf.take_map("EVENTS").context("find EVENTS ring buffer")?)
            .context("open EVENTS ring buffer")?;
        let drops = HashMap::try_from(ebpf.take_map("DROPS").context("find DROPS map")?)
            .context("open DROPS map")?;
        Ok(Self {
            _ebpf: ebpf,
            events,
            drops,
            sequence: 0,
            reported_drops: 0,
        })
    }

    /// Drain currently available ring-buffer events. The returned loss count is
    /// the delta since the previous call and must be sent to `WindowBuilder`.
    pub fn drain(&mut self) -> Result<(Vec<TraceEvent>, u64)> {
        let mut out = Vec::new();
        while let Some(sample) = self.events.next() {
            let raw = decode(sample.as_ref())?;
            let Some(name) = syscall_name(raw.nr) else {
                continue;
            };
            self.sequence += 1;
            out.push(to_trace_event(raw, name, self.sequence));
        }
        let total = self.drops.get(&0, 0).unwrap_or(0);
        let delta = total.saturating_sub(self.reported_drops);
        self.reported_drops = total;
        Ok((out, delta))
    }
}

fn decode(bytes: &[u8]) -> Result<RawSyscallEvent> {
    if bytes.len() != size_of::<RawSyscallEvent>() {
        bail!("unexpected eBPF ring-buffer record size {}", bytes.len());
    }
    // The BPF C record is repr(C), and `read_unaligned` avoids assuming the
    // ring-buffer sample has Rust alignment.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<RawSyscallEvent>()) })
}

fn to_trace_event(raw: RawSyscallEvent, name: &str, seq: u64) -> TraceEvent {
    let args = EventArgs {
        fd: i32::try_from(raw.args[0]).ok(),
        count: i64::try_from(raw.args[2]).ok(),
        buffer_addr: Some(raw.args[1]),
        ..EventArgs::default()
    };
    let errno = (raw.ret < 0).then(|| format!("ERRNO_{}", -raw.ret));
    let labels = build_labels(
        name,
        "",
        "",
        "",
        "",
        Some(raw.ret),
        errno.as_deref(),
        args.count,
        "",
    );
    TraceEvent::new(
        ProcessRef {
            pid: raw.tgid as i32,
            tid: raw.tid as i32,
            start_ns: 0,
            image_gen: 0,
            comm: String::new(),
        },
        seq,
        raw.enter_ns,
        raw.exit_ns,
        SyscallRef {
            nr: raw.nr as i32,
            name: name.into(),
            arch: "x86_64".into(),
        },
        args,
        Some(raw.ret),
        errno,
        labels,
        CaptureInfo {
            source: "ebpf".into(),
            truncated: false,
            raw_line: String::new(),
            lost: false,
        },
    )
}

/// x86_64 calls in SysDAG's configured file/descriptor/network/process classes.
fn syscall_name(nr: i64) -> Option<&'static str> {
    Some(match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        8 => "lseek",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        32 => "dup",
        33 => "dup2",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        72 => "fcntl",
        257 => "openat",
        288 => "accept4",
        292 => "dup3",
        293 => "pipe2",
        295 => "preadv",
        296 => "pwritev",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn translates_tracked_kernel_calls() {
        let e = to_trace_event(
            RawSyscallEvent {
                tid: 2,
                tgid: 1,
                enter_ns: 4,
                exit_ns: 6,
                nr: 1,
                ret: 3,
                args: [1, 0x1000, 3],
            },
            "write",
            7,
        );
        assert_eq!(e.capture.source, "ebpf");
        assert_eq!(e.syscall.name, "write");
        assert_eq!(e.args.buffer_addr, Some(0x1000));
        assert_eq!(syscall_name(257), Some("openat"));
    }
}
