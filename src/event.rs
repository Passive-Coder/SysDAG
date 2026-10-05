use serde::{Deserialize, Serialize};

use crate::labels::NodeLabels;
use crate::SCHEMA_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: i32,
    pub tid: i32,
    #[serde(default)]
    pub start_ns: u64,
    #[serde(default)]
    pub image_gen: u64,
    #[serde(default)]
    pub comm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRef {
    pub nr: i32,
    pub name: String,
    #[serde(default = "default_arch")]
    pub arch: String,
}

fn default_arch() -> String {
    "x86_64".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureInfo {
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub raw_line: String,
    #[serde(default)]
    pub lost: bool,
}

fn default_source() -> String {
    "strace".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirfd: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newfd: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_addr: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sock_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_fds: Option<(i32, i32)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_pid: Option<i32>,
    /// Vectored-I/O buffer addresses/lengths when strace exposes iovecs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iovecs: Vec<Iovec>,
    /// File descriptors received through Unix-domain SCM_RIGHTS ancillary data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub received_fds: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iovec {
    pub addr: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub schema_version: String,
    pub process: ProcessRef,
    pub seq: u64,
    pub enter_ns: u64,
    pub exit_ns: u64,
    pub syscall: SyscallRef,
    pub args: EventArgs,
    pub ret: Option<i64>,
    pub errno: Option<String>,
    pub labels: NodeLabels,
    pub capture: CaptureInfo,
    #[serde(default)]
    pub binary_digest: String,
}

impl TraceEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        process: ProcessRef,
        seq: u64,
        enter_ns: u64,
        exit_ns: u64,
        syscall: SyscallRef,
        args: EventArgs,
        ret: Option<i64>,
        errno: Option<String>,
        labels: NodeLabels,
        capture: CaptureInfo,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            process,
            seq,
            enter_ns,
            exit_ns,
            syscall,
            args,
            ret,
            errno,
            labels,
            capture,
            binary_digest: String::new(),
        }
    }

    pub fn success(&self) -> bool {
        self.errno.is_none() && self.ret.map(|r| r >= 0).unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParseStats {
    pub lines: u64,
    pub events: u64,
    pub rejected: u64,
    pub signals: u64,
    pub exits: u64,
    pub unfinished: u64,
    /// Completed calls dropped because their family is not tracked (Phase 1.3).
    #[serde(default)]
    pub unknown_syscalls: u64,
    /// Completed calls that parsed but carried no usable timestamp.
    #[serde(default)]
    pub malformed_records: u64,
    /// Estimated lost events: rejected lines plus unfinished calls never resumed.
    #[serde(default)]
    pub lost_events_estimate: u64,
}

impl ParseStats {
    /// Aggregate capture-quality signal used for the DEGRADED_CAPTURE rule.
    pub fn quality_loss(&self) -> u64 {
        self.unknown_syscalls + self.malformed_records + self.lost_events_estimate
    }

    /// True when loss/malformed volume exceeds a rate threshold of total lines.
    pub fn is_degraded(&self, max_rate_pct: f64) -> bool {
        if self.lines == 0 {
            return false;
        }
        let rate = self.quality_loss() as f64 / self.lines as f64 * 100.0;
        rate > max_rate_pct
    }
}
