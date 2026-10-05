//! eBPF ring-buffer hand-off types.
//!
//! The in-kernel program/loader is Linux-specific, but its output boundary is
//! deliberately portable: a relay writes one JSON envelope per line to a FIFO,
//! socket, or file.  Keeping this boundary in Rust lets the Phase 6 window and
//! detector pipeline consume eBPF events without a second graph implementation.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::event::TraceEvent;

/// A record emitted by the Linux ring-buffer relay. `lost` is emitted whenever
/// the kernel reports dropped ring-buffer records, so loss reaches the existing
/// DEGRADED_CAPTURE decision rule instead of silently biasing a score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum EbpfEnvelope {
    Event { event: TraceEvent },
    Lost { count: u64 },
}

impl EbpfEnvelope {
    /// Decode a relay JSON line and enforce that event provenance is explicit.
    pub fn parse_jsonl(line: &str) -> Result<Self> {
        let mut record: Self = serde_json::from_str(line).context("decode eBPF relay envelope")?;
        if let Self::Event { event } = &mut record {
            if event.capture.source.is_empty() || event.capture.source == "strace" {
                event.capture.source = "ebpf".into();
            }
        }
        if let Self::Lost { count } = record {
            if count == 0 {
                bail!("eBPF loss envelope count must be positive");
            }
        }
        Ok(record)
    }
}

/// Whether this host can attempt the Linux eBPF backend. This is intentionally
/// a capability check only; a caller still needs a bundled/signed BPF object
/// and the kernel privileges required to attach it.
pub fn linux_ebpf_available() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            bail!("BTF is unavailable at /sys/kernel/btf/vmlinux");
        }
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("eBPF is only supported on Linux");
    }
}

/// The version-2 collector must not be enabled until its kernel-side identity,
/// descriptor state, and checkpoint ordering have been verified on Linux x86_64.
/// This is deliberately independent of the working version-1 capability check.
pub fn loss_certification_available() -> Result<()> {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    bail!("UNAVAILABLE(target_kernel_not_verified): loss certification requires a verified native Linux x86_64 kernel");

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    bail!("UNAVAILABLE(version_2_collector_not_verified): kernel state and checkpoint ordering have not been validated");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef},
        labels::NodeLabels,
    };

    #[test]
    fn envelope_sets_ebpf_provenance_and_validates_loss() {
        let event = TraceEvent::new(
            ProcessRef {
                pid: 1,
                tid: 1,
                start_ns: 0,
                image_gen: 0,
                comm: String::new(),
            },
            1,
            1,
            1,
            SyscallRef {
                nr: 0,
                name: "read".into(),
                arch: "x86_64".into(),
            },
            EventArgs::default(),
            Some(1),
            None,
            NodeLabels {
                family: "file".into(),
                op: "FILE_READ".into(),
                result: "SUCCESS".into(),
                resource_kind: "FILE".into(),
                flags: "NONE".into(),
                bytes: "TINY".into(),
                path_class: "APP".into(),
            },
            CaptureInfo::default(),
        );
        let raw = serde_json::to_string(&EbpfEnvelope::Event { event }).unwrap();
        let mut version_two: serde_json::Value = serde_json::from_str(&raw).unwrap();
        version_two["proof"] = serde_json::json!({"fd": 3});
        assert!(EbpfEnvelope::parse_jsonl(&version_two.to_string()).is_err());
        let EbpfEnvelope::Event { event } = EbpfEnvelope::parse_jsonl(&raw).unwrap() else {
            panic!("expected event")
        };
        assert_eq!(event.capture.source, "ebpf");
        assert!(EbpfEnvelope::parse_jsonl(r#"{"kind":"lost","count":0}"#).is_err());
    }

    #[test]
    fn native_loss_certification_fails_closed() {
        let error = loss_certification_available().unwrap_err().to_string();
        assert!(error.starts_with("UNAVAILABLE("));
    }
}
