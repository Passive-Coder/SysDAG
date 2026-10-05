//! Bounded incremental event windows for live monitoring.

use std::collections::VecDeque;

use crate::{
    config::Config,
    event::TraceEvent,
    features::{encode, EncodedGraph},
    graph::{build_windows, GraphQuality},
};

/// Produces complete graph windows as soon as enough events arrive.  Its queue
/// is explicitly bounded; dropped oldest events are reported as capture loss.
pub struct WindowBuilder {
    cfg: Config,
    run_id: String,
    baseline_key: String,
    events: VecDeque<TraceEvent>,
    emitted: u64,
    evicted: u64,
    max_in_flight: usize,
}

impl WindowBuilder {
    pub fn new(
        cfg: Config,
        run_id: impl Into<String>,
        baseline_key: impl Into<String>,
        max_in_flight: usize,
    ) -> Self {
        Self {
            cfg,
            run_id: run_id.into(),
            baseline_key: baseline_key.into(),
            events: VecDeque::new(),
            emitted: 0,
            evicted: 0,
            max_in_flight: max_in_flight.max(1),
        }
    }

    pub fn push(&mut self, event: TraceEvent) -> Option<EncodedGraph> {
        self.events.push_back(event);
        while self.events.len() > self.max_in_flight {
            self.events.pop_front();
            self.evicted += 1;
        }
        let width = self.cfg.window.size.max(1);
        if self.events.len() < width {
            return None;
        }
        let slice: Vec<_> = self.events.iter().cloned().collect();
        let quality = GraphQuality {
            capture_loss: self.evicted,
            ..Default::default()
        };
        let graph = build_windows(
            &slice,
            &self.cfg,
            &format!("{}:live{}", self.run_id, self.emitted),
            &self.baseline_key,
            quality,
        )
        .into_iter()
        .last()?;
        self.emitted += 1;
        let keep = self.cfg.window.overlap.min(width.saturating_sub(1));
        while self.events.len() > keep {
            self.events.pop_front();
        }
        Some(encode(graph, &self.cfg))
    }

    /// Account for records the capture backend reports as dropped. The next
    /// emitted graph carries this quality loss into detector safeguards.
    pub fn record_capture_loss(&mut self, count: u64) {
        self.evicted = self.evicted.saturating_add(count);
    }

    pub fn evicted(&self) -> u64 {
        self.evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{CaptureInfo, EventArgs, ProcessRef, SyscallRef},
        labels::NodeLabels,
    };
    fn event(seq: u64) -> TraceEvent {
        TraceEvent::new(
            ProcessRef {
                pid: 1,
                tid: 1,
                start_ns: 0,
                image_gen: 0,
                comm: String::new(),
            },
            seq,
            seq,
            seq,
            SyscallRef {
                nr: 0,
                name: "read".into(),
                arch: "linux".into(),
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
        )
    }
    #[test]
    fn emits_before_end_of_stream_and_bounds_queue() {
        let mut cfg = Config::default();
        cfg.window.size = 3;
        cfg.window.overlap = 1;
        let mut b = WindowBuilder::new(cfg, "r", "k", 3);
        assert!(b.push(event(1)).is_none());
        assert!(b.push(event(2)).is_none());
        assert!(b.push(event(3)).is_some());
        assert!(b.push(event(4)).is_none());
        assert!(b.push(event(5)).is_some());
    }
}
