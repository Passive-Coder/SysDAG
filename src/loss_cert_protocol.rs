//! Version-2 proof relay. This module does not alter the version-1 `EbpfEnvelope`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::event::TraceEvent;

pub const LOSS_CERT_PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    UnsupportedSyscall,
    UnknownSyscall,
    SharedFdTable,
    Fork,
    Exec,
    MapFailure,
    CounterWrap,
    StateEvicted,
    OrderingAmbiguous,
    ProcessIdentityUnavailable,
    StateUpdateFailure,
    CorrelationFailure,
    CheckpointFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProof {
    pub process_incarnation: u64,
    pub kernel_ordinal: u64,
    pub fd: Option<i32>,
    pub fd_generation: Option<u64>,
    pub state_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<InvalidationReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadHighWater {
    pub tid: i32,
    pub kernel_ordinal: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorGeneration {
    pub fd: i32,
    pub generation: u64,
    pub state_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCheckpoint {
    pub process_incarnation: u64,
    pub high_water: Vec<ThreadHighWater>,
    pub descriptors: Vec<DescriptorGeneration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<InvalidationReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum LossCertEnvelopeV2 {
    Header {
        protocol_version: u8,
        collector_build: String,
        capability: CapabilityState,
    },
    Event {
        event: TraceEvent,
        proof: EventProof,
    },
    Checkpoint {
        checkpoint_id: u64,
        processes: Vec<ProcessCheckpoint>,
    },
    Lost {
        count: u64,
    },
}

#[derive(Debug)]
pub enum LossCertProtocolError {
    Decode(serde_json::Error),
    MissingHeader,
    DuplicateHeader,
    UnsupportedVersion(u8),
    InvalidMetadata(&'static str),
    OrdinalRegression { previous: u64, actual: u64 },
    CheckpointRegression { previous: u64, actual: u64 },
}

impl fmt::Display for LossCertProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "decode version-2 relay envelope: {error}"),
            Self::MissingHeader => write!(f, "version-2 stream requires a header first"),
            Self::DuplicateHeader => write!(f, "duplicate version-2 stream header"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported relay protocol version {version}")
            }
            Self::InvalidMetadata(reason) => {
                write!(f, "invalid version-2 proof metadata: {reason}")
            }
            Self::OrdinalRegression { previous, actual } => {
                write!(f, "kernel ordinal {actual} is not greater than {previous}")
            }
            Self::CheckpointRegression { previous, actual } => {
                write!(f, "checkpoint ID {actual} is not greater than {previous}")
            }
        }
    }
}

impl std::error::Error for LossCertProtocolError {}

impl From<serde_json::Error> for LossCertProtocolError {
    fn from(value: serde_json::Error) -> Self {
        Self::Decode(value)
    }
}

/// Validates one ordered JSONL stream. A parser instance must not be reused for
/// another stream because its header and ordinal state are stream scoped.
#[derive(Default)]
pub struct LossCertStreamParser {
    header_seen: bool,
    capability: Option<CapabilityState>,
    ordinals: HashMap<(u64, i32), u64>,
    high_water: HashMap<(u64, i32), u64>,
    checkpoint_id: u64,
}

impl LossCertStreamParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_jsonl(&mut self, line: &str) -> Result<LossCertEnvelopeV2, LossCertProtocolError> {
        let record: LossCertEnvelopeV2 = serde_json::from_str(line)?;
        match &record {
            LossCertEnvelopeV2::Header {
                protocol_version,
                collector_build,
                capability,
            } => {
                if self.header_seen {
                    return Err(LossCertProtocolError::DuplicateHeader);
                }
                if *protocol_version != LOSS_CERT_PROTOCOL_VERSION {
                    return Err(LossCertProtocolError::UnsupportedVersion(*protocol_version));
                }
                if collector_build.trim().is_empty() {
                    return Err(LossCertProtocolError::InvalidMetadata(
                        "collector_build must be nonempty",
                    ));
                }
                self.header_seen = true;
                self.capability = Some(*capability);
            }
            _ if !self.header_seen => return Err(LossCertProtocolError::MissingHeader),
            LossCertEnvelopeV2::Lost { count } => {
                if *count == 0 {
                    return Err(LossCertProtocolError::InvalidMetadata(
                        "lost count must be positive",
                    ));
                }
            }
            LossCertEnvelopeV2::Event { event, proof } => {
                if self.capability != Some(CapabilityState::Available) {
                    return Err(LossCertProtocolError::InvalidMetadata(
                        "unavailable capability cannot emit proof events",
                    ));
                }
                validate_event(event, proof)?;
                let key = (proof.process_incarnation, event.process.tid);
                if let Some(previous) = self.ordinals.get(&key) {
                    if proof.kernel_ordinal <= *previous {
                        return Err(LossCertProtocolError::OrdinalRegression {
                            previous: *previous,
                            actual: proof.kernel_ordinal,
                        });
                    }
                }
                if let Some(previous) = self.high_water.get(&key) {
                    if proof.kernel_ordinal <= *previous {
                        return Err(LossCertProtocolError::OrdinalRegression {
                            previous: *previous,
                            actual: proof.kernel_ordinal,
                        });
                    }
                }
                self.ordinals.insert(key, proof.kernel_ordinal);
            }
            LossCertEnvelopeV2::Checkpoint {
                checkpoint_id,
                processes,
            } => {
                if self.capability != Some(CapabilityState::Available) {
                    return Err(LossCertProtocolError::InvalidMetadata(
                        "unavailable capability cannot emit checkpoints",
                    ));
                }
                if *checkpoint_id <= self.checkpoint_id {
                    return Err(LossCertProtocolError::CheckpointRegression {
                        previous: self.checkpoint_id,
                        actual: *checkpoint_id,
                    });
                }
                let mut seen_processes = HashSet::new();
                let mut updates = Vec::new();
                for process in processes {
                    if process.process_incarnation == 0
                        || !seen_processes.insert(process.process_incarnation)
                    {
                        return Err(LossCertProtocolError::InvalidMetadata(
                            "checkpoint process incarnation must be positive and unique",
                        ));
                    }
                    let mut seen_threads = HashSet::new();
                    let mut seen_fds = HashSet::new();
                    for thread in &process.high_water {
                        if thread.tid <= 0
                            || thread.kernel_ordinal == 0
                            || !seen_threads.insert(thread.tid)
                        {
                            return Err(LossCertProtocolError::InvalidMetadata(
                                "checkpoint thread metadata invalid or duplicate",
                            ));
                        }
                        let key = (process.process_incarnation, thread.tid);
                        let prior = self
                            .ordinals
                            .get(&key)
                            .copied()
                            .unwrap_or(0)
                            .max(self.high_water.get(&key).copied().unwrap_or(0));
                        if thread.kernel_ordinal < prior {
                            return Err(LossCertProtocolError::OrdinalRegression {
                                previous: prior,
                                actual: thread.kernel_ordinal,
                            });
                        }
                        updates.push((key, thread.kernel_ordinal));
                    }
                    for descriptor in &process.descriptors {
                        if descriptor.fd < 0
                            || descriptor.generation == 0
                            || !seen_fds.insert(descriptor.fd)
                        {
                            return Err(LossCertProtocolError::InvalidMetadata(
                                "checkpoint descriptor metadata invalid or duplicate",
                            ));
                        }
                    }
                }
                for (key, ordinal) in updates {
                    self.high_water.insert(key, ordinal);
                }
                self.checkpoint_id = *checkpoint_id;
            }
        }
        Ok(record)
    }
}

fn validate_event(event: &TraceEvent, proof: &EventProof) -> Result<(), LossCertProtocolError> {
    if event.process.pid <= 0
        || event.process.tid <= 0
        || proof.process_incarnation == 0
        || proof.kernel_ordinal == 0
    {
        return Err(LossCertProtocolError::InvalidMetadata(
            "process identity and ordinal must be positive",
        ));
    }
    if event.capture.source != "ebpf" {
        return Err(LossCertProtocolError::InvalidMetadata(
            "version-2 event source must be ebpf",
        ));
    }
    match (proof.fd, proof.fd_generation) {
        (Some(fd), Some(generation)) if fd >= 0 && generation > 0 => {}
        (None, None) => {}
        _ => {
            return Err(LossCertProtocolError::InvalidMetadata(
                "fd and positive fd_generation must occur together",
            ))
        }
    }
    if proof.state_valid && proof.invalidation_reason.is_some() {
        return Err(LossCertProtocolError::InvalidMetadata(
            "valid event state cannot have an invalidation reason",
        ));
    }
    Ok(())
}
