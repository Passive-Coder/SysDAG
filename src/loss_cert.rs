//! Pure, bounded verification of version-2 descriptor-binding evidence.
//!
//! A certificate says only that two observed events refer to the same FD
//! binding in one process incarnation. It says nothing about data flow. A
//! positive result is conditional on a trusted producer upholding its kernel
//! state and process-identity invariants; a JSON header alone cannot prove
//! native provenance. Synthetic streams exercise the proof model only.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::loss_cert_protocol::{
    CapabilityState, LossCertEnvelopeV2, LossCertStreamParser, ProcessCheckpoint,
};

/// Test-only producer identity for the pure proof model. Native collector
/// builds require an explicit ABI review before being admitted here.
pub const SYNTHETIC_COLLECTOR_BUILD: &str = "synthetic-test";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateStatus {
    Certified,
    Unresolved,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub status: CertificateStatus,
    pub left_event_seq: u64,
    pub right_event_seq: u64,
    pub process_incarnation: Option<u64>,
    pub fd: Option<i32>,
    pub fd_generation: Option<u64>,
    pub left_kernel_ordinal: Option<u64>,
    pub right_kernel_ordinal: Option<u64>,
    pub checkpoint_high_water: Option<u64>,
    pub checkpoint_ids: Vec<u64>,
    pub reason: Option<String>,
}

#[derive(Clone)]
struct Retained {
    position: u64,
    envelope: LossCertEnvelopeV2,
}

/// Consumes validated envelopes. Direct callers still get fail-closed checks
/// for the ordering facts needed to issue a certificate.
pub struct LossCertVerifier {
    capacity: usize,
    retained: VecDeque<Retained>,
    position: u64,
    header_seen: bool,
    available: bool,
    invalid: bool,
    last_checkpoint_id: u64,
    last_ordinals: HashMap<(u64, i32), u64>,
    seen_seq: HashSet<u64>,
}

impl LossCertVerifier {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            retained: VecDeque::new(),
            position: 0,
            header_seen: false,
            available: false,
            invalid: capacity == 0,
            last_checkpoint_id: 0,
            last_ordinals: HashMap::new(),
            seen_seq: HashSet::new(),
        }
    }

    pub fn ingest(&mut self, envelope: LossCertEnvelopeV2) {
        self.position = self.position.saturating_add(1);
        match &envelope {
            LossCertEnvelopeV2::Header {
                protocol_version,
                capability,
                collector_build,
            } => {
                if self.header_seen || *protocol_version != 2 || collector_build.trim().is_empty() {
                    self.invalid = true;
                }
                self.header_seen = true;
                self.available = *capability == CapabilityState::Available
                    && collector_build == SYNTHETIC_COLLECTOR_BUILD;
            }
            _ if !self.header_seen => self.invalid = true,
            LossCertEnvelopeV2::Event { event, proof } => {
                let key = (proof.process_incarnation, event.process.tid);
                if proof.process_incarnation == 0
                    || proof.kernel_ordinal == 0
                    || self
                        .last_ordinals
                        .get(&key)
                        .is_some_and(|prior| proof.kernel_ordinal <= *prior)
                    || !self.seen_seq.insert(event.seq)
                {
                    self.invalid = true;
                }
                if !self.last_ordinals.contains_key(&key)
                    && self.last_ordinals.len() >= self.capacity
                {
                    self.invalid = true;
                } else {
                    self.last_ordinals.insert(key, proof.kernel_ordinal);
                }
                if self.seen_seq.len() > self.capacity {
                    self.invalid = true;
                }
            }
            LossCertEnvelopeV2::Checkpoint {
                checkpoint_id,
                processes,
            } => {
                if *checkpoint_id <= self.last_checkpoint_id {
                    self.invalid = true;
                }
                self.last_checkpoint_id = *checkpoint_id;
                for process in processes {
                    for water in &process.high_water {
                        let key = (process.process_incarnation, water.tid);
                        if self
                            .last_ordinals
                            .get(&key)
                            .is_some_and(|prior| water.kernel_ordinal < *prior)
                        {
                            self.invalid = true;
                        }
                        if !self.last_ordinals.contains_key(&key)
                            && self.last_ordinals.len() >= self.capacity
                        {
                            self.invalid = true;
                        } else {
                            self.last_ordinals.insert(key, water.kernel_ordinal);
                        }
                    }
                }
            }
            LossCertEnvelopeV2::Lost { count } => {
                if *count == 0 {
                    self.invalid = true;
                }
            }
        }
        self.retained.push_back(Retained {
            position: self.position,
            envelope,
        });
        while self.retained.len() > self.capacity {
            self.retained.pop_front();
        }
    }

    pub fn certify_pair(&self, left_event_seq: u64, right_event_seq: u64) -> CertificateRecord {
        let mut result = CertificateRecord {
            status: CertificateStatus::Unresolved,
            left_event_seq,
            right_event_seq,
            process_incarnation: None,
            fd: None,
            fd_generation: None,
            left_kernel_ordinal: None,
            right_kernel_ordinal: None,
            checkpoint_high_water: None,
            checkpoint_ids: Vec::new(),
            reason: Some("insufficient proof".into()),
        };
        if self.invalid || !self.header_seen || !self.available {
            result.reason = Some("invalid or unavailable proof stream".into());
            return result;
        }
        if left_event_seq == right_event_seq {
            result.reason = Some("distinct events required".into());
            return result;
        }
        let event_for = |seq| {
            self.retained.iter().find(|item| {
            matches!(&item.envelope, LossCertEnvelopeV2::Event { event, .. } if event.seq == seq)
        })
        };
        let (Some(left), Some(right)) = (event_for(left_event_seq), event_for(right_event_seq))
        else {
            result.reason = Some("cited event missing or evicted".into());
            return result;
        };
        let (
            LossCertEnvelopeV2::Event {
                event: left_event,
                proof: left_proof,
            },
            LossCertEnvelopeV2::Event {
                event: right_event,
                proof: right_proof,
            },
        ) = (&left.envelope, &right.envelope)
        else {
            unreachable!()
        };
        result.process_incarnation = Some(left_proof.process_incarnation);
        result.fd = left_proof.fd;
        result.fd_generation = left_proof.fd_generation;
        result.left_kernel_ordinal = Some(left_proof.kernel_ordinal);
        result.right_kernel_ordinal = Some(right_proof.kernel_ordinal);
        if left.position >= right.position
            || left_event.process.pid != right_event.process.pid
            || left_event.process.tid != right_event.process.tid
            || left_proof.process_incarnation == 0
            || left_proof.process_incarnation != right_proof.process_incarnation
            || left_proof.kernel_ordinal >= right_proof.kernel_ordinal
        {
            result.reason = Some("process identity or event order differs".into());
            return result;
        }
        if !left_event.success()
            || !right_event.success()
            || !descriptor_use(&left_event.syscall.name)
            || !descriptor_use(&right_event.syscall.name)
            || left_event.syscall.arch != "x86_64"
            || right_event.syscall.arch != "x86_64"
            || !syscall_number_matches(&left_event.syscall.name, left_event.syscall.nr)
            || !syscall_number_matches(&right_event.syscall.name, right_event.syscall.nr)
            || left_event.args.fd != left_proof.fd
            || right_event.args.fd != right_proof.fd
            || !left_proof.state_valid
            || !right_proof.state_valid
            || left_proof.invalidation_reason.is_some()
            || right_proof.invalidation_reason.is_some()
            || left_proof.fd.is_none()
            || left_proof.fd_generation.is_none()
            || left_proof.fd != right_proof.fd
            || left_proof.fd_generation != right_proof.fd_generation
        {
            result.reason = Some("descriptor binding or event state differs".into());
            return result;
        }
        let fd = left_proof.fd.unwrap();
        let generation = left_proof.fd_generation.unwrap();
        if fd < 0 || generation == 0 {
            result.reason = Some("invalid descriptor generation".into());
            return result;
        }

        // A checkpoint must be later in the relay, cover the second event's
        // ordinal, and independently report this exact live binding.
        let supporting = self
            .retained
            .iter()
            .filter_map(|item| {
                if item.position <= right.position {
                    return None;
                }
                let LossCertEnvelopeV2::Checkpoint {
                    checkpoint_id,
                    processes,
                } = &item.envelope
                else {
                    return None;
                };
                let process = processes
                    .iter()
                    .find(|p| p.process_incarnation == left_proof.process_incarnation)?;
                if checkpoint_supports(
                    process,
                    left_event.process.tid,
                    right_proof.kernel_ordinal,
                    fd,
                    generation,
                ) {
                    let water = process.high_water[0].kernel_ordinal;
                    Some((item.position, *checkpoint_id, water))
                } else {
                    None
                }
            })
            .next();
        let Some((checkpoint_position, checkpoint_id, checkpoint_high_water)) = supporting else {
            result.reason = Some("ordered checkpoint does not confirm binding".into());
            return result;
        };
        for item in self
            .retained
            .iter()
            .filter(|item| item.position > left.position && item.position <= checkpoint_position)
        {
            match &item.envelope {
                LossCertEnvelopeV2::Event { event, proof }
                    if proof.process_incarnation == left_proof.process_incarnation =>
                {
                    if event.process.tid != left_event.process.tid
                        || !proof.state_valid
                        || proof.invalidation_reason.is_some()
                        || !supported_operation(&event.syscall.name, event.syscall.nr)
                        || (item.position != right.position && mutates_binding(&event.syscall.name))
                    {
                        result.reason = Some("intervening mutation or invalidation".into());
                        return result;
                    }
                }
                LossCertEnvelopeV2::Checkpoint { processes, .. } => {
                    if processes.iter().any(|p| {
                        p.process_incarnation == left_proof.process_incarnation
                            && (p.invalidation_reason.is_some()
                                || p.descriptors.iter().any(|d| d.fd == fd && !d.state_valid))
                    }) {
                        result.reason = Some("checkpoint reports invalid state".into());
                        return result;
                    }
                }
                _ => {}
            }
        }
        result.status = CertificateStatus::Certified;
        result.checkpoint_ids.push(checkpoint_id);
        result.checkpoint_high_water = Some(checkpoint_high_water);
        result.reason = None;
        result
    }
}

fn checkpoint_supports(
    process: &ProcessCheckpoint,
    tid: i32,
    ordinal: u64,
    fd: i32,
    generation: u64,
) -> bool {
    process.invalidation_reason.is_none()
        && process.high_water.len() == 1
        && process
            .high_water
            .iter()
            .any(|water| water.tid == tid && water.kernel_ordinal >= ordinal)
        && process.descriptors.iter().any(|descriptor| {
            descriptor.fd == fd && descriptor.generation == generation && descriptor.state_valid
        })
}

fn descriptor_use(name: &str) -> bool {
    matches!(name, "read" | "write" | "sendto" | "recvfrom")
}

fn syscall_number_matches(name: &str, number: i32) -> bool {
    matches!(
        (name, number),
        ("read", 0) | ("write", 1) | ("sendto", 44) | ("recvfrom", 45)
    )
}

fn supported_operation(name: &str, number: i32) -> bool {
    syscall_number_matches(name, number)
        || matches!(
            (name, number),
            ("open", 2)
                | ("close", 3)
                | ("dup", 32)
                | ("dup2", 33)
                | ("socket", 41)
                | ("accept", 43)
                | ("openat", 257)
                | ("accept4", 288)
                | ("dup3", 292)
        )
}

fn mutates_binding(name: &str) -> bool {
    matches!(
        name,
        "open" | "openat" | "socket" | "accept" | "accept4" | "close" | "dup" | "dup2" | "dup3"
    )
}

/// Independently replay cited envelopes and require every saved fact to match.
/// The caller supplies the complete ordered evidence stream containing the
/// certificate's two events and supporting checkpoint.
pub fn verify_certificate(record: &CertificateRecord, envelopes: &[LossCertEnvelopeV2]) -> bool {
    if record.status != CertificateStatus::Certified
        || record.reason.is_some()
        || record.checkpoint_ids.len() != 1
    {
        return false;
    }
    let mut parser = LossCertStreamParser::new();
    let mut validated = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let Ok(line) = serde_json::to_string(envelope) else {
            return false;
        };
        let Ok(item) = parser.parse_jsonl(&line) else {
            return false;
        };
        validated.push(item);
    }
    let Some(LossCertEnvelopeV2::Header {
        capability: CapabilityState::Available,
        collector_build,
        ..
    }) = validated.first()
    else {
        return false;
    };
    if collector_build != SYNTHETIC_COLLECTOR_BUILD {
        return false;
    }

    let matching_event = |seq| {
        validated
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                if let LossCertEnvelopeV2::Event { event, proof } = item {
                    (event.seq == seq).then_some((index, event, proof))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    };
    let left = matching_event(record.left_event_seq);
    let right = matching_event(record.right_event_seq);
    if left.len() != 1 || right.len() != 1 {
        return false;
    }
    let (li, le, lp) = left[0];
    let (ri, re, rp) = right[0];
    if li >= ri
        || le.process.pid != re.process.pid
        || le.process.tid != re.process.tid
        || lp.process_incarnation == 0
        || lp.process_incarnation != rp.process_incarnation
        || lp.kernel_ordinal >= rp.kernel_ordinal
        || !le.success()
        || !re.success()
        || !descriptor_use(&le.syscall.name)
        || !descriptor_use(&re.syscall.name)
        || le.syscall.arch != "x86_64"
        || re.syscall.arch != "x86_64"
        || !syscall_number_matches(&le.syscall.name, le.syscall.nr)
        || !syscall_number_matches(&re.syscall.name, re.syscall.nr)
        || !lp.state_valid
        || !rp.state_valid
        || lp.invalidation_reason.is_some()
        || rp.invalidation_reason.is_some()
        || lp.fd.is_none()
        || lp.fd != rp.fd
        || lp.fd != le.args.fd
        || rp.fd != re.args.fd
        || lp.fd_generation.is_none()
        || lp.fd_generation != rp.fd_generation
        || record.process_incarnation != Some(lp.process_incarnation)
        || record.fd != lp.fd
        || record.fd_generation != lp.fd_generation
        || record.left_kernel_ordinal != Some(lp.kernel_ordinal)
        || record.right_kernel_ordinal != Some(rp.kernel_ordinal)
    {
        return false;
    }
    let fd = lp.fd.unwrap();
    let generation = lp.fd_generation.unwrap();
    let matching_checkpoints = validated
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            if let LossCertEnvelopeV2::Checkpoint {
                checkpoint_id,
                processes,
            } = item
            {
                (*checkpoint_id == record.checkpoint_ids[0]).then_some((index, processes))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if matching_checkpoints.len() != 1 {
        return false;
    }
    let (ci, processes) = matching_checkpoints[0];
    if ci <= ri {
        return false;
    }
    let Some(process) = processes
        .iter()
        .find(|p| p.process_incarnation == lp.process_incarnation)
    else {
        return false;
    };
    if !checkpoint_supports(process, le.process.tid, rp.kernel_ordinal, fd, generation)
        || record.checkpoint_high_water != Some(process.high_water[0].kernel_ordinal)
    {
        return false;
    }
    for item in &validated[(li + 1)..=ci] {
        match item {
            LossCertEnvelopeV2::Event { event, proof }
                if proof.process_incarnation == lp.process_incarnation =>
            {
                if event.process.tid != le.process.tid
                    || !proof.state_valid
                    || proof.invalidation_reason.is_some()
                    || !supported_operation(&event.syscall.name, event.syscall.nr)
                    || (event.seq != record.right_event_seq && mutates_binding(&event.syscall.name))
                {
                    return false;
                }
            }
            LossCertEnvelopeV2::Checkpoint { processes, .. } => {
                if processes.iter().any(|p| {
                    p.process_incarnation == lp.process_incarnation
                        && (p.invalidation_reason.is_some()
                            || p.descriptors.iter().any(|d| d.fd == fd && !d.state_valid))
                }) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}
