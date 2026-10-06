use sysdag::loss_cert::{verify_certificate, CertificateStatus, LossCertVerifier};
use sysdag::loss_cert_protocol::{LossCertEnvelopeV2, LossCertStreamParser};

const HEADER: &str = r#"{"kind":"header","protocol_version":2,"collector_build":"synthetic-test","capability":"available"}"#;

fn event(seq: u64, ordinal: u64, incarnation: u64, fd: i32, generation: u64, name: &str) -> String {
    let number = match name {
        "read" => 0,
        "write" => 1,
        "open" => 2,
        "close" => 3,
        "dup" => 32,
        "dup2" => 33,
        "socket" => 41,
        "accept" => 43,
        "sendto" => 44,
        "recvfrom" => 45,
        "openat" => 257,
        "accept4" => 288,
        "dup3" => 292,
        _ => 999,
    };
    format!(
        r#"{{"kind":"event","event":{{"schema_version":"1.0","process":{{"pid":123,"tid":123}},"seq":{seq},"enter_ns":1,"exit_ns":2,"syscall":{{"nr":{number},"name":"{name}","arch":"x86_64"}},"args":{{"fd":{fd}}},"ret":1,"errno":null,"labels":{{"family":"file","op":"FILE_READ","result":"SUCCESS","resource_kind":"FILE","flags":"NONE","bytes":"TINY","path_class":"APP"}},"capture":{{"source":"ebpf"}}}},"proof":{{"process_incarnation":{incarnation},"kernel_ordinal":{ordinal},"fd":{fd},"fd_generation":{generation},"state_valid":true}}}}"#
    )
}

fn checkpoint(id: u64, ordinal: u64, incarnation: u64, fd: i32, generation: u64) -> String {
    format!(
        r#"{{"kind":"checkpoint","checkpoint_id":{id},"processes":[{{"process_incarnation":{incarnation},"high_water":[{{"tid":123,"kernel_ordinal":{ordinal}}}],"descriptors":[{{"fd":{fd},"generation":{generation},"state_valid":true}}]}}]}}"#
    )
}

fn parsed(lines: &[String]) -> Vec<LossCertEnvelopeV2> {
    let mut parser = LossCertStreamParser::new();
    lines
        .iter()
        .map(|line| parser.parse_jsonl(line).unwrap())
        .collect()
}

fn certify(lines: &[String], left: u64, right: u64) -> (CertificateStatus, bool) {
    let envelopes = parsed(lines);
    let mut verifier = LossCertVerifier::new(64);
    for envelope in envelopes.iter().cloned() {
        verifier.ingest(envelope);
    }
    let record = verifier.certify_pair(left, right);
    let independently_verified = verify_certificate(&record, &envelopes);
    (record.status, independently_verified)
}

#[test]
fn checkpoint_supports_same_binding_across_unrelated_loss() {
    let lines = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        r#"{"kind":"lost","count":1}"#.into(),
        event(2, 3, 42, 3, 7, "write"),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2), (CertificateStatus::Certified, true));
}

#[test]
fn replacement_reincarnation_and_bad_checkpoint_never_certify() {
    let cases = [
        ("dropped close and reopen", event(2, 4, 42, 3, 9, "write"), checkpoint(1, 4, 42, 3, 9)),
        ("pid reuse", event(2, 2, 43, 3, 7, "write"), checkpoint(1, 2, 43, 3, 7)),
        ("checkpoint omits thread", event(2, 3, 42, 3, 7, "write"), r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[],"descriptors":[{"fd":3,"generation":7,"state_valid":true}]}]}"#.into()),
        ("checkpoint different generation", event(2, 3, 42, 3, 7, "write"), checkpoint(1, 3, 42, 3, 8)),
    ];
    for (label, second, proof) in cases {
        let lines = vec![HEADER.into(), event(1, 1, 42, 3, 7, "read"), second, proof];
        assert_eq!(
            certify(&lines, 1, 2).0,
            CertificateStatus::Unresolved,
            "{label}"
        );
    }
}

#[test]
fn unsupported_operation_invalidates_span() {
    let unsupported = event(3, 2, 42, 8, 1, "fcntl");
    let lines = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        unsupported,
        event(2, 3, 42, 3, 7, "write"),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
}

#[test]
fn intervening_descriptor_mutation_is_unresolved_even_if_proof_names_another_fd() {
    let lines = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        event(3, 2, 42, 8, 1, "dup2"),
        event(2, 3, 42, 3, 7, "write"),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
}

#[test]
fn independently_replayed_certificate_rejects_tampering() {
    let lines = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        event(2, 2, 42, 3, 7, "write"),
        checkpoint(1, 2, 42, 3, 7),
    ];
    let envelopes = parsed(&lines);
    let mut verifier = LossCertVerifier::new(64);
    for envelope in envelopes.iter().cloned() {
        verifier.ingest(envelope);
    }
    let certificate = verifier.certify_pair(1, 2);
    assert_eq!(certificate.status, CertificateStatus::Certified);
    assert!(verify_certificate(&certificate, &envelopes));
    let mut tampered = lines.clone();
    tampered[3] = checkpoint(1, 2, 42, 3, 8);
    assert!(!verify_certificate(&certificate, &parsed(&tampered)));
    let mut tampered = lines;
    tampered[2] = event(2, 3, 42, 3, 7, "write");
    tampered[3] = checkpoint(1, 3, 42, 3, 7);
    assert!(!verify_certificate(&certificate, &parsed(&tampered)));
    let mut tampered = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        event(2, 2, 42, 3, 7, "write"),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert!(!verify_certificate(&certificate, &parsed(&tampered)));
    tampered[3] = checkpoint(2, 2, 42, 3, 7);
    assert!(!verify_certificate(&certificate, &parsed(&tampered)));
}

#[test]
fn failure_and_invalidation_reasons_fail_closed() {
    let first = event(1, 1, 42, 3, 7, "read");
    let second = event(2, 3, 42, 3, 7, "write");
    let failed = event(1, 1, 42, 3, 7, "open")
        .replace("\"ret\":1", "\"ret\":-1,\"errno\":\"EBADF\"")
        .replace(",\"errno\":null", "");
    let lines = vec![
        HEADER.into(),
        failed,
        second.clone(),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
    let right_replacement = event(2, 3, 42, 3, 7, "open").replace("\"ret\":1", "\"ret\":3");
    let lines = vec![
        HEADER.into(),
        first.clone(),
        right_replacement,
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);

    for reason in [
        "fork",
        "exec",
        "shared_fd_table",
        "map_failure",
        "counter_wrap",
        "state_evicted",
        "ordering_ambiguous",
    ] {
        let invalid = event(3, 2, 42, 8, 1, "read").replace(
            "\"state_valid\":true",
            &format!("\"state_valid\":false,\"invalidation_reason\":\"{reason}\""),
        );
        let lines = vec![
            HEADER.into(),
            first.clone(),
            invalid,
            second.clone(),
            checkpoint(1, 3, 42, 3, 7),
        ];
        assert_eq!(
            certify(&lines, 1, 2).0,
            CertificateStatus::Unresolved,
            "{reason}"
        );
    }
}

#[test]
fn thread_sharing_and_retention_limit_fail_closed() {
    let other_thread = event(3, 2, 42, 8, 1, "read").replace("\"tid\":123", "\"tid\":124");
    let lines = vec![
        HEADER.into(),
        event(1, 1, 42, 3, 7, "read"),
        other_thread,
        event(2, 3, 42, 3, 7, "write"),
        checkpoint(1, 3, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
    let envelopes = parsed(&lines);
    let mut verifier = LossCertVerifier::new(2);
    for envelope in envelopes {
        verifier.ingest(envelope);
    }
    assert_eq!(
        verifier.certify_pair(1, 2).status,
        CertificateStatus::Unresolved
    );
}

#[test]
fn proof_fd_and_syscall_number_must_match_observed_use() {
    let first = event(1, 1, 42, 3, 7, "read");
    let mismatched_fd =
        event(2, 2, 42, 3, 7, "write").replace("\"args\":{\"fd\":3}", "\"args\":{\"fd\":4}");
    let lines = vec![
        HEADER.into(),
        first.clone(),
        mismatched_fd,
        checkpoint(1, 2, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
    let mismatched_number = event(2, 2, 42, 3, 7, "write").replace("\"nr\":1", "\"nr\":0");
    let lines = vec![
        HEADER.into(),
        first,
        mismatched_number,
        checkpoint(1, 2, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
}

#[test]
fn unknown_collector_build_cannot_issue_positive_certificate() {
    let header = HEADER.replace("synthetic-test", "unverified-native-build");
    let lines = vec![
        header,
        event(1, 1, 42, 3, 7, "read"),
        event(2, 2, 42, 3, 7, "write"),
        checkpoint(1, 2, 42, 3, 7),
    ];
    assert_eq!(certify(&lines, 1, 2).0, CertificateStatus::Unresolved);
}

#[test]
fn exhaustive_small_generation_model_has_no_false_positive() {
    for left_gen in 1..=2 {
        for right_gen in 1..=2 {
            for checkpoint_gen in 1..=2 {
                for loss in [false, true] {
                    let mut lines = vec![HEADER.into(), event(1, 1, 42, 3, left_gen, "read")];
                    if loss {
                        lines.push(r#"{"kind":"lost","count":1}"#.into());
                    }
                    lines.push(event(
                        2,
                        if loss { 3 } else { 2 },
                        42,
                        3,
                        right_gen,
                        "write",
                    ));
                    lines.push(checkpoint(
                        1,
                        if loss { 3 } else { 2 },
                        42,
                        3,
                        checkpoint_gen,
                    ));
                    let expected = if left_gen == right_gen && right_gen == checkpoint_gen {
                        CertificateStatus::Certified
                    } else {
                        CertificateStatus::Unresolved
                    };
                    assert_eq!(certify(&lines, 1, 2).0, expected);
                }
            }
        }
    }
}
