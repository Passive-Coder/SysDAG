use sysdag::ebpf::EbpfEnvelope;
use sysdag::loss_cert_protocol::{LossCertEnvelopeV2, LossCertProtocolError, LossCertStreamParser};

fn event(seq: u64, ordinal: u64) -> String {
    format!(
        r#"{{"kind":"event","event":{{"schema_version":"1.0","process":{{"pid":123,"tid":123}},"seq":{seq},"enter_ns":1,"exit_ns":2,"syscall":{{"nr":0,"name":"read","arch":"x86_64"}},"args":{{"fd":3}},"ret":1,"errno":null,"labels":{{"family":"file","op":"FILE_READ","result":"SUCCESS","resource_kind":"FILE","flags":"NONE","bytes":"TINY","path_class":"APP"}},"capture":{{"source":"ebpf"}}}},"proof":{{"process_incarnation":42,"kernel_ordinal":{ordinal},"fd":3,"fd_generation":7,"state_valid":true}}}}"#
    )
}

const HEADER: &str = r#"{"kind":"header","protocol_version":2,"collector_build":"test-build","capability":"available"}"#;

#[test]
fn valid_stream_round_trips_and_preserves_trace_event() {
    let mut parser = LossCertStreamParser::new();
    assert!(matches!(
        parser.parse_jsonl(HEADER).unwrap(),
        LossCertEnvelopeV2::Header { .. }
    ));
    let original: serde_json::Value = serde_json::from_str(&event(4, 1)).unwrap();
    let normalized: sysdag::event::TraceEvent =
        serde_json::from_value(original["event"].clone()).unwrap();
    let parsed = parser.parse_jsonl(&event(4, 1)).unwrap();
    let encoded = serde_json::to_value(parsed).unwrap();
    assert_eq!(encoded["event"], serde_json::to_value(normalized).unwrap());
    parser.parse_jsonl(r#"{"kind":"lost","count":2}"#).unwrap();
    parser.parse_jsonl(&event(5, 3)).unwrap();
    parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[{"tid":123,"kernel_ordinal":3}],"descriptors":[{"fd":3,"generation":7,"state_valid":true}]}]}"#).unwrap();
}

#[test]
fn legacy_encoding_and_parser_are_unchanged() {
    let legacy = r#"{"kind":"lost","count":2}"#;
    let parsed = EbpfEnvelope::parse_jsonl(legacy).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), legacy);
    let legacy_event: serde_json::Value = serde_json::from_str(&event(4, 1)).unwrap();
    let raw = serde_json::json!({"kind":"event","event":legacy_event["event"]}).to_string();
    let parsed = EbpfEnvelope::parse_jsonl(&raw).unwrap();
    let old_event: sysdag::event::TraceEvent =
        serde_json::from_value(legacy_event["event"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(parsed).unwrap()["event"],
        serde_json::to_value(old_event).unwrap()
    );
}

#[test]
fn stream_requires_header_and_rejects_mixed_versions() {
    let mut parser = LossCertStreamParser::new();
    assert!(matches!(
        parser.parse_jsonl(&event(4, 1)),
        Err(LossCertProtocolError::MissingHeader)
    ));
    parser.parse_jsonl(HEADER).unwrap();
    assert!(matches!(
        parser.parse_jsonl(HEADER),
        Err(LossCertProtocolError::DuplicateHeader)
    ));
    assert!(parser.parse_jsonl(r#"{"kind":"header","protocol_version":1,"collector_build":"x","capability":"available"}"#).is_err());
    assert!(parser
        .parse_jsonl(r#"{"kind":"event","event":{}}"#)
        .is_err());
}

#[test]
fn ordinals_and_checkpoint_ids_are_strictly_increasing() {
    let mut parser = LossCertStreamParser::new();
    parser.parse_jsonl(HEADER).unwrap();
    parser.parse_jsonl(&event(4, 2)).unwrap();
    assert!(matches!(
        parser.parse_jsonl(&event(5, 2)),
        Err(LossCertProtocolError::OrdinalRegression { .. })
    ));
    assert!(matches!(
        parser.parse_jsonl(&event(5, 1)),
        Err(LossCertProtocolError::OrdinalRegression { .. })
    ));
    parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":2,"processes":[{"process_incarnation":42,"high_water":[{"tid":123,"kernel_ordinal":2}],"descriptors":[]}]}"#).unwrap();
    assert!(matches!(
        parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":2,"processes":[]}"#),
        Err(LossCertProtocolError::CheckpointRegression { .. })
    ));
    assert!(matches!(
        parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[]}"#),
        Err(LossCertProtocolError::CheckpointRegression { .. })
    ));
}

#[test]
fn bad_loss_metadata_and_unknown_fields_fail_closed() {
    let mut parser = LossCertStreamParser::new();
    parser.parse_jsonl(HEADER).unwrap();
    for line in [
        r#"{"kind":"lost","count":0}"#,
        r#"{"kind":"lost","count":1,"extra":1}"#,
        r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[],"extra":1}"#,
        r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[],"descriptors":[{"fd":-1,"generation":1,"state_valid":true}]}]}"#,
    ] {
        assert!(parser.parse_jsonl(line).is_err(), "{line}");
    }
    let zero_generation = event(4, 1).replace("\"fd_generation\":7", "\"fd_generation\":0");
    assert!(parser.parse_jsonl(&zero_generation).is_err());
    let unknown_proof =
        event(4, 1).replace("\"state_valid\":true", "\"state_valid\":true,\"extra\":1");
    assert!(parser.parse_jsonl(&unknown_proof).is_err());
}

#[test]
fn unavailable_header_cannot_carry_proof_records() {
    let mut parser = LossCertStreamParser::new();
    parser
        .parse_jsonl(
            r#"{"kind":"header","protocol_version":2,"collector_build":"test-build","capability":"unavailable"}"#,
        )
        .unwrap();
    assert!(parser.parse_jsonl(&event(4, 1)).is_err());
    assert!(parser
        .parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[]}"#)
        .is_err());
}

#[test]
fn checkpoint_high_water_cannot_move_backwards() {
    let mut parser = LossCertStreamParser::new();
    parser.parse_jsonl(HEADER).unwrap();
    parser.parse_jsonl(&event(4, 3)).unwrap();
    assert!(matches!(
        parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[{"tid":123,"kernel_ordinal":2}],"descriptors":[]}]}"#),
        Err(LossCertProtocolError::OrdinalRegression { .. })
    ));
    parser.parse_jsonl(r#"{"kind":"checkpoint","checkpoint_id":1,"processes":[{"process_incarnation":42,"high_water":[{"tid":123,"kernel_ordinal":4}],"descriptors":[]}]}"#).unwrap();
    assert!(matches!(
        parser.parse_jsonl(&event(5, 4)),
        Err(LossCertProtocolError::OrdinalRegression { .. })
    ));
    parser.parse_jsonl(&event(5, 5)).unwrap();
}
