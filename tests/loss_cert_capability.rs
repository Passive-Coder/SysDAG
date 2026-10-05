use std::process::Command;

#[test]
fn requested_native_certification_fails_before_creating_output() {
    let output = std::env::temp_dir().join(format!(
        "sysdag-loss-cert-unavailable-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let result = Command::new(env!("CARGO_BIN_EXE_sysdag"))
        .args([
            "collect-ebpf",
            "--object",
            "/nonexistent/sysdag-cert.bpf.o",
            "--output",
        ])
        .arg(&output)
        .args(["--loss-certification", "--duration-secs", "1"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("UNAVAILABLE("));
    assert!(!output.exists());
}
