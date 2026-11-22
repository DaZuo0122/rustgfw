use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn request(host: &str) -> Vec<u8> {
    // HTTP/3 HEADERS with a QPACK static :method GET and literal :authority.
    let mut block = vec![0, 0, 0xd1, 0x50, host.len() as u8];
    block.extend(host.as_bytes());
    let mut frame = vec![1, block.len() as u8];
    frame.extend(block);
    frame
}

fn input(stream_id: u64, bytes: Vec<u8>) -> Value {
    json!({
        "event": "data", "scope": 42, "stream_id": stream_id,
        "origin": "192.0.2.1:12345", "target": "198.51.100.2:443",
        "reverse": false, "bytes": bytes,
    })
}

#[test]
fn cli_routes_two_http3_requests_through_expression_rules() {
    let rules = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/decoded-http3-rules.json"
    );
    let mut process = Command::new(env!("CARGO_BIN_EXE_rustgfw"))
        .arg("decoded-http3")
        .arg(format!("rules-file={rules}"))
        .env("RUST_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let records = [
        input(2, vec![0, 4, 0]), // client control stream and empty SETTINGS
        input(0, request("allowed.test")),
        input(4, request("blocked.test")),
        json!({ "event": "close_stream", "scope": 42, "stream_id": 0 }),
        json!({ "event": "close_connection", "scope": 42 }),
    ];
    {
        let stdin = process.stdin.as_mut().unwrap();
        for record in records {
            writeln!(stdin, "{record}").unwrap();
        }
    }
    let result = process.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    let decisions = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        decisions,
        vec![
            json!({"scope":"42","stream_id":0,"verdict":"accept"}),
            json!({"scope":"42","stream_id":4,"verdict":"drop_flow"}),
        ]
    );
}
