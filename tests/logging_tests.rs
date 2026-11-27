use rustgfw_core::{
    ConstantPolicy, FlowScope, Packet, Policy, Verdict,
    conditions::parse_expression,
    http::HttpConversation,
    inspect::{BidirectionalAnalyzerRule, DecodedStream, Inspect},
    rule_graph::{RuleGraph, RuleSpec},
};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn dependent_rule_logs_first_hits_and_final_action_without_payload() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || Capture(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let graph = RuleGraph::compile(vec![
            RuleSpec {
                id: "decision".into(),
                condition: parse_expression("payload == trigger").unwrap(),
                requires: Some("marker".into()),
                scope: None,
                action: Some(rustgfw_core::inspect::FlowAction::DropPacket),
                priority: 2,
            },
            RuleSpec {
                id: "marker".into(),
                condition: parse_expression("payload == private-secret").unwrap(),
                requires: None,
                scope: None,
                action: None,
                priority: 3,
            },
        ])
        .unwrap();
        let mut inspect = Inspect::with_analyzers(ConstantPolicy(Verdict::Accept), Vec::new())
            .with_rule_graph(graph);
        let udp = |payload: &[u8]| {
            let mut bytes = vec![0; 28 + payload.len()];
            let total_len = bytes.len() as u16;
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
            bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
            bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
            bytes[22..24].copy_from_slice(&443u16.to_be_bytes());
            bytes[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
            bytes[28..].copy_from_slice(payload);
            bytes
        };
        for (payload, expected) in [
            (b"private-secret".as_slice(), Verdict::Accept),
            (b"private-secret".as_slice(), Verdict::Accept),
            (b"trigger".as_slice(), Verdict::Drop),
        ] {
            let bytes = udp(payload);
            assert_eq!(
                inspect.evaluate(Packet {
                    bytes: &bytes,
                    original_len: bytes.len(),
                    checksum_ready: true,
                    scope: FlowScope(7),
                    capture_time: None,
                }),
                expected
            );
        }
    });
    let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(!output.contains("private-secret"));
    let events = output
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .filter(|event| event["fields"]["message"] == "rule hit recorded"
                && event["fields"]["rule_id"] == "marker")
            .count(),
        1
    );
    let decision = events
        .iter()
        .find(|event| event["fields"]["message"] == "UDP packet dropped")
        .unwrap();
    assert_eq!(decision["fields"]["rule_id"], "decision");
    assert_eq!(decision["fields"]["via"], "marker");
    assert_eq!(decision["fields"]["priority"], 2);
    assert_eq!(decision["fields"]["event_seq"], 3);
}

#[test]
fn decoded_block_emits_a_structured_event_without_payload() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || Capture(writer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut inspect =
            Inspect::with_analyzers((), Vec::new()).with_bidirectional_analyzers(vec![
                BidirectionalAnalyzerRule::exact(
                    "http.host",
                    vec!["blocked.test".into()],
                    None,
                    || Box::<HttpConversation>::default(),
                )
                .unwrap(),
            ]);
        let verdict = inspect.feed_decoded(DecodedStream {
            scope: FlowScope(7),
            stream_id: 11,
            origin: "192.0.2.1:12345".parse().unwrap(),
            target: "198.51.100.2:80".parse().unwrap(),
            reverse: false,
            bytes: b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
        });
        assert_eq!(verdict, Verdict::DropFlow);
    });
    let text = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    let event: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(event["fields"]["message"], "decoded TCP stream blocked");
    assert_eq!(event["fields"]["scope"], "7");
    assert_eq!(event["fields"]["stream_id"], 11);
    assert!(!text.contains("blocked.test"));
}
