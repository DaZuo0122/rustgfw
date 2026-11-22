use rustgfw_core::{
    FlowScope, Verdict,
    http::HttpConversation,
    inspect::{BidirectionalAnalyzerRule, DecodedStream, Inspect},
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
