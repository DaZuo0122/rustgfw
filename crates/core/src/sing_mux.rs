//! Visible sing-mux h2mux selector and padding wrapper.
use std::collections::HashMap;

use crate::{
    http2::{DataEvent, Http2Conversation},
    inspect::{Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch},
    sing_mux_request::StreamRequest,
};

pub const FIELDS: &[&str] = &["sing_mux.version", "sing_mux.protocol", "sing_mux.padding"];
const PADDED_WRITES: u8 = 16;
const H2_STREAM_FIELDS: &[&str] = &[
    "http2.stream_id",
    "http2.method",
    "http2.path",
    "http2.authority",
    "http2.status",
    "sing_mux.stream_id",
    "sing_mux.frame",
    "sing_mux.network",
    "sing_mux.host",
    "sing_mux.port",
];

#[derive(Default)]
pub(crate) struct Padding {
    buffer: Vec<u8>,
    writes: u8,
}

impl Padding {
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.buffer.extend_from_slice(bytes);
        let mut output = Vec::new();
        while self.writes < PADDED_WRITES && self.buffer.len() >= 4 {
            let data = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
            let padding = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize;
            let size = 4 + data + padding;
            if self.buffer.len() < size {
                break;
            }
            output.extend_from_slice(&self.buffer[4..4 + data]);
            self.buffer.drain(..size);
            self.writes += 1;
        }
        if self.writes == PADDED_WRITES {
            output.append(&mut self.buffer);
        }
        output
    }
}

#[derive(Default)]
pub(crate) struct Selector {
    buffer: Vec<u8>,
    pub(crate) selected: bool,
    pub(crate) version: u8,
    pub(crate) protocol: u8,
    pub(crate) padding: bool,
    pub(crate) finished: bool,
}

impl Selector {
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(bytes);
        let version = *self.buffer.first()?;
        if version > 1 {
            self.finished = true;
            return None;
        }
        let protocol = *self.buffer.get(1)?;
        if protocol > 2 {
            self.finished = true;
            return None;
        }
        let (header, padding) = if version == 0 {
            (2, false)
        } else {
            let flag = *self.buffer.get(2)?;
            if flag > 1 {
                self.finished = true;
                return None;
            }
            if flag == 0 {
                (3, false)
            } else {
                let length =
                    u16::from_be_bytes([*self.buffer.get(3)?, *self.buffer.get(4)?]) as usize;
                (5 + length, true)
            }
        };
        if self.buffer.len() < header {
            return None;
        }
        self.selected = true;
        self.version = version;
        self.protocol = protocol;
        self.padding = padding;
        Some(std::mem::take(&mut self.buffer).split_off(header))
    }
}

#[derive(Default)]
struct H2Stream {
    headers: Vec<Observation>,
    request: StreamRequest,
}

pub struct SingMuxH2 {
    selector: Selector,
    padded: [Padding; 2],
    http2: Http2Conversation,
    streams: HashMap<u32, H2Stream>,
    announced: bool,
    finished: bool,
}

impl Default for SingMuxH2 {
    fn default() -> Self {
        let mut http2 = Http2Conversation::default();
        http2.capture_data();
        Self {
            selector: Selector::default(),
            padded: Default::default(),
            http2,
            streams: HashMap::new(),
            announced: false,
            finished: false,
        }
    }
}

impl SingMuxH2 {
    fn metadata(&self) -> ObservationBatch {
        ObservationBatch {
            clear_fields: &[],
            context: Vec::new(),
            observations: vec![
                Observation {
                    field: "sing_mux.version",
                    value: self.selector.version.to_string(),
                },
                Observation {
                    field: "sing_mux.protocol",
                    value: "h2mux".into(),
                },
                Observation {
                    field: "sing_mux.padding",
                    value: self.selector.padding.to_string(),
                },
            ],
            provisional: false,
        }
    }

    fn header(&mut self, mut batch: ObservationBatch) -> ObservationBatch {
        let stream = batch
            .observations
            .iter()
            .find(|item| item.field == "http2.stream_id")
            .and_then(|item| item.value.parse::<u32>().ok());
        if let Some(stream) = stream {
            let connect = batch
                .observations
                .iter()
                .any(|item| item.field == "http2.method" && item.value == "CONNECT")
                && batch
                    .observations
                    .iter()
                    .any(|item| item.field == "http2.authority" && item.value == "localhost");
            if connect {
                self.streams.insert(
                    stream,
                    H2Stream {
                        headers: batch.observations.clone(),
                        request: StreamRequest::default(),
                    },
                );
            }
            if batch
                .observations
                .iter()
                .any(|item| item.field == "http2.status")
                && let Some(target) = self
                    .streams
                    .get(&stream)
                    .and_then(|state| state.request.target())
            {
                batch.context.extend(target.observations());
            }
            batch.observations.push(Observation {
                field: "sing_mux.stream_id",
                value: stream.to_string(),
            });
        }
        batch.clear_fields = H2_STREAM_FIELDS;
        batch
    }

    fn data(&mut self, event: DataEvent) -> Option<ObservationBatch> {
        if event.reverse {
            return None;
        }
        let state = self.streams.get_mut(&event.stream)?;
        let target = state.request.feed(&event.bytes).ok()??;
        let mut observations = target.observations();
        observations.push(Observation {
            field: "sing_mux.stream_id",
            value: event.stream.to_string(),
        });
        Some(ObservationBatch {
            clear_fields: H2_STREAM_FIELDS,
            context: state.headers.clone(),
            observations,
            provisional: false,
        })
    }
}

impl BidirectionalStreamAnalyzer for SingMuxH2 {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        let input = if self.selector.selected {
            bytes.to_vec()
        } else if reverse {
            return Analysis::Pending;
        } else {
            match self.selector.feed(bytes) {
                Some(bytes) => bytes,
                None => {
                    return if self.selector.finished {
                        Analysis::Finished
                    } else {
                        Analysis::Pending
                    };
                }
            }
        };
        if self.selector.protocol != 2 {
            self.finished = true;
            return Analysis::Finished;
        }
        let input = if self.selector.padding {
            self.padded[usize::from(reverse)].feed(&input)
        } else {
            input
        };
        let result = self.http2.feed(&input, reverse);
        let data_events = self.http2.take_data_events();
        let finished_streams = self.http2.take_finished_streams();
        let mut batches = Vec::new();
        if self.http2.recognized() && !self.announced && !matches!(result, Analysis::Finished) {
            batches.push(self.metadata());
            self.announced = true;
        }
        match result {
            Analysis::Batches {
                batches: headers,
                finished,
            } => {
                let mut data = data_events.into_iter().peekable();
                for (index, header) in headers.into_iter().enumerate() {
                    while data.peek().is_some_and(|event| event.before_batch == index) {
                        if let Some(batch) = self.data(data.next().unwrap()) {
                            batches.push(batch);
                        }
                    }
                    batches.push(self.header(header));
                }
                for event in data {
                    if let Some(batch) = self.data(event) {
                        batches.push(batch);
                    }
                }
                self.finished = finished;
            }
            Analysis::Finished => self.finished = true,
            Analysis::Pending => {
                for event in data_events {
                    if let Some(batch) = self.data(event) {
                        batches.push(batch);
                    }
                }
            }
            Analysis::Observations(_) | Analysis::FinalObservations(_) => unreachable!(),
        }
        for stream in finished_streams {
            self.streams.remove(&stream);
        }
        if batches.is_empty() {
            if self.finished {
                Analysis::Finished
            } else {
                Analysis::Pending
            }
        } else {
            Analysis::Batches {
                batches,
                finished: self.finished,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, payload.len() as u8, kind, flags];
        bytes.extend(stream.to_be_bytes());
        bytes.extend(payload);
        bytes
    }

    fn request() -> Vec<u8> {
        let mut block = vec![0x02, 7];
        block.extend(b"CONNECT");
        block.extend([0x01, 9]);
        block.extend(b"localhost");
        block
    }

    fn target_request(host: &str) -> Vec<u8> {
        let mut bytes = vec![0, 0, 3, host.len() as u8];
        bytes.extend(host.as_bytes());
        bytes.extend(443u16.to_be_bytes());
        bytes
    }

    fn client() -> Vec<u8> {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend(frame(4, 0, 0, &[]));
        bytes.extend(frame(1, 4, 1, &request()));
        bytes
    }

    fn batches(result: Analysis) -> Vec<ObservationBatch> {
        match result {
            Analysis::Batches { batches, .. } => batches,
            other => panic!("expected batches, got {other:?}"),
        }
    }

    fn value<'a>(batch: &'a ObservationBatch, field: &str) -> Option<&'a str> {
        batch
            .observations
            .iter()
            .find(|item| item.field == field)
            .map(|item| item.value.as_str())
    }

    #[test]
    fn selector_is_confirmed_by_h2_preface_and_preserves_stream_context() {
        let mut analyzer = SingMuxH2::default();
        let mut bytes = vec![0, 2];
        bytes.extend(client());
        let events = batches(analyzer.feed(&bytes, false));
        assert_eq!(value(&events[0], "sing_mux.protocol"), Some("h2mux"));
        assert_eq!(value(&events[1], "http2.method"), Some("CONNECT"));
        assert_eq!(value(&events[1], "http2.authority"), Some("localhost"));

        let mut response = frame(4, 0, 0, &[]);
        response.extend(frame(1, 5, 1, &[0x8d]));
        let replies = batches(analyzer.feed(&response, true));
        assert_eq!(
            replies[0]
                .context
                .iter()
                .find(|item| item.field == "http2.authority")
                .map(|item| item.value.as_str()),
            Some("localhost")
        );
        assert_eq!(value(&replies[0], "http2.status"), Some("404"));
    }

    #[test]
    fn padded_version_one_selector_handles_split_outer_write() {
        let mut analyzer = SingMuxH2::default();
        let inner = client();
        let mut bytes = vec![1, 2, 1, 0, 3, 7, 8, 9];
        bytes.extend((inner.len() as u16).to_be_bytes());
        bytes.extend(3u16.to_be_bytes());
        bytes.extend(&inner);
        bytes.extend([4, 5, 6]);
        assert!(matches!(
            analyzer.feed(&bytes[..6], false),
            Analysis::Pending
        ));
        assert!(matches!(
            analyzer.feed(&bytes[6..20], false),
            Analysis::Pending
        ));
        let events = batches(analyzer.feed(&bytes[20..], false));
        assert_eq!(value(&events[0], "sing_mux.version"), Some("1"));
        assert_eq!(value(&events[0], "sing_mux.padding"), Some("true"));
        assert_eq!(value(&events[1], "http2.authority"), Some("localhost"));
    }

    #[test]
    fn unconfirmed_selector_does_not_publish_mux_facts() {
        let mut analyzer = SingMuxH2::default();
        assert!(matches!(
            analyzer.feed(&[0, 2, 0, 0, 0, 0], false),
            Analysis::Pending
        ));
        assert!(!analyzer.announced);
    }

    #[test]
    fn h2_data_request_restores_the_right_stream_target() {
        let mut analyzer = SingMuxH2::default();
        let mut bytes = vec![0, 2];
        bytes.extend(client());
        bytes.extend(frame(1, 4, 3, &request()));
        let opening = batches(analyzer.feed(&bytes, false));
        assert_eq!(opening.len(), 3);

        let target_one = target_request("example.org");
        let mut padded_first = vec![2];
        padded_first.extend(&target_one[..5]);
        padded_first.extend([9, 10]);
        assert!(matches!(
            analyzer.feed(&frame(0, 8, 1, &padded_first), false),
            Analysis::Pending
        ));

        let other = batches(analyzer.feed(&frame(0, 0, 3, &target_request("other.test")), false));
        assert_eq!(value(&other[0], "sing_mux.host"), Some("other.test"));
        let matched = batches(analyzer.feed(&frame(0, 0, 1, &target_one[5..]), false));
        assert_eq!(value(&matched[0], "sing_mux.host"), Some("example.org"));
        assert_eq!(value(&matched[0], "sing_mux.stream_id"), Some("1"));
        assert_eq!(
            matched[0]
                .context
                .iter()
                .find(|item| item.field == "http2.method")
                .map(|item| item.value.as_str()),
            Some("CONNECT")
        );

        let mut response = frame(4, 0, 0, &[]);
        response.extend(frame(1, 5, 3, &[0x88]));
        response.extend(frame(1, 5, 1, &[0x8d]));
        let reply = batches(analyzer.feed(&response, true));
        assert_eq!(
            reply[0]
                .context
                .iter()
                .find(|item| item.field == "sing_mux.host")
                .map(|item| item.value.as_str()),
            Some("other.test")
        );
        assert_eq!(
            reply[1]
                .context
                .iter()
                .find(|item| item.field == "sing_mux.host")
                .map(|item| item.value.as_str()),
            Some("example.org")
        );
    }

    #[test]
    fn h2_headers_and_data_keep_wire_order_within_one_tcp_chunk() {
        let mut analyzer = SingMuxH2::default();
        let mut input = vec![0, 2];
        input.extend(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        input.extend(frame(4, 0, 0, &[]));
        input.extend(frame(1, 4, 1, &request()));
        input.extend(frame(0, 0, 1, &target_request("one.test")));
        input.extend(frame(1, 4, 3, &request()));
        input.extend(frame(0, 0, 3, &target_request("two.test")));
        let events = batches(analyzer.feed(&input, false));
        assert_eq!(events.len(), 5);
        assert_eq!(value(&events[2], "sing_mux.host"), Some("one.test"));
        assert_eq!(value(&events[4], "sing_mux.host"), Some("two.test"));
    }
}
