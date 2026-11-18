//! Visible sing-mux h2mux selector and padding wrapper.
use crate::{
    http2::Http2Conversation,
    inspect::{Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch},
};

pub const FIELDS: &[&str] = &["sing_mux.version", "sing_mux.protocol", "sing_mux.padding"];
const PADDED_WRITES: u8 = 16;

#[derive(Default)]
struct Padding {
    buffer: Vec<u8>,
    writes: u8,
}

impl Padding {
    fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
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
pub struct SingMuxH2 {
    selector: Vec<u8>,
    selected: bool,
    version: u8,
    padding: bool,
    padded: [Padding; 2],
    http2: Http2Conversation,
    announced: bool,
    finished: bool,
}

impl SingMuxH2 {
    fn select(&mut self, bytes: &[u8]) -> Option<Vec<u8>> {
        self.selector.extend_from_slice(bytes);
        let version = *self.selector.first()?;
        if version > 1 {
            self.finished = true;
            return None;
        }
        let protocol = *self.selector.get(1)?;
        if protocol != 2 {
            self.finished = true;
            return None;
        }
        let (header, padding) = if version == 0 {
            (2, false)
        } else {
            let flag = *self.selector.get(2)?;
            if flag > 1 {
                self.finished = true;
                return None;
            }
            if flag == 0 {
                (3, false)
            } else {
                let length =
                    u16::from_be_bytes([*self.selector.get(3)?, *self.selector.get(4)?]) as usize;
                (5 + length, true)
            }
        };
        if self.selector.len() < header {
            return None;
        }
        self.selected = true;
        self.version = version;
        self.padding = padding;
        Some(std::mem::take(&mut self.selector).split_off(header))
    }

    fn metadata(&self) -> ObservationBatch {
        ObservationBatch {
            clear_fields: &[],
            context: Vec::new(),
            observations: vec![
                Observation {
                    field: "sing_mux.version",
                    value: self.version.to_string(),
                },
                Observation {
                    field: "sing_mux.protocol",
                    value: "h2mux".into(),
                },
                Observation {
                    field: "sing_mux.padding",
                    value: self.padding.to_string(),
                },
            ],
        }
    }
}

impl BidirectionalStreamAnalyzer for SingMuxH2 {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        let input = if self.selected {
            bytes.to_vec()
        } else if reverse {
            return Analysis::Pending;
        } else {
            match self.select(bytes) {
                Some(bytes) => bytes,
                None => {
                    return if self.finished {
                        Analysis::Finished
                    } else {
                        Analysis::Pending
                    };
                }
            }
        };
        let input = if self.padding {
            self.padded[usize::from(reverse)].feed(&input)
        } else {
            input
        };
        let result = self.http2.feed(&input, reverse);
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
                batches.extend(headers);
                self.finished = finished;
            }
            Analysis::Finished => self.finished = true,
            Analysis::Pending => {}
            Analysis::Observations(_) | Analysis::FinalObservations(_) => unreachable!(),
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
}
