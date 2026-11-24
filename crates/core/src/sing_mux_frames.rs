//! Framing and first request metadata for visible sing-mux smux/yamux sessions.
use std::collections::HashMap;

use crate::{
    inspect::{Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch},
    sing_mux::{Padding, Selector},
    sing_mux_request::StreamRequest,
};

pub const FIELDS: &[&str] = &[
    "sing_mux.stream_id",
    "sing_mux.frame",
    "sing_mux.network",
    "sing_mux.host",
    "sing_mux.port",
];

const MAX_YAMUX_DATA: usize = 1024 * 1024;

struct Frame {
    stream_id: u32,
    kind: &'static str,
    data: Vec<u8>,
    request_data: bool,
    opens: bool,
    fin: bool,
    reset: bool,
}

#[derive(Default)]
struct StreamState {
    request: StreamRequest,
    fin_seen: [bool; 2],
}

#[derive(Default)]
struct Framing {
    buffer: Vec<u8>,
}

impl Framing {
    fn feed(&mut self, bytes: &[u8], protocol: u8) -> Result<Vec<Frame>, ()> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            let header = if protocol == 0 { 8 } else { 12 };
            if self.buffer.len() < header {
                return Ok(frames);
            }
            let (stream_id, kind, data_len, request_data, opens, fin, reset) = if protocol == 0 {
                let version = self.buffer[0];
                let cmd = self.buffer[1];
                if !(1..=2).contains(&version) || cmd > 4 || (version == 1 && cmd == 4) {
                    return Err(());
                }
                let length = u16::from_le_bytes([self.buffer[2], self.buffer[3]]) as usize;
                let stream = u32::from_le_bytes(self.buffer[4..8].try_into().unwrap());
                let name = match cmd {
                    0 => "open",
                    1 => "fin",
                    2 => "data",
                    3 => "noop",
                    _ => "window",
                };
                (stream, name, length, cmd == 2, cmd == 0, cmd == 1, false)
            } else {
                let version = self.buffer[0];
                let kind = self.buffer[1];
                let flags = u16::from_be_bytes([self.buffer[2], self.buffer[3]]);
                let stream = u32::from_be_bytes(self.buffer[4..8].try_into().unwrap());
                let length = u32::from_be_bytes(self.buffer[8..12].try_into().unwrap()) as usize;
                if version != 0
                    || kind > 3
                    || flags & !0x0f != 0
                    || (kind == 0 && length > MAX_YAMUX_DATA)
                {
                    return Err(());
                }
                let name = if kind == 0 || kind == 1 {
                    if flags & 0x01 != 0 {
                        "open"
                    } else if flags & 0x08 != 0 {
                        "reset"
                    } else if flags & 0x04 != 0 {
                        "fin"
                    } else {
                        if kind == 0 { "data" } else { "window" }
                    }
                } else {
                    match kind {
                        2 => "ping",
                        _ => "goaway",
                    }
                };
                (
                    stream,
                    name,
                    if kind == 0 { length } else { 0 },
                    kind == 0,
                    (kind == 0 || kind == 1) && flags & 0x01 != 0,
                    (kind == 0 || kind == 1) && flags & 0x04 != 0,
                    (kind == 0 || kind == 1) && flags & 0x08 != 0,
                )
            };
            let total = header + data_len;
            if self.buffer.len() < total {
                return Ok(frames);
            }
            frames.push(Frame {
                stream_id,
                kind,
                data: self.buffer[header..total].to_vec(),
                request_data,
                opens,
                fin,
                reset,
            });
            self.buffer.drain(..total);
        }
    }
}

fn observation(field: &'static str, value: impl Into<String>) -> Observation {
    Observation {
        field,
        value: value.into(),
    }
}

#[derive(Default)]
pub struct SingMuxFrames {
    selector: Selector,
    padded: [Padding; 2],
    framing: [Framing; 2],
    streams: HashMap<u32, StreamState>,
    announced: bool,
    finished: bool,
}

impl SingMuxFrames {
    fn metadata(&self) -> ObservationBatch {
        ObservationBatch {
            clear_fields: &[],
            context: Vec::new(),
            observations: vec![
                observation("sing_mux.version", self.selector.version.to_string()),
                observation(
                    "sing_mux.protocol",
                    if self.selector.protocol == 0 {
                        "smux"
                    } else {
                        "yamux"
                    },
                ),
                observation("sing_mux.padding", self.selector.padding.to_string()),
            ],
            allow_continues: true,
        }
    }

    fn frame(&mut self, frame: Frame, reverse: bool) -> ObservationBatch {
        let mut observations = vec![
            observation("sing_mux.stream_id", frame.stream_id.to_string()),
            observation("sing_mux.frame", frame.kind),
        ];
        if frame.opens && !reverse && frame.stream_id != 0 {
            self.streams.insert(frame.stream_id, StreamState::default());
        }
        let mut context = Vec::new();
        let mut closed = false;
        if let Some(stream) = self.streams.get_mut(&frame.stream_id) {
            if !reverse && frame.request_data && stream.request.target().is_none() {
                if let Ok(Some(parsed)) = stream.request.feed(&frame.data) {
                    observations.extend(parsed.observations());
                }
            } else if let Some(target) = stream.request.target() {
                context = target.observations();
            }
            if frame.fin {
                stream.fin_seen[usize::from(reverse)] = true;
            }
            closed = frame.reset || stream.fin_seen == [true, true];
        }
        if closed {
            self.streams.remove(&frame.stream_id);
        }
        ObservationBatch {
            clear_fields: FIELDS,
            context,
            observations,
            allow_continues: true,
        }
    }
}

impl BidirectionalStreamAnalyzer for SingMuxFrames {
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
                Some(input) => input,
                None => {
                    return if self.selector.finished {
                        Analysis::Finished
                    } else {
                        Analysis::Pending
                    };
                }
            }
        };
        if self.selector.protocol == 2 {
            self.finished = true;
            return Analysis::Finished;
        }
        let input = if self.selector.padding {
            self.padded[usize::from(reverse)].feed(&input)
        } else {
            input
        };
        let frames = match self.framing[usize::from(reverse)].feed(&input, self.selector.protocol) {
            Ok(frames) => frames,
            Err(()) => {
                self.finished = true;
                return Analysis::Finished;
            }
        };
        if frames.is_empty() {
            return Analysis::Pending;
        }
        let mut batches = Vec::new();
        if !self.announced {
            batches.push(self.metadata());
            self.announced = true;
        }
        for frame in frames {
            batches.push(self.frame(frame, reverse));
        }
        Analysis::Batches {
            batches,
            finished: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batches(analysis: Analysis) -> Vec<ObservationBatch> {
        match analysis {
            Analysis::Batches { batches, .. } => batches,
            other => panic!("{other:?}"),
        }
    }

    fn value<'a>(batch: &'a ObservationBatch, field: &str) -> Option<&'a str> {
        batch
            .observations
            .iter()
            .chain(&batch.context)
            .find(|item| item.field == field)
            .map(|item| item.value.as_str())
    }

    fn request_for(host: &str) -> Vec<u8> {
        let mut bytes = vec![0, 0, 3, host.len() as u8];
        bytes.extend(host.as_bytes());
        bytes.extend(443u16.to_be_bytes());
        bytes
    }

    fn request() -> Vec<u8> {
        request_for("example.org")
    }

    fn smux(cmd: u8, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![2, cmd];
        bytes.extend((payload.len() as u16).to_le_bytes());
        bytes.extend(id.to_le_bytes());
        bytes.extend(payload);
        bytes
    }

    fn yamux(flags: u16, id: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0];
        bytes.extend(flags.to_be_bytes());
        bytes.extend(id.to_be_bytes());
        bytes.extend((payload.len() as u32).to_be_bytes());
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn smux_interleaved_streams_restore_own_target() {
        let mut analyzer = SingMuxFrames::default();
        let mut input = vec![0, 0];
        input.extend(smux(0, 1, &[]));
        input.extend(smux(0, 3, &[]));
        input.extend(smux(2, 1, &request()[..5]));
        let first = batches(analyzer.feed(&input, false));
        assert_eq!(value(&first[0], "sing_mux.protocol"), Some("smux"));
        assert_eq!(value(&first[3], "sing_mux.host"), None);
        let second = batches(analyzer.feed(&smux(2, 1, &request()[5..]), false));
        assert_eq!(value(&second[0], "sing_mux.host"), Some("example.org"));
        let third = batches(analyzer.feed(&smux(2, 3, &[]), false));
        assert_eq!(value(&third[0], "sing_mux.host"), None);
        let fourth = batches(analyzer.feed(&smux(2, 1, &[]), true));
        assert_eq!(value(&fourth[0], "sing_mux.host"), Some("example.org"));
    }

    #[test]
    fn smux_releases_target_after_both_fin_directions() {
        let mut analyzer = SingMuxFrames::default();
        let mut opening = vec![0, 0];
        opening.extend(smux(0, 1, &[]));
        opening.extend(smux(2, 1, &request()));
        let opened = batches(analyzer.feed(&opening, false));
        assert_eq!(value(&opened[2], "sing_mux.host"), Some("example.org"));

        let client_fin = batches(analyzer.feed(&smux(1, 1, &[]), false));
        assert_eq!(value(&client_fin[0], "sing_mux.host"), Some("example.org"));
        assert!(analyzer.streams.contains_key(&1));
        let reply = batches(analyzer.feed(&smux(2, 1, b"reply"), true));
        assert_eq!(value(&reply[0], "sing_mux.host"), Some("example.org"));
        let server_fin = batches(analyzer.feed(&smux(1, 1, &[]), true));
        assert_eq!(value(&server_fin[0], "sing_mux.host"), Some("example.org"));
        assert!(!analyzer.streams.contains_key(&1));

        let mut reopened = smux(0, 1, &[]);
        reopened.extend(smux(2, 1, &request_for("new.test")));
        let fresh = batches(analyzer.feed(&reopened, false));
        assert_eq!(value(&fresh[0], "sing_mux.host"), None);
        assert_eq!(value(&fresh[1], "sing_mux.host"), Some("new.test"));
    }

    #[test]
    fn yamux_syn_data_exposes_destination() {
        let mut analyzer = SingMuxFrames::default();
        let mut input = vec![0, 1];
        input.extend(yamux(1, 1, &request()));
        assert!(matches!(
            analyzer.feed(&input[..9], false),
            Analysis::Pending
        ));
        let events = batches(analyzer.feed(&input[9..], false));
        assert_eq!(value(&events[0], "sing_mux.protocol"), Some("yamux"));
        assert_eq!(value(&events[1], "sing_mux.stream_id"), Some("1"));
        assert_eq!(value(&events[1], "sing_mux.host"), Some("example.org"));
        assert_eq!(value(&events[1], "sing_mux.port"), Some("443"));
    }

    #[test]
    fn yamux_window_update_can_open_stream_before_data() {
        let mut analyzer = SingMuxFrames::default();
        let mut opening = vec![0, 1, 0, 1, 0, 1];
        opening.extend(1u32.to_be_bytes());
        opening.extend(262144u32.to_be_bytes());
        let opened = batches(analyzer.feed(&opening, false));
        assert_eq!(value(&opened[1], "sing_mux.frame"), Some("open"));
        let data = batches(analyzer.feed(&yamux(0, 1, &request()), false));
        assert_eq!(value(&data[0], "sing_mux.host"), Some("example.org"));
    }

    #[test]
    fn yamux_fin_is_half_close_and_reset_releases_stream() {
        let mut analyzer = SingMuxFrames::default();
        let mut opening = vec![0, 1];
        opening.extend(yamux(1, 1, &request()));
        batches(analyzer.feed(&opening, false));
        let client_fin = batches(analyzer.feed(&yamux(4, 1, &[]), false));
        assert_eq!(value(&client_fin[0], "sing_mux.host"), Some("example.org"));
        assert!(analyzer.streams.contains_key(&1));
        let server_fin = batches(analyzer.feed(&yamux(4, 1, &[]), true));
        assert_eq!(value(&server_fin[0], "sing_mux.host"), Some("example.org"));
        assert!(!analyzer.streams.contains_key(&1));

        let opened = batches(analyzer.feed(&yamux(1, 3, &request()), false));
        assert_eq!(value(&opened[0], "sing_mux.host"), Some("example.org"));
        let reset = batches(analyzer.feed(&yamux(8, 3, &[]), true));
        assert_eq!(value(&reset[0], "sing_mux.host"), Some("example.org"));
        assert!(!analyzer.streams.contains_key(&3));
    }

    #[test]
    fn padded_smux_frames_are_unwrapped_before_request_parsing() {
        let mut analyzer = SingMuxFrames::default();
        let mut inner = smux(0, 1, &[]);
        inner.extend(smux(2, 1, &request()));
        let mut input = vec![1, 0, 1, 0, 2, 7, 8];
        input.extend((inner.len() as u16).to_be_bytes());
        input.extend(2u16.to_be_bytes());
        input.extend(inner);
        input.extend([9, 10]);
        let events = batches(analyzer.feed(&input, false));
        assert_eq!(value(&events[0], "sing_mux.padding"), Some("true"));
        assert_eq!(value(&events[2], "sing_mux.host"), Some("example.org"));
    }
}
