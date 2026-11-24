//! Cleartext HTTP/2 frame inspection with per-stream request correlation.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch};
use httlib_hpack::Decoder;
use std::collections::HashMap;

pub const FIELDS: &[&str] = &[
    "http2.stream_id",
    "http2.method",
    "http2.path",
    "http2.authority",
    "http2.status",
];
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAME: usize = 65536;
const MAX_BLOCK: usize = 65536;
const MAX_STREAMS: usize = 256;

struct HeaderBlock {
    stream: u32,
    bytes: Vec<u8>,
    end_stream: bool,
}

pub(crate) struct DataEvent {
    pub before_batch: usize,
    pub stream: u32,
    pub reverse: bool,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
struct Direction {
    bytes: Vec<u8>,
    decoder: Decoder<'static>,
    first_frame: bool,
    pending: Option<HeaderBlock>,
}

#[derive(Default)]
pub struct Http2Conversation {
    directions: [Direction; 2],
    client: Option<usize>,
    requests: HashMap<u32, Vec<Observation>>,
    capture_data: bool,
    data_events: Vec<DataEvent>,
    finished_streams: Vec<u32>,
    finished: bool,
}

fn observation(field: &'static str, value: impl Into<String>) -> Observation {
    Observation {
        field,
        value: value.into(),
    }
}

fn data_payload(flags: u8, payload: &[u8]) -> Result<&[u8], ()> {
    if flags & 8 == 0 {
        return Ok(payload);
    }
    let padding = usize::from(*payload.first().ok_or(())?);
    if padding + 1 > payload.len() {
        return Err(());
    }
    Ok(&payload[1..payload.len() - padding])
}

impl Http2Conversation {
    pub(crate) fn capture_data(&mut self) {
        self.capture_data = true;
    }

    pub(crate) fn take_data_events(&mut self) -> Vec<DataEvent> {
        std::mem::take(&mut self.data_events)
    }

    pub(crate) fn take_finished_streams(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.finished_streams)
    }

    pub(crate) fn recognized(&self) -> bool {
        self.client
            .is_some_and(|direction| self.directions[direction].first_frame)
    }

    fn headers(
        &mut self,
        direction: usize,
        mut block: HeaderBlock,
    ) -> Result<Option<ObservationBatch>, ()> {
        let mut decoded = Vec::new();
        self.directions[direction]
            .decoder
            .decode(&mut block.bytes, &mut decoded)
            .map_err(|_| ())?;
        if !block.bytes.is_empty() || decoded.len() > 128 {
            return Err(());
        }
        let mut values = vec![observation("http2.stream_id", block.stream.to_string())];
        for (name, value, _) in decoded {
            let field = match name.as_slice() {
                b":method" => "http2.method",
                b":path" => "http2.path",
                b":authority" => "http2.authority",
                b":status" => "http2.status",
                _ => continue,
            };
            let value = String::from_utf8(value).map_err(|_| ())?;
            values.push(observation(field, value));
        }
        let is_request = values.iter().any(|item| item.field == "http2.method");
        let is_response = values.iter().any(|item| item.field == "http2.status");
        if is_request {
            if !self.requests.contains_key(&block.stream) && self.requests.len() == MAX_STREAMS {
                return Err(());
            }
            self.requests.insert(block.stream, values.clone());
        }
        let context = if is_response {
            self.requests
                .get(&block.stream)
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        if block.end_stream && self.client != Some(direction) {
            self.requests.remove(&block.stream);
            self.finished_streams.push(block.stream);
        }
        Ok((is_request || is_response).then_some(ObservationBatch {
            clear_fields: FIELDS,
            context,
            observations: values,
            allow_continues: true,
        }))
    }

    fn frame(
        &mut self,
        direction: usize,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
    ) -> Result<Option<ObservationBatch>, ()> {
        let state = &mut self.directions[direction];
        if !state.first_frame {
            if kind != 4 || flags & 1 != 0 || stream != 0 || !payload.len().is_multiple_of(6) {
                return Err(());
            }
            state.first_frame = true;
        }
        if let Some(pending) = &state.pending
            && (kind != 9 || stream != pending.stream)
        {
            return Err(());
        }
        match kind {
            0 => {
                if stream == 0 {
                    return Err(());
                }
                data_payload(flags, payload)?;
                if flags & 1 != 0 && self.client != Some(direction) {
                    self.requests.remove(&stream);
                    self.finished_streams.push(stream);
                }
                Ok(None)
            }
            1 => {
                if stream == 0 {
                    return Err(());
                }
                let pad = if flags & 8 != 0 {
                    usize::from(*payload.first().ok_or(())?)
                } else {
                    0
                };
                let offset = usize::from(flags & 8 != 0) + if flags & 0x20 != 0 { 5 } else { 0 };
                if offset + pad > payload.len() {
                    return Err(());
                }
                let bytes = payload[offset..payload.len() - pad].to_vec();
                if bytes.len() > MAX_BLOCK {
                    return Err(());
                }
                let block = HeaderBlock {
                    stream,
                    bytes,
                    end_stream: flags & 1 != 0,
                };
                if flags & 4 != 0 {
                    self.headers(direction, block)
                } else {
                    self.directions[direction].pending = Some(block);
                    Ok(None)
                }
            }
            9 => {
                let pending = self.directions[direction].pending.as_mut().ok_or(())?;
                if pending.bytes.len() + payload.len() > MAX_BLOCK {
                    return Err(());
                }
                pending.bytes.extend_from_slice(payload);
                if flags & 4 != 0 {
                    let block = self.directions[direction].pending.take().unwrap();
                    self.headers(direction, block)
                } else {
                    Ok(None)
                }
            }
            3 => {
                if stream == 0 || payload.len() != 4 {
                    return Err(());
                }
                self.requests.remove(&stream);
                self.finished_streams.push(stream);
                Ok(None)
            }
            4 => {
                if stream != 0
                    || (flags & 1 != 0 && !payload.is_empty())
                    || (flags & 1 == 0 && !payload.len().is_multiple_of(6))
                {
                    return Err(());
                }
                if flags & 1 == 0 {
                    for setting in payload.as_chunks::<6>().0 {
                        if setting[..2] == [0, 1] {
                            let size = u32::from_be_bytes(setting[2..6].try_into().unwrap());
                            if size as usize > MAX_BLOCK {
                                return Err(());
                            }
                            self.directions[1 - direction]
                                .decoder
                                .set_max_dynamic_size(size);
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn parse_direction(
        &mut self,
        direction: usize,
        batches: &mut Vec<ObservationBatch>,
    ) -> Result<(), ()> {
        loop {
            let bytes = &self.directions[direction].bytes;
            if bytes.len() < 9 {
                return Ok(());
            }
            let length =
                usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
            if length > MAX_FRAME {
                return Err(());
            }
            if bytes.len() < 9 + length {
                return Ok(());
            }
            let kind = bytes[3];
            let flags = bytes[4];
            let stream = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) & 0x7fff_ffff;
            let payload = bytes[9..9 + length].to_vec();
            self.directions[direction].bytes.drain(..9 + length);
            let batch = self.frame(direction, kind, flags, stream, &payload)?;
            if self.capture_data && kind == 0 {
                self.data_events.push(DataEvent {
                    before_batch: batches.len(),
                    stream,
                    reverse: self.client != Some(direction),
                    bytes: data_payload(flags, &payload)?.to_vec(),
                });
            }
            if let Some(batch) = batch {
                batches.push(batch);
            }
        }
    }
}

impl BidirectionalStreamAnalyzer for Http2Conversation {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        self.data_events.clear();
        self.finished_streams.clear();
        let direction = usize::from(reverse);
        self.directions[direction].bytes.extend_from_slice(bytes);
        let mut batches = Vec::new();
        if self.client.is_none() {
            let input = &self.directions[direction].bytes;
            if input.starts_with(PREFACE) {
                self.client = Some(direction);
                self.directions[direction].bytes.drain(..PREFACE.len());
            } else if PREFACE.starts_with(input) {
                return Analysis::Pending;
            } else if input.len() > MAX_FRAME + 9 {
                self.finished = true;
                return Analysis::Finished;
            } else {
                return Analysis::Pending;
            }
        }
        let result = self.parse_direction(direction, &mut batches).and_then(|_| {
            if self.client == Some(direction) && self.directions[1 - direction].bytes.len() >= 9 {
                self.parse_direction(1 - direction, &mut batches)?;
            }
            Ok(())
        });
        if result.is_err() {
            self.finished = true;
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

    fn request(path: &str) -> Vec<u8> {
        let mut bytes = vec![0x82, 0x04, path.len() as u8];
        bytes.extend(path.as_bytes());
        bytes.extend([0x01, 12]);
        bytes.extend(b"example.test");
        bytes
    }

    fn batches(result: Analysis) -> Vec<ObservationBatch> {
        match result {
            Analysis::Batches { batches, .. } => batches,
            other => panic!("expected header batches, got {other:?}"),
        }
    }

    fn value<'a>(values: &'a [Observation], field: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|item| item.field == field)
            .map(|item| item.value.as_str())
    }

    #[test]
    fn interleaved_stream_responses_restore_matching_request() {
        let mut analyzer = Http2Conversation::default();
        let mut start = PREFACE.to_vec();
        start.extend(frame(4, 0, 0, &[]));
        let first = request("/one");
        start.extend(frame(1, 4, 1, &first));
        start.extend(frame(1, 4, 3, &request("/two")));
        let requests = batches(analyzer.feed(&start, false));
        assert_eq!(requests.len(), 2);
        assert_eq!(
            value(&requests[0].observations, "http2.stream_id"),
            Some("1")
        );
        assert_eq!(value(&requests[1].observations, "http2.path"), Some("/two"));

        let mut replies = frame(4, 0, 0, &[]);
        replies.extend(frame(1, 5, 3, &[0x8d]));
        replies.extend(frame(1, 5, 1, &[0x88]));
        let responses = batches(analyzer.feed(&replies, true));
        assert_eq!(responses.len(), 2);
        assert_eq!(value(&responses[0].context, "http2.path"), Some("/two"));
        assert_eq!(
            value(&responses[0].observations, "http2.status"),
            Some("404")
        );
        assert_eq!(value(&responses[1].context, "http2.path"), Some("/one"));
        assert_eq!(
            value(&responses[1].observations, "http2.status"),
            Some("200")
        );
        assert!(analyzer.requests.is_empty());
    }

    #[test]
    fn split_preface_and_continuation_complete_one_header_block() {
        let mut analyzer = Http2Conversation::default();
        assert!(matches!(
            analyzer.feed(&PREFACE[..8], false),
            Analysis::Pending
        ));
        let mut data = PREFACE[8..].to_vec();
        data.extend(frame(4, 0, 0, &[]));
        let headers = request("/split");
        data.extend(frame(1, 0, 1, &headers[..2]));
        assert!(matches!(analyzer.feed(&data, false), Analysis::Pending));
        let result = batches(analyzer.feed(&frame(9, 4, 1, &headers[2..]), false));
        assert_eq!(value(&result[0].observations, "http2.path"), Some("/split"));
        assert_eq!(
            value(&result[0].observations, "http2.authority"),
            Some("example.test")
        );
    }

    #[test]
    fn continuation_on_another_stream_ends_inspection() {
        let mut analyzer = Http2Conversation::default();
        let mut data = PREFACE.to_vec();
        data.extend(frame(4, 0, 0, &[]));
        data.extend(frame(1, 0, 1, &[0x82]));
        data.extend(frame(9, 4, 3, &[0x84]));
        assert!(matches!(analyzer.feed(&data, false), Analysis::Finished));
    }

    #[test]
    fn response_data_end_stream_releases_request_context() {
        let mut analyzer = Http2Conversation::default();
        let mut client = PREFACE.to_vec();
        client.extend(frame(4, 0, 0, &[]));
        client.extend(frame(1, 4, 1, &request("/data")));
        batches(analyzer.feed(&client, false));
        let mut server = frame(4, 0, 0, &[]);
        server.extend(frame(1, 4, 1, &[0x88]));
        batches(analyzer.feed(&server, true));
        assert_eq!(analyzer.requests.len(), 1);
        assert!(matches!(
            analyzer.feed(&frame(0, 1, 1, b"body"), true),
            Analysis::Pending
        ));
        assert!(analyzer.requests.is_empty());
    }

    #[test]
    fn informational_response_keeps_request_until_final_response() {
        let mut analyzer = Http2Conversation::default();
        let mut client = PREFACE.to_vec();
        client.extend(frame(4, 0, 0, &[]));
        client.extend(frame(1, 4, 1, &request("/probe")));
        batches(analyzer.feed(&client, false));

        let mut server = frame(4, 0, 0, &[]);
        server.extend(frame(1, 4, 1, b"\x08\x03103"));
        let interim = batches(analyzer.feed(&server, true));
        assert!(interim[0].allow_continues);
        assert_eq!(value(&interim[0].observations, "http2.status"), Some("103"));
        assert_eq!(value(&interim[0].context, "http2.path"), Some("/probe"));
        assert!(analyzer.requests.contains_key(&1));

        let final_response = batches(analyzer.feed(&frame(1, 5, 1, b"\x08\x03403"), true));
        assert!(final_response[0].allow_continues);
        assert_eq!(
            value(&final_response[0].observations, "http2.status"),
            Some("403")
        );
        assert_eq!(
            value(&final_response[0].context, "http2.path"),
            Some("/probe")
        );
        assert!(analyzer.requests.is_empty());
    }

    #[test]
    fn server_preface_arriving_first_still_pairs_response() {
        let mut analyzer = Http2Conversation::default();
        let mut server = frame(4, 0, 0, &[]);
        server.extend(frame(1, 5, 1, &[0x8d]));
        assert!(matches!(analyzer.feed(&server, true), Analysis::Pending));
        let mut client = PREFACE.to_vec();
        client.extend(frame(4, 0, 0, &[]));
        client.extend(frame(1, 4, 1, &request("/early")));
        let events = batches(analyzer.feed(&client, false));
        assert_eq!(events.len(), 2);
        assert_eq!(value(&events[1].context, "http2.path"), Some("/early"));
        assert_eq!(value(&events[1].observations, "http2.status"), Some("404"));
    }
}
