//! HTTP/3 inspection over ordered, already decrypted QUIC stream bytes.
//! One instance owns the QPACK state for one QUIC connection.
use crate::inspect::{Analysis, Observation, ObservationBatch};
use compcol::qpack::QpackDecoder;
use std::collections::HashMap;

pub const FIELDS: &[&str] = &[
    "http3.stream_id",
    "http3.method",
    "http3.path",
    "http3.authority",
    "http3.status",
    "http3.request_header_name",
    "http3.response_header_name",
];

pub struct Http3Event {
    pub stream_id: u64,
    pub reverse: bool,
    /// A response observed before its request can be blocked immediately, but
    /// an Allow must wait for the request context before becoming terminal.
    pub provisional: bool,
    pub batch: ObservationBatch,
}
const MAX_FRAME: usize = 65_536;
const MAX_STREAMS: usize = 256;
const MAX_BLOCKED: usize = 16;
const MAX_EARLY_RESPONSES: usize = 16;

#[derive(Default)]
struct Stream {
    bytes: Vec<u8>,
    kind: Option<u64>,
    first_frame: bool,
    headers_seen: bool,
    skip: u64,
    ignored: bool,
}

struct Blocked {
    stream_id: u64,
    reverse: bool,
    block: Vec<u8>,
}

/// Feed each QUIC stream in byte order. `reverse` is false for client bytes.
/// The QUIC adapter owns decryption, transport reassembly, stream lifetime and
/// ALPN validation; this type only parses HTTP/3 and QPACK.
pub struct Http3Conversation {
    streams: HashMap<(u64, bool), Stream>,
    decoders: [QpackDecoder; 2],
    requests: HashMap<u64, Vec<Observation>>,
    early_responses: HashMap<u64, Vec<Vec<Observation>>>,
    blocked: Vec<Blocked>,
}

impl Default for Http3Conversation {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            decoders: std::array::from_fn(|_| QpackDecoder::with_limits(MAX_FRAME, MAX_FRAME)),
            requests: HashMap::new(),
            early_responses: HashMap::new(),
            blocked: Vec::new(),
        }
    }
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for &byte in bytes.get(1..width)? {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, width))
}

fn observation(field: &'static str, value: impl Into<String>) -> Observation {
    Observation {
        field,
        value: value.into(),
    }
}

impl Http3Conversation {
    /// Feed one contiguous chunk from a QUIC stream. Stream IDs follow RFC 9000.
    pub fn feed(&mut self, stream_id: u64, reverse: bool, bytes: &[u8]) -> Analysis {
        let batches = self
            .feed_events(stream_id, reverse, bytes)
            .into_iter()
            .map(|event| event.batch)
            .collect::<Vec<_>>();
        if batches.is_empty() {
            Analysis::Pending
        } else {
            Analysis::Batches {
                batches,
                finished: false,
            }
        }
    }

    /// Events retain their request stream ID even if a QPACK update on another
    /// stream is what finally unblocks the header section.
    pub fn feed_events(&mut self, stream_id: u64, reverse: bool, bytes: &[u8]) -> Vec<Http3Event> {
        let key = (stream_id, reverse);
        if !self.streams.contains_key(&key) && self.streams.len() >= MAX_STREAMS {
            return Vec::new();
        }
        let state = self.streams.entry(key).or_default();
        if state.ignored {
            return Vec::new();
        }
        let mut events = Vec::new();
        for chunk in bytes.chunks(8192) {
            self.streams
                .get_mut(&key)
                .unwrap()
                .bytes
                .extend_from_slice(chunk);
            if self.parse_stream(stream_id, reverse, &mut events).is_err() {
                tracing::debug!(stream_id, reverse, "HTTP/3 stream parsing stopped");
                let state = self.streams.get_mut(&key).unwrap();
                state.bytes.clear();
                state.ignored = true;
                break;
            }
        }
        events
    }

    pub fn close_stream(&mut self, stream_id: u64) {
        self.streams.remove(&(stream_id, false));
        self.streams.remove(&(stream_id, true));
        self.requests.remove(&stream_id);
        self.early_responses.remove(&stream_id);
        self.blocked.retain(|item| item.stream_id != stream_id);
    }

    fn parse_stream(
        &mut self,
        stream_id: u64,
        reverse: bool,
        events: &mut Vec<Http3Event>,
    ) -> Result<(), ()> {
        let key = (stream_id, reverse);
        let direction = usize::from(reverse);
        let uni = stream_id & 2 != 0;
        if uni && self.streams[&key].kind.is_none() {
            let state = self.streams.get_mut(&key).unwrap();
            let Some((kind, width)) = varint(&state.bytes) else {
                return Ok(());
            };
            state.bytes.drain(..width);
            state.kind = Some(kind);
        }
        if uni && self.streams[&key].kind == Some(2) {
            let bytes = std::mem::take(&mut self.streams.get_mut(&key).unwrap().bytes);
            self.decoders[direction]
                .feed_encoder_stream(&bytes)
                .map_err(|_| ())?;
            self.retry_blocked(direction, events);
            return Ok(());
        }
        if uni && self.streams[&key].kind != Some(0) {
            self.streams.get_mut(&key).unwrap().bytes.clear();
            return Ok(());
        }
        if !uni && stream_id & 3 != 0 {
            return Err(());
        }
        loop {
            let state = self.streams.get_mut(&key).unwrap();
            if state.skip != 0 {
                let available = state.skip.min(state.bytes.len() as u64) as usize;
                state.bytes.drain(..available);
                state.skip -= available as u64;
                if state.skip != 0 {
                    break;
                }
            }
            let Some((kind, type_width)) = varint(&state.bytes) else {
                break;
            };
            let Some((length, length_width)) = varint(&state.bytes[type_width..]) else {
                break;
            };
            let header = type_width + length_width;
            if uni && !state.first_frame && kind != 4 {
                return Err(());
            }
            if uni && matches!(kind, 0 | 1) || !uni && kind == 0 && !state.headers_seen {
                return Err(());
            }
            state.first_frame = true;
            if !uni && kind == 1 {
                let length = usize::try_from(length).map_err(|_| ())?;
                if length > MAX_FRAME {
                    return Err(());
                }
                if state.bytes.len() < header + length {
                    break;
                }
                let payload = state.bytes[header..header + length].to_vec();
                state.bytes.drain(..header + length);
                state.headers_seen = true;
                events.extend(self.headers(stream_id, reverse, payload));
            } else {
                state.bytes.drain(..header);
                state.skip = length;
            }
        }
        Ok(())
    }

    fn headers(&mut self, stream_id: u64, reverse: bool, block: Vec<u8>) -> Vec<Http3Event> {
        // QPACK can unblock a later section before an earlier one. Keep the
        // HTTP message order within each QUIC stream.
        if self
            .blocked
            .iter()
            .any(|item| item.stream_id == stream_id && item.reverse == reverse)
        {
            if self.blocked.len() < MAX_BLOCKED {
                self.blocked.push(Blocked {
                    stream_id,
                    reverse,
                    block,
                });
            }
            return Vec::new();
        }
        let fields = match self.decoders[usize::from(reverse)].decode_field_section(&block) {
            Ok(fields) => fields,
            Err(_) => {
                // A field section can arrive before its QPACK encoder inserts.
                if block.first().copied().unwrap_or(0) != 0 && self.blocked.len() < MAX_BLOCKED {
                    self.blocked.push(Blocked {
                        stream_id,
                        reverse,
                        block,
                    });
                }
                return Vec::new();
            }
        };
        let mut values = vec![observation("http3.stream_id", stream_id.to_string())];
        for field in fields {
            let name = match field.name.as_slice() {
                b":method" => "http3.method",
                b":path" => "http3.path",
                b":authority" => "http3.authority",
                b":status" => "http3.status",
                _ => {
                    if !field.name.starts_with(b":")
                        && let Ok(name) = String::from_utf8(field.name)
                    {
                        let field = if reverse {
                            "http3.response_header_name"
                        } else {
                            "http3.request_header_name"
                        };
                        values.push(observation(field, name));
                    }
                    continue;
                }
            };
            let Ok(value) = String::from_utf8(field.value) else {
                return Vec::new();
            };
            values.push(observation(name, value));
        }
        let is_request = values.iter().any(|item| item.field == "http3.method");
        let is_response = values.iter().any(|item| item.field == "http3.status");
        if is_request {
            self.requests.insert(stream_id, values.clone());
            let mut events = vec![Http3Event {
                stream_id,
                reverse,
                provisional: false,
                batch: ObservationBatch {
                    clear_fields: FIELDS,
                    context: Vec::new(),
                    observations: values.clone(),
                },
            }];
            if let Some(responses) = self.early_responses.remove(&stream_id) {
                events.extend(responses.into_iter().map(|observations| Http3Event {
                    stream_id,
                    reverse: true,
                    provisional: false,
                    batch: ObservationBatch {
                        clear_fields: FIELDS,
                        context: values.clone(),
                        observations,
                    },
                }));
            }
            return events;
        }
        if is_response {
            let context = self.requests.get(&stream_id).cloned().unwrap_or_default();
            if context.is_empty() {
                let pending = self.early_responses.entry(stream_id).or_default();
                if pending.len() == MAX_EARLY_RESPONSES {
                    pending.remove(0);
                }
                pending.push(values.clone());
            }
            return vec![Http3Event {
                stream_id,
                reverse,
                provisional: context.is_empty(),
                batch: ObservationBatch {
                    clear_fields: FIELDS,
                    context,
                    observations: values,
                },
            }];
        }
        Vec::new()
    }

    fn retry_blocked(&mut self, direction: usize, events: &mut Vec<Http3Event>) {
        let mut pending = std::mem::take(&mut self.blocked);
        for item in pending.drain(..) {
            if usize::from(item.reverse) == direction {
                events.extend(self.headers(item.stream_id, item.reverse, item.block));
            } else {
                self.blocked.push(item);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compcol::{hpack::HeaderField, qpack::QpackEncoder};

    fn varint(value: usize) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 16384 {
            vec![0x40 | (value >> 8) as u8, value as u8]
        } else {
            ((value as u32) | 0x8000_0000).to_be_bytes().to_vec()
        }
    }

    fn frame(kind: usize, payload: &[u8]) -> Vec<u8> {
        let mut bytes = varint(kind);
        bytes.extend(varint(payload.len()));
        bytes.extend(payload);
        bytes
    }

    fn batches(result: Analysis) -> Vec<ObservationBatch> {
        match result {
            Analysis::Batches { batches, .. } => batches,
            other => panic!("expected headers, got {other:?}"),
        }
    }

    fn value<'a>(values: &'a [Observation], name: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|item| item.field == name)
            .map(|item| item.value.as_str())
    }

    #[test]
    fn fragmented_interleaved_requests_restore_response_context() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        let block0 = encoder.encode_field_section(&[
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/one"),
            HeaderField::new(b":authority", b"first.test"),
        ]);
        let block4 = encoder.encode_field_section(&[
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/two"),
            HeaderField::new(b":authority", b"second.test"),
        ]);
        let request0 = frame(1, &block0);
        assert!(matches!(
            h3.feed(0, false, &request0[..2]),
            Analysis::Pending
        ));
        let request4 = batches(h3.feed(4, false, &frame(1, &block4)));
        assert_eq!(value(&request4[0].observations, "http3.path"), Some("/two"));
        let request0 = batches(h3.feed(0, false, &request0[2..]));
        assert_eq!(
            value(&request0[0].observations, "http3.authority"),
            Some("first.test")
        );

        let reply = encoder.encode_field_section(&[HeaderField::new(b":status", b"200")]);
        let response4 = batches(h3.feed(4, true, &frame(1, &reply)));
        assert_eq!(value(&response4[0].context, "http3.path"), Some("/two"));
        let response0 = batches(h3.feed(0, true, &frame(1, &reply)));
        assert_eq!(value(&response0[0].context, "http3.path"), Some("/one"));
        h3.close_stream(4);
        assert!(!h3.requests.contains_key(&4));
    }

    #[test]
    fn auth_header_name_follows_the_request_without_exposing_its_value() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        let request = frame(
            1,
            &encoder.encode_field_section(&[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/auth"),
                HeaderField::new(b":authority", b"hysteria"),
                HeaderField::new(b"hysteria-auth", b"secret-token"),
                HeaderField::new(b"hysteria-cc-rx", b"0"),
            ]),
        );
        let request = batches(h3.feed(0, false, &request));
        assert_eq!(value(&request[0].observations, "http3.path"), Some("/auth"));
        assert_eq!(
            value(&request[0].observations, "http3.request_header_name"),
            Some("hysteria-auth")
        );
        assert!(
            request[0]
                .observations
                .iter()
                .all(|observation| !observation.value.contains("secret-token"))
        );

        let response = frame(
            1,
            &encoder.encode_field_section(&[
                HeaderField::new(b":status", b"233"),
                HeaderField::new(b"hysteria-udp", b"true"),
            ]),
        );
        let response = batches(h3.feed(0, true, &response));
        assert_eq!(
            value(&response[0].observations, "http3.status"),
            Some("233")
        );
        assert_eq!(
            value(&response[0].context, "http3.request_header_name"),
            Some("hysteria-auth")
        );
        assert_eq!(
            value(&response[0].observations, "http3.response_header_name"),
            Some("hysteria-udp")
        );
    }

    #[test]
    fn early_responses_are_replayed_with_late_request_context() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        let interim = frame(
            1,
            &encoder.encode_field_section(&[HeaderField::new(b":status", b"103")]),
        );
        let final_response = frame(
            1,
            &encoder.encode_field_section(&[HeaderField::new(b":status", b"200")]),
        );
        let first = h3.feed_events(4, true, &interim);
        assert_eq!(first.len(), 1);
        assert!(first[0].reverse);
        assert_eq!(
            value(&first[0].batch.observations, "http3.status"),
            Some("103")
        );
        assert!(first[0].batch.context.is_empty());
        let second = h3.feed_events(4, true, &final_response);
        assert_eq!(second.len(), 1);
        assert_eq!(
            value(&second[0].batch.observations, "http3.status"),
            Some("200")
        );

        let request = frame(
            1,
            &encoder.encode_field_section(&[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/late"),
            ]),
        );
        let events = h3.feed_events(4, false, &request);
        assert_eq!(events.len(), 3);
        assert!(!events[0].reverse);
        assert_eq!(
            value(&events[0].batch.observations, "http3.path"),
            Some("/late")
        );
        for (event, status) in events[1..].iter().zip(["103", "200"]) {
            assert!(event.reverse);
            assert_eq!(value(&event.batch.context, "http3.path"), Some("/late"));
            assert_eq!(
                value(&event.batch.observations, "http3.status"),
                Some(status)
            );
        }
        assert!(!h3.early_responses.contains_key(&4));
    }

    #[test]
    fn late_request_still_sees_final_response_after_many_interim_headers() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        let interim = frame(
            1,
            &encoder.encode_field_section(&[HeaderField::new(b":status", b"103")]),
        );
        for _ in 0..MAX_EARLY_RESPONSES {
            assert_eq!(h3.feed_events(0, true, &interim).len(), 1);
        }
        let final_response = frame(
            1,
            &encoder.encode_field_section(&[HeaderField::new(b":status", b"403")]),
        );
        assert_eq!(h3.feed_events(0, true, &final_response).len(), 1);
        let request = frame(
            1,
            &encoder.encode_field_section(&[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/late"),
            ]),
        );
        let events = h3.feed_events(0, false, &request);
        assert_eq!(events.len(), MAX_EARLY_RESPONSES + 1);
        let last = events.last().unwrap();
        assert_eq!(value(&last.batch.observations, "http3.status"), Some("403"));
        assert_eq!(value(&last.batch.context, "http3.path"), Some("/late"));
    }

    #[test]
    fn late_qpack_encoder_stream_unblocks_headers() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::with_dynamic_table(512);
        let fields = [
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":authority", b"dynamic.test"),
            HeaderField::new(b"x-request-id", b"a-repeated-value-for-qpack"),
        ];
        let encoded = encoder.encode(&fields);
        assert!(!encoded.encoder_stream.is_empty());
        assert!(matches!(
            h3.feed(0, false, &frame(1, &encoded.field_section)),
            Analysis::Pending
        ));
        let mut updates = vec![2];
        updates.extend(encoded.encoder_stream);
        let cut = updates.len() / 2;
        assert!(matches!(
            h3.feed(2, false, &updates[..cut]),
            Analysis::Pending
        ));
        let events = batches(h3.feed(2, false, &updates[cut..]));
        assert_eq!(
            value(&events[0].observations, "http3.authority"),
            Some("dynamic.test")
        );
        assert_eq!(value(&events[0].observations, "http3.stream_id"), Some("0"));
    }

    #[test]
    fn qpack_unblocking_preserves_response_order_on_one_stream() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::with_dynamic_table(512);
        let interim = encoder.encode(&[
            HeaderField::new(b":status", b"103"),
            HeaderField::new(b"x-test", b"dynamic-value-long-enough-to-insert"),
        ]);
        assert!(!interim.encoder_stream.is_empty());
        assert!(
            h3.feed_events(4, true, &frame(1, &interim.field_section))
                .is_empty()
        );

        let mut static_encoder = QpackEncoder::new();
        let final_response =
            static_encoder.encode_field_section(&[HeaderField::new(b":status", b"403")]);
        assert!(
            h3.feed_events(4, true, &frame(1, &final_response))
                .is_empty()
        );
        let mut updates = vec![2];
        updates.extend(interim.encoder_stream);
        let events = h3.feed_events(3, true, &updates);
        assert_eq!(events.len(), 2);
        assert_eq!(
            value(&events[0].batch.observations, "http3.status"),
            Some("103")
        );
        assert_eq!(
            value(&events[1].batch.observations, "http3.status"),
            Some("403")
        );
    }

    #[test]
    fn control_stream_requires_settings_first() {
        let mut h3 = Http3Conversation::default();
        assert!(matches!(h3.feed(2, false, &[0, 4, 0]), Analysis::Pending));
        assert!(h3.streams[&(2, false)].first_frame);
        assert!(matches!(h3.feed(6, false, &[0, 1, 0]), Analysis::Pending));
        assert!(h3.streams[&(6, false)].ignored);
    }

    #[test]
    fn large_data_and_extension_frames_are_skipped_across_chunks() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        let request = encoder.encode_field_section(&[
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":path", b"/after"),
        ]);
        batches(h3.feed(0, false, &frame(1, &request)));
        let data = frame(0, &vec![0x55; 131_072]);
        assert!(matches!(
            h3.feed(0, false, &data[..50_000]),
            Analysis::Pending
        ));
        assert!(h3.streams[&(0, false)].skip > 0);
        assert!(h3.streams[&(0, false)].bytes.is_empty());
        assert!(matches!(
            h3.feed(0, false, &data[50_000..]),
            Analysis::Pending
        ));
        assert_eq!(h3.streams[&(0, false)].skip, 0);
        assert!(!h3.streams[&(0, false)].ignored);

        let mut extension = frame(0x21, &vec![0x33; 131_072]);
        extension.extend(frame(1, &request));
        let found = batches(h3.feed(4, false, &extension));
        assert_eq!(value(&found[0].observations, "http3.path"), Some("/after"));
        assert!(h3.streams[&(4, false)].bytes.is_empty());
    }

    #[test]
    fn data_before_headers_stops_that_request_stream() {
        let mut h3 = Http3Conversation::default();
        assert!(matches!(
            h3.feed(0, false, &frame(0, b"body")),
            Analysis::Pending
        ));
        assert!(h3.streams[&(0, false)].ignored);
    }

    #[test]
    fn two_byte_frame_length_preserves_long_authority() {
        let mut h3 = Http3Conversation::default();
        let mut encoder = QpackEncoder::new();
        encoder.set_huffman(false);
        let host = format!("{}.test", "a".repeat(72));
        let block = encoder.encode_field_section(&[
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":authority", host.as_bytes()),
        ]);
        assert!(block.len() >= 64);
        let result = batches(h3.feed(0, false, &frame(1, &block)));
        assert_eq!(
            value(&result[0].observations, "http3.authority"),
            Some(host.as_str())
        );
    }
}
