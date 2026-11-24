//! Incremental HTTP/1 message inspection and request/response correlation.
use crate::inspect::{
    Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch, StreamAnalyzer,
};
use std::collections::VecDeque;

pub const FIELDS: &[&str] = &[
    "http.host",
    "http.method",
    "http.target",
    "http.request_version",
    "http.status",
    "http.response_version",
    "http.upgrade_offer",
    "http.upgrade_selected",
];
const REQUEST_FIELDS: &[&str] = FIELDS;
const RESPONSE_FIELDS: &[&str] = &[
    "http.status",
    "http.response_version",
    "http.upgrade_selected",
];

#[derive(Default)]
enum Body {
    #[default]
    None,
    Fixed(usize),
    ChunkSize(Vec<u8>),
    ChunkData(usize),
    ChunkDataEnd(u8),
    Trailers(Vec<u8>),
}

pub struct HttpMessages {
    header: Vec<u8>,
    body: Body,
    finished: bool,
    limit: usize,
}
pub type HttpFirstMessage = HttpMessages;

impl Default for HttpMessages {
    fn default() -> Self {
        Self::with_header_limit(16384)
    }
}

impl HttpMessages {
    pub fn with_header_limit(limit: usize) -> Self {
        Self {
            header: Vec::new(),
            body: Body::None,
            finished: false,
            limit,
        }
    }
}

impl StreamAnalyzer for HttpMessages {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        self.feed_with(bytes, |_| Vec::new())
    }
}

impl HttpMessages {
    fn feed_with(
        &mut self,
        bytes: &[u8],
        mut on_message: impl FnMut(&mut Message) -> Vec<Observation>,
    ) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        let mut batches = Vec::new();
        let mut cursor = 0;
        while cursor < bytes.len() {
            match &mut self.body {
                Body::None => {
                    if self.header.len() == self.limit {
                        self.finished = true;
                        break;
                    }
                    self.header.push(bytes[cursor]);
                    cursor += 1;
                    if self.header.ends_with(b"\r\n\r\n") {
                        let Some(mut message) = parse_message(&self.header) else {
                            self.finished = true;
                            break;
                        };
                        let context = on_message(&mut message);
                        let provisional = message.observations.iter().any(|item| {
                            item.field == "http.status"
                                && item.value.starts_with('1')
                                && item.value != "101"
                        });
                        self.header.clear();
                        self.body = message.body;
                        self.finished = !message.continue_after;
                        batches.push(ObservationBatch {
                            clear_fields: message.clear_fields,
                            context,
                            observations: message.observations,
                            provisional,
                        });
                        if self.finished {
                            break;
                        }
                    }
                }
                Body::Fixed(remaining) => {
                    let skip = (*remaining).min(bytes.len() - cursor);
                    *remaining -= skip;
                    cursor += skip;
                    if *remaining == 0 {
                        self.body = Body::None;
                    }
                }
                Body::ChunkData(remaining) => {
                    let skip = (*remaining).min(bytes.len() - cursor);
                    *remaining -= skip;
                    cursor += skip;
                    if *remaining == 0 {
                        self.body = Body::ChunkDataEnd(0);
                    }
                }
                Body::ChunkSize(line) => {
                    if line.len() == self.limit {
                        self.finished = true;
                        break;
                    }
                    line.push(bytes[cursor]);
                    cursor += 1;
                    if line.ends_with(b"\r\n") {
                        let Some(size) = chunk_size(line) else {
                            self.finished = true;
                            break;
                        };
                        self.body = if size == 0 {
                            Body::Trailers(Vec::new())
                        } else {
                            Body::ChunkData(size)
                        };
                    }
                }
                Body::ChunkDataEnd(stage) => {
                    let expected = if *stage == 0 { b'\r' } else { b'\n' };
                    if bytes[cursor] != expected {
                        self.finished = true;
                        break;
                    }
                    cursor += 1;
                    if *stage == 1 {
                        self.body = Body::ChunkSize(Vec::new());
                    } else {
                        *stage = 1;
                    }
                }
                Body::Trailers(line) => {
                    if line.len() == self.limit {
                        self.finished = true;
                        break;
                    }
                    line.push(bytes[cursor]);
                    cursor += 1;
                    if line.ends_with(b"\r\n") {
                        if line.len() == 2 {
                            self.body = Body::None;
                        } else if line[..line.len() - 2].contains(&b':') {
                            line.clear();
                        } else {
                            self.finished = true;
                            break;
                        }
                    }
                }
            }
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

/// Associates responses with requests in HTTP/1 wire order, including pipelined requests.
pub struct HttpConversation {
    directions: [HttpMessages; 2],
    pending: VecDeque<Vec<Observation>>,
    finished: [bool; 2],
}

impl Default for HttpConversation {
    fn default() -> Self {
        Self::with_header_limit(16384)
    }
}

impl HttpConversation {
    pub fn with_header_limit(limit: usize) -> Self {
        Self {
            directions: [
                HttpMessages::with_header_limit(limit),
                HttpMessages::with_header_limit(limit),
            ],
            pending: VecDeque::new(),
            finished: [false; 2],
        }
    }
}

impl BidirectionalStreamAnalyzer for HttpConversation {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished.iter().all(|done| *done) {
            return Analysis::Finished;
        }
        let direction = usize::from(reverse);
        let mut tunnel = false;
        let result = self.directions[direction].feed_with(bytes, |message| {
            let request = message
                .observations
                .iter()
                .any(|item| item.field == "http.method");
            if request {
                self.pending.push_back(message.observations.clone());
                return Vec::new();
            }
            message.clear_fields = FIELDS;
            let status = message
                .observations
                .iter()
                .find(|item| item.field == "http.status")
                .and_then(|item| item.value.parse::<u16>().ok());
            let interim = status.is_some_and(|code| (100..200).contains(&code) && code != 101);
            let context = if interim {
                self.pending.front().cloned().unwrap_or_default()
            } else {
                self.pending.pop_front().unwrap_or_default()
            };
            if !interim {
                let method = context
                    .iter()
                    .find(|item| item.field == "http.method")
                    .map(|item| item.value.as_str());
                if method == Some("HEAD") {
                    message.body = Body::None;
                    message.continue_after = message.head_can_continue;
                } else if method == Some("CONNECT")
                    && status.is_some_and(|code| (200..300).contains(&code))
                {
                    message.body = Body::None;
                    message.continue_after = false;
                    tunnel = true;
                }
                if status == Some(101) {
                    tunnel = true;
                }
            }
            context
        });
        let (batches, finished) = match result {
            Analysis::Batches { batches, finished } => (batches, finished),
            Analysis::Finished => (Vec::new(), true),
            Analysis::Pending => (Vec::new(), false),
            Analysis::Observations(_) | Analysis::FinalObservations(_) => unreachable!(),
        };
        self.finished[direction] |= finished;
        if tunnel {
            self.finished = [true; 2];
        }
        if !batches.is_empty() {
            Analysis::Batches {
                batches,
                finished: self.finished.iter().all(|done| *done),
            }
        } else if self.finished.iter().all(|done| *done) {
            Analysis::Finished
        } else {
            Analysis::Pending
        }
    }
}

struct Message {
    observations: Vec<Observation>,
    clear_fields: &'static [&'static str],
    body: Body,
    continue_after: bool,
    head_can_continue: bool,
}

fn chunk_size(line: &[u8]) -> Option<usize> {
    let line = line.strip_suffix(b"\r\n")?;
    let number = line.split(|&byte| byte == b';').next()?.trim_ascii();
    if number.is_empty() || !number.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    usize::from_str_radix(std::str::from_utf8(number).ok()?, 16).ok()
}

fn http_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn upgrade_tokens(value: &[u8]) -> Vec<String> {
    let Ok(value) = std::str::from_utf8(value) else {
        return Vec::new();
    };
    value
        .split(',')
        .map(str::trim_ascii)
        .filter(|part| {
            let mut components = part.split('/');
            let valid = components.next().is_some_and(http_token)
                && components.next().is_none_or(http_token);
            valid && components.next().is_none()
        })
        .map(str::to_ascii_lowercase)
        .collect()
}

fn parse_message(header: &[u8]) -> Option<Message> {
    let mut lines = header.split(|&byte| byte == b'\n');
    let first = lines.next()?;
    let first = std::str::from_utf8(first.strip_suffix(b"\r").unwrap_or(first)).ok()?;
    let mut words = first.split_ascii_whitespace();
    let start = words.next()?;
    let (mut observations, clear_fields, request, no_response_body, http11) =
        if matches!(start, "HTTP/1.0" | "HTTP/1.1") {
            let status = words.next()?;
            if status.len() != 3
                || !status.bytes().all(|byte| byte.is_ascii_digit())
                || status.starts_with('0')
            {
                return None;
            }
            let code = status.parse::<u16>().ok()?;
            (
                vec![
                    Observation {
                        field: "http.response_version",
                        value: start.into(),
                    },
                    Observation {
                        field: "http.status",
                        value: status.into(),
                    },
                ],
                RESPONSE_FIELDS,
                false,
                (100..200).contains(&code) || matches!(code, 204 | 304),
                start == "HTTP/1.1",
            )
        } else {
            let (Some(target), Some(version)) = (words.next(), words.next()) else {
                return None;
            };
            if words.next().is_some()
                || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
                || !start
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            {
                return None;
            }
            let mut observations = vec![
                Observation {
                    field: "http.method",
                    value: start.into(),
                },
                Observation {
                    field: "http.target",
                    value: target.into(),
                },
                Observation {
                    field: "http.request_version",
                    value: version.into(),
                },
            ];
            let absolute = target
                .split_once("://")
                .filter(|(scheme, _)| {
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                })
                .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default());
            if let Some(authority) = absolute.or_else(|| (start == "CONNECT").then_some(target))
                && !authority.is_empty()
            {
                observations.push(Observation {
                    field: "http.host",
                    value: authority.to_ascii_lowercase(),
                });
            }
            (
                observations,
                REQUEST_FIELDS,
                true,
                false,
                version == "HTTP/1.1",
            )
        };

    let mut content_length = None;
    let mut framing_valid = true;
    let mut transfer_codings = Vec::new();
    let mut connection_close = false;
    let mut connection_upgrade = false;
    let mut upgrades = Vec::new();
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            framing_valid = false;
            continue;
        };
        let name = &line[..colon];
        let value = line[colon + 1..].trim_ascii();
        if request
            && name.eq_ignore_ascii_case(b"host")
            && let Ok(value) = std::str::from_utf8(value)
        {
            observations.push(Observation {
                field: "http.host",
                value: value.to_ascii_lowercase(),
            });
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            let Ok(value) = std::str::from_utf8(value) else {
                framing_valid = false;
                continue;
            };
            for part in value.split(',') {
                let part = part.trim_ascii();
                if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                    framing_valid = false;
                    continue;
                }
                let Ok(length) = part.parse::<usize>() else {
                    framing_valid = false;
                    continue;
                };
                if content_length.is_some_and(|previous| previous != length) {
                    framing_valid = false;
                }
                content_length = Some(length);
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_codings.extend(
                value
                    .split(|&byte| byte == b',')
                    .map(|coding| coding.trim_ascii().to_vec()),
            );
        } else if name.eq_ignore_ascii_case(b"connection") {
            for token in value.split(|&byte| byte == b',') {
                let token = token.trim_ascii();
                connection_close |= token.eq_ignore_ascii_case(b"close");
                connection_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
            }
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            upgrades.extend(upgrade_tokens(value));
        }
    }
    if http11 && connection_upgrade {
        let field = if request {
            Some("http.upgrade_offer")
        } else if observations
            .iter()
            .any(|item| item.field == "http.status" && item.value == "101")
        {
            Some("http.upgrade_selected")
        } else {
            None
        };
        if let Some(field) = field {
            for protocol in upgrades {
                if !observations
                    .iter()
                    .any(|item| item.field == field && item.value == protocol)
                {
                    observations.push(Observation {
                        field,
                        value: protocol,
                    });
                }
            }
        }
    }
    let (body, continue_after) = if no_response_body {
        let switching = observations
            .iter()
            .any(|item| item.field == "http.status" && item.value == "101");
        (Body::None, !connection_close && !switching)
    } else if !framing_valid || connection_close {
        (Body::None, false)
    } else if let Some(last) = transfer_codings.last() {
        let valid = content_length.is_none()
            && http11
            && last.eq_ignore_ascii_case(b"chunked")
            && transfer_codings[..transfer_codings.len() - 1]
                .iter()
                .all(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case(b"chunked"));
        if valid {
            (Body::ChunkSize(Vec::new()), true)
        } else {
            (Body::None, false)
        }
    } else if let Some(length) = content_length {
        if length == 0 {
            (Body::None, true)
        } else {
            (Body::Fixed(length), true)
        }
    } else {
        (Body::None, request)
    };
    Some(Message {
        observations,
        clear_fields,
        body,
        continue_after,
        head_can_continue: framing_valid && !connection_close,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlates_pipelined_responses_without_consuming_informational_response() {
        let mut conversation = HttpConversation::default();
        let (requests, _) = batches(conversation.feed(
            b"GET /one HTTP/1.1\r\nHost: one.test\r\n\r\nGET /two HTTP/1.1\r\nHost: two.test\r\n\r\n",
            false,
        ));
        assert_eq!(requests.len(), 2);
        let (responses, _) = batches(conversation.feed(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            true,
        ));
        assert_eq!(responses.len(), 3);
        assert_eq!(target(&responses[0]), Some("/one"));
        assert_eq!(target(&responses[1]), Some("/one"));
        assert_eq!(target(&responses[2]), Some("/two"));
        assert!(responses[0].provisional);
        assert!(!responses[1].provisional);
        assert!(!responses[2].provisional);
        assert!(responses.iter().all(|batch| batch.clear_fields == FIELDS));
    }

    #[test]
    fn head_response_length_does_not_hide_following_response() {
        let mut conversation = HttpConversation::default();
        let (requests, _) = batches(conversation.feed(
            b"HEAD /head HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n",
            false,
        ));
        assert_eq!(requests.len(), 2);
        let (responses, finished) = batches(conversation.feed(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            true,
        ));
        assert!(!finished);
        assert_eq!(responses.len(), 2);
        assert_eq!(target(&responses[0]), Some("/head"));
        assert_eq!(target(&responses[1]), Some("/next"));
    }

    #[test]
    fn successful_connect_ends_http_inspection() {
        let mut conversation = HttpConversation::default();
        let (requests, _) =
            batches(conversation.feed(b"CONNECT relay.test:443 HTTP/1.1\r\n\r\n", false));
        assert_eq!(requests.len(), 1);
        let (responses, finished) = batches(conversation.feed(
            b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\nGET /tunnel HTTP/1.1\r\n\r\n",
            true,
        ));
        assert_eq!(responses.len(), 1);
        assert!(finished);
        assert_eq!(
            conversation.feed(b"GET /inside HTTP/1.1\r\n\r\n", false),
            Analysis::Finished
        );
    }

    #[test]
    fn upgrade_offer_and_selection_are_correlated() {
        let mut conversation = HttpConversation::default();
        assert_eq!(
            conversation.feed(
                b"GET /ws HTTP/1.1\r\nHost: relay.test\r\nConnection: keep-alive, Upgr",
                false,
            ),
            Analysis::Pending
        );
        let (offers, finished) =
            batches(conversation.feed(b"ade\r\nUpgrade: WebSocket, h2c\r\n\r\n", false));
        assert!(!finished);
        assert_eq!(offers.len(), 1);
        assert!(
            offers[0]
                .observations
                .iter()
                .any(|item| { item.field == "http.upgrade_offer" && item.value == "websocket" })
        );
        assert!(
            offers[0]
                .observations
                .iter()
                .any(|item| item.field == "http.upgrade_offer" && item.value == "h2c")
        );
        let (responses, finished) = batches(conversation.feed(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            true,
        ));
        assert!(finished);
        assert_eq!(responses.len(), 1);
        assert!(
            responses[0]
                .context
                .iter()
                .any(|item| item.field == "http.upgrade_offer" && item.value == "websocket")
        );
        assert!(
            responses[0]
                .observations
                .iter()
                .any(|item| { item.field == "http.upgrade_selected" && item.value == "websocket" })
        );
        assert_eq!(conversation.feed(b"\x81\x00", true), Analysis::Finished);
    }

    #[test]
    fn upgrade_header_alone_or_non_switching_response_is_not_selection() {
        let (request, _) =
            batches(HttpMessages::default().feed(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"));
        assert!(
            !request[0]
                .observations
                .iter()
                .any(|item| item.field == "http.upgrade_offer")
        );
        let (response, _) = batches(
            HttpMessages::default()
                .feed(b"HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"),
        );
        assert!(
            !response[0]
                .observations
                .iter()
                .any(|item| item.field == "http.upgrade_selected")
        );
    }

    fn target(batch: &ObservationBatch) -> Option<&str> {
        batch
            .context
            .iter()
            .find(|item| item.field == "http.target")
            .map(|item| item.value.as_str())
    }

    fn batches(result: Analysis) -> (Vec<ObservationBatch>, bool) {
        let Analysis::Batches { batches, finished } = result else {
            panic!("expected HTTP message batches");
        };
        (batches, finished)
    }

    #[test]
    fn request_without_host_still_reports_request_line() {
        let (batches, finished) =
            batches(HttpMessages::default().feed(b"OPTIONS * HTTP/1.0\r\n\r\n"));
        assert!(!finished);
        assert_eq!(batches.len(), 1);
        assert_eq!(
            batches[0].observations,
            vec![
                Observation {
                    field: "http.method",
                    value: "OPTIONS".into()
                },
                Observation {
                    field: "http.target",
                    value: "*".into()
                },
                Observation {
                    field: "http.request_version",
                    value: "HTTP/1.0".into()
                },
            ]
        );
    }

    #[test]
    fn fragmented_response_reports_status_and_version() {
        let mut analyzer = HttpMessages::default();
        assert_eq!(analyzer.feed(b"HTTP/1.1 404 Not Fo"), Analysis::Pending);
        let (batches, finished) = batches(analyzer.feed(b"und\r\nServer: test\r\n\r\n"));
        assert!(finished);
        assert_eq!(
            batches[0].observations,
            vec![
                Observation {
                    field: "http.response_version",
                    value: "HTTP/1.1".into()
                },
                Observation {
                    field: "http.status",
                    value: "404".into()
                },
            ]
        );
        assert_eq!(analyzer.feed(b"body"), Analysis::Finished);
    }

    #[test]
    fn malformed_response_status_is_not_an_observation() {
        assert_eq!(
            HttpMessages::default().feed(b"HTTP/1.1 OK\r\n\r\n"),
            Analysis::Finished
        );
    }

    #[test]
    fn lowercase_method_does_not_claim_connect_authority() {
        let (batches, _) =
            batches(HttpMessages::default().feed(b"connect example.test:443 HTTP/1.1\r\n\r\n"));
        let values = &batches[0].observations;
        assert!(!values.iter().any(|value| value.field == "http.host"));
        assert_eq!(values[0].value, "connect");
    }

    #[test]
    fn parses_pipelined_requests_and_skips_fixed_length_body() {
        let mut analyzer = HttpMessages::default();
        let (batches, finished) = batches(analyzer.feed(
            b"POST /one HTTP/1.1\r\nHost: first.test\r\nContent-Length: 39\r\n\r\nGET /fake HTTP/1.1\r\nHost: fake.test\r\n\r\nGET /two HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
        ));
        assert!(!finished);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].observations[1].value, "/one");
        assert_eq!(batches[1].observations[1].value, "/two");
    }

    #[test]
    fn ambiguous_framing_stops_after_visible_header() {
        let (batches, finished) = batches(HttpMessages::default().feed(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nGET /fake HTTP/1.1\r\n\r\n",
        ));
        assert!(finished);
        assert_eq!(batches.len(), 1);
    }

    #[test]
    fn chunked_request_with_extension_and_trailer_reaches_next_request() {
        let fake = b"GET /fake HTTP/1.1\r\nHost: fake.test\r\n\r\n";
        let mut wire =
            b"POST /one HTTP/1.1\r\nHost: first.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
                .to_vec();
        wire.extend(format!("{:x};sig=test\r\n", fake.len()).bytes());
        wire.extend(fake);
        wire.extend(
            b"\r\n0\r\nX-Trailer: yes\r\n\r\nGET /two HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
        );
        let mut analyzer = HttpMessages::default();
        let mut found = Vec::new();
        for byte in wire {
            match analyzer.feed(&[byte]) {
                Analysis::Batches { batches, finished } => {
                    assert!(!finished);
                    found.extend(batches);
                }
                Analysis::Pending => {}
                other => panic!("unexpected analysis: {other:?}"),
            }
        }
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].observations[1].value, "/one");
        assert_eq!(found[1].observations[1].value, "/two");
        assert!(
            found[1]
                .observations
                .iter()
                .any(|item| item.field == "http.host" && item.value == "blocked.test")
        );
    }

    #[test]
    fn chunked_response_reaches_next_status() {
        let mut analyzer = HttpMessages::default();
        let (batches, finished) = batches(analyzer.feed(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        ));
        assert!(!finished);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].observations[1].value, "200");
        assert_eq!(batches[1].observations[1].value, "404");
    }

    #[test]
    fn skips_fragmented_response_body_before_next_status() {
        let mut analyzer = HttpMessages::default();
        let first = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nAB";
        let (first_batches, finished) = batches(analyzer.feed(first));
        assert!(!finished);
        assert_eq!(first_batches.len(), 1);
        let (batches, finished) =
            batches(analyzer.feed(b"CDHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));
        assert!(!finished);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].observations[1].value, "404");
    }
}
