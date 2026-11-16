//! First HTTP/1 message in each reassembled TCP direction.
use crate::inspect::{Analysis, Observation, StreamAnalyzer};

pub const FIELDS: &[&str] = &[
    "http.host",
    "http.method",
    "http.target",
    "http.request_version",
    "http.status",
    "http.response_version",
];

pub struct HttpFirstMessage {
    header: Vec<u8>,
    finished: bool,
    limit: usize,
}

impl Default for HttpFirstMessage {
    fn default() -> Self {
        Self::with_header_limit(16384)
    }
}

impl HttpFirstMessage {
    pub fn with_header_limit(limit: usize) -> Self {
        Self {
            header: Vec::new(),
            finished: false,
            limit,
        }
    }
}

impl StreamAnalyzer for HttpFirstMessage {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        for &byte in bytes {
            if self.header.len() == self.limit {
                self.finished = true;
                return Analysis::Finished;
            }
            self.header.push(byte);
            if self.header.ends_with(b"\r\n\r\n") {
                self.finished = true;
                return parse_message(&self.header);
            }
        }
        Analysis::Pending
    }
}

fn parse_message(header: &[u8]) -> Analysis {
    let mut lines = header.split(|&byte| byte == b'\n');
    let first = lines.next().unwrap_or_default();
    let Ok(first) = std::str::from_utf8(first.strip_suffix(b"\r").unwrap_or(first)) else {
        return Analysis::Finished;
    };
    let mut words = first.split_ascii_whitespace();
    let Some(start) = words.next() else {
        return Analysis::Finished;
    };
    if matches!(start, "HTTP/1.0" | "HTTP/1.1") {
        let Some(status) = words.next() else {
            return Analysis::Finished;
        };
        if status.len() != 3
            || !status.bytes().all(|byte| byte.is_ascii_digit())
            || status.starts_with('0')
        {
            return Analysis::Finished;
        }
        return Analysis::FinalObservations(vec![
            Observation {
                field: "http.response_version",
                value: start.into(),
            },
            Observation {
                field: "http.status",
                value: status.into(),
            },
        ]);
    }
    let (Some(target), Some(version)) = (words.next(), words.next()) else {
        return Analysis::Finished;
    };
    if words.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !start
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Analysis::Finished;
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
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(colon) = line.iter().position(|&byte| byte == b':')
            && line[..colon].eq_ignore_ascii_case(b"host")
            && let Ok(value) = std::str::from_utf8(line[colon + 1..].trim_ascii())
        {
            observations.push(Observation {
                field: "http.host",
                value: value.to_ascii_lowercase(),
            });
        }
    }
    Analysis::FinalObservations(observations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_without_host_still_reports_request_line() {
        let result = HttpFirstMessage::default().feed(b"OPTIONS * HTTP/1.0\r\n\r\n");
        assert_eq!(
            result,
            Analysis::FinalObservations(vec![
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
            ])
        );
    }

    #[test]
    fn fragmented_response_reports_status_and_version() {
        let mut analyzer = HttpFirstMessage::default();
        assert_eq!(analyzer.feed(b"HTTP/1.1 404 Not Fo"), Analysis::Pending);
        assert_eq!(
            analyzer.feed(b"und\r\nServer: test\r\n\r\n"),
            Analysis::FinalObservations(vec![
                Observation {
                    field: "http.response_version",
                    value: "HTTP/1.1".into()
                },
                Observation {
                    field: "http.status",
                    value: "404".into()
                },
            ])
        );
        assert_eq!(analyzer.feed(b"body"), Analysis::Finished);
    }

    #[test]
    fn malformed_response_status_is_not_an_observation() {
        let result = HttpFirstMessage::default().feed(b"HTTP/1.1 OK\r\n\r\n");
        assert_eq!(result, Analysis::Finished);
    }

    #[test]
    fn lowercase_method_does_not_claim_connect_authority() {
        let result = HttpFirstMessage::default().feed(b"connect example.test:443 HTTP/1.1\r\n\r\n");
        let Analysis::FinalObservations(values) = result else {
            panic!("expected request line observations");
        };
        assert!(!values.iter().any(|value| value.field == "http.host"));
        assert_eq!(values[0].value, "connect");
    }
}
