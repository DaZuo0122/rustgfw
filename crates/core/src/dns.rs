//! DNS header, question, and selected answer inspection.
use crate::inspect::{
    Analysis, DatagramAnalysis, DatagramAnalyzer, Observation, ObservationBatch, StreamAnalyzer,
    UdpStreamAnalysis, UdpStreamAnalyzer,
};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const FIELDS: &[&str] = &[
    "dns.id",
    "dns.qr",
    "dns.opcode",
    "dns.qname",
    "dns.qtype",
    "dns.rcode",
    "dns.answer_ipv4",
    "dns.answer_ipv6",
    "dns.answer_cname",
];

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidDns;

fn word(message: &[u8], offset: usize) -> Result<u16, InvalidDns> {
    Ok(u16::from_be_bytes(
        message
            .get(offset..offset + 2)
            .ok_or(InvalidDns)?
            .try_into()
            .unwrap(),
    ))
}
fn name(message: &[u8], offset: &mut usize) -> Result<String, InvalidDns> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut output = String::new();
    let mut wire_len = 1;
    // Each pointer must go backwards; label traversal may lead back to the same
    // pointer, so also bound total traversal to reject compression cycles.
    for _ in 0..message.len() {
        let len = *message.get(cursor).ok_or(InvalidDns)?;
        if len & 0xc0 == 0xc0 {
            let target = usize::from(word(message, cursor)? & 0x3fff);
            if target >= cursor {
                return Err(InvalidDns);
            }
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = target;
        } else if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(output);
        } else {
            if len & 0xc0 != 0 {
                return Err(InvalidDns);
            }
            cursor += 1;
            let label = message
                .get(cursor..cursor + usize::from(len))
                .ok_or(InvalidDns)?;
            wire_len += usize::from(len) + 1;
            if wire_len > 255 || !label.is_ascii() || label.contains(&b'.') || label.contains(&0) {
                return Err(InvalidDns);
            }
            if !output.is_empty() {
                output.push('.');
            }
            output.push_str(
                &std::str::from_utf8(label)
                    .map_err(|_| InvalidDns)?
                    .to_ascii_lowercase(),
            );
            cursor += usize::from(len);
        }
    }
    Err(InvalidDns)
}

struct DnsMessage {
    id: u16,
    response: bool,
    opcode: u8,
    rcode: u8,
    questions: Vec<(String, u16, u16)>,
    answers: Vec<Answer>,
}

enum Answer {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Cname(String),
}

fn parse_message(message: &[u8]) -> Result<DnsMessage, InvalidDns> {
    if message.len() < 12 {
        return Err(InvalidDns);
    }
    let flags = word(message, 2)?;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let count = word(message, 4)?;
    let mut cursor = 12;
    let mut questions = Vec::new();
    let mut answers = Vec::new();
    if opcode == 0 {
        for _ in 0..count {
            let qname = name(message, &mut cursor)?;
            let qtype = word(message, cursor)?;
            let class = word(message, cursor + 2)?;
            cursor += 4;
            questions.push((qname, qtype, class));
        }
        for _ in 0..word(message, 6)? {
            name(message, &mut cursor)?;
            let kind = word(message, cursor)?;
            let class = word(message, cursor + 2)?;
            let length = usize::from(word(message, cursor + 8)?);
            cursor += 10;
            let data = message.get(cursor..cursor + length).ok_or(InvalidDns)?;
            if class == 1 {
                match kind {
                    1 => answers.push(Answer::Ipv4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(data).map_err(|_| InvalidDns)?,
                    ))),
                    28 => answers.push(Answer::Ipv6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(data).map_err(|_| InvalidDns)?,
                    ))),
                    5 => {
                        let mut end = cursor;
                        let target = name(message, &mut end)?;
                        if end != cursor + length {
                            return Err(InvalidDns);
                        }
                        answers.push(Answer::Cname(target));
                    }
                    _ => {}
                }
            }
            cursor += length;
        }
    }
    Ok(DnsMessage {
        id: word(message, 0)?,
        response: flags & 0x8000 != 0,
        opcode,
        rcode: (flags & 0x0f) as u8,
        questions,
        answers,
    })
}

/// Extract query questions; responses and nonstandard opcodes produce no names.
pub fn questions(message: &[u8]) -> Result<Vec<String>, InvalidDns> {
    let message = parse_message(message)?;
    if message.response {
        return Ok(Vec::new());
    }
    Ok(message
        .questions
        .into_iter()
        .filter(|(_, _, class)| *class == 1)
        .map(|(name, _, _)| name)
        .collect())
}

fn observations(message: DnsMessage) -> Vec<Observation> {
    let mut result = vec![
        Observation {
            field: "dns.id",
            value: message.id.to_string(),
        },
        Observation {
            field: "dns.qr",
            value: if message.response {
                "response"
            } else {
                "query"
            }
            .into(),
        },
        Observation {
            field: "dns.opcode",
            value: message.opcode.to_string(),
        },
    ];
    if message.response {
        result.push(Observation {
            field: "dns.rcode",
            value: message.rcode.to_string(),
        });
    }
    if message.questions.len() == 1 && message.questions[0].2 == 1 {
        result.push(Observation {
            field: "dns.qtype",
            value: message.questions[0].1.to_string(),
        });
    }
    result.extend(
        message
            .questions
            .into_iter()
            .filter_map(|(name, _, class)| {
                (class == 1).then_some(Observation {
                    field: "dns.qname",
                    value: name,
                })
            }),
    );
    if message.response {
        result.extend(message.answers.into_iter().map(|answer| match answer {
            Answer::Ipv4(address) => Observation {
                field: "dns.answer_ipv4",
                value: address.to_string(),
            },
            Answer::Ipv6(address) => Observation {
                field: "dns.answer_ipv6",
                value: address.to_string(),
            },
            Answer::Cname(name) => Observation {
                field: "dns.answer_cname",
                value: name,
            },
        }));
    }
    result
}

#[derive(Default)]
pub struct DnsDatagram;
impl DatagramAnalyzer for DnsDatagram {
    fn inspect(&self, payload: &[u8]) -> DatagramAnalysis {
        match questions(payload) {
            Ok(names) => DatagramAnalysis::Observations(
                names
                    .into_iter()
                    .map(|value| Observation {
                        field: "dns.qname",
                        value,
                    })
                    .collect(),
            ),
            Err(_) => DatagramAnalysis::Malformed,
        }
    }
}

/// Stateful UDP rule adapter; each datagram replaces the previous DNS fields.
pub struct DnsUdp;
impl UdpStreamAnalyzer for DnsUdp {
    fn feed(&mut self, payload: &[u8], _: bool) -> UdpStreamAnalysis {
        match parse_message(payload) {
            Ok(message) => UdpStreamAnalysis::ReplaceFields {
                fields: FIELDS.to_vec(),
                observations: observations(message),
            },
            Err(_) => UdpStreamAnalysis::Drop,
        }
    }
}

pub struct DnsTcp {
    pending: Vec<u8>,
    message_limit: usize,
}
impl Default for DnsTcp {
    fn default() -> Self {
        Self::with_message_limit(65535)
    }
}
impl DnsTcp {
    pub fn with_message_limit(message_limit: usize) -> Self {
        Self {
            pending: Vec::new(),
            message_limit,
        }
    }
}
impl StreamAnalyzer for DnsTcp {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        self.pending.extend_from_slice(bytes);
        let mut batches = Vec::new();
        let mut consumed = 0;
        while self.pending.len() - consumed >= 2 {
            let len = usize::from(word(&self.pending, consumed).unwrap());
            if len > self.message_limit {
                return finished_batches(batches);
            }
            if self.pending.len() - consumed < len + 2 {
                break;
            }
            match parse_message(&self.pending[consumed + 2..consumed + 2 + len]) {
                Ok(message) => batches.push(ObservationBatch {
                    clear_fields: FIELDS,
                    context: Vec::new(),
                    observations: observations(message),
                    allow_continues: true,
                }),
                Err(_) => return finished_batches(batches),
            }
            consumed += len + 2;
        }
        self.pending.drain(..consumed);
        if batches.is_empty() {
            Analysis::Pending
        } else {
            Analysis::Batches {
                batches,
                finished: false,
            }
        }
    }
}

fn finished_batches(batches: Vec<ObservationBatch>) -> Analysis {
    if batches.is_empty() {
        Analysis::Finished
    } else {
        Analysis::Batches {
            batches,
            finished: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FlowScope, Packet, Policy, Verdict,
        inspect::{DatagramPort, DatagramRule, Inspect, InspectLimits},
    };
    fn query() -> Vec<u8> {
        let mut q = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }

    fn field<'a>(items: &'a [Observation], name: &str) -> Option<&'a str> {
        items
            .iter()
            .find(|item| item.field == name)
            .map(|item| item.value.as_str())
    }

    #[test]
    fn udp_exposes_query_type_and_response_code_per_datagram() {
        let mut analyzer = DnsUdp;
        let mut request = query();
        let qtype = request.len() - 4;
        request[qtype..qtype + 2].copy_from_slice(&28u16.to_be_bytes());
        let UdpStreamAnalysis::ReplaceFields {
            fields,
            observations: request_fields,
        } = analyzer.feed(&request, false)
        else {
            panic!("expected DNS request observations");
        };
        assert_eq!(fields, FIELDS);
        assert_eq!(field(&request_fields, "dns.id"), Some("1"));
        assert_eq!(field(&request_fields, "dns.qr"), Some("query"));
        assert_eq!(field(&request_fields, "dns.qname"), Some("example.com"));
        assert_eq!(field(&request_fields, "dns.qtype"), Some("28"));
        assert_eq!(field(&request_fields, "dns.rcode"), None);

        let mut response = request.clone();
        response[2] = 0x81;
        response[3] = 0x83;
        let UdpStreamAnalysis::ReplaceFields {
            observations: response_fields,
            ..
        } = analyzer.feed(&response, true)
        else {
            panic!("expected DNS response observations");
        };
        assert_eq!(field(&response_fields, "dns.qr"), Some("response"));
        assert_eq!(field(&response_fields, "dns.qname"), Some("example.com"));
        assert_eq!(field(&response_fields, "dns.qtype"), Some("28"));
        assert_eq!(field(&response_fields, "dns.rcode"), Some("3"));
        assert!(questions(&response).unwrap().is_empty());
    }

    #[test]
    fn response_exposes_compressed_cname_and_address_answers() {
        let mut response = query();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 3;
        let cname = b"\x05alias\xc0\x0c";
        let alias_offset = response.len() + 12;
        response.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 30, 0, cname.len() as u8]);
        response.extend_from_slice(cname);
        response.extend_from_slice(&[
            0xc0,
            alias_offset as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            30,
            0,
            4,
            203,
            0,
            113,
            7,
        ]);
        response.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        response.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        let UdpStreamAnalysis::ReplaceFields { observations, .. } = DnsUdp.feed(&response, true)
        else {
            panic!("expected DNS answer observations");
        };
        assert_eq!(field(&observations, "dns.qname"), Some("example.com"));
        assert_eq!(
            field(&observations, "dns.answer_cname"),
            Some("alias.example.com")
        );
        assert_eq!(field(&observations, "dns.answer_ipv4"), Some("203.0.113.7"));
        assert_eq!(field(&observations, "dns.answer_ipv6"), Some("2001:db8::7"));
        assert!(questions(&response).unwrap().is_empty());

        let mut short_a = response.clone();
        short_a[alias_offset + cname.len() + 11] = 3;
        assert!(matches!(
            DnsUdp.feed(&short_a, true),
            UdpStreamAnalysis::Drop
        ));
        let mut extra_cname = response;
        extra_cname[alias_offset - 1] = (cname.len() + 1) as u8;
        assert!(matches!(
            DnsUdp.feed(&extra_cname, true),
            UdpStreamAnalysis::Drop
        ));
    }

    #[test]
    fn tcp_batches_consecutive_messages_and_keeps_earlier_valid_message() {
        let first = query();
        let mut second = query();
        let qtype = second.len() - 4;
        second[qtype..qtype + 2].copy_from_slice(&28u16.to_be_bytes());
        let mut wire = Vec::new();
        for message in [&first, &second] {
            wire.extend_from_slice(&(message.len() as u16).to_be_bytes());
            wire.extend_from_slice(message);
        }
        let Analysis::Batches { batches, finished } = DnsTcp::default().feed(&wire) else {
            panic!("expected separate DNS messages");
        };
        assert!(!finished);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].clear_fields, FIELDS);
        assert_eq!(field(&batches[0].observations, "dns.qtype"), Some("1"));
        assert_eq!(field(&batches[1].observations, "dns.qtype"), Some("28"));

        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0]);
        let Analysis::Batches { batches, finished } = DnsTcp::default().feed(&wire) else {
            panic!("valid messages before malformed one must still be reported");
        };
        assert!(finished);
        assert_eq!(batches.len(), 2);
    }
    #[test]
    fn compressed_questions_and_cycles() {
        let mut q = query();
        q[5] = 2;
        q.extend([0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(questions(&q).unwrap(), ["example.com", "example.com"]);
        let UdpStreamAnalysis::ReplaceFields { observations, .. } = DnsUdp.feed(&q, false) else {
            panic!("expected multi-question DNS observations");
        };
        assert_eq!(field(&observations, "dns.qname"), Some("example.com"));
        assert_eq!(field(&observations, "dns.qtype"), None);
        for len in 0..q.len() {
            assert!(questions(&q[..len]).is_err());
        }
        q[12] = 0xc0;
        q[13] = 12;
        assert_eq!(questions(&q), Err(InvalidDns));
    }
    #[test]
    fn tcp_multiple_messages_split_at_every_byte() {
        let q = query();
        let mut wire = (q.len() as u16).to_be_bytes().to_vec();
        wire.extend(q);
        wire.extend(wire.clone());
        let mut parser = DnsTcp::default();
        let mut names = Vec::new();
        for byte in wire {
            if let Analysis::Batches { batches, .. } = parser.feed(&[byte]) {
                names.extend(
                    batches
                        .into_iter()
                        .flat_map(|batch| batch.observations)
                        .filter(|item| item.field == "dns.qname")
                        .map(|item| item.value),
                );
            }
        }
        assert_eq!(names, ["example.com", "example.com"]);
    }
    #[test]
    fn configured_message_limit_rejects_declared_length() {
        let q = query();
        let mut wire = (q.len() as u16).to_be_bytes().to_vec();
        wire.extend(q);
        let mut limited = DnsTcp::with_message_limit(wire.len() - 3);
        assert_eq!(limited.feed(&wire[..1]), Analysis::Pending);
        assert_eq!(limited.feed(&wire[1..2]), Analysis::Finished);
        assert!(matches!(
            DnsTcp::with_message_limit(wire.len() - 2).feed(&wire),
            Analysis::Batches { .. }
        ));
    }
    #[test]
    fn udp_does_not_cache_query_verdict() {
        let mut policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            vec![
                DatagramRule::exact(
                    "dns.qname",
                    vec!["example.com".into()],
                    Some(DatagramPort::Destination(53)),
                    DnsDatagram,
                )
                .unwrap(),
            ],
            InspectLimits::default(),
        );
        let mut p = crate::packet::udp(false);
        p.truncate(28);
        p.extend(query());
        let size = p.len() as u16;
        p[2..4].copy_from_slice(&size.to_be_bytes());
        p[24..26].copy_from_slice(&(size - 20).to_be_bytes());
        let mut run = |bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
                capture_time: None,
            })
        };
        assert_eq!(run(&p), Verdict::Drop);
        p[41] = b'z';
        assert_eq!(run(&p), Verdict::Accept);
        p[40] = 0xff;
        assert_eq!(run(&p), Verdict::Drop);
    }
}
