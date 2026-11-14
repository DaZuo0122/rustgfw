//! DNS question inspection. UDP decisions apply to one datagram, not its socket.
use crate::{
    Packet, Policy, Verdict,
    inspect::{Analysis, Observation, StreamAnalyzer},
    packet::{self, Protocol},
};

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

/// Extract query questions; responses and nonstandard opcodes produce no names.
pub fn questions(message: &[u8]) -> Result<Vec<String>, InvalidDns> {
    if message.len() < 12 {
        return Err(InvalidDns);
    }
    if word(message, 2)? & 0xf800 != 0 {
        return Ok(Vec::new());
    }
    let count = word(message, 4)?;
    let mut cursor = 12;
    let mut names = Vec::new();
    for _ in 0..count {
        let qname = name(message, &mut cursor)?;
        word(message, cursor)?;
        let class = word(message, cursor + 2)?;
        cursor += 4;
        if class == 1 {
            names.push(qname);
        }
    }
    Ok(names)
}

pub struct DnsPolicy<P> {
    inner: P,
    names: Vec<String>,
}
impl<P> DnsPolicy<P> {
    pub fn new(inner: P, names: Vec<String>) -> Self {
        Self {
            inner,
            names: names
                .into_iter()
                .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
                .collect(),
        }
    }
}
impl<P: Policy> Policy for DnsPolicy<P> {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
        let verdict = self.inner.evaluate(packet);
        if verdict != Verdict::Accept || self.names.is_empty() {
            return verdict;
        }
        let Ok(t) = packet::parse(packet.bytes) else {
            return verdict;
        };
        if t.protocol != Protocol::Udp || t.destination.port() != 53 {
            return verdict;
        }
        match questions(t.payload) {
            Ok(names) if names.iter().any(|n| self.names.contains(n)) => Verdict::Drop,
            Err(_) => Verdict::Drop,
            _ => verdict,
        }
    }
}

#[derive(Default)]
pub struct DnsTcp {
    pending: Vec<u8>,
}
impl StreamAnalyzer for DnsTcp {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        self.pending.extend_from_slice(bytes);
        let mut names = Vec::new();
        let mut consumed = 0;
        while self.pending.len() - consumed >= 2 {
            let len = usize::from(word(&self.pending, consumed).unwrap());
            if self.pending.len() - consumed < len + 2 {
                break;
            }
            match questions(&self.pending[consumed + 2..consumed + 2 + len]) {
                Ok(found) => names.extend(found),
                Err(_) => return Analysis::Finished,
            }
            consumed += len + 2;
        }
        self.pending.drain(..consumed);
        if names.is_empty() {
            Analysis::Pending
        } else {
            Analysis::Observations(
                names
                    .into_iter()
                    .map(|value| Observation {
                        field: "dns.qname",
                        value,
                    })
                    .collect(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        let mut q = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }
    #[test]
    fn compressed_questions_and_cycles() {
        let mut q = query();
        q[5] = 2;
        q.extend([0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(questions(&q).unwrap(), ["example.com", "example.com"]);
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
            if let Analysis::Observations(found) = parser.feed(&[byte]) {
                names.extend(found.into_iter().map(|o| o.value));
            }
        }
        assert_eq!(names, ["example.com", "example.com"]);
    }
    #[test]
    fn udp_does_not_cache_query_verdict() {
        let mut policy = DnsPolicy::new(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["example.com".into()],
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
            })
        };
        assert_eq!(run(&p), Verdict::Drop);
        p[41] = b'z';
        assert_eq!(run(&p), Verdict::Accept);
    }
}
