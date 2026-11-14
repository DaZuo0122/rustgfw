//! Incremental stream analysis. Each direction shares reassembly across analyzers.
use crate::{
    Packet, Policy, Verdict,
    packet::{self, Protocol},
    tcp::Reassembler,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Analysis {
    Pending,
    Host(String),
    /// Nonterminal observations, e.g. multiple DNS messages on one TCP stream.
    Names(Vec<String>),
    Finished,
}

pub trait StreamAnalyzer {
    fn feed(&mut self, bytes: &[u8]) -> Analysis;
}

/// HTTP/1 initial request headers. Subsequent keep-alive requests need a
/// transaction parser and are deliberately not advertised by this analyzer.
#[derive(Default)]
pub struct HttpHost {
    header: Vec<u8>,
    finished: bool,
}
impl StreamAnalyzer for HttpHost {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        for &byte in bytes {
            if self.header.len() == 16384 {
                self.finished = true;
                return Analysis::Finished;
            }
            self.header.push(byte);
            if self.header.ends_with(b"\r\n\r\n") {
                self.finished = true;
                let Ok(text) = std::str::from_utf8(&self.header) else {
                    return Analysis::Finished;
                };
                let mut lines = text.split("\r\n");
                let first = lines.next().unwrap_or_default();
                if !first.ends_with(" HTTP/1.1") && !first.ends_with(" HTTP/1.0") {
                    return Analysis::Finished;
                }
                for line in lines {
                    if let Some((key, value)) = line.split_once(':')
                        && key.eq_ignore_ascii_case("host")
                    {
                        return Analysis::Host(value.trim().to_ascii_lowercase());
                    }
                }
                return Analysis::Finished;
            }
        }
        Analysis::Pending
    }
}

struct Direction {
    reassembly: Reassembler,
    analyzers: Vec<Option<Box<dyn StreamAnalyzer>>>,
}
struct Flow {
    directions: [Direction; 2],
    blocked: bool,
    seen: Instant,
    initial_syn: Option<(usize, u32)>,
    fin_seen: [bool; 2],
}
impl Flow {
    fn finished(&self) -> bool {
        !self.blocked
            && self
                .directions
                .iter()
                .all(|d| d.analyzers.iter().all(Option::is_none))
    }
}
type Key = (SocketAddr, SocketAddr);

pub struct AnalyzerRule {
    pub port: Option<u16>,
    pub hosts: Vec<String>,
    pub factory: fn() -> Box<dyn StreamAnalyzer>,
}

/// Transport policy runs first; application matches can additionally block.
/// Inspection is passive: packets before a match are accepted, as in OpenGFW.
pub struct Inspect<P> {
    transport: P,
    analyzers: Vec<AnalyzerRule>,
    flows: HashMap<Key, Flow>,
    sweep: Instant,
}
impl<P> Inspect<P> {
    pub fn new(transport: P, hosts: Vec<String>, factory: fn() -> Box<dyn StreamAnalyzer>) -> Self {
        Self::with_analyzers(
            transport,
            vec![AnalyzerRule {
                hosts,
                factory,
                port: None,
            }],
        )
    }
    pub fn with_analyzers(transport: P, mut analyzers: Vec<AnalyzerRule>) -> Self {
        analyzers.retain(|a| !a.hosts.is_empty());
        for a in &mut analyzers {
            for host in &mut a.hosts {
                host.make_ascii_lowercase();
            }
        }
        Self {
            transport,
            analyzers,
            flows: HashMap::new(),
            sweep: Instant::now(),
        }
    }
    pub fn clear_flows(&mut self) {
        self.flows.clear();
    }
}
impl<P: Policy> Policy for Inspect<P> {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
        let verdict = self.transport.evaluate(packet);
        if verdict != Verdict::Accept || self.analyzers.is_empty() {
            return verdict;
        }
        let Ok(t) = packet::parse(packet.bytes) else {
            return verdict;
        };
        if t.protocol != Protocol::Tcp {
            return verdict;
        }
        if !self.analyzers.iter().any(|a| {
            a.port
                .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
        }) {
            return verdict;
        }
        let now = Instant::now();
        if now >= self.sweep {
            self.flows
                .retain(|_, f| now.duration_since(f.seen) < Duration::from_secs(120));
            self.sweep = now + Duration::from_secs(1);
        }
        let (key, direction) = if t.source <= t.destination {
            ((t.source, t.destination), 0)
        } else {
            ((t.destination, t.source), 1)
        };
        let initial_syn = (t.tcp_flags & 0x12 == 2).then_some((direction, t.tcp_sequence.unwrap()));
        if let Some(syn) = initial_syn
            && self
                .flows
                .get(&key)
                .is_some_and(|f| f.initial_syn != Some(syn))
        {
            self.flows.remove(&key);
        }
        if self.flows.len() >= 4096 && !self.flows.contains_key(&key) {
            self.flows.retain(|_, flow| !flow.finished());
            if self.flows.len() >= 4096 {
                // Active inspection cannot be silently bypassed at capacity.
                return Verdict::Drop;
            }
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            directions: std::array::from_fn(|_| Direction {
                reassembly: Reassembler::new(16384),
                analyzers: self
                    .analyzers
                    .iter()
                    .map(|a| {
                        a.port
                            .is_none_or(|p| key.0.port() == p || key.1.port() == p)
                            .then(|| (a.factory)())
                    })
                    .collect(),
            }),
            blocked: false,
            seen: now,
            initial_syn,
            fin_seen: [false; 2],
        });
        flow.seen = now;
        if flow.blocked {
            return Verdict::DropFlow;
        }
        let d = &mut flow.directions[direction];
        if d.analyzers.iter().any(Option::is_some) {
            match d
                .reassembly
                .feed(t.tcp_sequence.unwrap(), t.tcp_flags & 2 != 0, t.payload)
            {
                Ok(bytes) => {
                    for (slot, rule) in d.analyzers.iter_mut().zip(&self.analyzers) {
                        let Some(analyzer) = slot else {
                            continue;
                        };
                        match analyzer.feed(&bytes) {
                            Analysis::Host(host) => {
                                flow.blocked |= rule.hosts.iter().any(|h| h == &host);
                                *slot = None;
                            }
                            Analysis::Finished => *slot = None,
                            Analysis::Names(names) => {
                                flow.blocked |= names.iter().any(|name| rule.hosts.contains(name));
                            }
                            Analysis::Pending => {}
                        }
                    }
                }
                Err(_) => flow.blocked = true,
            }
        }
        let result = if flow.blocked {
            Verdict::DropFlow
        } else {
            verdict
        };
        // A half-close leaves the other direction active. Blocked flows retain
        // their verdict until timeout or a new initial SYN replaces them.
        if t.tcp_flags & 1 != 0 {
            flow.fin_seen[direction] = true;
        }
        if !flow.blocked && (t.tcp_flags & 4 != 0 || flow.fin_seen == [true, true]) {
            self.flows.remove(&key);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_header_and_case() {
        let mut a = HttpHost::default();
        assert_eq!(a.feed(b"GET / HTTP/1.1\r\nHo"), Analysis::Pending);
        assert_eq!(
            a.feed(b"st: EXAMPLE.COM\r\n\r\nbody"),
            Analysis::Host("example.com".into())
        );
        assert_eq!(a.feed(b"more"), Analysis::Finished);
    }
    fn tcp(seq: u32, flags: u8, payload: &[u8], reverse: bool) -> Vec<u8> {
        let mut b = vec![0; 40];
        b[0] = 0x45;
        b[9] = 6;
        b[12] = 10;
        b[16] = 20;
        b[20..22].copy_from_slice(&12345u16.to_be_bytes());
        b[23] = 80;
        b[24..28].copy_from_slice(&seq.to_be_bytes());
        b[32] = 0x50;
        b[33] = flags;
        b.extend_from_slice(payload);
        let len = b.len() as u16;
        b[2..4].copy_from_slice(&len.to_be_bytes());
        if reverse {
            b.swap(12, 16);
            b.swap(20, 22);
            b.swap(21, 23);
        }
        b
    }
    #[test]
    fn policy_reassembles_then_blocks_both_directions() {
        let mut p = Inspect::new(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["example.com".into()],
            || Box::<HttpHost>::default(),
        );
        let mut feed = |seq, flags, bytes: &[u8], rev| {
            let b = tcp(seq, flags, bytes, rev);
            p.evaluate(Packet {
                bytes: &b,
                original_len: b.len(),
                checksum_ready: true,
            })
        };
        assert_eq!(feed(100, 2, b"", false), Verdict::Accept);
        let first = b"GET / HTTP/1.1\r\nHost: ";
        assert_eq!(
            feed(101 + first.len() as u32, 16, b"example.com\r\n\r\n", false),
            Verdict::Accept
        );
        assert_eq!(feed(101, 16, first, false), Verdict::DropFlow);
        assert_eq!(feed(500, 16, b"reply", true), Verdict::DropFlow);
    }

    #[test]
    fn multiple_analyzers_and_reused_connection() {
        let mut p = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule {
                    hosts: vec!["unrelated.test".into()],
                    port: None,
                    factory: || Box::<HttpHost>::default(),
                },
                AnalyzerRule {
                    hosts: vec!["blocked.test".into()],
                    port: None,
                    factory: || Box::<HttpHost>::default(),
                },
            ],
        );
        let mut feed = |seq, flags, bytes: &[u8]| {
            let b = tcp(seq, flags, bytes, false);
            p.evaluate(Packet {
                bytes: &b,
                original_len: b.len(),
                checksum_ready: true,
            })
        };
        assert_eq!(feed(100, 2, b""), Verdict::Accept);
        assert_eq!(
            feed(101, 16, b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"),
            Verdict::DropFlow
        );
        // Same SYN is a retransmission, not a new connection.
        assert_eq!(feed(100, 2, b""), Verdict::DropFlow);
        assert_eq!(feed(5000, 2, b""), Verdict::Accept);
        assert_eq!(
            feed(5001, 16, b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"),
            Verdict::Accept
        );
        assert_eq!(p.flows.len(), 1);
        assert!(
            p.flows.values().next().unwrap().directions[0]
                .analyzers
                .iter()
                .all(Option::is_none)
        );
    }

    #[test]
    fn unrelated_tcp_ports_do_not_consume_inspection_capacity() {
        let mut p = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![AnalyzerRule {
                hosts: vec!["blocked.test".into()],
                port: Some(53),
                factory: || Box::<HttpHost>::default(),
            }],
        );
        let packet = tcp(100, 2, b"", false);
        assert_eq!(
            p.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
            }),
            Verdict::Accept
        );
        assert!(p.flows.is_empty());
    }

    #[test]
    fn completed_tcp_close_releases_inspection_flow() {
        let mut p = Inspect::new(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["blocked.test".into()],
            || Box::<HttpHost>::default(),
        );
        let feed = |p: &mut Inspect<crate::ConstantPolicy>, flags, reverse| {
            let bytes = tcp(100, flags, b"", reverse);
            p.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
            })
        };
        assert_eq!(feed(&mut p, 2, false), Verdict::Accept);
        assert_eq!(feed(&mut p, 17, false), Verdict::Accept);
        assert_eq!(p.flows.len(), 1);
        assert_eq!(feed(&mut p, 17, true), Verdict::Accept);
        assert!(p.flows.is_empty());
    }

    #[test]
    fn completed_inspection_does_not_exhaust_capacity() {
        fn feed(
            p: &mut Inspect<crate::ConstantPolicy>,
            port: u16,
            seq: u32,
            flags: u8,
            payload: &[u8],
            reverse: bool,
        ) -> Verdict {
            let mut bytes = tcp(seq, flags, payload, reverse);
            let port_offset = if reverse { 22 } else { 20 };
            bytes[port_offset..port_offset + 2].copy_from_slice(&port.to_be_bytes());
            p.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
            })
        }
        let mut p = Inspect::new(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["blocked.test".into()],
            || Box::<HttpHost>::default(),
        );
        for port in 10000u16..14096 {
            assert_eq!(feed(&mut p, port, 100, 2, b"", false), Verdict::Accept);
            assert_eq!(
                feed(
                    &mut p,
                    port,
                    101,
                    16,
                    b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                    false
                ),
                Verdict::Accept
            );
            assert_eq!(
                feed(&mut p, port, 500, 16, b"HTTP/1.1 200 OK\r\n\r\n", true),
                Verdict::Accept
            );
        }
        assert_eq!(p.flows.len(), 4096);
        assert_eq!(feed(&mut p, 15000, 100, 2, b"", false), Verdict::Accept);
        assert_eq!(p.flows.len(), 1);
        assert_eq!(
            feed(
                &mut p,
                15000,
                101,
                16,
                b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
                false
            ),
            Verdict::DropFlow
        );
    }
}
