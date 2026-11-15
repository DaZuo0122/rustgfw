//! Incremental stream analysis. Each direction shares reassembly across analyzers.
use crate::{
    FlowScope, Packet, Policy, Verdict,
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
    /// Nonterminal facts; a stream may report more facts on later packets.
    Observations(Vec<Observation>),
    /// Facts from an analyzer that has completed inspection.
    FinalObservations(Vec<Observation>),
    Finished,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub field: &'static str,
    pub value: String,
}

pub trait StreamAnalyzer {
    fn feed(&mut self, bytes: &[u8]) -> Analysis;
}

pub enum DatagramAnalysis {
    Observations(Vec<Observation>),
    Malformed,
}

pub trait DatagramAnalyzer: Send + Sync {
    fn inspect(&self, payload: &[u8]) -> DatagramAnalysis;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramPort {
    Source(u16),
    Destination(u16),
    Either(u16),
}
impl DatagramPort {
    fn matches(self, source: u16, destination: u16) -> bool {
        match self {
            Self::Source(port) => source == port,
            Self::Destination(port) => destination == port,
            Self::Either(port) => source == port || destination == port,
        }
    }
}

/// HTTP/1 initial request headers. Subsequent keep-alive requests need a
/// transaction parser and are deliberately not advertised by this analyzer.
pub struct HttpHost {
    header: Vec<u8>,
    finished: bool,
    limit: usize,
}
impl Default for HttpHost {
    fn default() -> Self {
        Self::with_header_limit(16384)
    }
}
impl HttpHost {
    pub fn with_header_limit(limit: usize) -> Self {
        Self {
            header: Vec::new(),
            finished: false,
            limit,
        }
    }
}
impl StreamAnalyzer for HttpHost {
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
                let mut lines = self.header.split(|&byte| byte == b'\n');
                let first = lines.next().unwrap_or_default();
                let Ok(first) = std::str::from_utf8(first.strip_suffix(b"\r").unwrap_or(first))
                else {
                    return Analysis::Finished;
                };
                let mut request = first.split_ascii_whitespace();
                let (Some(method), Some(target), Some(version)) =
                    (request.next(), request.next(), request.next())
                else {
                    return Analysis::Finished;
                };
                if request.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
                    return Analysis::Finished;
                }
                let mut hosts = Vec::new();
                let absolute = target
                    .split_once("://")
                    .filter(|(scheme, _)| {
                        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
                    })
                    .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default());
                if let Some(authority) =
                    absolute.or_else(|| method.eq_ignore_ascii_case("CONNECT").then_some(target))
                    && !authority.is_empty()
                {
                    hosts.push(Observation {
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
                        hosts.push(Observation {
                            field: "http.host",
                            value: value.to_ascii_lowercase(),
                        });
                    }
                }
                return if hosts.is_empty() {
                    Analysis::Finished
                } else {
                    Analysis::FinalObservations(hosts)
                };
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
type Key = (FlowScope, SocketAddr, SocketAddr);

pub struct AnalyzerRule {
    pub port: Option<u16>,
    pub factory: Box<dyn Fn() -> Box<dyn StreamAnalyzer> + Send + Sync>,
    pub matches: Box<dyn Fn(&Observation) -> bool + Send + Sync>,
}

pub struct DatagramRule {
    pub port: Option<DatagramPort>,
    pub analyzer: Box<dyn DatagramAnalyzer>,
    pub matches: Box<dyn Fn(&Observation) -> bool + Send + Sync>,
}
impl DatagramRule {
    pub fn exact(
        field: &'static str,
        values: Vec<String>,
        port: Option<DatagramPort>,
        analyzer: impl DatagramAnalyzer + 'static,
    ) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let values: Vec<_> = values
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        Some(Self {
            port,
            analyzer: Box::new(analyzer),
            matches: Box::new(move |observation| {
                observation.field == field
                    && values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(&observation.value))
            }),
        })
    }
}
impl AnalyzerRule {
    pub fn exact(
        field: &'static str,
        values: Vec<String>,
        port: Option<u16>,
        factory: impl Fn() -> Box<dyn StreamAnalyzer> + Send + Sync + 'static,
    ) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let values: Vec<_> = values
            .into_iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        Some(Self {
            port,
            factory: Box::new(factory),
            matches: Box::new(move |observation| {
                observation.field == field
                    && values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(&observation.value))
            }),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InspectLimits {
    pub max_flows: usize,
    pub idle: Duration,
    pub reorder_bytes: usize,
}
impl Default for InspectLimits {
    fn default() -> Self {
        Self {
            max_flows: 16384,
            idle: Duration::from_secs(120),
            reorder_bytes: 16384,
        }
    }
}

/// Transport policy runs first; application matches can additionally block.
/// Inspection is passive: packets before a match are accepted, as in OpenGFW.
pub struct Inspect<P> {
    transport: P,
    analyzers: Vec<AnalyzerRule>,
    datagrams: Vec<DatagramRule>,
    flows: HashMap<Key, Flow>,
    completed_since_compaction: bool,
    sweep: Instant,
    limits: InspectLimits,
}
impl<P> Inspect<P> {
    pub fn http_hosts(transport: P, hosts: Vec<String>) -> Self {
        Self::with_analyzers(
            transport,
            AnalyzerRule::exact("http.host", hosts, None, || Box::<HttpHost>::default())
                .into_iter()
                .collect(),
        )
    }
    pub fn with_analyzers(transport: P, analyzers: Vec<AnalyzerRule>) -> Self {
        Self::with_limits(transport, analyzers, InspectLimits::default())
    }
    pub fn with_limits(transport: P, analyzers: Vec<AnalyzerRule>, limits: InspectLimits) -> Self {
        Self::with_datagrams(transport, analyzers, Vec::new(), limits)
    }
    pub fn with_datagrams(
        transport: P,
        analyzers: Vec<AnalyzerRule>,
        datagrams: Vec<DatagramRule>,
        limits: InspectLimits,
    ) -> Self {
        Self {
            transport,
            analyzers,
            datagrams,
            flows: HashMap::new(),
            completed_since_compaction: false,
            sweep: Instant::now(),
            limits,
        }
    }
    pub fn clear_flows(&mut self) {
        self.flows.clear();
        self.completed_since_compaction = false;
    }
}
impl<P: Policy> Policy for Inspect<P> {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
        let verdict = self.transport.evaluate(packet);
        if verdict != Verdict::Accept || (self.analyzers.is_empty() && self.datagrams.is_empty()) {
            return verdict;
        }
        let Ok(t) = packet::parse(packet.bytes) else {
            return verdict;
        };
        if t.protocol == Protocol::Udp {
            for rule in &self.datagrams {
                if rule
                    .port
                    .is_some_and(|port| !port.matches(t.source.port(), t.destination.port()))
                {
                    continue;
                }
                match rule.analyzer.inspect(t.payload) {
                    DatagramAnalysis::Malformed => return Verdict::Drop,
                    DatagramAnalysis::Observations(observations)
                        if observations.iter().any(|value| (rule.matches)(value)) =>
                    {
                        return Verdict::Drop;
                    }
                    DatagramAnalysis::Observations(_) => {}
                }
            }
            return verdict;
        }
        if self.analyzers.is_empty() {
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
                .retain(|_, f| now.duration_since(f.seen) < self.limits.idle);
            self.sweep = now + Duration::from_secs(1);
        }
        let (key, direction) = if t.source <= t.destination {
            ((packet.scope, t.source, t.destination), 0)
        } else {
            ((packet.scope, t.destination, t.source), 1)
        };
        let initial_syn = (t.tcp_flags & 0x12 == 2).then_some((direction, t.tcp_sequence.unwrap()));
        if self
            .flows
            .get(&key)
            .is_some_and(|f| now.duration_since(f.seen) >= self.limits.idle)
        {
            self.flows.remove(&key);
        }
        if let Some(syn) = initial_syn
            && self
                .flows
                .get(&key)
                .is_some_and(|f| f.initial_syn != Some(syn))
        {
            self.flows.remove(&key);
        }
        if self.flows.len() >= self.limits.max_flows && !self.flows.contains_key(&key) {
            if self.completed_since_compaction {
                self.flows.retain(|_, flow| !flow.finished());
                self.completed_since_compaction = false;
            }
            if self.flows.len() >= self.limits.max_flows {
                // Active inspection cannot be silently bypassed at capacity.
                return Verdict::Drop;
            }
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            directions: std::array::from_fn(|_| Direction {
                reassembly: Reassembler::new(self.limits.reorder_bytes),
                analyzers: self
                    .analyzers
                    .iter()
                    .map(|a| {
                        a.port
                            .is_none_or(|p| key.1.port() == p || key.2.port() == p)
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
                            Analysis::Finished => *slot = None,
                            Analysis::Observations(observations) => {
                                flow.blocked |= observations.iter().any(|o| (rule.matches)(o));
                            }
                            Analysis::FinalObservations(observations) => {
                                flow.blocked |= observations.iter().any(|o| (rule.matches)(o));
                                *slot = None;
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
        self.completed_since_compaction |= flow.finished();
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
    fn custom_udp_analyzer_respects_destination_port_and_each_datagram() {
        struct PayloadWord;
        impl DatagramAnalyzer for PayloadWord {
            fn inspect(&self, payload: &[u8]) -> DatagramAnalysis {
                DatagramAnalysis::Observations(vec![Observation {
                    field: "custom.udp",
                    value: String::from_utf8_lossy(payload).into_owned(),
                }])
            }
        }
        let mut policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            vec![
                DatagramRule::exact(
                    "custom.udp",
                    vec!["dns".into()],
                    Some(DatagramPort::Destination(53)),
                    PayloadWord,
                )
                .unwrap(),
            ],
            InspectLimits::default(),
        );
        let mut bytes = crate::packet::udp(false);
        let mut evaluate = |bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(evaluate(&bytes), Verdict::Drop);
        bytes[22..24].copy_from_slice(&54u16.to_be_bytes());
        assert_eq!(evaluate(&bytes), Verdict::Accept);
        bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
        bytes[28..].copy_from_slice(b"ok!");
        assert_eq!(evaluate(&bytes), Verdict::Accept);
    }
    #[test]
    fn fragmented_header_and_case() {
        let mut a = HttpHost::default();
        assert_eq!(a.feed(b"GET / HTTP/1.1\r\nHo"), Analysis::Pending);
        assert_eq!(
            a.feed(b"st: EXAMPLE.COM\r\n\r\nbody"),
            Analysis::FinalObservations(vec![Observation {
                field: "http.host",
                value: "example.com".into(),
            }])
        );
        assert_eq!(a.feed(b"more"), Analysis::Finished);
    }
    #[test]
    fn http_reports_every_visible_authority() {
        let mut absolute = HttpHost::default();
        assert_eq!(
            absolute.feed(
                b"GET http://Blocked.Test/path HTTP/1.1\r\nHost: allowed.test\r\nHost: also-blocked.test\r\n\r\n"
            ),
            Analysis::FinalObservations(vec![
                Observation {
                    field: "http.host",
                    value: "blocked.test".into(),
                },
                Observation {
                    field: "http.host",
                    value: "allowed.test".into(),
                },
                Observation {
                    field: "http.host",
                    value: "also-blocked.test".into(),
                },
            ])
        );
        let mut connect = HttpHost::default();
        assert_eq!(
            connect.feed(b"CONNECT blocked.test:443 HTTP/1.1\r\n\r\n"),
            Analysis::FinalObservations(vec![Observation {
                field: "http.host",
                value: "blocked.test:443".into(),
            }])
        );
    }
    #[test]
    fn http_policy_blocks_absolute_uri_or_second_host() {
        for request in [
            b"GET http://blocked.test/path HTTP/1.1\r\nHost: allowed.test\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nHost: blocked.test\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nX-Binary: \xff\r\nHost: blocked.test\r\n\r\n".as_slice(),
        ] {
            let mut policy = Inspect::http_hosts(
                crate::ConstantPolicy(Verdict::Accept),
                vec!["blocked.test".into()],
            );
            let syn = tcp(100, 2, b"", false);
            assert_eq!(
                policy.evaluate(Packet {
                    bytes: &syn,
                    original_len: syn.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                }),
                Verdict::Accept
            );
            let data = tcp(101, 16, request, false);
            assert_eq!(
                policy.evaluate(Packet {
                    bytes: &data,
                    original_len: data.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                }),
                Verdict::DropFlow
            );
        }
    }
    #[test]
    fn custom_analyzer_matches_its_own_field() {
        struct Token;
        impl StreamAnalyzer for Token {
            fn feed(&mut self, bytes: &[u8]) -> Analysis {
                Analysis::Observations(vec![Observation {
                    field: "custom.token",
                    value: String::from_utf8_lossy(bytes).into_owned(),
                }])
            }
        }
        let packet = tcp(101, 16, b"BLOCK", false);
        let evaluate = |field| {
            let mut policy = Inspect::with_analyzers(
                crate::ConstantPolicy(Verdict::Accept),
                vec![
                    AnalyzerRule::exact(field, vec!["block".into()], None, || Box::new(Token))
                        .unwrap(),
                ],
            );
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(evaluate("custom.token"), Verdict::DropFlow);
        assert_eq!(evaluate("http.host"), Verdict::Accept);
    }
    #[test]
    fn tcp_dns_observations_continue_across_messages() {
        fn query(host: &str) -> Vec<u8> {
            let mut dns = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for label in host.split('.') {
                dns.push(label.len() as u8);
                dns.extend_from_slice(label.as_bytes());
            }
            dns.extend([0, 0, 1, 0, 1]);
            let mut wire = (dns.len() as u16).to_be_bytes().to_vec();
            wire.extend(dns);
            wire
        }
        let mut policy = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule::exact("dns.qname", vec!["blocked.test".into()], Some(53), || {
                    Box::<crate::dns::DnsTcp>::default()
                })
                .unwrap(),
            ],
        );
        let mut feed = |seq, flags, payload: &[u8]| {
            let mut bytes = tcp(seq, flags, payload, false);
            bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(100, 2, b""), Verdict::Accept);
        let first = query("allowed.test");
        assert_eq!(feed(101, 16, &first), Verdict::Accept);
        assert_eq!(
            feed(101 + first.len() as u32, 16, &query("blocked.test")),
            Verdict::DropFlow
        );
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
        let mut p = Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["example.com".into()],
        );
        let mut feed = |seq, flags, bytes: &[u8], rev| {
            let b = tcp(seq, flags, bytes, rev);
            p.evaluate(Packet {
                bytes: &b,
                original_len: b.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
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
    fn identical_endpoints_in_distinct_scopes_do_not_share_inspection() {
        let mut policy = Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["blocked.test".into()],
        );
        let mut feed = |scope, seq, flags, payload: &[u8], reverse| {
            let bytes = tcp(seq, flags, payload, reverse);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope(scope),
            })
        };
        assert_eq!(feed(1, 100, 2, b"", false), Verdict::Accept);
        assert_eq!(feed(2, 100, 2, b"", false), Verdict::Accept);
        assert_eq!(
            feed(
                1,
                101,
                16,
                b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
                false
            ),
            Verdict::DropFlow
        );
        assert_eq!(feed(1, 500, 16, b"reply", true), Verdict::DropFlow);
        assert_eq!(
            feed(
                2,
                101,
                16,
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                false
            ),
            Verdict::Accept
        );
        assert_eq!(feed(2, 500, 16, b"reply", true), Verdict::Accept);
    }

    #[test]
    fn multiple_analyzers_and_reused_connection() {
        let mut p = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule::exact("http.host", vec!["unrelated.test".into()], None, || {
                    Box::<HttpHost>::default()
                })
                .unwrap(),
                AnalyzerRule::exact("http.host", vec!["blocked.test".into()], None, || {
                    Box::<HttpHost>::default()
                })
                .unwrap(),
            ],
        );
        let mut feed = |seq, flags, bytes: &[u8]| {
            let b = tcp(seq, flags, bytes, false);
            p.evaluate(Packet {
                bytes: &b,
                original_len: b.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(100, 2, b""), Verdict::Accept);
        assert_eq!(
            feed(101, 16, b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"),
            Verdict::DropFlow
        );
        // Same SYN is a retransmission, not a new connection.
        assert_eq!(feed(100, 2, b""), Verdict::DropFlow);
        assert_eq!(feed(101, 4, b""), Verdict::DropFlow);
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
            vec![
                AnalyzerRule::exact("http.host", vec!["blocked.test".into()], Some(53), || {
                    Box::<HttpHost>::default()
                })
                .unwrap(),
            ],
        );
        let packet = tcp(100, 2, b"", false);
        assert_eq!(
            p.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            }),
            Verdict::Accept
        );
        assert!(p.flows.is_empty());
    }

    #[test]
    fn configured_limits_keep_active_inspection_fail_closed() {
        let mut policy = Inspect::with_limits(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule::exact("http.host", vec!["blocked.test".into()], None, || {
                    Box::<HttpHost>::default()
                })
                .unwrap(),
            ],
            InspectLimits {
                max_flows: 1,
                reorder_bytes: 2,
                ..InspectLimits::default()
            },
        );
        let first = tcp(100, 2, b"", false);
        let mut second = first.clone();
        second[20..22].copy_from_slice(&12346u16.to_be_bytes());
        let mut feed = |bytes: &[u8]| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(&first), Verdict::Accept);
        assert_eq!(feed(&second), Verdict::Drop);
        assert_eq!(feed(&tcp(104, 16, b"abc", false)), Verdict::DropFlow);
        assert_eq!(feed(&second), Verdict::Drop);
    }

    #[test]
    fn analyzer_factory_can_capture_header_budget() {
        let request = b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
        for (budget, expected) in [(16, Verdict::Accept), (64, Verdict::DropFlow)] {
            let mut policy = Inspect::with_analyzers(
                crate::ConstantPolicy(Verdict::Accept),
                vec![
                    AnalyzerRule::exact(
                        "http.host",
                        vec!["blocked.test".into()],
                        None,
                        move || Box::new(HttpHost::with_header_limit(budget)),
                    )
                    .unwrap(),
                ],
            );
            let packet = tcp(101, 16, request, false);
            assert_eq!(
                policy.evaluate(Packet {
                    bytes: &packet,
                    original_len: packet.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                }),
                expected
            );
        }
    }

    #[test]
    fn completed_tcp_close_releases_inspection_flow() {
        let mut p = Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["blocked.test".into()],
        );
        let feed = |p: &mut Inspect<crate::ConstantPolicy>, flags, reverse| {
            let bytes = tcp(100, flags, b"", reverse);
            p.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
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
                scope: FlowScope::default(),
            })
        }
        let mut p = Inspect::with_limits(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule::exact("http.host", vec!["blocked.test".into()], None, || {
                    Box::<HttpHost>::default()
                })
                .unwrap(),
            ],
            InspectLimits {
                max_flows: 4096,
                ..InspectLimits::default()
            },
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
