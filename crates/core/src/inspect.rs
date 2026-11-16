//! Incremental stream analysis. Each direction shares reassembly across analyzers.
use crate::{
    Decision, FlowScope, Packet, Policy, Verdict,
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

/// One instance observes both directions of a reassembled TCP flow.
/// `reverse` is relative to the first packet that created the flow.
pub trait BidirectionalStreamAnalyzer {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis;
}

pub enum DatagramAnalysis {
    Observations(Vec<Observation>),
    Malformed,
}

pub trait DatagramAnalyzer: Send + Sync {
    fn inspect(&self, payload: &[u8]) -> DatagramAnalysis;
}

/// A stateful UDP analyzer receives both directions of one endpoint pair.
pub trait UdpStreamAnalyzer {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis;
}

pub enum UdpStreamAnalysis {
    Pending,
    Observations(Vec<Observation>),
    FinalObservations(Vec<Observation>),
    Finished,
    /// Reject only this datagram while retaining the stream state.
    Drop,
    /// Remove facts that no longer describe the latest datagram.
    ClearFields(Vec<&'static str>),
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
    origin: SocketAddr,
    target: SocketAddr,
    bidirectional: Vec<Option<Box<dyn BidirectionalStreamAnalyzer>>>,
    facts: HashMap<&'static str, Vec<String>>,
    allowed: bool,
    blocked: bool,
    seen: Instant,
    initial_syn: Option<(usize, u32)>,
    fin_seen: [bool; 2],
}

struct UdpFlow {
    origin: SocketAddr,
    target: SocketAddr,
    analyzers: Vec<Option<Box<dyn UdpStreamAnalyzer>>>,
    facts: HashMap<&'static str, Vec<String>>,
    allowed: bool,
    blocked: bool,
    seen: Instant,
}
impl UdpFlow {
    fn finished(&self) -> bool {
        !self.allowed && !self.blocked && self.analyzers.iter().all(Option::is_none)
    }
}
impl Flow {
    fn finished(&self) -> bool {
        !self.blocked
            && !self.allowed
            && self.bidirectional.iter().all(Option::is_none)
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

pub struct BidirectionalAnalyzerRule {
    pub port: Option<u16>,
    pub factory: Box<dyn Fn() -> Box<dyn BidirectionalStreamAnalyzer> + Send + Sync>,
    pub matches: Box<dyn Fn(&Observation) -> bool + Send + Sync>,
}

/// The latest observation batch for each field in one bidirectional flow.
/// `source` and `destination` belong to the current packet; `origin` and
/// `target` remain fixed from the first packet that created the flow.
pub struct FlowContext<'a> {
    pub protocol: Protocol,
    pub scope: FlowScope,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub origin: SocketAddr,
    pub target: SocketAddr,
    pub reverse: bool,
    pub payload: &'a [u8],
    facts: &'a HashMap<&'static str, Vec<String>>,
    updated: &'a [&'static str],
}
impl FlowContext<'_> {
    pub fn get(&self, field: &str) -> Option<&str> {
        self.values(field)?.last().map(String::as_str)
    }

    pub fn values(&self, field: &str) -> Option<&[String]> {
        self.facts.get(field).map(Vec::as_slice)
    }

    pub fn updated(&self, field: &str) -> bool {
        self.updated.contains(&field)
    }
}

fn store_observations(
    facts: &mut HashMap<&'static str, Vec<String>>,
    observations: Vec<Observation>,
    updated: &mut Vec<&'static str>,
) {
    let mut latest = HashMap::<&'static str, Vec<String>>::new();
    for observation in observations {
        latest
            .entry(observation.field)
            .or_default()
            .push(observation.value);
    }
    updated.extend(latest.keys().copied());
    facts.extend(latest);
}

fn match_tcp_observations(
    facts: &mut HashMap<&'static str, Vec<String>>,
    observations: Vec<Observation>,
    matcher: &dyn Fn(&Observation) -> bool,
    retain: bool,
    updated: &mut Vec<&'static str>,
) -> bool {
    let blocked = observations.iter().any(matcher);
    if retain {
        store_observations(facts, observations, updated);
    }
    blocked
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowAction {
    /// Stop application inspection for this flow; transport policy still runs.
    Allow,
    Block,
    /// Drop only the current UDP datagram; for TCP, block the stream.
    DropPacket,
    /// Accept this UDP datagram with a new payload. Ignored for TCP.
    ReplaceUdpPayload(Vec<u8>),
}

type FlowMatch = dyn for<'a> Fn(&FlowContext<'a>) -> Option<FlowAction> + Send + Sync;
/// Compose facts from multiple analyzers into an ordered flow decision.
pub struct FlowRule {
    matches: Box<FlowMatch>,
}
impl FlowRule {
    pub fn new(
        matches: impl for<'a> Fn(&FlowContext<'a>) -> Option<FlowAction> + Send + Sync + 'static,
    ) -> Self {
        Self {
            matches: Box::new(matches),
        }
    }
}

pub struct UdpStreamRule {
    pub port: Option<DatagramPort>,
    pub factory: Box<dyn Fn() -> Box<dyn UdpStreamAnalyzer> + Send + Sync>,
}
impl UdpStreamRule {
    pub fn new(
        port: Option<DatagramPort>,
        factory: impl Fn() -> Box<dyn UdpStreamAnalyzer> + Send + Sync + 'static,
    ) -> Self {
        Self {
            port,
            factory: Box::new(factory),
        }
    }
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
    /// Register an analyzer whose facts are evaluated by flow-level rules.
    pub fn observing(
        port: Option<u16>,
        factory: impl Fn() -> Box<dyn StreamAnalyzer> + Send + Sync + 'static,
    ) -> Self {
        Self {
            port,
            factory: Box::new(factory),
            matches: Box::new(|_| false),
        }
    }

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

impl BidirectionalAnalyzerRule {
    pub fn observing(
        port: Option<u16>,
        factory: impl Fn() -> Box<dyn BidirectionalStreamAnalyzer> + Send + Sync + 'static,
    ) -> Self {
        Self {
            port,
            factory: Box::new(factory),
            matches: Box::new(|_| false),
        }
    }

    pub fn exact(
        field: &'static str,
        values: Vec<String>,
        port: Option<u16>,
        factory: impl Fn() -> Box<dyn BidirectionalStreamAnalyzer> + Send + Sync + 'static,
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

/// Transport policy runs first; application rules then decide per flow or packet.
/// Inspection is passive: packets before a match are accepted, as in OpenGFW.
pub struct Inspect<P> {
    transport: P,
    analyzers: Vec<AnalyzerRule>,
    bidirectional_analyzers: Vec<BidirectionalAnalyzerRule>,
    flow_rules: Vec<FlowRule>,
    datagrams: Vec<DatagramRule>,
    udp_analyzers: Vec<UdpStreamRule>,
    udp_rules: Vec<FlowRule>,
    flows: HashMap<Key, Flow>,
    udp_flows: HashMap<Key, UdpFlow>,
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
            bidirectional_analyzers: Vec::new(),
            flow_rules: Vec::new(),
            datagrams,
            udp_analyzers: Vec::new(),
            udp_rules: Vec::new(),
            flows: HashMap::new(),
            udp_flows: HashMap::new(),
            completed_since_compaction: false,
            sweep: Instant::now(),
            limits,
        }
    }
    pub fn clear_flows(&mut self) {
        self.flows.clear();
        self.udp_flows.clear();
        self.completed_since_compaction = false;
    }

    pub fn with_flow_rules(mut self, rules: Vec<FlowRule>) -> Self {
        self.clear_flows();
        self.flow_rules = rules;
        self
    }

    pub fn with_bidirectional_analyzers(
        mut self,
        analyzers: Vec<BidirectionalAnalyzerRule>,
    ) -> Self {
        self.clear_flows();
        self.bidirectional_analyzers = analyzers;
        self
    }

    pub fn with_udp_streams(mut self, analyzers: Vec<UdpStreamRule>, rules: Vec<FlowRule>) -> Self {
        self.clear_flows();
        self.udp_analyzers = analyzers;
        self.udp_rules = rules;
        self
    }

    fn expire_idle_flows(&mut self, now: Instant) {
        if now >= self.sweep {
            self.flows
                .retain(|_, flow| now.duration_since(flow.seen) < self.limits.idle);
            self.udp_flows
                .retain(|_, flow| now.duration_since(flow.seen) < self.limits.idle);
            self.sweep = now + Duration::from_secs(1);
        }
    }

    fn compact_completed_flows(&mut self) {
        if self.completed_since_compaction {
            self.flows.retain(|_, flow| !flow.finished());
            self.udp_flows.retain(|_, flow| !flow.finished());
            self.completed_since_compaction = false;
        }
    }

    fn inspect_udp(&mut self, packet: Packet<'_>, transport: &packet::Transport<'_>) -> Decision {
        let has_stream = !self.udp_analyzers.is_empty() || !self.udp_rules.is_empty();
        let state = has_stream.then(|| {
            let now = Instant::now();
            self.expire_idle_flows(now);
            let key = if transport.source <= transport.destination {
                (packet.scope, transport.source, transport.destination)
            } else {
                (packet.scope, transport.destination, transport.source)
            };
            (now, key)
        });
        if let Some((now, key)) = state
            && let Some(flow) = self.udp_flows.get(&key)
            && now.duration_since(flow.seen) < self.limits.idle
        {
            if flow.allowed {
                return Verdict::Accept.into();
            }
            if flow.blocked {
                return Verdict::DropFlow.into();
            }
        }
        for rule in &self.datagrams {
            if rule.port.is_some_and(|port| {
                !port.matches(transport.source.port(), transport.destination.port())
            }) {
                continue;
            }
            match rule.analyzer.inspect(transport.payload) {
                DatagramAnalysis::Malformed => return Verdict::Drop.into(),
                DatagramAnalysis::Observations(observations)
                    if observations.iter().any(|value| (rule.matches)(value)) =>
                {
                    return Verdict::Drop.into();
                }
                DatagramAnalysis::Observations(_) => {}
            }
        }
        let Some((now, key)) = state else {
            return Verdict::Accept.into();
        };
        if self
            .udp_flows
            .get(&key)
            .is_some_and(|flow| now.duration_since(flow.seen) >= self.limits.idle)
        {
            self.udp_flows.remove(&key);
        }
        if self.udp_rules.is_empty()
            && !self.udp_flows.contains_key(&key)
            && !self.udp_analyzers.iter().any(|rule| {
                rule.port.is_none_or(|port| {
                    port.matches(transport.source.port(), transport.destination.port())
                })
            })
        {
            return Verdict::Accept.into();
        }
        if !self.udp_flows.contains_key(&key)
            && self.flows.len() + self.udp_flows.len() >= self.limits.max_flows
        {
            self.compact_completed_flows();
            if self.flows.len() + self.udp_flows.len() >= self.limits.max_flows {
                return Verdict::Drop.into();
            }
        }
        let flow = self.udp_flows.entry(key).or_insert_with(|| UdpFlow {
            origin: transport.source,
            target: transport.destination,
            analyzers: self
                .udp_analyzers
                .iter()
                .map(|rule| {
                    rule.port
                        .is_none_or(|port| {
                            port.matches(transport.source.port(), transport.destination.port())
                        })
                        .then(|| (rule.factory)())
                })
                .collect(),
            facts: HashMap::new(),
            allowed: false,
            blocked: false,
            seen: now,
        });
        flow.seen = now;
        if flow.blocked {
            return Verdict::DropFlow.into();
        }
        let mut drop_packet = false;
        let mut replacement = None;
        let mut updated = Vec::new();
        if !flow.allowed {
            let reverse = transport.source != flow.origin;
            for slot in &mut flow.analyzers {
                let Some(analyzer) = slot else {
                    continue;
                };
                match analyzer.feed(transport.payload, reverse) {
                    UdpStreamAnalysis::Pending => {}
                    UdpStreamAnalysis::Observations(observations) => {
                        if !self.udp_rules.is_empty() {
                            store_observations(&mut flow.facts, observations, &mut updated);
                        }
                    }
                    UdpStreamAnalysis::FinalObservations(observations) => {
                        if !self.udp_rules.is_empty() {
                            store_observations(&mut flow.facts, observations, &mut updated);
                        }
                        *slot = None;
                    }
                    UdpStreamAnalysis::Finished => *slot = None,
                    UdpStreamAnalysis::Drop => drop_packet = true,
                    UdpStreamAnalysis::ClearFields(fields) => {
                        for field in fields {
                            flow.facts.remove(field);
                        }
                    }
                }
            }
            if !self.udp_rules.is_empty() {
                let context = FlowContext {
                    protocol: Protocol::Udp,
                    scope: packet.scope,
                    source: transport.source,
                    destination: transport.destination,
                    origin: flow.origin,
                    target: flow.target,
                    reverse: transport.source != flow.origin,
                    payload: transport.payload,
                    facts: &flow.facts,
                    updated: &updated,
                };
                if let Some(action) = self
                    .udp_rules
                    .iter()
                    .find_map(|rule| (rule.matches)(&context))
                {
                    match action {
                        FlowAction::Allow => flow.allowed = true,
                        FlowAction::Block => flow.blocked = true,
                        FlowAction::DropPacket => drop_packet = true,
                        FlowAction::ReplaceUdpPayload(payload) => replacement = Some(payload),
                    }
                }
            }
        }
        self.completed_since_compaction |= flow.finished();
        if flow.blocked {
            Verdict::DropFlow.into()
        } else if drop_packet {
            Verdict::Drop.into()
        } else if let Some(payload) = replacement {
            packet::replace_udp_payload(packet.bytes, &payload)
                .map(Decision::Replace)
                .unwrap_or_else(|_| Verdict::Drop.into())
        } else {
            Verdict::Accept.into()
        }
    }
}
impl<P: Policy> Policy for Inspect<P> {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
        self.decide(packet).verdict()
    }

    fn decide(&mut self, packet: Packet<'_>) -> Decision {
        let transport_decision = self.transport.decide(packet);
        let verdict = transport_decision.verdict();
        if verdict != Verdict::Accept
            || (self.analyzers.is_empty()
                && self.bidirectional_analyzers.is_empty()
                && self.datagrams.is_empty()
                && self.flow_rules.is_empty()
                && self.udp_analyzers.is_empty()
                && self.udp_rules.is_empty())
        {
            return transport_decision;
        }
        let packet = match &transport_decision {
            Decision::Verdict(_) => packet,
            Decision::Replace(replacement) => Packet {
                bytes: replacement,
                original_len: replacement.len(),
                checksum_ready: true,
                scope: packet.scope,
            },
        };
        let Ok(t) = packet::parse(packet.bytes) else {
            return transport_decision;
        };
        if t.protocol == Protocol::Udp {
            return match self.inspect_udp(packet, &t) {
                Decision::Verdict(Verdict::Accept) => transport_decision,
                other => other,
            };
        }
        if self.analyzers.is_empty()
            && self.bidirectional_analyzers.is_empty()
            && self.flow_rules.is_empty()
        {
            return transport_decision;
        }
        if self.flow_rules.is_empty()
            && !self.analyzers.iter().any(|a| {
                a.port
                    .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
            })
            && !self.bidirectional_analyzers.iter().any(|a| {
                a.port
                    .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
            })
        {
            return transport_decision;
        }
        let now = Instant::now();
        self.expire_idle_flows(now);
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
        if self.flows.len() + self.udp_flows.len() >= self.limits.max_flows
            && !self.flows.contains_key(&key)
        {
            self.compact_completed_flows();
            if self.flows.len() + self.udp_flows.len() >= self.limits.max_flows {
                // Active inspection cannot be silently bypassed at capacity.
                return Verdict::Drop.into();
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
            origin: t.source,
            target: t.destination,
            bidirectional: self
                .bidirectional_analyzers
                .iter()
                .map(|a| {
                    a.port
                        .is_none_or(|p| key.1.port() == p || key.2.port() == p)
                        .then(|| (a.factory)())
                })
                .collect(),
            facts: HashMap::new(),
            allowed: false,
            blocked: false,
            seen: now,
            initial_syn,
            fin_seen: [false; 2],
        });
        flow.seen = now;
        if flow.blocked {
            return Verdict::DropFlow.into();
        }
        let mut updated = Vec::new();
        if !flow.allowed {
            let d = &mut flow.directions[direction];
            if d.analyzers.iter().any(Option::is_some)
                || flow.bidirectional.iter().any(Option::is_some)
            {
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
                                    flow.blocked |= match_tcp_observations(
                                        &mut flow.facts,
                                        observations,
                                        rule.matches.as_ref(),
                                        !self.flow_rules.is_empty(),
                                        &mut updated,
                                    );
                                }
                                Analysis::FinalObservations(observations) => {
                                    flow.blocked |= match_tcp_observations(
                                        &mut flow.facts,
                                        observations,
                                        rule.matches.as_ref(),
                                        !self.flow_rules.is_empty(),
                                        &mut updated,
                                    );
                                    *slot = None;
                                }
                                Analysis::Pending => {}
                            }
                        }
                        for (slot, rule) in flow
                            .bidirectional
                            .iter_mut()
                            .zip(&self.bidirectional_analyzers)
                        {
                            let Some(analyzer) = slot else {
                                continue;
                            };
                            match analyzer.feed(&bytes, t.source != flow.origin) {
                                Analysis::Finished => *slot = None,
                                Analysis::Observations(observations) => {
                                    flow.blocked |= match_tcp_observations(
                                        &mut flow.facts,
                                        observations,
                                        rule.matches.as_ref(),
                                        !self.flow_rules.is_empty(),
                                        &mut updated,
                                    );
                                }
                                Analysis::FinalObservations(observations) => {
                                    flow.blocked |= match_tcp_observations(
                                        &mut flow.facts,
                                        observations,
                                        rule.matches.as_ref(),
                                        !self.flow_rules.is_empty(),
                                        &mut updated,
                                    );
                                    *slot = None;
                                }
                                Analysis::Pending => {}
                            }
                        }
                    }
                    Err(_) => flow.blocked = true,
                }
            }
        }
        if !flow.blocked && !flow.allowed && !self.flow_rules.is_empty() {
            let context = FlowContext {
                protocol: Protocol::Tcp,
                scope: packet.scope,
                source: t.source,
                destination: t.destination,
                origin: flow.origin,
                target: flow.target,
                reverse: t.source != flow.origin,
                payload: t.payload,
                facts: &flow.facts,
                updated: &updated,
            };
            for rule in &self.flow_rules {
                let Some(action) = (rule.matches)(&context) else {
                    continue;
                };
                match action {
                    FlowAction::Allow => flow.allowed = true,
                    FlowAction::Block | FlowAction::DropPacket => flow.blocked = true,
                    FlowAction::ReplaceUdpPayload(_) => continue,
                }
                break;
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
        if result == Verdict::Accept {
            transport_decision
        } else {
            result.into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn udp(payload: &[u8], reverse: bool) -> Vec<u8> {
        let mut packet = crate::packet::udp(reverse);
        packet.truncate(28);
        packet.extend_from_slice(payload);
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[24..26].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        packet
    }

    fn evaluate_udp(
        policy: &mut impl Policy,
        scope: u128,
        payload: &[u8],
        reverse: bool,
    ) -> Verdict {
        let bytes = udp(payload, reverse);
        policy.evaluate(Packet {
            bytes: &bytes,
            original_len: bytes.len(),
            checksum_ready: true,
            scope: FlowScope(scope),
        })
    }

    #[test]
    fn udp_stream_analyzer_combines_request_and_reverse_reply_per_scope() {
        struct Exchange {
            requested: bool,
        }
        impl UdpStreamAnalyzer for Exchange {
            fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
                if !reverse && payload == b"request" {
                    self.requested = true;
                    UdpStreamAnalysis::Observations(vec![Observation {
                        field: "udp.request",
                        value: "request".into(),
                    }])
                } else if reverse && self.requested && payload == b"deny" {
                    UdpStreamAnalysis::Observations(vec![Observation {
                        field: "udp.reply",
                        value: "deny".into(),
                    }])
                } else {
                    UdpStreamAnalysis::Pending
                }
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    vec![UdpStreamRule::new(
                        Some(DatagramPort::Destination(53)),
                        || Box::new(Exchange { requested: false }),
                    )],
                    vec![FlowRule::new(|context| {
                        (context.protocol == Protocol::Udp
                            && context.reverse
                            && context.origin.port() == 12345
                            && context.target.port() == 53
                            && context.source.port() == 53
                            && context.destination.port() == 12345
                            && context.get("udp.request") == Some("request")
                            && context.get("udp.reply") == Some("deny"))
                        .then_some(FlowAction::Block)
                    })],
                );
        assert_eq!(
            evaluate_udp(&mut policy, 1, b"request", false),
            Verdict::Accept
        );
        assert_eq!(evaluate_udp(&mut policy, 2, b"deny", true), Verdict::Accept);
        assert_eq!(
            evaluate_udp(&mut policy, 1, b"deny", true),
            Verdict::DropFlow
        );
        assert_eq!(
            evaluate_udp(&mut policy, 1, b"later", false),
            Verdict::DropFlow
        );
        assert_eq!(
            evaluate_udp(&mut policy, 2, b"request", false),
            Verdict::Accept
        );
        policy.clear_flows();
        assert_eq!(evaluate_udp(&mut policy, 1, b"deny", true), Verdict::Accept);
    }

    #[test]
    fn udp_stream_rule_drops_one_datagram_then_allows_later_traffic() {
        struct Word;
        impl UdpStreamAnalyzer for Word {
            fn feed(&mut self, payload: &[u8], _: bool) -> UdpStreamAnalysis {
                UdpStreamAnalysis::Observations(vec![Observation {
                    field: "udp.word",
                    value: String::from_utf8_lossy(payload).into_owned(),
                }])
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    vec![UdpStreamRule::new(None, || Box::new(Word))],
                    vec![
                        FlowRule::new(|context| {
                            (context.get("udp.word") == Some("allow")).then_some(FlowAction::Allow)
                        }),
                        FlowRule::new(|context| {
                            (context.get("udp.word") == Some("bad"))
                                .then_some(FlowAction::DropPacket)
                        }),
                    ],
                );
        assert_eq!(evaluate_udp(&mut policy, 0, b"bad", false), Verdict::Drop);
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"good", false),
            Verdict::Accept
        );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"allow", false),
            Verdict::Accept
        );
        assert_eq!(evaluate_udp(&mut policy, 0, b"bad", false), Verdict::Accept);
    }

    #[test]
    fn udp_flow_rule_replaces_only_the_matching_datagram() {
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    Vec::new(),
                    vec![FlowRule::new(|context| {
                        (context.payload == b"old")
                            .then(|| FlowAction::ReplaceUdpPayload(b"new payload".to_vec()))
                    })],
                );
        let original = udp(b"old", false);
        let decision = policy.decide(Packet {
            bytes: &original,
            original_len: original.len(),
            checksum_ready: true,
            scope: FlowScope::default(),
        });
        let Decision::Replace(replaced) = decision else {
            panic!("expected a rewritten packet");
        };
        assert_eq!(packet::parse(&replaced).unwrap().payload, b"new payload");
        let later = udp(b"later", false);
        assert_eq!(
            policy.decide(Packet {
                bytes: &later,
                original_len: later.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            }),
            Decision::Verdict(Verdict::Accept)
        );
    }

    #[test]
    fn layered_policies_inspect_and_preserve_replaced_packets() {
        let inner = || {
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    Vec::new(),
                    vec![FlowRule::new(|context| {
                        (context.payload == b"old")
                            .then(|| FlowAction::ReplaceUdpPayload(b"inner".to_vec()))
                    })],
                )
        };
        let original = udp(b"old", false);
        let packet = Packet {
            bytes: &original,
            original_len: original.len(),
            checksum_ready: true,
            scope: FlowScope::default(),
        };

        let mut passthrough = Inspect::with_analyzers(inner(), Vec::new());
        let Decision::Replace(output) = passthrough.decide(packet) else {
            panic!("inner replacement was lost");
        };
        assert_eq!(packet::parse(&output).unwrap().payload, b"inner");

        let mut rewrite = Inspect::with_analyzers(inner(), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(|context| {
                (context.payload == b"inner")
                    .then(|| FlowAction::ReplaceUdpPayload(b"outer".to_vec()))
            })],
        );
        let Decision::Replace(output) = rewrite.decide(packet) else {
            panic!("outer replacement was lost");
        };
        assert_eq!(packet::parse(&output).unwrap().payload, b"outer");

        let mut block = Inspect::with_analyzers(inner(), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(|context| {
                (context.payload == b"inner").then_some(FlowAction::Block)
            })],
        );
        assert_eq!(block.decide(packet), Decision::Verdict(Verdict::DropFlow));
    }

    #[test]
    fn udp_field_update_is_scoped_to_the_current_datagram() {
        struct Marker;
        impl UdpStreamAnalyzer for Marker {
            fn feed(&mut self, payload: &[u8], _: bool) -> UdpStreamAnalysis {
                if payload == b"marked" {
                    UdpStreamAnalysis::Observations(vec![Observation {
                        field: "marker.value",
                        value: "yes".into(),
                    }])
                } else if payload == b"clear" {
                    UdpStreamAnalysis::ClearFields(vec!["marker.value"])
                } else {
                    UdpStreamAnalysis::Pending
                }
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    vec![UdpStreamRule::new(None, || Box::new(Marker))],
                    vec![
                        FlowRule::new(|context| {
                            (context.updated("marker.value")
                                && context.get("marker.value") == Some("yes"))
                            .then_some(FlowAction::DropPacket)
                        }),
                        FlowRule::new(|context| {
                            (context.payload == b"hold"
                                && context.get("marker.value") == Some("yes"))
                            .then_some(FlowAction::DropPacket)
                        }),
                    ],
                );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"marked", false),
            Verdict::Drop
        );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"later", false),
            Verdict::Accept
        );
        assert_eq!(evaluate_udp(&mut policy, 0, b"hold", false), Verdict::Drop);
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"clear", false),
            Verdict::Accept
        );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"hold", false),
            Verdict::Accept
        );
    }

    #[test]
    fn udp_stream_port_selection_keeps_reverse_packets() {
        struct Reply;
        impl UdpStreamAnalyzer for Reply {
            fn feed(&mut self, _: &[u8], reverse: bool) -> UdpStreamAnalysis {
                if reverse {
                    UdpStreamAnalysis::Drop
                } else {
                    UdpStreamAnalysis::Pending
                }
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    vec![UdpStreamRule::new(
                        Some(DatagramPort::Destination(53)),
                        || Box::new(Reply),
                    )],
                    Vec::new(),
                );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"request", false),
            Verdict::Accept
        );
        assert_eq!(evaluate_udp(&mut policy, 0, b"reply", true), Verdict::Drop);
    }

    #[test]
    fn udp_terminal_allow_skips_later_datagram_rules() {
        struct Word;
        impl DatagramAnalyzer for Word {
            fn inspect(&self, payload: &[u8]) -> DatagramAnalysis {
                DatagramAnalysis::Observations(vec![Observation {
                    field: "udp.word",
                    value: String::from_utf8_lossy(payload).into_owned(),
                }])
            }
        }
        let mut policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            vec![DatagramRule::exact("udp.word", vec!["bad".into()], None, Word).unwrap()],
            InspectLimits::default(),
        )
        .with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(|context| {
                (context.source.port() == 12345).then_some(FlowAction::Allow)
            })],
        );
        assert_eq!(evaluate_udp(&mut policy, 1, b"bad", false), Verdict::Drop);
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"allow", false),
            Verdict::Accept
        );
        assert_eq!(evaluate_udp(&mut policy, 0, b"bad", false), Verdict::Accept);
    }

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
    fn flow_rule_combines_facts_without_crossing_scopes_or_new_connections() {
        struct Word(&'static str, &'static [u8]);
        impl StreamAnalyzer for Word {
            fn feed(&mut self, bytes: &[u8]) -> Analysis {
                if bytes == self.1 {
                    Analysis::Observations(vec![
                        Observation {
                            field: self.0,
                            value: "unrelated".into(),
                        },
                        Observation {
                            field: self.0,
                            value: String::from_utf8_lossy(bytes).into_owned(),
                        },
                    ])
                } else {
                    Analysis::Pending
                }
            }
        }
        let mut policy = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![
                AnalyzerRule::observing(None, || Box::new(Word("first", b"alpha"))),
                AnalyzerRule::observing(None, || Box::new(Word("second", b"beta"))),
            ],
        )
        .with_flow_rules(vec![FlowRule::new(|context| {
            (context
                .values("first")
                .is_some_and(|values| values.iter().any(|value| value == "alpha"))
                && context.get("second") == Some("beta"))
            .then_some(FlowAction::Block)
        })]);
        let mut feed = |scope, seq, flags, payload: &[u8]| {
            let bytes = tcp(seq, flags, payload, false);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope(scope),
            })
        };
        assert_eq!(feed(1, 100, 2, b""), Verdict::Accept);
        assert_eq!(feed(2, 100, 2, b""), Verdict::Accept);
        assert_eq!(feed(1, 101, 16, b"alpha"), Verdict::Accept);
        assert_eq!(feed(2, 101, 16, b"beta"), Verdict::Accept);
        assert_eq!(feed(1, 106, 16, b"beta"), Verdict::DropFlow);
        assert_eq!(feed(1, 1000, 2, b""), Verdict::Accept);
        assert_eq!(feed(1, 1001, 16, b"beta"), Verdict::Accept);
    }
    #[test]
    fn expression_rules_combine_protocol_endpoint_and_analyzer_fields() {
        use crate::conditions::{MatchRule, parse_expression};

        let mut policy = Inspect::with_analyzers(
            crate::ConstantPolicy(Verdict::Accept),
            vec![AnalyzerRule::observing(Some(80), || Box::<HttpHost>::default())],
        )
        .with_flow_rules(vec![
            MatchRule {
                condition: parse_expression(
                    r#"proto == tcp && src.ip in 10.0.0.0/8 && (http.host == "blocked.test" || tls.sni == "blocked.test")"#,
                )
                .unwrap(),
                action: FlowAction::Block,
            }
            .into_flow_rule(),
            MatchRule {
                condition: parse_expression(r#"http.host == "allowed.test""#).unwrap(),
                action: FlowAction::Allow,
            }
            .into_flow_rule(),
        ]);
        let mut feed = |scope, seq, flags, payload: &[u8]| {
            let bytes = tcp(seq, flags, payload, false);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope(scope),
            })
        };
        assert_eq!(feed(1, 100, 2, b""), Verdict::Accept);
        assert_eq!(
            feed(1, 101, 16, b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"),
            Verdict::DropFlow
        );
        assert_eq!(feed(2, 100, 2, b""), Verdict::Accept);
        assert_eq!(
            feed(2, 101, 16, b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"),
            Verdict::Accept
        );
    }

    #[test]
    fn one_bidirectional_tcp_analyzer_combines_reassembled_request_and_reply() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        struct Exchange {
            requested: bool,
        }
        impl BidirectionalStreamAnalyzer for Exchange {
            fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
                if !reverse && bytes == b"request" {
                    self.requested = true;
                    Analysis::Observations(vec![Observation {
                        field: "exchange.request",
                        value: "seen".into(),
                    }])
                } else if reverse && self.requested && bytes == b"reject" {
                    Analysis::Observations(vec![Observation {
                        field: "exchange.reply",
                        value: "reject".into(),
                    }])
                } else {
                    Analysis::Pending
                }
            }
        }

        let created = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&created);
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_bidirectional_analyzers(vec![BidirectionalAnalyzerRule::observing(
                    Some(80),
                    move || {
                        count.fetch_add(1, Ordering::Relaxed);
                        Box::new(Exchange { requested: false })
                    },
                )])
                .with_flow_rules(vec![FlowRule::new(|context| {
                    (context.protocol == Protocol::Tcp
                        && context.reverse
                        && context.source.port() == 80
                        && context.destination.port() == 12345
                        && context.origin.port() == 12345
                        && context.target.port() == 80
                        && context.get("exchange.request") == Some("seen")
                        && context.get("exchange.reply") == Some("reject"))
                    .then_some(FlowAction::Block)
                })]);
        let mut feed = |seq, flags, payload: &[u8], reverse| {
            let bytes = tcp(seq, flags, payload, reverse);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(100, 2, b"", false), Verdict::Accept);
        assert_eq!(feed(500, 18, b"", true), Verdict::Accept);
        assert_eq!(feed(101, 16, b"request", false), Verdict::Accept);
        assert_eq!(feed(504, 16, b"ect", true), Verdict::Accept);
        assert_eq!(feed(501, 16, b"rej", true), Verdict::DropFlow);
        assert_eq!(created.load(Ordering::Relaxed), 1);
        assert_eq!(feed(108, 16, b"later", false), Verdict::DropFlow);
        assert_eq!(feed(1000, 2, b"", false), Verdict::Accept);
        assert_eq!(created.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn bidirectional_analyzer_can_match_directly_without_flow_rules() {
        struct Reply;
        impl BidirectionalStreamAnalyzer for Reply {
            fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
                if reverse && bytes == b"deny" {
                    Analysis::FinalObservations(vec![Observation {
                        field: "reply.word",
                        value: "deny".into(),
                    }])
                } else {
                    Analysis::Pending
                }
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_bidirectional_analyzers(vec![
                    BidirectionalAnalyzerRule::exact(
                        "reply.word",
                        vec!["deny".into()],
                        Some(80),
                        || Box::new(Reply),
                    )
                    .unwrap(),
                ]);
        let mut feed = |seq, flags, payload: &[u8], reverse| {
            let bytes = tcp(seq, flags, payload, reverse);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(100, 2, b"", false), Verdict::Accept);
        assert_eq!(feed(500, 18, b"", true), Verdict::Accept);
        assert_eq!(feed(501, 16, b"deny", true), Verdict::DropFlow);
    }

    #[test]
    fn flow_allow_is_terminal_for_inspection_but_keeps_transport_policy() {
        struct Transport;
        impl Policy for Transport {
            fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
                if packet.bytes.ends_with(b"transport-drop") {
                    Verdict::Drop
                } else {
                    Verdict::Accept
                }
            }
        }
        struct Word;
        impl StreamAnalyzer for Word {
            fn feed(&mut self, bytes: &[u8]) -> Analysis {
                Analysis::Observations(vec![Observation {
                    field: "decision",
                    value: String::from_utf8_lossy(bytes).into_owned(),
                }])
            }
        }
        let mut policy = Inspect::with_analyzers(
            Transport,
            vec![AnalyzerRule::observing(None, || Box::new(Word))],
        )
        .with_flow_rules(vec![
            FlowRule::new(|context| {
                (context.get("decision") == Some("allow")).then_some(FlowAction::Allow)
            }),
            FlowRule::new(|context| {
                (context.get("decision") == Some("deny")).then_some(FlowAction::Block)
            }),
        ]);
        let mut feed = |seq, flags, payload: &[u8]| {
            let bytes = tcp(seq, flags, payload, false);
            policy.evaluate(Packet {
                bytes: &bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(feed(100, 2, b""), Verdict::Accept);
        assert_eq!(feed(101, 16, b"allow"), Verdict::Accept);
        assert_eq!(feed(106, 16, b"deny"), Verdict::Accept);
        assert_eq!(feed(110, 16, b"transport-drop"), Verdict::Drop);
        assert_eq!(feed(1000, 2, b""), Verdict::Accept);
        assert_eq!(feed(1001, 16, b"deny"), Verdict::DropFlow);
    }
    #[test]
    fn flow_rules_can_match_endpoints_without_analyzers_in_order() {
        let packet = tcp(100, 2, b"", false);
        let evaluate = |first: FlowAction| {
            let mut policy =
                Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                    .with_flow_rules(vec![
                        FlowRule::new(move |context| {
                            (context.destination.port() == 80).then(|| first.clone())
                        }),
                        FlowRule::new(|_| Some(FlowAction::Block)),
                    ]);
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            })
        };
        assert_eq!(evaluate(FlowAction::Allow), Verdict::Accept);
        assert_eq!(evaluate(FlowAction::Block), Verdict::DropFlow);
        assert_eq!(evaluate(FlowAction::DropPacket), Verdict::DropFlow);
        assert_eq!(
            evaluate(FlowAction::ReplaceUdpPayload(b"ignored".to_vec())),
            Verdict::DropFlow
        );
    }
    #[test]
    fn engine_policy_replacement_drops_old_inspection_decisions() {
        struct OnePacket {
            bytes: Vec<u8>,
            verdict: Option<Verdict>,
        }
        impl crate::PacketIo for OnePacket {
            fn process_one(&mut self, policy: &mut dyn Policy) -> std::io::Result<()> {
                self.verdict = Some(policy.evaluate(Packet {
                    bytes: &self.bytes,
                    original_len: self.bytes.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                }));
                Ok(())
            }
        }
        let mut engine = crate::Engine::new(Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["old.test".into()],
        ));
        let mut packet = OnePacket {
            bytes: tcp(100, 2, b"", false),
            verdict: None,
        };
        engine.step(&mut packet).unwrap();
        packet.bytes = tcp(101, 16, b"GET / HTTP/1.1\r\nHost: old.test\r\n\r\n", false);
        engine.step(&mut packet).unwrap();
        assert_eq!(packet.verdict, Some(Verdict::DropFlow));

        engine.replace_policy(Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["new.test".into()],
        ));
        engine.step(&mut packet).unwrap();
        assert_eq!(packet.verdict, Some(Verdict::Accept));
        packet.bytes = tcp(1000, 2, b"", false);
        engine.step(&mut packet).unwrap();
        packet.bytes = tcp(1001, 16, b"GET / HTTP/1.1\r\nHost: new.test\r\n\r\n", false);
        engine.step(&mut packet).unwrap();
        assert_eq!(packet.verdict, Some(Verdict::DropFlow));
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
