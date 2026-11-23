//! Incremental stream analysis. Each direction shares reassembly across analyzers.
pub use crate::http::HttpFirstMessage as HttpHost;
use crate::{
    Decision, FlowScope, Packet, Policy, Verdict,
    http3::Http3Conversation,
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
    /// Ordered messages from one feed; each has its own fact replacement scope.
    Batches {
        batches: Vec<ObservationBatch>,
        finished: bool,
    },
    Finished,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub field: &'static str,
    pub value: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ObservationBatch {
    pub clear_fields: &'static [&'static str],
    /// Facts restored for this event without marking them as fresh observations.
    pub context: Vec<Observation>,
    pub observations: Vec<Observation>,
}

pub trait StreamAnalyzer {
    fn feed(&mut self, bytes: &[u8]) -> Analysis;
}

/// One instance observes both directions of a reassembled TCP flow.
/// `reverse` is relative to the first packet that created the flow.
pub trait BidirectionalStreamAnalyzer {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis;
}

/// Observes payload-bearing TCP packets before stream reassembly. Packet
/// boundaries and sequence numbers are preserved for wire-shape models.
pub trait TcpPacketAnalyzer {
    fn feed(&mut self, sequence: u32, payload: &[u8], reverse: bool) -> Analysis;
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
    /// Replace this datagram's fields and publish the new observation batch.
    ReplaceFields {
        fields: Vec<&'static str>,
        observations: Vec<Observation>,
    },
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

struct Direction {
    reassembly: Reassembler,
    analyzers: Vec<Option<Box<dyn StreamAnalyzer>>>,
}
struct TcpAnalyzerSets<'a> {
    directional: &'a [AnalyzerRule],
    bidirectional: &'a [BidirectionalAnalyzerRule],
    packets: &'a [TcpPacketRule],
}
struct Flow {
    directions: [Direction; 2],
    origin: SocketAddr,
    target: SocketAddr,
    bidirectional: Vec<Option<Box<dyn BidirectionalStreamAnalyzer>>>,
    packet_analyzers: Vec<Option<Box<dyn TcpPacketAnalyzer>>>,
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
struct Http3Flow {
    origin: SocketAddr,
    target: SocketAddr,
    facts: HashMap<&'static str, Vec<String>>,
    allowed: bool,
    blocked: bool,
    seen: Instant,
}
struct Http3Connection {
    analyzer: Http3Conversation,
    seen: Instant,
}
impl UdpFlow {
    fn finished(&self, has_rules: bool) -> bool {
        !has_rules && !self.allowed && !self.blocked && self.analyzers.iter().all(Option::is_none)
    }
}
impl Flow {
    fn new(
        origin: SocketAddr,
        target: SocketAddr,
        initial_syn: Option<(usize, u32)>,
        analyzers: TcpAnalyzerSets<'_>,
        reorder_bytes: usize,
        now: Instant,
    ) -> Self {
        let port_matches =
            |port: Option<u16>| port.is_none_or(|p| origin.port() == p || target.port() == p);
        Self {
            directions: std::array::from_fn(|_| Direction {
                reassembly: Reassembler::new(reorder_bytes),
                analyzers: analyzers
                    .directional
                    .iter()
                    .map(|rule| port_matches(rule.port).then(|| (rule.factory)()))
                    .collect(),
            }),
            origin,
            target,
            bidirectional: analyzers
                .bidirectional
                .iter()
                .map(|rule| port_matches(rule.port).then(|| (rule.factory)()))
                .collect(),
            packet_analyzers: analyzers
                .packets
                .iter()
                .map(|rule| port_matches(rule.port).then(|| (rule.factory)()))
                .collect(),
            facts: HashMap::new(),
            allowed: false,
            blocked: false,
            seen: now,
            initial_syn,
            fin_seen: [false; 2],
        }
    }

    fn finished(&self, has_rules: bool) -> bool {
        !has_rules
            && !self.blocked
            && !self.allowed
            && self.bidirectional.iter().all(Option::is_none)
            && self.packet_analyzers.iter().all(Option::is_none)
            && self
                .directions
                .iter()
                .all(|d| d.analyzers.iter().all(Option::is_none))
    }
}
type Key = (FlowScope, SocketAddr, SocketAddr);
type DecodedKey = (FlowScope, u64);

/// Bytes already decoded from a transport or proxy connection.
/// `scope` identifies the outer connection and `stream_id` identifies one
/// logical stream within it. The caller supplies bytes in order per direction.
/// `origin` and `target` are the current path endpoints; they may change when
/// the outer connection migrates, while `scope` and `stream_id` stay stable.
pub struct DecodedStream<'a> {
    pub scope: FlowScope,
    pub stream_id: u64,
    pub origin: SocketAddr,
    pub target: SocketAddr,
    pub reverse: bool,
    pub bytes: &'a [u8],
}

/// Verdict for an HTTP/3 request stream. A QPACK update can yield a verdict
/// for a request stream other than the stream carrying the current input.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedVerdict {
    pub stream_id: u64,
    pub verdict: Verdict,
}

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

fn collect_tcp_analysis(
    analysis: Analysis,
    matcher: &dyn Fn(&Observation) -> bool,
    facts: &mut HashMap<&'static str, Vec<String>>,
    blocked: &mut bool,
    updated: &mut Vec<&'static str>,
    batches: &mut Vec<ObservationBatch>,
    has_rules: bool,
) -> bool {
    match analysis {
        Analysis::Finished => true,
        Analysis::Observations(observations) => {
            *blocked |= match_tcp_observations(facts, observations, matcher, has_rules, updated);
            false
        }
        Analysis::FinalObservations(observations) => {
            *blocked |= match_tcp_observations(facts, observations, matcher, has_rules, updated);
            true
        }
        Analysis::Batches {
            batches: messages,
            finished,
        } => {
            *blocked |= messages
                .iter()
                .any(|message| message.observations.iter().any(matcher));
            if has_rules {
                batches.extend(messages);
            }
            finished
        }
        Analysis::Pending => false,
    }
}

#[derive(Default)]
struct TcpAnalysis {
    updated: Vec<&'static str>,
    batches: Vec<ObservationBatch>,
}

struct TcpEvent<'a> {
    scope: FlowScope,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &'a [u8],
}

fn analyze_tcp_bytes(
    flow: &mut Flow,
    bytes: &[u8],
    direction: usize,
    reverse: bool,
    analyzers: &[AnalyzerRule],
    bidirectional: &[BidirectionalAnalyzerRule],
    has_rules: bool,
) -> TcpAnalysis {
    let mut output = TcpAnalysis::default();
    for (slot, rule) in flow.directions[direction]
        .analyzers
        .iter_mut()
        .zip(analyzers)
    {
        let Some(analyzer) = slot else {
            continue;
        };
        if collect_tcp_analysis(
            analyzer.feed(bytes),
            rule.matches.as_ref(),
            &mut flow.facts,
            &mut flow.blocked,
            &mut output.updated,
            &mut output.batches,
            has_rules,
        ) {
            *slot = None;
        }
    }
    for (slot, rule) in flow.bidirectional.iter_mut().zip(bidirectional) {
        let Some(analyzer) = slot else {
            continue;
        };
        if collect_tcp_analysis(
            analyzer.feed(bytes, reverse),
            rule.matches.as_ref(),
            &mut flow.facts,
            &mut flow.blocked,
            &mut output.updated,
            &mut output.batches,
            has_rules,
        ) {
            *slot = None;
        }
    }
    output
}

fn evaluate_tcp_batches(
    flow: &mut Flow,
    rules: &[FlowRule],
    event: TcpEvent<'_>,
    analysis: TcpAnalysis,
) {
    if flow.blocked || flow.allowed || rules.is_empty() {
        return;
    }
    if analysis.batches.is_empty() {
        apply_tcp_flow_rules(
            flow,
            rules,
            event.scope,
            event.source,
            event.destination,
            event.payload,
            &analysis.updated,
        );
        return;
    }
    for batch in analysis.batches {
        let mut batch_updated = analysis.updated.clone();
        for field in batch.clear_fields {
            flow.facts.remove(field);
            batch_updated.retain(|item| item != field);
        }
        store_observations(&mut flow.facts, batch.context, &mut Vec::new());
        store_observations(&mut flow.facts, batch.observations, &mut batch_updated);
        apply_tcp_flow_rules(
            flow,
            rules,
            event.scope,
            event.source,
            event.destination,
            event.payload,
            &batch_updated,
        );
        if flow.allowed || flow.blocked {
            break;
        }
    }
}

fn apply_tcp_flow_rules(
    flow: &mut Flow,
    rules: &[FlowRule],
    scope: FlowScope,
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    updated: &[&'static str],
) {
    let context = FlowContext {
        protocol: Protocol::Tcp,
        scope,
        source,
        destination,
        origin: flow.origin,
        target: flow.target,
        reverse: source != flow.origin,
        payload,
        facts: &flow.facts,
        updated,
    };
    for (rule_index, rule) in rules.iter().enumerate() {
        let Some(action) = (rule.matches)(&context) else {
            continue;
        };
        tracing::debug!(protocol = "tcp", scope = scope.0, rule_index,
            action = action_label(&action), source = %source, destination = %destination,
            "application rule matched");
        match action {
            FlowAction::Allow => flow.allowed = true,
            FlowAction::Block | FlowAction::DropPacket => flow.blocked = true,
            FlowAction::ReplaceUdpPayload(_) => continue,
        }
        break;
    }
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

fn action_label(action: &FlowAction) -> &'static str {
    match action {
        FlowAction::Allow => "allow",
        FlowAction::Block => "block",
        FlowAction::DropPacket => "drop_packet",
        FlowAction::ReplaceUdpPayload(_) => "replace_udp_payload",
    }
}

type FlowMatch = dyn for<'a> Fn(&FlowContext<'a>) -> Option<FlowAction> + Send + Sync;
type FlowCandidate = dyn Fn(Protocol, SocketAddr, SocketAddr) -> bool + Send + Sync;
/// Compose facts from multiple analyzers into an ordered flow decision.
pub struct FlowRule {
    matches: Box<FlowMatch>,
    candidate: Option<Box<FlowCandidate>>,
}
impl FlowRule {
    pub fn new(
        matches: impl for<'a> Fn(&FlowContext<'a>) -> Option<FlowAction> + Send + Sync + 'static,
    ) -> Self {
        Self {
            matches: Box::new(matches),
            candidate: None,
        }
    }

    /// A conservative hint for deciding whether a new flow needs inspection.
    /// Return true if the rule could match either direction at any later point.
    pub fn with_candidate(
        matches: impl for<'a> Fn(&FlowContext<'a>) -> Option<FlowAction> + Send + Sync + 'static,
        candidate: impl Fn(Protocol, SocketAddr, SocketAddr) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            matches: Box::new(matches),
            candidate: Some(Box::new(candidate)),
        }
    }

    fn might_match(&self, protocol: Protocol, source: SocketAddr, destination: SocketAddr) -> bool {
        self.candidate
            .as_ref()
            .is_none_or(|candidate| candidate(protocol, source, destination))
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

/// Register a raw TCP packet analyzer whose observations feed flow rules.
pub struct TcpPacketRule {
    pub port: Option<u16>,
    pub factory: Box<dyn Fn() -> Box<dyn TcpPacketAnalyzer> + Send + Sync>,
}
impl TcpPacketRule {
    pub fn new(
        port: Option<u16>,
        factory: impl Fn() -> Box<dyn TcpPacketAnalyzer> + Send + Sync + 'static,
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
    tcp_packet_analyzers: Vec<TcpPacketRule>,
    flow_rules: Vec<FlowRule>,
    datagrams: Vec<DatagramRule>,
    udp_analyzers: Vec<UdpStreamRule>,
    udp_rules: Vec<FlowRule>,
    flows: HashMap<Key, Flow>,
    decoded_flows: HashMap<DecodedKey, Flow>,
    http3_connections: HashMap<FlowScope, Http3Connection>,
    http3_flows: HashMap<DecodedKey, Http3Flow>,
    udp_flows: HashMap<Key, UdpFlow>,
    completed_since_compaction: bool,
    sweep: Instant,
    limits: InspectLimits,
}
impl<P> Inspect<P> {
    pub fn http_hosts(transport: P, hosts: Vec<String>) -> Self {
        Self::with_analyzers(transport, Vec::new()).with_bidirectional_analyzers(
            BidirectionalAnalyzerRule::exact("http.host", hosts, None, || {
                Box::<crate::http::HttpConversation>::default()
            })
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
            tcp_packet_analyzers: Vec::new(),
            flow_rules: Vec::new(),
            datagrams,
            udp_analyzers: Vec::new(),
            udp_rules: Vec::new(),
            flows: HashMap::new(),
            decoded_flows: HashMap::new(),
            http3_connections: HashMap::new(),
            http3_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            completed_since_compaction: false,
            sweep: Instant::now(),
            limits,
        }
    }
    pub fn clear_flows(&mut self) {
        self.flows.clear();
        self.decoded_flows.clear();
        self.http3_connections.clear();
        self.http3_flows.clear();
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

    pub fn with_tcp_packet_analyzers(mut self, analyzers: Vec<TcpPacketRule>) -> Self {
        self.clear_flows();
        self.tcp_packet_analyzers = analyzers;
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
            self.decoded_flows
                .retain(|_, flow| now.duration_since(flow.seen) < self.limits.idle);
            self.http3_connections
                .retain(|_, connection| now.duration_since(connection.seen) < self.limits.idle);
            self.http3_flows
                .retain(|_, flow| now.duration_since(flow.seen) < self.limits.idle);
            self.udp_flows
                .retain(|_, flow| now.duration_since(flow.seen) < self.limits.idle);
            self.sweep = now + Duration::from_secs(1);
        }
    }

    fn compact_completed_flows(&mut self) {
        if self.completed_since_compaction {
            let tcp_has_rules = !self.flow_rules.is_empty();
            let udp_has_rules = !self.udp_rules.is_empty();
            self.flows.retain(|_, flow| !flow.finished(tcp_has_rules));
            self.udp_flows
                .retain(|_, flow| !flow.finished(udp_has_rules));
            self.completed_since_compaction = false;
        }
    }

    fn active_count(&self) -> usize {
        self.flows.len()
            + self.udp_flows.len()
            + self.decoded_flows.len()
            + self.http3_connections.len()
            + self.http3_flows.len()
    }

    /// Inspect ordered bytes supplied by a decoder outside the packet I/O path.
    /// The verdict applies to this logical stream; the caller decides how to
    /// enforce it. Call `close_decoded` when the stream ends.
    pub fn feed_decoded(&mut self, input: DecodedStream<'_>) -> Verdict {
        if self.analyzers.is_empty()
            && self.bidirectional_analyzers.is_empty()
            && self.flow_rules.is_empty()
        {
            return Verdict::Accept;
        }
        let now = Instant::now();
        self.expire_idle_flows(now);
        let key = (input.scope, input.stream_id);
        if !self.decoded_flows.contains_key(&key)
            && !self
                .flow_rules
                .iter()
                .any(|rule| rule.might_match(Protocol::Tcp, input.origin, input.target))
            && !self.analyzers.iter().any(|rule| {
                rule.port
                    .is_none_or(|p| input.origin.port() == p || input.target.port() == p)
            })
            && !self.bidirectional_analyzers.iter().any(|rule| {
                rule.port
                    .is_none_or(|p| input.origin.port() == p || input.target.port() == p)
            })
        {
            return Verdict::Accept;
        }
        if !self.decoded_flows.contains_key(&key) && self.active_count() >= self.limits.max_flows {
            self.compact_completed_flows();
            if self.active_count() >= self.limits.max_flows {
                tracing::warn!(
                    scope = input.scope.0,
                    stream_id = input.stream_id,
                    limit = self.limits.max_flows,
                    "decoded stream capacity reached"
                );
                return Verdict::DropFlow;
            }
        }
        let flow = self.decoded_flows.entry(key).or_insert_with(|| {
            Flow::new(
                input.origin,
                input.target,
                None,
                TcpAnalyzerSets {
                    directional: &self.analyzers,
                    bidirectional: &self.bidirectional_analyzers,
                    packets: &[],
                },
                self.limits.reorder_bytes,
                now,
            )
        });
        flow.seen = now;
        if flow.blocked {
            return Verdict::DropFlow;
        }
        let (source, destination) = if input.reverse {
            (input.target, input.origin)
        } else {
            (input.origin, input.target)
        };
        let analysis = if !flow.allowed {
            analyze_tcp_bytes(
                flow,
                input.bytes,
                usize::from(input.reverse),
                input.reverse,
                &self.analyzers,
                &self.bidirectional_analyzers,
                !self.flow_rules.is_empty(),
            )
        } else {
            TcpAnalysis::default()
        };
        evaluate_tcp_batches(
            flow,
            &self.flow_rules,
            TcpEvent {
                scope: input.scope,
                source,
                destination,
                payload: input.bytes,
            },
            analysis,
        );
        if flow.blocked {
            tracing::info!(scope = input.scope.0, stream_id = input.stream_id,
                origin = %flow.origin, target = %flow.target, "decoded TCP stream blocked");
            Verdict::DropFlow
        } else {
            Verdict::Accept
        }
    }

    /// Release all analyzers and facts for one decoded logical stream.
    pub fn close_decoded(&mut self, scope: FlowScope, stream_id: u64) {
        self.decoded_flows.remove(&(scope, stream_id));
    }

    /// Inspect decrypted, ordered HTTP/3 QUIC stream bytes. The caller must
    /// verify ALPN and handle QUIC decryption/reassembly. Returned verdicts
    /// apply to request streams, including those released by QPACK updates.
    pub fn feed_http3(&mut self, input: DecodedStream<'_>) -> Vec<DecodedVerdict> {
        let now = Instant::now();
        self.expire_idle_flows(now);
        if !self.http3_connections.contains_key(&input.scope)
            && self.active_count() >= self.limits.max_flows
        {
            tracing::warn!(
                scope = input.scope.0,
                stream_id = input.stream_id,
                limit = self.limits.max_flows,
                "HTTP/3 connection capacity reached"
            );
            return vec![DecodedVerdict {
                stream_id: input.stream_id,
                verdict: Verdict::DropFlow,
            }];
        }
        let connection = self
            .http3_connections
            .entry(input.scope)
            .or_insert_with(|| Http3Connection {
                analyzer: Http3Conversation::default(),
                seen: now,
            });
        connection.seen = now;
        let events = connection
            .analyzer
            .feed_events(input.stream_id, input.reverse, input.bytes);
        let mut decisions = Vec::new();
        for event in events {
            let key = (input.scope, event.stream_id);
            if !self.http3_flows.contains_key(&key) && self.active_count() >= self.limits.max_flows
            {
                tracing::warn!(
                    scope = input.scope.0,
                    stream_id = event.stream_id,
                    limit = self.limits.max_flows,
                    "HTTP/3 request capacity reached"
                );
                decisions.push(DecodedVerdict {
                    stream_id: event.stream_id,
                    verdict: Verdict::DropFlow,
                });
                continue;
            }
            let flow = self.http3_flows.entry(key).or_insert_with(|| Http3Flow {
                origin: input.origin,
                target: input.target,
                facts: HashMap::new(),
                allowed: false,
                blocked: false,
                seen: now,
            });
            flow.seen = now;
            let was_blocked = flow.blocked;
            if !flow.blocked && !flow.allowed {
                let mut updated = Vec::new();
                for field in event.batch.clear_fields {
                    flow.facts.remove(field);
                }
                store_observations(&mut flow.facts, event.batch.context, &mut Vec::new());
                store_observations(&mut flow.facts, event.batch.observations, &mut updated);
                let (source, destination) = if event.reverse {
                    (input.target, input.origin)
                } else {
                    (input.origin, input.target)
                };
                let context = FlowContext {
                    protocol: Protocol::Udp,
                    scope: input.scope,
                    source,
                    destination,
                    origin: flow.origin,
                    target: flow.target,
                    reverse: event.reverse,
                    payload: &[],
                    facts: &flow.facts,
                    updated: &updated,
                };
                for (rule_index, rule) in self.udp_rules.iter().enumerate() {
                    let Some(action) = (rule.matches)(&context) else {
                        continue;
                    };
                    tracing::debug!(
                        protocol = "http3",
                        scope = input.scope.0,
                        stream_id = event.stream_id,
                        rule_index,
                        action = action_label(&action),
                        "application rule matched"
                    );
                    match action {
                        FlowAction::Allow if !event.provisional => flow.allowed = true,
                        FlowAction::Allow => {}
                        FlowAction::Block | FlowAction::DropPacket => flow.blocked = true,
                        FlowAction::ReplaceUdpPayload(_) => continue,
                    }
                    break;
                }
            }
            if !was_blocked && flow.blocked {
                tracing::info!(scope = input.scope.0, stream_id = event.stream_id,
                    origin = %flow.origin, target = %flow.target, "HTTP/3 request blocked");
            }
            decisions.push(DecodedVerdict {
                stream_id: event.stream_id,
                verdict: if flow.blocked {
                    Verdict::DropFlow
                } else {
                    Verdict::Accept
                },
            });
        }
        if decisions.is_empty()
            && self
                .http3_flows
                .get(&(input.scope, input.stream_id))
                .is_some_and(|flow| flow.blocked)
        {
            decisions.push(DecodedVerdict {
                stream_id: input.stream_id,
                verdict: Verdict::DropFlow,
            });
        }
        decisions
    }

    pub fn close_http3_stream(&mut self, scope: FlowScope, stream_id: u64) {
        self.http3_flows.remove(&(scope, stream_id));
        if let Some(connection) = self.http3_connections.get_mut(&scope) {
            connection.analyzer.close_stream(stream_id);
        }
    }

    pub fn close_http3_connection(&mut self, scope: FlowScope) {
        self.http3_connections.remove(&scope);
        self.http3_flows
            .retain(|(item_scope, _), _| *item_scope != scope);
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
                DatagramAnalysis::Malformed => {
                    tracing::warn!(scope = packet.scope.0, source = %transport.source,
                        destination = %transport.destination, "datagram analyzer rejected malformed input");
                    return Verdict::Drop.into();
                }
                DatagramAnalysis::Observations(observations)
                    if observations.iter().any(|value| (rule.matches)(value)) =>
                {
                    tracing::info!(scope = packet.scope.0, source = %transport.source,
                        destination = %transport.destination, "datagram rule dropped packet");
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
        if !self.udp_flows.contains_key(&key)
            && !self.udp_analyzers.iter().any(|rule| {
                rule.port.is_none_or(|port| {
                    port.matches(transport.source.port(), transport.destination.port())
                })
            })
            && !self.udp_rules.iter().any(|rule| {
                rule.might_match(Protocol::Udp, transport.source, transport.destination)
            })
        {
            return Verdict::Accept.into();
        }
        if !self.udp_flows.contains_key(&key) && self.active_count() >= self.limits.max_flows {
            self.compact_completed_flows();
            if self.active_count() >= self.limits.max_flows {
                tracing::warn!(scope = packet.scope.0, source = %transport.source,
                    destination = %transport.destination, limit = self.limits.max_flows,
                    "UDP inspection capacity reached");
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
                    UdpStreamAnalysis::ReplaceFields {
                        fields,
                        observations,
                    } => {
                        for field in fields {
                            flow.facts.remove(field);
                            updated.retain(|value| *value != field);
                        }
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
                            updated.retain(|value| *value != field);
                        }
                    }
                }
            }
            if !drop_packet && !self.udp_rules.is_empty() {
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
                if let Some((rule_index, action)) =
                    self.udp_rules.iter().enumerate().find_map(|(index, rule)| {
                        (rule.matches)(&context).map(|action| (index, action))
                    })
                {
                    tracing::debug!(protocol = "udp", scope = packet.scope.0, rule_index,
                        action = action_label(&action), source = %transport.source,
                        destination = %transport.destination, "application rule matched");
                    match action {
                        FlowAction::Allow => flow.allowed = true,
                        FlowAction::Block => {
                            flow.blocked = true;
                            tracing::info!(scope = packet.scope.0, source = %transport.source,
                                destination = %transport.destination, "UDP flow blocked");
                        }
                        FlowAction::DropPacket => {
                            drop_packet = true;
                        }
                        FlowAction::ReplaceUdpPayload(payload) => replacement = Some(payload),
                    }
                }
            }
        }
        self.completed_since_compaction |= flow.finished(!self.udp_rules.is_empty());
        if flow.blocked {
            Verdict::DropFlow.into()
        } else if drop_packet {
            tracing::info!(scope = packet.scope.0, source = %transport.source,
                destination = %transport.destination, "UDP packet dropped");
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
        if verdict != Verdict::Accept {
            tracing::debug!(
                scope = packet.scope.0,
                ?verdict,
                "transport policy decided packet"
            );
        }
        if verdict != Verdict::Accept
            || (self.analyzers.is_empty()
                && self.bidirectional_analyzers.is_empty()
                && self.tcp_packet_analyzers.is_empty()
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
            && self.tcp_packet_analyzers.is_empty()
            && self.flow_rules.is_empty()
        {
            return transport_decision;
        }
        let (key, direction) = if t.source <= t.destination {
            ((packet.scope, t.source, t.destination), 0)
        } else {
            ((packet.scope, t.destination, t.source), 1)
        };
        let now = Instant::now();
        self.expire_idle_flows(now);
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
        if !self.flows.contains_key(&key)
            && !self
                .flow_rules
                .iter()
                .any(|rule| rule.might_match(Protocol::Tcp, t.source, t.destination))
            && !self.analyzers.iter().any(|a| {
                a.port
                    .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
            })
            && !self.bidirectional_analyzers.iter().any(|a| {
                a.port
                    .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
            })
            && !self.tcp_packet_analyzers.iter().any(|a| {
                a.port
                    .is_none_or(|port| t.source.port() == port || t.destination.port() == port)
            })
        {
            return transport_decision;
        }
        if self.active_count() >= self.limits.max_flows && !self.flows.contains_key(&key) {
            self.compact_completed_flows();
            if self.active_count() >= self.limits.max_flows {
                tracing::warn!(scope = packet.scope.0, source = %t.source,
                    destination = %t.destination, limit = self.limits.max_flows,
                    "TCP inspection capacity reached");
                // Active inspection cannot be silently bypassed at capacity.
                return Verdict::Drop.into();
            }
        }
        let flow = self.flows.entry(key).or_insert_with(|| {
            Flow::new(
                t.source,
                t.destination,
                initial_syn,
                TcpAnalyzerSets {
                    directional: &self.analyzers,
                    bidirectional: &self.bidirectional_analyzers,
                    packets: &self.tcp_packet_analyzers,
                },
                self.limits.reorder_bytes,
                now,
            )
        });
        flow.seen = now;
        if flow.blocked {
            return Verdict::DropFlow.into();
        }
        let mut analysis = TcpAnalysis::default();
        if !flow.allowed && !t.payload.is_empty() {
            let reverse = t.source != flow.origin;
            for slot in &mut flow.packet_analyzers {
                let Some(analyzer) = slot else {
                    continue;
                };
                if collect_tcp_analysis(
                    analyzer.feed(t.tcp_sequence.unwrap(), t.payload, reverse),
                    &|_| false,
                    &mut flow.facts,
                    &mut flow.blocked,
                    &mut analysis.updated,
                    &mut analysis.batches,
                    !self.flow_rules.is_empty(),
                ) {
                    *slot = None;
                }
            }
        }
        if !flow.allowed {
            let has_analyzers = flow.directions[direction]
                .analyzers
                .iter()
                .any(Option::is_some)
                || flow.bidirectional.iter().any(Option::is_some);
            if has_analyzers {
                match flow.directions[direction].reassembly.feed(
                    t.tcp_sequence.unwrap(),
                    t.tcp_flags & 2 != 0,
                    t.payload,
                ) {
                    Ok(bytes) => {
                        let reverse = t.source != flow.origin;
                        let stream_analysis = analyze_tcp_bytes(
                            flow,
                            &bytes,
                            direction,
                            reverse,
                            &self.analyzers,
                            &self.bidirectional_analyzers,
                            !self.flow_rules.is_empty(),
                        );
                        analysis.updated.extend(stream_analysis.updated);
                        analysis.batches.extend(stream_analysis.batches);
                    }
                    Err(_) => {
                        flow.blocked = true;
                        tracing::warn!(scope = packet.scope.0, source = %t.source,
                            destination = %t.destination, "TCP reassembly failed");
                    }
                }
            }
        }
        evaluate_tcp_batches(
            flow,
            &self.flow_rules,
            TcpEvent {
                scope: packet.scope,
                source: t.source,
                destination: t.destination,
                payload: t.payload,
            },
            analysis,
        );
        let result = if flow.blocked {
            tracing::info!(scope = packet.scope.0, source = %t.source,
                destination = %t.destination, origin = %flow.origin, target = %flow.target,
                "TCP flow blocked");
            Verdict::DropFlow
        } else {
            verdict
        };
        self.completed_since_compaction |= flow.finished(!self.flow_rules.is_empty());
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

    #[test]
    fn http3_rules_evaluate_the_matching_request_stream() {
        use compcol::{hpack::HeaderField, qpack::QpackEncoder};

        let mut inspect = Inspect::with_analyzers((), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(|context| {
                (context.updated("http3.status")
                    && context.get("http3.status") == Some("404")
                    && context.get("http3.path") == Some("/two"))
                .then_some(FlowAction::Block)
            })],
        );
        let mut encoder = QpackEncoder::new();
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let feed = |inspect: &mut Inspect<()>, stream_id, reverse, bytes: &[u8]| {
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(91),
                stream_id,
                origin,
                target,
                reverse,
                bytes,
            })
        };
        for (stream_id, path) in [(0, "/one"), (4, "/two")] {
            let block = encoder.encode_field_section(&[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", path.as_bytes()),
            ]);
            let mut frame = vec![1, block.len() as u8];
            frame.extend(block);
            assert_eq!(
                feed(&mut inspect, stream_id, false, &frame),
                vec![DecodedVerdict {
                    stream_id,
                    verdict: Verdict::Accept,
                }]
            );
        }
        let block = encoder.encode_field_section(&[HeaderField::new(b":status", b"404")]);
        let mut frame = vec![1, block.len() as u8];
        frame.extend(block);
        assert_eq!(
            feed(&mut inspect, 0, true, &frame),
            vec![DecodedVerdict {
                stream_id: 0,
                verdict: Verdict::Accept,
            }]
        );
        assert_eq!(
            feed(&mut inspect, 4, true, &frame),
            vec![DecodedVerdict {
                stream_id: 4,
                verdict: Verdict::DropFlow,
            }]
        );
        assert_eq!(
            feed(&mut inspect, 4, true, &[0, 1, b'x']),
            vec![DecodedVerdict {
                stream_id: 4,
                verdict: Verdict::DropFlow,
            }]
        );
        inspect.close_http3_stream(FlowScope(91), 4);
        inspect.close_http3_connection(FlowScope(91));
        assert!(inspect.http3_flows.is_empty());
        assert!(inspect.http3_connections.is_empty());
    }

    #[test]
    fn http3_expression_correlates_hysteria_auth_request_and_reply() {
        use crate::conditions::{MatchRule, parse_expression};
        use compcol::{hpack::HeaderField, qpack::QpackEncoder};

        let rule = MatchRule {
            condition: parse_expression(
                "fresh.http3.status == 233 && http3.method == POST && http3.path == /auth && http3.authority == hysteria && http3.request_header_name == hysteria-auth",
            )
            .unwrap(),
            action: FlowAction::Block,
        };
        let mut inspect = Inspect::with_analyzers((), Vec::new())
            .with_udp_streams(Vec::new(), vec![rule.into_flow_rule()]);
        let mut encoder = QpackEncoder::new();
        let frame = |fields: &[HeaderField], encoder: &mut QpackEncoder| {
            let block = encoder.encode_field_section(fields);
            let mut bytes = vec![1];
            if block.len() < 64 {
                bytes.push(block.len() as u8);
            } else {
                bytes.extend([0x40 | (block.len() >> 8) as u8, block.len() as u8]);
            }
            bytes.extend(block);
            bytes
        };
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let feed = |inspect: &mut Inspect<()>, stream_id, reverse, bytes: &[u8]| {
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(98),
                stream_id,
                origin,
                target,
                reverse,
                bytes,
            })
        };
        let request = frame(
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/auth"),
                HeaderField::new(b":authority", b"hysteria"),
                HeaderField::new(b"hysteria-auth", b"secret-token"),
            ],
            &mut encoder,
        );
        assert_eq!(
            feed(&mut inspect, 0, false, &request)[0].verdict,
            Verdict::Accept
        );
        let response = frame(&[HeaderField::new(b":status", b"233")], &mut encoder);
        assert_eq!(
            feed(&mut inspect, 0, true, &response)[0].verdict,
            Verdict::DropFlow
        );

        let ordinary_request = frame(
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":path", b"/auth"),
                HeaderField::new(b":authority", b"hysteria"),
            ],
            &mut encoder,
        );
        assert_eq!(
            feed(&mut inspect, 4, false, &ordinary_request)[0].verdict,
            Verdict::Accept
        );
        let ordinary_reply = frame(
            &[
                HeaderField::new(b":status", b"233"),
                HeaderField::new(b"hysteria-auth", b"not-a-request-header"),
            ],
            &mut encoder,
        );
        assert_eq!(
            feed(&mut inspect, 4, true, &ordinary_reply)[0].verdict,
            Verdict::Accept
        );
    }

    #[test]
    fn http3_migration_keeps_request_facts_and_uses_current_path() {
        use compcol::{hpack::HeaderField, qpack::QpackEncoder};

        let old_client = "192.0.2.1:12345".parse().unwrap();
        let old_server = "198.51.100.2:443".parse().unwrap();
        let new_client = "192.0.2.9:54321".parse().unwrap();
        let new_server = "198.51.100.8:443".parse().unwrap();
        let mut inspect = Inspect::with_analyzers((), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(move |context| {
                (context.updated("http3.status")
                    && context.get("http3.path") == Some("/migrated")
                    && context.origin == old_client
                    && context.target == old_server
                    && context.source == new_server
                    && context.destination == new_client
                    && context.reverse)
                    .then_some(FlowAction::Block)
            })],
        );
        let mut encoder = QpackEncoder::new();
        let frame = |fields: &[HeaderField], encoder: &mut QpackEncoder| {
            let block = encoder.encode_field_section(fields);
            let mut frame = vec![1, block.len() as u8];
            frame.extend(block);
            frame
        };
        let request = frame(
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/migrated"),
            ],
            &mut encoder,
        );
        let response = frame(&[HeaderField::new(b":status", b"403")], &mut encoder);
        assert_eq!(
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(93),
                stream_id: 0,
                origin: old_client,
                target: old_server,
                reverse: false,
                bytes: &request,
            }),
            vec![DecodedVerdict {
                stream_id: 0,
                verdict: Verdict::Accept,
            }]
        );
        assert_eq!(
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(93),
                stream_id: 0,
                origin: new_client,
                target: new_server,
                reverse: true,
                bytes: &response,
            }),
            vec![DecodedVerdict {
                stream_id: 0,
                verdict: Verdict::DropFlow,
            }]
        );
        assert_eq!(
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(94),
                stream_id: 0,
                origin: new_client,
                target: new_server,
                reverse: true,
                bytes: &response,
            }),
            vec![DecodedVerdict {
                stream_id: 0,
                verdict: Verdict::Accept,
            }]
        );
    }

    #[test]
    fn http3_late_request_rechecks_early_response_rule() {
        use compcol::{hpack::HeaderField, qpack::QpackEncoder};

        let mut inspect = Inspect::with_analyzers((), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![
                FlowRule::new(|context| {
                    (context.updated("http3.status")
                        && context.get("http3.status") == Some("403")
                        && context.get("http3.path") == Some("/late"))
                    .then_some(FlowAction::Block)
                }),
                FlowRule::new(|context| {
                    (context.updated("http3.status") && context.get("http3.status") == Some("403"))
                        .then_some(FlowAction::Allow)
                }),
            ],
        );
        let mut encoder = QpackEncoder::new();
        let frame = |fields: &[HeaderField], encoder: &mut QpackEncoder| {
            let block = encoder.encode_field_section(fields);
            let mut frame = vec![1, block.len() as u8];
            frame.extend(block);
            frame
        };
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let response = frame(&[HeaderField::new(b":status", b"403")], &mut encoder);
        assert_eq!(
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(96),
                stream_id: 4,
                origin,
                target,
                reverse: true,
                bytes: &response,
            }),
            vec![DecodedVerdict {
                stream_id: 4,
                verdict: Verdict::Accept,
            }]
        );
        let request = frame(
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/late"),
            ],
            &mut encoder,
        );
        assert_eq!(
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(96),
                stream_id: 4,
                origin,
                target,
                reverse: false,
                bytes: &request,
            }),
            vec![
                DecodedVerdict {
                    stream_id: 4,
                    verdict: Verdict::Accept,
                },
                DecodedVerdict {
                    stream_id: 4,
                    verdict: Verdict::DropFlow,
                },
            ]
        );
    }

    #[test]
    fn decoded_stream_migration_updates_packet_endpoints() {
        let old_client = "192.0.2.1:12345".parse().unwrap();
        let old_server = "198.51.100.2:443".parse().unwrap();
        let new_client = "192.0.2.9:54321".parse().unwrap();
        let new_server = "198.51.100.8:443".parse().unwrap();
        let mut inspect =
            Inspect::with_analyzers((), Vec::new()).with_flow_rules(vec![FlowRule::new(
                move |context| {
                    (context.origin == old_client
                        && context.target == old_server
                        && context.source == new_server
                        && context.destination == new_client
                        && context.reverse)
                        .then_some(FlowAction::Block)
                },
            )]);
        assert_eq!(
            inspect.feed_decoded(DecodedStream {
                scope: FlowScope(95),
                stream_id: 0,
                origin: old_client,
                target: old_server,
                reverse: false,
                bytes: b"request",
            }),
            Verdict::Accept
        );
        assert_eq!(
            inspect.feed_decoded(DecodedStream {
                scope: FlowScope(95),
                stream_id: 0,
                origin: new_client,
                target: new_server,
                reverse: true,
                bytes: b"response",
            }),
            Verdict::DropFlow
        );
    }

    #[test]
    fn http3_qpack_update_reports_the_unblocked_request_stream() {
        use compcol::{hpack::HeaderField, qpack::QpackEncoder};

        let mut inspect = Inspect::with_analyzers((), Vec::new()).with_udp_streams(
            Vec::new(),
            vec![FlowRule::new(|context| {
                (context.updated("http3.authority")
                    && context.get("http3.authority") == Some("blocked.test"))
                .then_some(FlowAction::Block)
            })],
        );
        let mut encoder = QpackEncoder::with_dynamic_table(512);
        let encoded = encoder.encode(&[
            HeaderField::new(b":method", b"GET"),
            HeaderField::new(b":authority", b"blocked.test"),
        ]);
        assert!(!encoded.encoder_stream.is_empty());
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let feed = |inspect: &mut Inspect<()>, stream_id, bytes: &[u8]| {
            inspect.feed_http3(DecodedStream {
                scope: FlowScope(92),
                stream_id,
                origin,
                target,
                reverse: false,
                bytes,
            })
        };
        let mut request = vec![1, encoded.field_section.len() as u8];
        request.extend(encoded.field_section);
        assert!(feed(&mut inspect, 0, &request).is_empty());
        let mut updates = vec![2];
        updates.extend(encoded.encoder_stream);
        assert_eq!(
            feed(&mut inspect, 2, &updates),
            vec![DecodedVerdict {
                stream_id: 0,
                verdict: Verdict::DropFlow,
            }]
        );
    }

    fn request_batch(observations: Vec<Observation>, finished: bool) -> Analysis {
        Analysis::Batches {
            batches: vec![ObservationBatch {
                clear_fields: crate::http::FIELDS,
                context: Vec::new(),
                observations,
            }],
            finished,
        }
    }

    #[test]
    fn expression_text_operators_keep_field_and_payload_case_semantics() {
        use crate::conditions::parse_expression;

        let source = "192.0.2.1:1234".parse().unwrap();
        let destination = "198.51.100.2:80".parse().unwrap();
        let facts = HashMap::from([
            (
                "http.host",
                vec!["other.test".into(), "Api.Example.Com".into()],
            ),
            ("http.method", vec!["GET".into()]),
            ("http.target", vec!["/Admin".into()]),
            ("tls.alpn", vec!["h2".into()]),
            ("tls.server_alpn", vec!["h2".into()]),
        ]);
        let context = FlowContext {
            protocol: Protocol::Tcp,
            scope: FlowScope::default(),
            source,
            destination,
            origin: source,
            target: destination,
            reverse: false,
            payload: b"prefix BYTES suffix",
            facts: &facts,
            updated: &["http.host"],
        };
        for expression in [
            "http.host ends_with .example.com",
            "fresh.http.host starts_with api.",
            "http.host contains AMPLE",
            "http.method == GET",
            "http.target == /Admin",
            "tls.alpn == h2",
            "tls.server_alpn == h2",
            "payload contains BYTES",
            "payload starts_with prefix",
            "payload ends_with suffix",
            "payload contains \"\"",
            "payload_hex contains 0x4259544553",
            "payload_hex starts_with 0x707265666978",
        ] {
            assert!(
                parse_expression(expression).unwrap().matches(&context),
                "{expression}"
            );
        }
        for expression in [
            "payload contains bytes",
            "payload_hex contains 0x00ff",
            "http.host ends_with .invalid.test",
            "http.method == get",
            "http.target == /admin",
            "tls.alpn == H2",
            "tls.server_alpn == H2",
            "fresh.dns.qname contains example",
        ] {
            assert!(
                !parse_expression(expression).unwrap().matches(&context),
                "{expression}"
            );
        }
        assert!(parse_expression("src.port contains 1234").is_err());
        assert!(parse_expression("payload_hex == 0x0").is_err());
        assert!(parse_expression("payload_hex == 0xzz").is_err());
        assert!(parse_expression("payload_hex == 0x€€").is_err());
    }

    #[test]
    fn expression_numeric_and_presence_conditions_use_current_packet_and_facts() {
        use crate::conditions::parse_expression;

        let source = "192.0.2.1:1234".parse().unwrap();
        let destination = "198.51.100.2:51820".parse().unwrap();
        let facts = HashMap::from([
            ("wireguard.type", vec!["data".into()]),
            (
                "wireguard.counter",
                vec!["invalid".into(), "7".into(), "12".into()],
            ),
        ]);
        let context = FlowContext {
            protocol: Protocol::Udp,
            scope: FlowScope::default(),
            source,
            destination,
            origin: source,
            target: destination,
            reverse: false,
            payload: &[0; 32],
            facts: &facts,
            updated: &["wireguard.type"],
        };
        for expression in [
            "dst.port >= 51820",
            "src.port < 2000",
            "src.port != 443",
            "payload.len == 32",
            "payload.len > 16 && payload.len <= 32",
            "wireguard.type exists",
            "fresh.wireguard.type exists",
            "proto != tcp",
            "wireguard.type != initiation",
            "wireguard.counter > 10",
            "wireguard.counter <= 7",
        ] {
            assert!(
                parse_expression(expression).unwrap().matches(&context),
                "{expression}"
            );
        }
        for expression in [
            "dst.port > 51820",
            "src.port >= 2000",
            "payload.len < 32",
            "dns.qname exists",
            "fresh.dns.qname exists",
            "wireguard.type != data",
            "wireguard.counter < 7",
            "fresh.wireguard.counter > 10",
        ] {
            assert!(
                !parse_expression(expression).unwrap().matches(&context),
                "{expression}"
            );
        }
    }

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

    fn evaluate_bytes(policy: &mut dyn Policy, bytes: &[u8]) -> Verdict {
        policy.evaluate(Packet {
            bytes,
            original_len: bytes.len(),
            checksum_ready: true,
            scope: FlowScope::default(),
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
    fn rejected_udp_datagram_does_not_match_stale_observations() {
        struct Word;
        impl UdpStreamAnalyzer for Word {
            fn feed(&mut self, payload: &[u8], _: bool) -> UdpStreamAnalysis {
                if payload == b"invalid" {
                    UdpStreamAnalysis::Drop
                } else {
                    UdpStreamAnalysis::Observations(vec![Observation {
                        field: "udp.word",
                        value: String::from_utf8_lossy(payload).into_owned(),
                    }])
                }
            }
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    vec![UdpStreamRule::new(None, || Box::new(Word))],
                    vec![FlowRule::new(|context| {
                        (!context.updated("udp.word") && context.get("udp.word") == Some("old"))
                            .then_some(FlowAction::Block)
                    })],
                );
        assert_eq!(evaluate_udp(&mut policy, 0, b"old", false), Verdict::Accept);
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"invalid", false),
            Verdict::Drop
        );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"next", false),
            Verdict::Accept
        );
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
            a.feed(b"st: EXAMPLE.COM\r\nConnection: close\r\n\r\nbody"),
            request_batch(
                vec![
                    Observation {
                        field: "http.method",
                        value: "GET".into()
                    },
                    Observation {
                        field: "http.target",
                        value: "/".into()
                    },
                    Observation {
                        field: "http.request_version",
                        value: "HTTP/1.1".into()
                    },
                    Observation {
                        field: "http.host",
                        value: "example.com".into()
                    },
                ],
                true
            )
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
            request_batch(vec![
                Observation { field: "http.method", value: "GET".into() },
                Observation { field: "http.target", value: "http://Blocked.Test/path".into() },
                Observation { field: "http.request_version", value: "HTTP/1.1".into() },
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
            ], false)
        );
        let mut connect = HttpHost::default();
        assert_eq!(
            connect.feed(b"CONNECT blocked.test:443 HTTP/1.1\r\n\r\n"),
            request_batch(
                vec![
                    Observation {
                        field: "http.method",
                        value: "CONNECT".into()
                    },
                    Observation {
                        field: "http.target",
                        value: "blocked.test:443".into()
                    },
                    Observation {
                        field: "http.request_version",
                        value: "HTTP/1.1".into()
                    },
                    Observation {
                        field: "http.host",
                        value: "blocked.test:443".into()
                    },
                ],
                false
            )
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
    fn http_policy_inspects_second_request_in_one_tcp_segment() {
        let mut policy = Inspect::http_hosts(
            crate::ConstantPolicy(Verdict::Accept),
            vec!["blocked.test".into()],
        );
        let payload = b"GET /one HTTP/1.1\r\nHost: allowed.test\r\n\r\nGET /two HTTP/1.1\r\nHost: blocked.test\r\n\r\n";
        let packet = tcp(100, 16, payload, false);
        assert_eq!(
            policy.evaluate(Packet {
                bytes: &packet,
                original_len: packet.len(),
                checksum_ready: true,
                scope: FlowScope::default(),
            }),
            Verdict::DropFlow
        );
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
    fn expression_candidates_skip_unrelated_flows_at_capacity() {
        use crate::conditions::{MatchRule, parse_expression};

        let limits = InspectLimits {
            max_flows: 0,
            ..InspectLimits::default()
        };
        let mut udp_policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            Vec::new(),
            limits,
        )
        .with_udp_streams(
            Vec::new(),
            vec![
                MatchRule {
                    condition: parse_expression("dst.port == 53").unwrap(),
                    action: FlowAction::Block,
                }
                .into_flow_rule(),
            ],
        );
        let mut unrelated_udp = udp(b"other", false);
        unrelated_udp[22..24].copy_from_slice(&9999u16.to_be_bytes());
        let related_udp = udp(b"query", false);
        assert_eq!(
            evaluate_bytes(&mut udp_policy, &unrelated_udp),
            Verdict::Accept
        );
        assert_eq!(evaluate_bytes(&mut udp_policy, &related_udp), Verdict::Drop);

        let mut tcp_policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            Vec::new(),
            limits,
        )
        .with_flow_rules(vec![
            MatchRule {
                condition: parse_expression("dst.port == 80").unwrap(),
                action: FlowAction::Block,
            }
            .into_flow_rule(),
        ]);
        let mut unrelated_tcp = tcp(100, 2, b"", false);
        unrelated_tcp[22..24].copy_from_slice(&443u16.to_be_bytes());
        let related_tcp = tcp(100, 2, b"", false);
        assert_eq!(
            evaluate_bytes(&mut tcp_policy, &unrelated_tcp),
            Verdict::Accept
        );
        assert_eq!(evaluate_bytes(&mut tcp_policy, &related_tcp), Verdict::Drop);
    }

    #[test]
    fn expression_candidate_keeps_reverse_packet_rule_state() {
        use crate::conditions::{MatchRule, parse_expression};

        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_udp_streams(
                    Vec::new(),
                    vec![
                        MatchRule {
                            condition: parse_expression("src.port == 53 && reverse == true")
                                .unwrap(),
                            action: FlowAction::Block,
                        }
                        .into_flow_rule(),
                    ],
                );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"query", false),
            Verdict::Accept
        );
        assert_eq!(
            evaluate_udp(&mut policy, 0, b"reply", true),
            Verdict::DropFlow
        );
    }

    #[test]
    fn rule_only_flows_survive_capacity_compaction_until_reverse_packet() {
        use crate::conditions::{MatchRule, parse_expression};

        let limits = InspectLimits {
            max_flows: 1,
            ..InspectLimits::default()
        };
        let rule = || {
            MatchRule {
                condition: parse_expression("reverse == true").unwrap(),
                action: FlowAction::Block,
            }
            .into_flow_rule()
        };
        let mut udp_policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            Vec::new(),
            limits,
        )
        .with_udp_streams(Vec::new(), vec![rule()]);
        let first_udp = udp(b"query", false);
        let mut second_udp = udp(b"query", false);
        second_udp[20..22].copy_from_slice(&12346u16.to_be_bytes());
        let reply_udp = udp(b"reply", true);
        assert_eq!(evaluate_bytes(&mut udp_policy, &first_udp), Verdict::Accept);
        assert_eq!(evaluate_bytes(&mut udp_policy, &second_udp), Verdict::Drop);
        assert_eq!(
            evaluate_bytes(&mut udp_policy, &reply_udp),
            Verdict::DropFlow
        );

        let mut tcp_policy = Inspect::with_datagrams(
            crate::ConstantPolicy(Verdict::Accept),
            Vec::new(),
            Vec::new(),
            limits,
        )
        .with_flow_rules(vec![rule()]);
        let first_tcp = tcp(100, 2, b"", false);
        let mut second_tcp = tcp(200, 2, b"", false);
        second_tcp[20..22].copy_from_slice(&12346u16.to_be_bytes());
        let reply_tcp = tcp(500, 0x12, b"", true);
        assert_eq!(evaluate_bytes(&mut tcp_policy, &first_tcp), Verdict::Accept);
        assert_eq!(evaluate_bytes(&mut tcp_policy, &second_tcp), Verdict::Drop);
        assert_eq!(
            evaluate_bytes(&mut tcp_policy, &reply_tcp),
            Verdict::DropFlow
        );
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
            feed(
                5001,
                16,
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
            ),
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
                    b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n",
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

    #[test]
    fn decoded_streams_share_rules_but_keep_independent_context() {
        fn feed(
            policy: &mut Inspect<crate::ConstantPolicy>,
            scope: u128,
            stream_id: u64,
            reverse: bool,
            bytes: &[u8],
        ) -> Verdict {
            policy.feed_decoded(DecodedStream {
                scope: FlowScope(scope),
                stream_id,
                origin: "192.0.2.1:12345".parse().unwrap(),
                target: "198.51.100.2:443".parse().unwrap(),
                reverse,
                bytes,
            })
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_bidirectional_analyzers(vec![BidirectionalAnalyzerRule::observing(
                    None,
                    || Box::<crate::http::HttpConversation>::default(),
                )])
                .with_flow_rules(vec![FlowRule::new(|context| {
                    (context.updated("http.status")
                        && context.get("http.status") == Some("403")
                        && context.get("http.host") == Some("blocked.test"))
                    .then_some(FlowAction::Block)
                })]);

        assert_eq!(
            feed(&mut policy, 11, 7, false, b"GET / HTTP/1.1\r\nHost: block"),
            Verdict::Accept
        );
        assert_eq!(
            feed(&mut policy, 11, 7, false, b"ed.test\r\n\r\n"),
            Verdict::Accept
        );
        assert_eq!(
            feed(
                &mut policy,
                11,
                8,
                false,
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"
            ),
            Verdict::Accept
        );
        assert_eq!(
            feed(&mut policy, 11, 8, true, b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            Verdict::Accept
        );
        assert_eq!(
            feed(&mut policy, 11, 7, true, b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            Verdict::DropFlow
        );
        assert_eq!(feed(&mut policy, 11, 7, true, b"again"), Verdict::DropFlow);

        policy.close_decoded(FlowScope(11), 7);
        assert_eq!(
            feed(
                &mut policy,
                11,
                7,
                false,
                b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n"
            ),
            Verdict::Accept
        );
        assert_eq!(
            feed(&mut policy, 11, 7, true, b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            Verdict::Accept
        );
        assert_eq!(
            feed(
                &mut policy,
                12,
                7,
                false,
                b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"
            ),
            Verdict::Accept
        );
        assert_eq!(policy.decoded_flows.len(), 3);
    }

    #[test]
    fn decoded_input_can_inspect_h2mux_substream_destination() {
        fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
            let mut bytes = vec![0, 0, payload.len() as u8, kind, flags];
            bytes.extend(stream.to_be_bytes());
            bytes.extend(payload);
            bytes
        }
        let mut policy =
            Inspect::with_analyzers(crate::ConstantPolicy(Verdict::Accept), Vec::new())
                .with_bidirectional_analyzers(vec![BidirectionalAnalyzerRule::observing(
                    None,
                    || Box::<crate::sing_mux::SingMuxH2>::default(),
                )])
                .with_flow_rules(vec![FlowRule::new(|context| {
                    (context.updated("sing_mux.host")
                        && context.get("sing_mux.protocol") == Some("h2mux")
                        && context.get("sing_mux.host") == Some("example.org")
                        && context.get("http2.method") == Some("CONNECT"))
                    .then_some(FlowAction::Block)
                })]);
        let origin = "192.0.2.1:12345".parse().unwrap();
        let target = "198.51.100.2:443".parse().unwrap();
        let mut carrier = b"\x00\x02PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        carrier.extend(frame(4, 0, 0, &[]));
        let mut headers = vec![0x02, 7];
        headers.extend(b"CONNECT");
        headers.extend([0x01, 9]);
        headers.extend(b"localhost");
        carrier.extend(frame(1, 4, 1, &headers));
        assert_eq!(
            policy.feed_decoded(DecodedStream {
                scope: FlowScope(44),
                stream_id: 1,
                origin,
                target,
                reverse: false,
                bytes: &carrier,
            }),
            Verdict::Accept
        );

        let mut request = vec![0, 0, 3, 11];
        request.extend(b"example.org");
        request.extend(443u16.to_be_bytes());
        let data = frame(0, 0, 1, &request);
        assert_eq!(
            policy.feed_decoded(DecodedStream {
                scope: FlowScope(44),
                stream_id: 1,
                origin,
                target,
                reverse: false,
                bytes: &data,
            }),
            Verdict::DropFlow
        );
    }
}
