//! Ordered transport rules with bidirectional flow decisions.
use crate::{
    Packet, Policy, Verdict,
    packet::{self, ParseError, Protocol},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Rule {
    pub protocol: Option<Protocol>,
    /// Matches either endpoint so reply packets obey the same rule.
    pub port: Option<u16>,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey(Protocol, SocketAddr, SocketAddr);
struct Flow {
    verdict: Verdict,
    seen: Instant,
}

pub struct Rules {
    rules: Vec<Rule>,
    default: Verdict,
    flows: HashMap<FlowKey, Flow>,
    capacity: usize,
    idle: Duration,
    next_sweep: Instant,
}
impl Rules {
    pub fn new(rules: Vec<Rule>, default: Verdict) -> Self {
        Self {
            rules,
            default,
            flows: HashMap::new(),
            capacity: 65536,
            idle: Duration::from_secs(120),
            next_sweep: Instant::now(),
        }
    }
    /// Cached decisions belong to this ruleset; replacement invalidates them.
    pub fn replace(&mut self, rules: Vec<Rule>, default: Verdict) {
        self.rules = rules;
        self.default = default;
        self.flows.clear();
    }
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn evaluate_at(&mut self, packet: Packet<'_>, now: Instant) -> Verdict {
        if packet.bytes.len() < packet.original_len {
            return Verdict::Drop;
        }
        let transport = match packet::parse(packet.bytes) {
            Ok(p) => p,
            Err(ParseError::Unsupported) => return self.default,
            Err(_) => return Verdict::Drop,
        };
        if now >= self.next_sweep {
            self.flows
                .retain(|_, flow| now.saturating_duration_since(flow.seen) < self.idle);
            self.next_sweep = now + Duration::from_secs(1);
        }
        let (a, b) = if transport.source <= transport.destination {
            (transport.source, transport.destination)
        } else {
            (transport.destination, transport.source)
        };
        let key = FlowKey(transport.protocol, a, b);
        if let Some(flow) = self.flows.get_mut(&key)
            && now.saturating_duration_since(flow.seen) < self.idle
        {
            flow.seen = now;
            return flow.verdict;
        }
        let verdict = self
            .rules
            .iter()
            .find(|rule| {
                rule.protocol
                    .is_none_or(|protocol| protocol == transport.protocol)
                    && rule
                        .port
                        .is_none_or(|port| port == a.port() || port == b.port())
            })
            .map_or(self.default, |rule| rule.verdict);
        // At capacity, evaluate uncached. Filtering never depends on cache admission.
        if self.flows.len() < self.capacity || self.flows.contains_key(&key) {
            self.flows.insert(key, Flow { verdict, seen: now });
        }
        verdict
    }
}
impl Policy for Rules {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict {
        self.evaluate_at(packet, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(bytes: &[u8]) -> Packet<'_> {
        Packet {
            bytes,
            original_len: bytes.len(),
            checksum_ready: true,
        }
    }
    #[test]
    fn reverse_flow_reload_expiration_and_capacity() {
        let mut rules = Rules::new(
            vec![Rule {
                protocol: Some(Protocol::Udp),
                port: Some(53),
                verdict: Verdict::Drop,
            }],
            Verdict::Accept,
        );
        let now = Instant::now();
        assert_eq!(
            rules.evaluate_at(packet(&packet::udp(false)), now),
            Verdict::Drop
        );
        assert_eq!(
            rules.evaluate_at(packet(&packet::udp(true)), now),
            Verdict::Drop
        );
        assert_eq!(rules.flow_count(), 1);
        rules.replace(vec![], Verdict::Accept);
        assert_eq!(rules.flow_count(), 0);
        assert_eq!(
            rules.evaluate_at(packet(&packet::udp(false)), now),
            Verdict::Accept
        );
        let mut other = packet::udp(false);
        other[12] = 30;
        rules.evaluate_at(packet(&other), now + Duration::from_secs(121));
        assert_eq!(rules.flow_count(), 1);
        rules.capacity = 1;
        rules.evaluate_at(packet(&packet::udp(false)), now + Duration::from_secs(121));
        assert_eq!(rules.flow_count(), 1);
    }
}
