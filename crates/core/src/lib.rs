//! OS-independent packet policy execution. No kernel identifiers enter policy code.
use std::io;
pub mod conditions;
pub mod dns;
pub mod fet;
pub mod http;
pub mod http2;
pub mod inspect;
pub mod offload;
pub mod openvpn;
pub mod packet;
pub mod quic;
pub mod rules;
pub mod sing_mux;
pub mod sing_mux_frames;
pub(crate) mod sing_mux_request;
pub mod socks;
pub mod ssh;
pub mod tcp;
pub mod tls;
pub mod trojan;
pub mod wireguard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    /// Drop this packet and block both directions of its transport flow.
    DropFlow,
}

/// An accepted replacement is a complete IP packet, including headers and
/// checksums. The I/O backend submits it using its own reinjection semantics.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Verdict(Verdict),
    Replace(Vec<u8>),
}
impl Decision {
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::Verdict(verdict) => *verdict,
            Self::Replace(_) => Verdict::Accept,
        }
    }
}
impl From<Verdict> for Decision {
    fn from(verdict: Verdict) -> Self {
        Self::Verdict(verdict)
    }
}

/// Capture conditions matter: a truncated packet must not be parsed as complete.
#[derive(Clone, Copy)]
pub struct Packet<'a> {
    pub bytes: &'a [u8],
    pub original_len: usize,
    pub checksum_ready: bool,
    /// Backend-defined traffic domain. Distinct domains never share flow state.
    pub scope: FlowScope,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowScope(pub u128);

pub trait Policy {
    fn evaluate(&mut self, packet: Packet<'_>) -> Verdict;

    /// Backends use this entry point so a policy can return a modified packet.
    fn decide(&mut self, packet: Packet<'_>) -> Decision {
        self.evaluate(packet).into()
    }
}

/// A backend owns the pending kernel packet until its decision is submitted.
/// Returning an error must terminate the runner; verdict failures are never hidden.
pub trait PacketIo {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()>;
}

/// Kernel policy installation is distinct from packet acceptance/reinjection.
/// Handles and replacement semantics are backend-owned. Any offloaded flow
/// decisions from an old policy must be cleared before a new policy runs.
pub trait KernelPolicy {
    type Rule;
    type Handle;
    fn install(&mut self, rule: &Self::Rule) -> io::Result<Self::Handle>;
    fn revoke(&mut self, handle: &Self::Handle) -> io::Result<()>;
}

pub struct Engine<P> {
    policy: P,
}
impl<P: Policy> Engine<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }
    pub fn step(&mut self, io: &mut impl PacketIo) -> io::Result<()> {
        io.process_one(&mut self.policy)
    }

    /// Replace the userspace policy between packet steps. The old policy and
    /// its flow state are returned to the caller. Kernel offloads must be
    /// updated or cleared by the backend before packets use the new policy.
    pub fn replace_policy(&mut self, next: P) -> P {
        std::mem::replace(&mut self.policy, next)
    }
}

/// Explicit bootstrap policy; not a DPI ruleset.
pub struct ConstantPolicy(pub Verdict);
impl Policy for ConstantPolicy {
    fn evaluate(&mut self, _: Packet<'_>) -> Verdict {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{packet::Protocol, rules};
    struct Fake {
        result: Option<Verdict>,
        fail: bool,
    }
    impl PacketIo for Fake {
        fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
            self.result = Some(policy.evaluate(Packet {
                bytes: &[0x45],
                original_len: 20,
                checksum_ready: false,
                scope: FlowScope::default(),
            }));
            if self.fail {
                Err(io::Error::other("verdict failed"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn submits_policy_and_propagates_failure() {
        let mut backend = Fake {
            result: None,
            fail: false,
        };
        let mut engine = Engine::new(ConstantPolicy(Verdict::Drop));
        engine.step(&mut backend).unwrap();
        assert_eq!(backend.result, Some(Verdict::Drop));
        backend.fail = true;
        assert!(engine.step(&mut backend).is_err());
    }

    #[test]
    fn replacing_policy_discards_the_previous_flow_cache() {
        struct DatagramIo {
            bytes: Vec<u8>,
            verdict: Option<Verdict>,
        }
        impl PacketIo for DatagramIo {
            fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
                self.verdict = Some(policy.evaluate(Packet {
                    bytes: &self.bytes,
                    original_len: self.bytes.len(),
                    checksum_ready: true,
                    scope: FlowScope::default(),
                }));
                Ok(())
            }
        }
        let mut io = DatagramIo {
            bytes: packet::udp(false),
            verdict: None,
        };
        let mut engine = Engine::new(rules::Rules::new(
            vec![rules::Rule {
                protocol: Some(Protocol::Udp),
                port: Some(53),
                verdict: Verdict::Drop,
            }],
            Verdict::Accept,
        ));
        engine.step(&mut io).unwrap();
        assert_eq!(io.verdict, Some(Verdict::Drop));
        let old = engine.replace_policy(rules::Rules::new(Vec::new(), Verdict::Accept));
        assert_eq!(old.flow_count(), 1);
        engine.step(&mut io).unwrap();
        assert_eq!(io.verdict, Some(Verdict::Accept));
    }
}
