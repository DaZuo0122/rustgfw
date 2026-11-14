//! OS-independent packet policy execution. No kernel identifiers enter policy code.
use std::io;
pub mod dns;
pub mod inspect;
pub mod offload;
pub mod packet;
pub mod rules;
pub mod tcp;
pub mod tls;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    /// Drop this TCP packet and ask the backend to block both flow directions.
    DropFlow,
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
}

/// A backend owns the pending kernel packet until its decision is submitted.
/// Returning an error must terminate the runner; verdict failures are never hidden.
pub trait PacketIo {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()>;
}

/// Kernel policy installation is distinct from packet acceptance/reinjection.
/// Handles are backend-owned and must be revoked before replacing a ruleset.
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
}
