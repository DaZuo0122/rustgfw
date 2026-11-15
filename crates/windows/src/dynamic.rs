//! Exact WFP flow blocks driven by WinDivert's local FLOW lifetime events.
use crate::{
    Handle,
    flow::{FlowEvent, FlowEvents, FlowKind},
    wfp::{LocalFlow, WfpPolicy},
};
use libloading::Library;
use rustgfw_core::{KernelPolicy, packet::Protocol};
use std::{
    collections::HashMap,
    ffi::c_int,
    io,
    net::SocketAddr,
    path::Path,
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Shutdown = unsafe extern "C" fn(Handle, u32) -> c_int;
const SHUTDOWN_RECV: u32 = 1;
const BLOCK_LIFETIME: Duration = Duration::from_secs(300);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    local: SocketAddr,
    remote: SocketAddr,
    protocol: u8,
}

impl FlowKey {
    fn from_event(event: &FlowEvent) -> Self {
        Self {
            local: event.local,
            remote: event.remote,
            protocol: event.protocol,
        }
    }
}

pub enum Command {
    Event(FlowEvent),
    Block {
        local: SocketAddr,
        remote: SocketAddr,
        protocol: Protocol,
        interface_index: u32,
    },
    EventsEnded,
}

struct Active<H> {
    endpoint_id: u64,
    attempted: bool,
    block: Option<(H, Instant)>,
}

struct State<P: KernelPolicy<Rule = LocalFlow>> {
    policy: P,
    active: HashMap<FlowKey, Vec<Active<P::Handle>>>,
}

impl<P: KernelPolicy<Rule = LocalFlow>> State<P> {
    fn new(policy: P) -> Self {
        Self {
            policy,
            active: HashMap::new(),
        }
    }

    fn event(&mut self, event: FlowEvent) -> io::Result<()> {
        if !matches!(event.protocol, 6 | 17) {
            return Ok(());
        }
        let key = FlowKey::from_event(&event);
        match event.kind {
            FlowKind::Established => {
                let entries = self.active.entry(key).or_default();
                if entries
                    .iter()
                    .any(|entry| entry.endpoint_id == event.endpoint_id)
                {
                    return Ok(());
                }
                // The FLOW event has no network-domain identity. If a tuple
                // overlaps, stop offloading until it becomes unambiguous.
                for entry in entries.iter_mut() {
                    if let Some((block, _)) = entry.block.take() {
                        self.policy.revoke(&block)?;
                    }
                    entry.attempted = false;
                }
                entries.push(Active {
                    endpoint_id: event.endpoint_id,
                    attempted: false,
                    block: None,
                });
            }
            FlowKind::Deleted => {
                if let Some(entries) = self.active.get_mut(&key) {
                    if let Some(position) = entries
                        .iter()
                        .position(|entry| entry.endpoint_id == event.endpoint_id)
                    {
                        let entry = entries.remove(position);
                        if let Some((block, _)) = entry.block {
                            self.policy.revoke(&block)?;
                        }
                    }
                    if entries.is_empty() {
                        self.active.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    fn expire_blocks(&mut self, now: Instant) -> io::Result<()> {
        for entries in self.active.values_mut() {
            for entry in entries {
                if entry
                    .block
                    .as_ref()
                    .is_some_and(|(_, expires_at)| *expires_at <= now)
                {
                    let (block, _) = entry.block.take().unwrap();
                    self.policy.revoke(&block)?;
                    // Keep `attempted` set: a missed FLOW delete could make
                    // this endpoint ID stale, so do not offload it again.
                }
            }
        }
        Ok(())
    }

    fn block(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        protocol: Protocol,
        interface_index: u32,
    ) {
        let key = FlowKey {
            local,
            remote,
            protocol: match protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
            },
        };
        if !self
            .active
            .get(&key)
            .is_some_and(|entries| entries.len() == 1 && !entries[0].attempted)
            || interface_index == 0
        {
            return;
        }
        match LocalFlow::on_interface(local, remote, protocol, interface_index) {
            Ok(flow) => self.block_resolved(flow),
            Err(error) => {
                self.active.get_mut(&key).unwrap()[0].attempted = true;
                eprintln!("WFP interface lookup failed: {error}; using WinDivert policy");
            }
        }
    }

    fn block_resolved(&mut self, flow: LocalFlow) {
        let key = FlowKey {
            local: flow.local,
            remote: flow.remote,
            protocol: match flow.protocol {
                Protocol::Tcp => 6,
                Protocol::Udp => 17,
            },
        };
        let Some(entries) = self.active.get_mut(&key) else {
            return;
        };
        if entries.len() != 1 || entries[0].attempted {
            return;
        }
        entries[0].attempted = true;
        let result = self.policy.install(&flow);
        match result {
            Ok(block) => entries[0].block = Some((block, Instant::now() + BLOCK_LIFETIME)),
            Err(error) => {
                eprintln!("WFP dynamic flow offload unavailable: {error}; using WinDivert policy")
            }
        }
    }
}

/// Opens FLOW monitoring before the packet handle; a dynamic WFP session
/// owns all exact filters and removes them when monitoring stops.
pub struct FlowBlocker {
    sender: Option<Sender<Command>>,
    worker: Option<JoinHandle<()>>,
    events: Option<JoinHandle<()>>,
    flow_handle: usize,
    shutdown: Shutdown,
    _library: Library,
}

impl FlowBlocker {
    pub fn start(dll: impl AsRef<Path>) -> io::Result<Self> {
        let path = dll.as_ref().to_path_buf();
        // SAFETY: the loaded DLL remains live while the function pointer is used.
        let library = unsafe { Library::new(&path) }.map_err(io::Error::other)?;
        let shutdown = unsafe {
            *library
                .get::<Shutdown>(b"WinDivertShutdown\0")
                .map_err(io::Error::other)?
        };

        let (sender, receiver) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let policy = match WfpPolicy::open() {
                Ok(policy) => {
                    let _ = ready_tx.send(Ok(()));
                    policy
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            let mut state = State::new(policy);
            let mut next_expiry_check = Instant::now() + EXPIRY_CHECK_INTERVAL;
            loop {
                let now = Instant::now();
                if now >= next_expiry_check {
                    if let Err(error) = state.expire_blocks(now) {
                        eprintln!("WFP block expiry failed: {error}; closing dynamic WFP session");
                        break;
                    }
                    next_expiry_check = now + EXPIRY_CHECK_INTERVAL;
                }
                let command = match receiver
                    .recv_timeout(next_expiry_check.saturating_duration_since(Instant::now()))
                {
                    Ok(command) => command,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let result = match command {
                    Command::Event(event) => state.event(event),
                    Command::Block {
                        local,
                        remote,
                        protocol,
                        interface_index,
                    } => {
                        state.block(local, remote, protocol, interface_index);
                        Ok(())
                    }
                    Command::EventsEnded => break,
                };
                if let Err(error) = result {
                    eprintln!("WFP flow lifecycle failed: {error}; closing dynamic WFP session");
                    break;
                }
            }
        });
        if let Err(error) = ready_rx
            .recv()
            .map_err(io::Error::other)?
            .map_err(io::Error::other)
        {
            drop(sender);
            let _ = worker.join();
            return Err(error);
        }

        let (flow_ready_tx, flow_ready_rx) = mpsc::sync_channel(1);
        let event_sender = sender.clone();
        let events = thread::spawn(move || {
            let mut source = match FlowEvents::open(&path) {
                Ok(source) => source,
                Err(error) => {
                    let _ = flow_ready_tx.send(Err(error.to_string()));
                    return;
                }
            };
            if flow_ready_tx.send(Ok(source.raw_handle())).is_err() {
                return;
            }
            loop {
                match source.receive_one() {
                    Ok(event) => {
                        if event_sender.send(Command::Event(event)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        if error.raw_os_error() != Some(232) {
                            // ERROR_NO_DATA follows WinDivertShutdown.
                            eprintln!("WinDivert FLOW monitoring stopped: {error}");
                        }
                        break;
                    }
                }
            }
            let _ = event_sender.send(Command::EventsEnded);
        });
        let flow_handle = match flow_ready_rx
            .recv()
            .map_err(io::Error::other)?
            .map_err(io::Error::other)
        {
            Ok(handle) => handle,
            Err(error) => {
                drop(sender);
                let _ = events.join();
                let _ = worker.join();
                return Err(error);
            }
        };
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            events: Some(events),
            flow_handle,
            shutdown,
            _library: library,
        })
    }

    pub fn sender(&self) -> Sender<Command> {
        self.sender.as_ref().unwrap().clone()
    }
}

impl Drop for FlowBlocker {
    fn drop(&mut self) {
        // SAFETY: FLOW handle is live until the receive thread joins; the DLL
        // is retained by this object and WinDivertShutdown may wake Recv.
        unsafe { (self.shutdown)(self.flow_handle as Handle, SHUTDOWN_RECV) };
        if let Some(events) = self.events.take() {
            let _ = events.join();
        }
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::LocalScope;

    #[derive(Default)]
    struct FakePolicy {
        installed: Vec<LocalFlow>,
        revoked: Vec<usize>,
    }

    impl KernelPolicy for FakePolicy {
        type Rule = LocalFlow;
        type Handle = usize;

        fn install(&mut self, flow: &LocalFlow) -> io::Result<usize> {
            self.installed.push(*flow);
            Ok(self.installed.len())
        }

        fn revoke(&mut self, block: &usize) -> io::Result<()> {
            self.revoked.push(*block);
            Ok(())
        }
    }

    fn event(kind: FlowKind, endpoint_id: u64) -> FlowEvent {
        FlowEvent {
            kind,
            endpoint_id,
            parent_endpoint_id: 0,
            process_id: 42,
            local: "192.0.2.1:12345".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
            protocol: 6,
            outbound: true,
        }
    }

    fn request() -> LocalFlow {
        LocalFlow {
            local: "192.0.2.1:12345".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            scope: LocalScope::InterfaceLuid(9),
        }
    }

    #[test]
    fn exact_blocks_follow_endpoint_lifetime_and_avoid_ambiguous_tuples() {
        let mut state = State::new(FakePolicy::default());
        state.block_resolved(request());
        assert!(state.policy.installed.is_empty());

        state.event(event(FlowKind::Established, 1)).unwrap();
        state.block_resolved(request());
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 1);

        state.event(event(FlowKind::Established, 2)).unwrap();
        assert_eq!(state.policy.revoked, [1]);
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 1);

        state.event(event(FlowKind::Deleted, 1)).unwrap();
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 2);
        state.event(event(FlowKind::Deleted, 2)).unwrap();
        assert_eq!(state.policy.revoked, [1, 2]);
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 2);
    }

    #[test]
    fn expired_wfp_block_reverts_to_packet_policy() {
        let mut state = State::new(FakePolicy::default());
        state.event(event(FlowKind::Established, 1)).unwrap();
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 1);
        state.expire_blocks(Instant::now()).unwrap();
        assert!(state.policy.revoked.is_empty());

        state
            .expire_blocks(Instant::now() + BLOCK_LIFETIME)
            .unwrap();
        assert_eq!(state.policy.revoked, [1]);
        state.block_resolved(request());
        assert_eq!(state.policy.installed.len(), 1);
        state.event(event(FlowKind::Deleted, 1)).unwrap();
        assert_eq!(state.policy.revoked, [1]);
    }
}
