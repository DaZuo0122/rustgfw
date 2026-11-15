//! Linux NFQUEUE adapter. Firewall ownership remains with the operator.
#![cfg(target_os = "linux")]
use rustgfw_core::{FlowScope, Packet, PacketIo, Policy, Verdict};
use std::io;
use std::os::fd::AsRawFd;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
pub mod conntrack;
pub mod nft;
mod offload_worker;

struct BlockedFlow {
    installed: Option<Instant>,
    retry_after: Instant,
    inflight: bool,
}

fn offload_due(block: Option<&BlockedFlow>, now: Instant) -> bool {
    block.is_none_or(|block| {
        now >= block.retry_after
            && !block.inflight
            && block
                .installed
                .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(115))
    })
}

fn untracked_scope(indev: u32, outdev: u32, mark: u32) -> FlowScope {
    let (first, second) = if indev <= outdev {
        (indev, outdev)
    } else {
        (outdev, indev)
    };
    FlowScope(
        (1u128 << 96) | (u128::from(first) << 64) | (u128::from(second) << 32) | u128::from(mark),
    )
}

pub struct NfQueue {
    queue: nfq::Queue,
    dynamic_table: Option<String>,
    mark_offload: Option<u32>,
    destroy_events: Option<conntrack::DestroyEvents>,
    offload_worker: Option<offload_worker::Worker>,
    blocked_ct: HashMap<conntrack::ConntrackKey, BlockedFlow>,
    closing_ct: HashMap<conntrack::ConntrackKey, Instant>,
    pending_blocks: HashSet<conntrack::ConntrackKey>,
    pending_unblocks: HashSet<conntrack::ConntrackKey>,
    pending_since: Option<Instant>,
}
impl NfQueue {
    pub fn open(number: u16) -> io::Result<Self> {
        let mut queue = nfq::Queue::open()?;
        queue.bind(number)?;
        queue.set_recv_conntrack(number, true)?;
        queue.set_fail_open(number, false)?;
        queue.set_recv_gso(number, false)?;
        queue.set_recv_enobufs(true)?;
        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        // SAFETY: fd remains owned by queue; timeout points to a live timeval.
        let result = unsafe {
            libc::setsockopt(
                queue.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            queue,
            dynamic_table: None,
            mark_offload: None,
            destroy_events: None,
            offload_worker: None,
            blocked_ct: HashMap::new(),
            closing_ct: HashMap::new(),
            pending_blocks: HashSet::new(),
            pending_unblocks: HashSet::new(),
            pending_since: None,
        })
    }
    pub fn set_dynamic_table(&mut self, table: &str) -> io::Result<()> {
        let events = conntrack::DestroyEvents::open()?;
        let worker = offload_worker::Worker::start(table.to_owned())?;
        self.destroy_events = Some(events);
        self.offload_worker = Some(worker);
        self.dynamic_table = Some(table.to_owned());
        Ok(())
    }
    pub fn set_mark_offload(&mut self, mask: u32) {
        self.mark_offload = Some(mask);
    }
    pub fn stop_offload(&mut self) -> io::Result<()> {
        if let Some(worker) = self.offload_worker.take() {
            worker.stop()?;
        }
        Ok(())
    }
    fn drain_offload_results(&mut self) -> io::Result<()> {
        let Some(worker) = &self.offload_worker else {
            return Ok(());
        };
        while let Some(completion) = worker.try_completion()? {
            match completion {
                offload_worker::Completion::Block(keys, result) => {
                    let now = Instant::now();
                    for key in keys {
                        if let Some(block) = self.blocked_ct.get_mut(&key) {
                            block.inflight = false;
                            if result.is_ok() {
                                block.installed = Some(now);
                                block.retry_after = now;
                            } else {
                                block.retry_after = now + Duration::from_secs(1);
                            }
                        }
                    }
                    if let Err(error) = result {
                        eprintln!("nft flow offload failed: {error}; blocking in userspace");
                    }
                }
                offload_worker::Completion::Unblock(result) => result?,
            }
        }
        Ok(())
    }
    fn flush_pending_if_due(&mut self) -> io::Result<()> {
        let count = self.pending_blocks.len() + self.pending_unblocks.len();
        if count >= 16
            || (count > 0
                && self
                    .pending_since
                    .is_some_and(|at| at.elapsed() >= Duration::from_millis(10)))
        {
            self.flush_pending()?;
        }
        Ok(())
    }
    fn flush_pending(&mut self) -> io::Result<()> {
        let Some(worker) = &self.offload_worker else {
            return Ok(());
        };
        if !self.pending_unblocks.is_empty() {
            let keys: Vec<_> = self.pending_unblocks.iter().copied().collect();
            worker.unblock(keys)?;
            self.pending_unblocks.clear();
        }
        if !self.pending_blocks.is_empty() {
            let keys: Vec<_> = self.pending_blocks.iter().copied().collect();
            worker.block(keys.clone())?;
            for key in &keys {
                if let Some(block) = self.blocked_ct.get_mut(key) {
                    block.inflight = true;
                }
            }
            self.pending_blocks.clear();
        }
        self.pending_since = None;
        Ok(())
    }
}
impl PacketIo for NfQueue {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
        self.drain_offload_results()?;
        self.closing_ct
            .retain(|_, at| at.elapsed() < Duration::from_secs(120));
        if let (Some(events), Some(table)) = (&self.destroy_events, &self.dynamic_table) {
            let table = table.clone();
            let result = events.drain(|key| {
                if let Some(block) = self.blocked_ct.remove(&key) {
                    self.closing_ct.insert(key, Instant::now());
                    self.pending_blocks.remove(&key);
                    if block.installed.is_some() || block.inflight {
                        if self.pending_blocks.is_empty() && self.pending_unblocks.is_empty() {
                            self.pending_since = Some(Instant::now());
                        }
                        self.pending_unblocks.insert(key);
                    }
                }
                Ok(())
            });
            if let Err(error) = result {
                if !conntrack::events_lost(&error) {
                    return Err(error);
                }
                self.stop_offload()?;
                nft::NftPolicy::new("/usr/sbin/nft").flush_blocked_flows(&table)?;
                self.blocked_ct.clear();
                self.closing_ct.clear();
                self.pending_blocks.clear();
                self.pending_unblocks.clear();
                self.pending_since = None;
                self.dynamic_table = None;
                self.destroy_events = None;
                eprintln!(
                    "conntrack destroy events lost; disabled ID offload, continuing in userspace"
                );
            }
        }
        self.flush_pending_if_due()?;
        let mut message = self.queue.recv()?;
        let bytes = message.get_payload();
        let conntrack = message.get_conntrack();
        let has_conntrack = conntrack.is_some();
        let scope = conntrack.map_or_else(
            || {
                untracked_scope(
                    message.get_indev(),
                    message.get_outdev(),
                    message.get_nfmark(),
                )
            },
            |ct| {
                conntrack::ConntrackKey {
                    id: ct.get_id(),
                    zone: ct.get_zone(),
                }
                .scope()
            },
        );
        let conntrack_key =
            conntrack
                .filter(|ct| ct.get_id() != 0)
                .map(|ct| conntrack::ConntrackKey {
                    id: ct.get_id(),
                    zone: ct.get_zone(),
                });
        let rst = rustgfw_core::packet::parse(bytes).ok().is_some_and(|p| {
            p.protocol == rustgfw_core::packet::Protocol::Tcp && p.tcp_flags & 4 != 0
        });
        let cached_block =
            conntrack_key.is_some_and(|key| self.blocked_ct.contains_key(&key)) && !rst;
        let verdict = if cached_block {
            Verdict::DropFlow
        } else if bytes.is_empty() || bytes.len() < message.get_original_len() {
            Verdict::Drop
        } else {
            policy.evaluate(Packet {
                bytes,
                original_len: message.get_original_len(),
                checksum_ready: message.is_checksum_ready(),
                scope,
            })
        };
        let close_blocked = verdict == Verdict::DropFlow
            && rst
            && self.dynamic_table.is_some()
            && conntrack_key.is_some_and(|key| self.blocked_ct.contains_key(&key));
        if close_blocked && let Some(key) = conntrack_key {
            let block = self.blocked_ct.remove(&key).unwrap();
            self.pending_blocks.remove(&key);
            if block.installed.is_some() || block.inflight {
                if self.pending_blocks.is_empty() && self.pending_unblocks.is_empty() {
                    self.pending_since = Some(Instant::now());
                }
                self.pending_unblocks.insert(key);
            }
            self.closing_ct.insert(key, Instant::now());
        }
        let mark_block =
            verdict == Verdict::DropFlow && !rst && has_conntrack && self.mark_offload.is_some();
        if mark_block {
            message.set_nfmark(message.get_nfmark() | self.mark_offload.unwrap());
        }
        message.set_verdict(
            if verdict == Verdict::Accept || close_blocked || mark_block {
                nfq::Verdict::Accept
            } else {
                nfq::Verdict::Drop
            },
        );
        self.queue.verdict(message)?;
        if verdict == Verdict::DropFlow
            && !close_blocked
            && self.dynamic_table.is_some()
            && let Some(key) = conntrack_key
            && offload_due(self.blocked_ct.get(&key), Instant::now())
            && !self.closing_ct.contains_key(&key)
        {
            let now = Instant::now();
            self.blocked_ct.entry(key).or_insert(BlockedFlow {
                installed: None,
                retry_after: now,
                inflight: false,
            });
            if self.pending_blocks.is_empty() && self.pending_unblocks.is_empty() {
                self.pending_since = Some(now);
            }
            self.pending_blocks.insert(key);
        }
        self.flush_pending_if_due()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untracked_flow_scope_uses_path_and_packet_mark() {
        let a = untracked_scope(3, 9, 4);
        assert_eq!(a, untracked_scope(9, 3, 4));
        assert_ne!(a, untracked_scope(5, 9, 4));
        assert_ne!(a, untracked_scope(3, 9, 8));
        assert_ne!(
            a,
            conntrack::ConntrackKey {
                id: 1,
                zone: nfq::ConntrackZone::default(),
            }
            .scope()
        );
    }

    #[test]
    fn renews_expired_kernel_block_without_repeating_fresh_inserts() {
        let now = Instant::now();
        assert!(offload_due(None, now));
        let fresh = BlockedFlow {
            installed: Some(now - Duration::from_secs(114)),
            retry_after: now,
            inflight: false,
        };
        assert!(!offload_due(Some(&fresh), now));
        let expired = BlockedFlow {
            installed: Some(now - Duration::from_secs(115)),
            retry_after: now,
            inflight: false,
        };
        assert!(offload_due(Some(&expired), now));
        let failed = BlockedFlow {
            installed: None,
            retry_after: now + Duration::from_secs(1),
            inflight: false,
        };
        assert!(!offload_due(Some(&failed), now));
        assert!(offload_due(Some(&failed), now + Duration::from_secs(1)));
        let inflight = BlockedFlow {
            installed: None,
            retry_after: now,
            inflight: true,
        };
        assert!(!offload_due(Some(&inflight), now));
    }

    #[test]
    #[ignore = "requires nft and NFQUEUE in an isolated network namespace"]
    fn lost_destroy_events_flush_and_disable_id_offload() -> io::Result<()> {
        use rustgfw_core::KernelPolicy;
        use std::{os::unix::net::UnixDatagram, process::Command};

        let mut nft = nft::NftPolicy::new("/usr/sbin/nft");
        let handle = nft.install(&nft::Plan {
            hook: nft::Hook::Output,
            queue: 100,
            rules: vec![],
            dynamic: nft::DynamicOffload::IdSet,
            bypass_without_listener: false,
        })?;
        let result = (|| {
            let mut queue = NfQueue::open(100)?;
            let key = conntrack::ConntrackKey {
                id: 12345,
                zone: nfq::ConntrackZone::default(),
            };
            let mut overrun = [0u8; 16];
            overrun[..4].copy_from_slice(&16u32.to_ne_bytes());
            overrun[4..6].copy_from_slice(&(libc::NLMSG_OVERRUN as u16).to_ne_bytes());
            let malformed = [0u8; 16];
            let truncated = vec![0u8; 65537];
            for event in [&overrun[..], &malformed[..], &truncated[..]] {
                queue.set_dynamic_table(handle.table_name())?;
                nft.block_tcp_flow(handle.table_name(), key)?;
                queue.blocked_ct.insert(
                    key,
                    BlockedFlow {
                        installed: Some(Instant::now()),
                        retry_after: Instant::now(),
                        inflight: false,
                    },
                );
                let (sender, receiver) = UnixDatagram::pair()?;
                queue.destroy_events = Some(conntrack::DestroyEvents::from_fd(receiver.into()));
                sender.send(event)?;
                let error = queue
                    .process_one(&mut rustgfw_core::ConstantPolicy(Verdict::Accept))
                    .unwrap_err();
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ));
                assert!(queue.dynamic_table.is_none());
                assert!(queue.destroy_events.is_none());
                assert!(queue.blocked_ct.is_empty());
                let output = Command::new("/usr/sbin/nft")
                    .args(["list", "set", "inet", handle.table_name(), "blocked_ct"])
                    .output()?;
                assert!(output.status.success());
                assert!(!String::from_utf8_lossy(&output.stdout).contains("elements ="));
            }
            Ok::<_, io::Error>(())
        })();
        nft.revoke(&handle)?;
        result
    }
}
