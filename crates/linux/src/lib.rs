//! Linux NFQUEUE adapter. Firewall ownership remains with the operator.
#![cfg(target_os = "linux")]
use rustgfw_core::{Packet, PacketIo, Policy, Verdict};
use std::io;
use std::os::fd::AsRawFd;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
pub mod conntrack;
pub mod nft;

struct BlockedFlow {
    installed: Option<Instant>,
    retry_after: Instant,
}

fn offload_due(block: Option<&BlockedFlow>, now: Instant) -> bool {
    block.is_none_or(|block| {
        now >= block.retry_after
            && block
                .installed
                .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(115))
    })
}

pub struct NfQueue {
    queue: nfq::Queue,
    dynamic_table: Option<String>,
    destroy_events: Option<conntrack::DestroyEvents>,
    blocked_ct: HashMap<u32, BlockedFlow>,
    closing_ct: HashMap<u32, Instant>,
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
            destroy_events: None,
            blocked_ct: HashMap::new(),
            closing_ct: HashMap::new(),
        })
    }
    pub fn set_dynamic_table(&mut self, table: &str) -> io::Result<()> {
        self.destroy_events = Some(conntrack::DestroyEvents::open()?);
        self.dynamic_table = Some(table.to_owned());
        Ok(())
    }
}
impl PacketIo for NfQueue {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
        self.closing_ct
            .retain(|_, at| at.elapsed() < Duration::from_secs(120));
        if let (Some(events), Some(table)) = (&self.destroy_events, &self.dynamic_table) {
            events.drain(|id| {
                if let Some(block) = self.blocked_ct.remove(&id) {
                    self.closing_ct.insert(id, Instant::now());
                    if block.installed.is_some() {
                        nft::NftPolicy::new("/usr/sbin/nft").unblock_tcp_flow(table, id)
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            })?;
        }
        let mut message = self.queue.recv()?;
        let bytes = message.get_payload();
        let conntrack_id = message
            .get_conntrack()
            .map(|ct| ct.get_id())
            .filter(|id| *id != 0);
        let rst = rustgfw_core::packet::parse(bytes).ok().is_some_and(|p| {
            p.protocol == rustgfw_core::packet::Protocol::Tcp && p.tcp_flags & 4 != 0
        });
        let cached_block = conntrack_id.is_some_and(|id| self.blocked_ct.contains_key(&id)) && !rst;
        let verdict = if cached_block {
            Verdict::DropFlow
        } else if bytes.is_empty() || bytes.len() < message.get_original_len() {
            Verdict::Drop
        } else {
            policy.evaluate(Packet {
                bytes,
                original_len: message.get_original_len(),
                checksum_ready: message.is_checksum_ready(),
            })
        };
        let close_blocked = verdict == Verdict::DropFlow
            && rst
            && self.dynamic_table.is_some()
            && conntrack_id.is_some_and(|id| self.blocked_ct.contains_key(&id));
        if close_blocked && let (Some(table), Some(id)) = (&self.dynamic_table, conntrack_id) {
            if self.blocked_ct[&id].installed.is_some() {
                nft::NftPolicy::new("/usr/sbin/nft").unblock_tcp_flow(table, id)?;
            }
            self.blocked_ct.remove(&id);
            self.closing_ct.insert(id, Instant::now());
        }
        message.set_verdict(if verdict == Verdict::Accept || close_blocked {
            nfq::Verdict::Accept
        } else {
            nfq::Verdict::Drop
        });
        self.queue.verdict(message)?;
        if verdict == Verdict::DropFlow
            && !close_blocked
            && let Some(table) = &self.dynamic_table
            && let Some(conntrack_id) = conntrack_id
            && offload_due(self.blocked_ct.get(&conntrack_id), Instant::now())
            && !self.closing_ct.contains_key(&conntrack_id)
        {
            let previous = self.blocked_ct.get(&conntrack_id);
            let installed = previous.and_then(|block| block.installed);
            match nft::NftPolicy::new("/usr/sbin/nft").block_tcp_flow(table, conntrack_id) {
                Ok(()) => {
                    let now = Instant::now();
                    self.blocked_ct.insert(
                        conntrack_id,
                        BlockedFlow {
                            installed: Some(now),
                            retry_after: now,
                        },
                    );
                }
                Err(error) => {
                    if previous.is_none_or(|block| block.installed.is_some()) {
                        eprintln!("nft flow offload failed: {error}; blocking in userspace");
                    }
                    self.blocked_ct.insert(
                        conntrack_id,
                        BlockedFlow {
                            installed,
                            retry_after: Instant::now() + Duration::from_secs(1),
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renews_expired_kernel_block_without_repeating_fresh_inserts() {
        let now = Instant::now();
        assert!(offload_due(None, now));
        let fresh = BlockedFlow {
            installed: Some(now - Duration::from_secs(114)),
            retry_after: now,
        };
        assert!(!offload_due(Some(&fresh), now));
        let expired = BlockedFlow {
            installed: Some(now - Duration::from_secs(115)),
            retry_after: now,
        };
        assert!(offload_due(Some(&expired), now));
        let failed = BlockedFlow {
            installed: None,
            retry_after: now + Duration::from_secs(1),
        };
        assert!(!offload_due(Some(&failed), now));
        assert!(offload_due(Some(&failed), now + Duration::from_secs(1)));
    }
}
