//! Linux NFQUEUE adapter. Firewall ownership remains with the operator.
#![cfg(target_os = "linux")]
use rustgfw_core::{FlowScope, Packet, PacketIo, Policy, Verdict};
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
    blocked_ct: HashMap<conntrack::ConntrackKey, BlockedFlow>,
    closing_ct: HashMap<conntrack::ConntrackKey, Instant>,
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
            blocked_ct: HashMap::new(),
            closing_ct: HashMap::new(),
        })
    }
    pub fn set_dynamic_table(&mut self, table: &str) -> io::Result<()> {
        self.destroy_events = Some(conntrack::DestroyEvents::open()?);
        self.dynamic_table = Some(table.to_owned());
        Ok(())
    }
    pub fn set_mark_offload(&mut self, mask: u32) {
        self.mark_offload = Some(mask);
    }
}
impl PacketIo for NfQueue {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
        self.closing_ct
            .retain(|_, at| at.elapsed() < Duration::from_secs(120));
        if let (Some(events), Some(table)) = (&self.destroy_events, &self.dynamic_table) {
            events.drain(|key| {
                if let Some(block) = self.blocked_ct.remove(&key) {
                    self.closing_ct.insert(key, Instant::now());
                    if block.installed.is_some() {
                        nft::NftPolicy::new("/usr/sbin/nft").unblock_tcp_flow(table, key)
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
        if close_blocked && let (Some(table), Some(key)) = (&self.dynamic_table, conntrack_key) {
            if self.blocked_ct[&key].installed.is_some() {
                nft::NftPolicy::new("/usr/sbin/nft").unblock_tcp_flow(table, key)?;
            }
            self.blocked_ct.remove(&key);
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
            && let Some(table) = &self.dynamic_table
            && let Some(key) = conntrack_key
            && offload_due(self.blocked_ct.get(&key), Instant::now())
            && !self.closing_ct.contains_key(&key)
        {
            let previous = self.blocked_ct.get(&key);
            let installed = previous.and_then(|block| block.installed);
            match nft::NftPolicy::new("/usr/sbin/nft").block_tcp_flow(table, key) {
                Ok(()) => {
                    let now = Instant::now();
                    self.blocked_ct.insert(
                        key,
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
                        key,
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
