//! Conntrack destroy notifications from NETLINK_NETFILTER.
use std::{
    error::Error,
    fmt, io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

#[derive(Debug)]
pub(crate) struct EventsLost;

impl fmt::Display for EventsLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("conntrack destroy events lost")
    }
}

impl Error for EventsLost {}

pub(crate) fn events_lost(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<EventsLost>())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConntrackKey {
    pub id: u32,
    pub zone: nfq::ConntrackZone,
}

impl ConntrackKey {
    pub fn scope(self) -> rustgfw_core::FlowScope {
        let direction = match self.zone.direction {
            nfq::ZoneDirection::Both => 0,
            nfq::ZoneDirection::Original => 1,
            nfq::ZoneDirection::Reply => 2,
        };
        rustgfw_core::FlowScope(
            1 + u128::from(self.zone.id) + (direction << 16) + (u128::from(self.id) << 32),
        )
    }
}

pub struct DestroyEvents {
    fd: OwnedFd,
}

impl DestroyEvents {
    #[cfg(test)]
    pub(crate) fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn open() -> io::Result<Self> {
        // SAFETY: libc socket/bind arguments are initialized and the returned fd is owned.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zero is a valid sockaddr_nl baseline, including its padding.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 1 << (3 - 1); // NFNLGRP_CONNTRACK_DESTROY
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
    pub fn drain(
        &self,
        mut on_destroy: impl FnMut(ConntrackKey) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; 65536];
        loop {
            let size = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if size < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOBUFS) {
                    return Err(io::Error::other(EventsLost));
                }
                return match error.kind() {
                    io::ErrorKind::WouldBlock => Ok(()),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(error),
                };
            }
            if size == 0 {
                return Ok(());
            }
            if size as usize > buffer.len() {
                return Err(io::Error::other(EventsLost));
            }
            // A malformed datagram can hide a destroy notification. Treat it
            // like a receive overrun so stale kernel ID blocks are cleared.
            for key in parse_destroy_keys(&buffer[..size as usize])
                .map_err(|_| io::Error::other(EventsLost))?
            {
                on_destroy(key)?;
            }
        }
    }
}

fn parse_attrs(
    data: &[u8],
    mut on_attr: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut attr = 0;
    while attr + 4 <= data.len() {
        let len = u16::from_ne_bytes(data[attr..attr + 2].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(data[attr + 2..attr + 4].try_into().unwrap()) & 0x3fff;
        if len < 4 || attr + len > data.len() {
            return Err(io::Error::other("malformed conntrack netlink attribute"));
        }
        on_attr(ty, &data[attr + 4..attr + len])?;
        attr += (len + 3) & !3;
    }
    Ok(())
}

fn parse_destroy_keys(buffer: &[u8]) -> io::Result<Vec<ConntrackKey>> {
    let mut keys = Vec::new();
    let mut pos = 0;
    while pos + 16 <= buffer.len() {
        let len = u32::from_ne_bytes(buffer[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buffer[pos + 4..pos + 6].try_into().unwrap());
        if len < 16 || pos + len > buffer.len() {
            return Err(io::Error::other("malformed conntrack netlink message"));
        }
        if kind == libc::NLMSG_OVERRUN as u16 {
            return Err(io::Error::other(EventsLost));
        }
        if kind == (1 << 8 | 2) {
            if len < 20 {
                return Err(io::Error::other("truncated conntrack destroy message"));
            }
            // NFNL_SUBSYS_CTNETLINK / IPCTNL_MSG_CT_DELETE
            let mut id = 0;
            let mut zone = nfq::ConntrackZone::default();
            parse_attrs(&buffer[pos + 20..pos + len], |ty, value| {
                match ty {
                    12 if value.len() == 4 => id = u32::from_be_bytes(value.try_into().unwrap()),
                    18 if value.len() == 2 => {
                        zone = nfq::ConntrackZone {
                            id: u16::from_be_bytes(value.try_into().unwrap()),
                            direction: nfq::ZoneDirection::Both,
                        }
                    }
                    1 | 2 => parse_attrs(value, |nested, value| {
                        if nested == 3 && value.len() == 2 {
                            zone = nfq::ConntrackZone {
                                id: u16::from_be_bytes(value.try_into().unwrap()),
                                direction: if ty == 1 {
                                    nfq::ZoneDirection::Original
                                } else {
                                    nfq::ZoneDirection::Reply
                                },
                            };
                        }
                        Ok(())
                    })?,
                    _ => {}
                }
                Ok(())
            })?;
            if id != 0 {
                keys.push(ConntrackKey { id, zone });
            }
        }
        pos += (len + 3) & !3;
    }
    if pos < buffer.len() {
        return Err(io::Error::other("truncated conntrack netlink header"));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgfw_core::{Packet, Policy, Verdict, inspect::Inspect, rules::Rules};
    use std::os::unix::net::UnixDatagram;
    fn attr(ty: u16, value: &[u8]) -> Vec<u8> {
        let len = (value.len() + 4) as u16;
        let mut bytes = Vec::from(len.to_ne_bytes());
        bytes.extend_from_slice(&ty.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }
    fn destroy(attrs: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes.extend_from_slice(attrs);
        let len = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&len.to_ne_bytes());
        bytes[4..6].copy_from_slice(&(1u16 << 8 | 2).to_ne_bytes());
        bytes
    }
    #[test]
    fn parses_destroy_id_and_zone() -> io::Result<()> {
        let id = attr(12, &42u32.to_be_bytes());
        let mut bytes = destroy(&id);
        assert_eq!(
            parse_destroy_keys(&bytes)?,
            vec![ConntrackKey {
                id: 42,
                zone: nfq::ConntrackZone::default(),
            }]
        );
        let zone = attr(18, &7u16.to_be_bytes());
        bytes = destroy(&[id.clone(), zone].concat());
        assert_eq!(
            parse_destroy_keys(&bytes)?,
            vec![ConntrackKey {
                id: 42,
                zone: nfq::ConntrackZone {
                    id: 7,
                    direction: nfq::ZoneDirection::Both
                },
            }]
        );
        let tuple_zone = attr(3, &8u16.to_be_bytes());
        bytes = destroy(&[id, attr(2, &tuple_zone)].concat());
        assert_eq!(
            parse_destroy_keys(&bytes)?,
            vec![ConntrackKey {
                id: 42,
                zone: nfq::ConntrackZone {
                    id: 8,
                    direction: nfq::ZoneDirection::Reply
                },
            }]
        );
        assert_ne!(
            ConntrackKey {
                id: 42,
                zone: nfq::ConntrackZone::default()
            }
            .scope(),
            ConntrackKey {
                id: 42,
                zone: nfq::ConntrackZone {
                    id: 8,
                    direction: nfq::ZoneDirection::Reply
                }
            }
            .scope()
        );
        bytes[4..6].copy_from_slice(&0u16.to_ne_bytes());
        assert!(parse_destroy_keys(&bytes)?.is_empty());
        Ok(())
    }
    #[test]
    fn rejects_event_loss_and_truncated_messages() {
        let mut bytes = vec![0; 16];
        bytes[0..4].copy_from_slice(&16u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&(libc::NLMSG_OVERRUN as u16).to_ne_bytes());
        assert!(events_lost(&parse_destroy_keys(&bytes).unwrap_err()));
        bytes[4..6].copy_from_slice(&(1u16 << 8 | 2).to_ne_bytes());
        assert!(parse_destroy_keys(&bytes).is_err());
        assert!(parse_destroy_keys(&bytes[..3]).is_err());
    }
    #[test]
    fn equal_tuples_with_distinct_conntrack_ids_keep_separate_inspection() {
        let mut policy = Inspect::http_hosts(
            Rules::new(vec![], Verdict::Accept),
            vec!["blocked.test".into()],
        );
        let mut bytes = vec![0; 40 + b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n".len()];
        let length = bytes.len() as u16;
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..22].copy_from_slice(&12345u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&80u16.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = 0x18;
        bytes[40..].copy_from_slice(b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n");
        let zone = nfq::ConntrackZone {
            id: 8,
            direction: nfq::ZoneDirection::Reply,
        };
        let evaluate = |policy: &mut Inspect<Rules>, bytes: &[u8], id| {
            policy.evaluate(Packet {
                bytes,
                original_len: bytes.len(),
                checksum_ready: true,
                scope: ConntrackKey { id, zone }.scope(),
            })
        };
        assert_eq!(evaluate(&mut policy, &bytes, 42), Verdict::DropFlow);
        bytes[40..].copy_from_slice(b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
        assert_eq!(evaluate(&mut policy, &bytes, 43), Verdict::Accept);
    }
    #[test]
    fn malformed_and_truncated_event_datagrams_report_lost_lifecycle() -> io::Result<()> {
        let (sender, receiver) = UnixDatagram::pair()?;
        let events = DestroyEvents::from_fd(receiver.into());
        sender.send(&[0; 16])?;
        assert!(events_lost(&events.drain(|_| Ok(())).unwrap_err()));
        sender.send(&vec![0; 65537])?;
        assert!(events_lost(&events.drain(|_| Ok(())).unwrap_err()));
        Ok(())
    }
    #[test]
    #[ignore = "requires netfilter permissions in an isolated network namespace"]
    fn opens_destroy_subscription() -> io::Result<()> {
        DestroyEvents::open().map(|_| ())
    }
    #[test]
    #[ignore = "runs a real 40-second conntrack expiry in an isolated network namespace"]
    fn observes_udp_destroy() -> io::Result<()> {
        use rustgfw_core::KernelPolicy;
        use std::{
            net::UdpSocket,
            time::{Duration, Instant},
        };
        let events = DestroyEvents::open()?;
        let mut nft = crate::nft::NftPolicy::new("/usr/sbin/nft");
        let handle = nft.install(&crate::nft::Plan {
            hook: crate::nft::Hook::Output,
            queue: 100,
            dynamic: crate::nft::DynamicOffload::IdSet,
            rules: vec![],
            bypass_without_listener: true,
        })?;
        let result = (|| {
            let receiver = UdpSocket::bind("127.0.0.1:0")?;
            let sender = UdpSocket::bind("127.0.0.1:0")?;
            sender.send_to(b"destroy-event", receiver.local_addr()?)?;
            let mut data = [0; 32];
            receiver.recv_from(&mut data)?;
            drop(sender);
            drop(receiver);
            let deadline = Instant::now() + Duration::from_secs(40);
            let mut ids = Vec::new();
            while Instant::now() < deadline && ids.is_empty() {
                events.drain(|id| {
                    ids.push(id);
                    Ok(())
                })?;
                std::thread::sleep(Duration::from_millis(100));
            }
            if ids.is_empty() {
                return Err(io::Error::other(
                    "no conntrack destroy event before timeout",
                ));
            }
            Ok::<_, io::Error>(())
        })();
        nft.revoke(&handle)?;
        result
    }
}
