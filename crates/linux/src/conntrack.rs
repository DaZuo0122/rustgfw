//! Conntrack destroy notifications from NETLINK_NETFILTER.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub struct DestroyEvents {
    fd: OwnedFd,
}

impl DestroyEvents {
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
    pub fn drain(&self, mut on_destroy: impl FnMut(u32) -> io::Result<()>) -> io::Result<()> {
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
                    return Err(io::Error::other("conntrack destroy events lost (ENOBUFS)"));
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
                return Err(io::Error::other("conntrack destroy datagram truncated"));
            }
            for id in parse_destroy_ids(&buffer[..size as usize])? {
                on_destroy(id)?;
            }
        }
    }
}

fn parse_destroy_ids(buffer: &[u8]) -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut pos = 0;
    while pos + 16 <= buffer.len() {
        let len = u32::from_ne_bytes(buffer[pos..pos + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(buffer[pos + 4..pos + 6].try_into().unwrap());
        if len < 16 || pos + len > buffer.len() {
            return Err(io::Error::other("malformed conntrack netlink message"));
        }
        if kind == libc::NLMSG_OVERRUN as u16 {
            return Err(io::Error::other(
                "conntrack destroy events lost (NLMSG_OVERRUN)",
            ));
        }
        if kind == (1 << 8 | 2) {
            if len < 20 {
                return Err(io::Error::other("truncated conntrack destroy message"));
            }
            // NFNL_SUBSYS_CTNETLINK / IPCTNL_MSG_CT_DELETE
            let mut attr = pos + 20; // nlmsghdr + nfgenmsg
            while attr + 4 <= pos + len {
                let alen = u16::from_ne_bytes(buffer[attr..attr + 2].try_into().unwrap()) as usize;
                let ty =
                    u16::from_ne_bytes(buffer[attr + 2..attr + 4].try_into().unwrap()) & 0x3fff;
                if alen < 4 || attr + alen > pos + len {
                    return Err(io::Error::other("malformed conntrack destroy attribute"));
                }
                if ty == 12 && alen == 8 {
                    // CTA_ID, network byte order
                    let id = u32::from_be_bytes(buffer[attr + 4..attr + 8].try_into().unwrap());
                    if id != 0 {
                        ids.push(id);
                    }
                }
                attr += (alen + 3) & !3;
            }
        }
        pos += (len + 3) & !3;
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_destroy_id_and_ignores_other_messages() -> io::Result<()> {
        let mut bytes = vec![0; 28];
        bytes[0..4].copy_from_slice(&28u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&(1u16 << 8 | 2).to_ne_bytes());
        bytes[20..22].copy_from_slice(&8u16.to_ne_bytes());
        bytes[22..24].copy_from_slice(&12u16.to_ne_bytes());
        bytes[24..28].copy_from_slice(&42u32.to_be_bytes());
        assert_eq!(parse_destroy_ids(&bytes)?, vec![42]);
        bytes[4..6].copy_from_slice(&0u16.to_ne_bytes());
        assert!(parse_destroy_ids(&bytes)?.is_empty());
        Ok(())
    }
    #[test]
    fn rejects_event_loss_and_truncated_messages() {
        let mut bytes = vec![0; 16];
        bytes[0..4].copy_from_slice(&16u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&(libc::NLMSG_OVERRUN as u16).to_ne_bytes());
        assert!(parse_destroy_ids(&bytes).is_err());
        bytes[4..6].copy_from_slice(&(1u16 << 8 | 2).to_ne_bytes());
        assert!(parse_destroy_ids(&bytes).is_err());
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
