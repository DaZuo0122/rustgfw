//! WinDivert packet I/O. Captured addresses are kept intact for reinjection.
#![cfg(target_os = "windows")]

use libloading::Library;
use rustgfw_core::{
    Packet, PacketIo, Policy, Verdict,
    offload::{self, Action},
    packet::Protocol,
    rules::Rule,
};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    io,
    path::Path,
};
pub mod wfp;

const PACKET_CAPACITY: usize = 40 + 65535; // WINDIVERT_MTU_MAX
const FLAG_DROP: u64 = 0x0002;

/// A higher-priority WinDivert DROP handle can enforce these rules without
/// sending the matching forwarded packets through the user-space loop.
pub fn static_drop_filter(rules: &[Rule]) -> Option<String> {
    let clauses = offload::compile(rules)
        .into_iter()
        .take_while(|rule| rule.action == Action::Drop)
        .map(|rule| {
            let protocol = match rule.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            match rule.port {
                Some(port) => format!(
                    "({protocol} and ({protocol}.SrcPort == {port} or {protocol}.DstPort == {port}))"
                ),
                None => protocol.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    (!clauses.is_empty()).then(|| clauses.join(" or "))
}

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum Layer {
    Network = 0,
    Forward = 1,
}

// WinDivert 2.2 WINDIVERT_ADDRESS. The bitfields are opaque: the exact bytes
// returned by Recv are passed back to Send, including direction and interface.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}
impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}
const _: () = assert!(std::mem::size_of::<Address>() == 80);

type Handle = *mut c_void;
type Open = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> Handle;
type Recv = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> c_int;
type Send = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> c_int;
type Close = unsafe extern "C" fn(Handle) -> c_int;

pub struct WinDivert {
    _library: Library,
    handle: Handle,
    drop_handle: Option<Handle>,
    layer: Layer,
    open: Open,
    recv: Recv,
    send: Send,
    close: Close,
    packet: Vec<u8>,
}
impl WinDivert {
    /// The DLL and matching signed driver must be deployed together.
    pub fn open(dll: impl AsRef<Path>, layer: Layer, filter: &str) -> io::Result<Self> {
        let filter =
            CString::new(filter).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: the DLL path is explicitly supplied by the caller. The
        // copied function pointers remain valid while `_library` is held.
        let library = unsafe { Library::new(dll.as_ref()) }.map_err(io::Error::other)?;
        let (open, recv, send, close) = unsafe {
            (
                *library
                    .get::<Open>(b"WinDivertOpen\0")
                    .map_err(io::Error::other)?,
                *library
                    .get::<Recv>(b"WinDivertRecv\0")
                    .map_err(io::Error::other)?,
                *library
                    .get::<Send>(b"WinDivertSend\0")
                    .map_err(io::Error::other)?,
                *library
                    .get::<Close>(b"WinDivertClose\0")
                    .map_err(io::Error::other)?,
            )
        };
        // SAFETY: the function signature follows WinDivert 2.2; the CString
        // and DLL remain live for the call.
        let handle = unsafe { open(filter.as_ptr(), layer as u32, 0, 0) };
        if handle == (-1isize) as Handle {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _library: library,
            handle,
            drop_handle: None,
            layer,
            open,
            recv,
            send,
            close,
            packet: vec![0; PACKET_CAPACITY],
        })
    }

    /// Apply a static filter at priority 1, before the packet handle at 0.
    pub fn install_drop_filter(&mut self, filter: &str) -> io::Result<()> {
        let filter =
            CString::new(filter).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: the DLL and filter string are live through the call.
        let handle = unsafe { (self.open)(filter.as_ptr(), self.layer as u32, 1, FLAG_DROP) };
        if handle == (-1isize) as Handle {
            return Err(io::Error::last_os_error());
        }
        if let Some(old) = self.drop_handle.replace(handle) {
            unsafe { (self.close)(old) };
        }
        Ok(())
    }
}
impl PacketIo for WinDivert {
    fn process_one(&mut self, policy: &mut dyn Policy) -> io::Result<()> {
        let mut address = Address::default();
        let mut length = 0u32;
        // SAFETY: the packet and address buffers outlive the synchronous call.
        let received = unsafe {
            (self.recv)(
                self.handle,
                self.packet.as_mut_ptr().cast(),
                self.packet.len() as u32,
                &mut length,
                &mut address,
            )
        };
        if received == 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = &self.packet[..length as usize];
        let verdict = policy.evaluate(Packet {
            bytes,
            original_len: bytes.len(),
            checksum_ready: false,
        });
        if verdict != Verdict::Accept {
            return Ok(());
        }
        let mut sent = 0u32;
        // SAFETY: the captured packet and address remain unchanged and live
        // through Send; WinDivert uses the address to preserve direction.
        let result = unsafe {
            (self.send)(
                self.handle,
                bytes.as_ptr().cast(),
                length,
                &mut sent,
                &address,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if sent != length {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "WinDivertSend reinjected only part of the packet",
            ));
        }
        Ok(())
    }
}
impl Drop for WinDivert {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by WinDivertOpen and the DLL is
        // still loaded while Drop runs.
        unsafe {
            if let Some(handle) = self.drop_handle.take() {
                (self.close)(handle);
            }
            (self.close)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgfw_core::{
        ConstantPolicy,
        inspect::{HttpHost, Inspect},
        rules::Rules,
    };
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicI16, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };

    static OPEN_LAYER: AtomicU32 = AtomicU32::new(u32::MAX);
    static OPEN_PRIORITY: AtomicI16 = AtomicI16::new(i16::MIN);
    static OPEN_FLAGS: AtomicU64 = AtomicU64::new(0);
    static CLOSED_DROP: AtomicUsize = AtomicUsize::new(0);

    struct FakeIo {
        received: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        address_preserved: bool,
    }

    unsafe extern "C" fn receive(
        handle: Handle,
        packet: *mut c_void,
        capacity: u32,
        length: *mut u32,
        address: *mut Address,
    ) -> c_int {
        // SAFETY: the test owns the state and receive buffers through this call.
        unsafe {
            let state = &mut *handle.cast::<FakeIo>();
            let next = state.received.pop_front().unwrap();
            assert!(next.len() <= capacity as usize);
            std::ptr::copy_nonoverlapping(next.as_ptr(), packet.cast::<u8>(), next.len());
            *length = next.len() as u32;
            (*address).flags = 0x1234_5678;
            (*address).data[0] = 9;
        }
        1
    }

    unsafe extern "C" fn send(
        handle: Handle,
        packet: *const c_void,
        length: u32,
        sent: *mut u32,
        address: *const Address,
    ) -> c_int {
        // SAFETY: the test owns the state and captured packet through this call.
        unsafe {
            let state = &mut *handle.cast::<FakeIo>();
            state.address_preserved &= (*address).flags == 0x1234_5678 && (*address).data[0] == 9;
            state
                .sent
                .push(std::slice::from_raw_parts(packet.cast::<u8>(), length as usize).to_vec());
            *sent = length;
        }
        1
    }

    unsafe extern "C" fn close(handle: Handle) -> c_int {
        if handle == 2usize as Handle {
            CLOSED_DROP.fetch_add(1, Ordering::Relaxed);
        }
        1
    }

    unsafe extern "C" fn open(_: *const c_char, layer: u32, priority: i16, flags: u64) -> Handle {
        OPEN_LAYER.store(layer, Ordering::Relaxed);
        OPEN_PRIORITY.store(priority, Ordering::Relaxed);
        OPEN_FLAGS.store(flags, Ordering::Relaxed);
        2usize as Handle
    }

    fn fixture(received: Vec<Vec<u8>>) -> (WinDivert, Box<FakeIo>) {
        let mut state = Box::new(FakeIo {
            received: received.into(),
            sent: Vec::new(),
            address_preserved: true,
        });
        let io = WinDivert {
            // SAFETY: kernel32 stays loaded while the fake symbols are used.
            _library: unsafe { Library::new("kernel32.dll") }.unwrap(),
            handle: state.as_mut() as *mut FakeIo as Handle,
            drop_handle: None,
            layer: Layer::Network,
            open,
            recv: receive,
            send,
            close,
            packet: vec![0; PACKET_CAPACITY],
        };
        (io, state)
    }

    fn tcp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        let length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn address_layout_matches_windivert_2_2() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert_eq!(std::mem::align_of::<Address>(), 8);
    }

    #[test]
    fn drop_filter_stops_at_accept_barrier() {
        let rules = [
            Rule {
                protocol: Some(Protocol::Tcp),
                port: Some(443),
                verdict: Verdict::Drop,
            },
            Rule {
                protocol: Some(Protocol::Udp),
                port: Some(53),
                verdict: Verdict::Accept,
            },
            Rule {
                protocol: Some(Protocol::Udp),
                port: Some(500),
                verdict: Verdict::Drop,
            },
        ];
        assert_eq!(
            static_drop_filter(&rules).as_deref(),
            Some("(tcp and (tcp.SrcPort == 443 or tcp.DstPort == 443))")
        );
    }

    #[test]
    fn forward_drop_handle_uses_higher_priority_and_closes() {
        let (mut io, _state) = fixture(vec![]);
        io.layer = Layer::Forward;
        CLOSED_DROP.store(0, Ordering::Relaxed);
        io.install_drop_filter("tcp").unwrap();
        assert_eq!(OPEN_LAYER.load(Ordering::Relaxed), Layer::Forward as u32);
        assert_eq!(OPEN_PRIORITY.load(Ordering::Relaxed), 1);
        assert_eq!(OPEN_FLAGS.load(Ordering::Relaxed), FLAG_DROP);
        drop(io);
        assert_eq!(CLOSED_DROP.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn accepts_by_reinjecting_packet_with_its_address() {
        let packet = [0x45, 1, 2, 3].to_vec();
        let (mut io, state) = fixture(vec![packet.clone(), packet.clone()]);
        io.process_one(&mut ConstantPolicy(Verdict::Accept))
            .unwrap();
        io.process_one(&mut ConstantPolicy(Verdict::Drop)).unwrap();
        assert_eq!(state.sent, [packet]);
        assert!(state.address_preserved);
        drop(io);
    }

    #[test]
    fn http_match_drops_both_directions_without_reinjection() {
        let allowed = tcp_packet(12345, 80, b"GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n");
        let blocked = tcp_packet(12346, 80, b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n");
        let mut reply = tcp_packet(80, 12346, b"HTTP/1.1 200 OK\r\n\r\n");
        reply[12..16].copy_from_slice(&[198, 51, 100, 2]);
        reply[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let (mut io, state) = fixture(vec![allowed.clone(), blocked, reply]);
        let mut policy = Inspect::new(
            Rules::new(vec![], Verdict::Accept),
            vec!["blocked.test".into()],
            || Box::<HttpHost>::default(),
        );
        for _ in 0..3 {
            io.process_one(&mut policy).unwrap();
        }
        assert_eq!(state.sent, [allowed]);
        assert!(state.address_preserved);
        drop(io);
    }
}
