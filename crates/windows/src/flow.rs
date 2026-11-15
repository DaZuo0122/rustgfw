//! WinDivert FLOW events provide local connection lifetimes for WFP offload.
use crate::{Address, Close, Handle, Open, Recv};
use libloading::Library;
use std::{
    ffi::CString,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    ptr,
};

const LAYER_FLOW: u32 = 2;
const FLAG_SNIFF: u64 = 0x0001;
const FLAG_RECV_ONLY: u64 = 0x0004;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowKind {
    Established,
    Deleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEvent {
    pub kind: FlowKind,
    pub endpoint_id: u64,
    pub parent_endpoint_id: u64,
    pub process_id: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: u8,
    pub outbound: bool,
}

fn address_ip(bytes: &[u8]) -> IpAddr {
    let mut octets = [0; 16];
    for index in 0..4 {
        let start = index * 4;
        let word = u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap());
        octets[start..start + 4].copy_from_slice(&word.to_be_bytes());
    }
    let ipv6 = Ipv6Addr::from(octets);
    ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4)
}

fn parse(address: &Address) -> io::Result<FlowEvent> {
    if address.flags & 0xff != LAYER_FLOW {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WinDivert event is not from the FLOW layer",
        ));
    }
    let kind = match (address.flags >> 8) & 0xff {
        1 => FlowKind::Established,
        2 => FlowKind::Deleted,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown WinDivert FLOW event",
            ));
        }
    };
    let data = &address.data;
    Ok(FlowEvent {
        kind,
        endpoint_id: u64::from_ne_bytes(data[..8].try_into().unwrap()),
        parent_endpoint_id: u64::from_ne_bytes(data[8..16].try_into().unwrap()),
        process_id: u32::from_ne_bytes(data[16..20].try_into().unwrap()),
        local: SocketAddr::new(
            address_ip(&data[20..36]),
            u16::from_ne_bytes(data[52..54].try_into().unwrap()),
        ),
        remote: SocketAddr::new(
            address_ip(&data[36..52]),
            u16::from_ne_bytes(data[54..56].try_into().unwrap()),
        ),
        protocol: data[56],
        outbound: address.flags & (1 << 17) != 0,
    })
}

fn open_handle(open: Open) -> io::Result<Handle> {
    let filter = CString::new("true").unwrap();
    // SAFETY: the filter string is live for the synchronous call.
    let handle = unsafe { open(filter.as_ptr(), LAYER_FLOW, 0, FLAG_SNIFF | FLAG_RECV_ONLY) };
    if handle == (-1isize) as Handle {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

/// The FLOW handle must open before the packet handle to observe new flows.
/// WinDivert cannot replay events from before its handle was opened.
pub struct FlowEvents {
    _library: Library,
    handle: Handle,
    recv: Recv,
    close: Close,
}

impl FlowEvents {
    pub fn open(dll: impl AsRef<Path>) -> io::Result<Self> {
        // SAFETY: the caller supplies the DLL; function pointers stay valid
        // while `_library` is retained by this object.
        let library = unsafe { Library::new(dll.as_ref()) }.map_err(io::Error::other)?;
        let (open, recv, close) = unsafe {
            (
                *library
                    .get::<Open>(b"WinDivertOpen\0")
                    .map_err(io::Error::other)?,
                *library
                    .get::<Recv>(b"WinDivertRecv\0")
                    .map_err(io::Error::other)?,
                *library
                    .get::<Close>(b"WinDivertClose\0")
                    .map_err(io::Error::other)?,
            )
        };
        Ok(Self {
            _library: library,
            handle: open_handle(open)?,
            recv,
            close,
        })
    }

    pub(crate) fn raw_handle(&self) -> usize {
        self.handle as usize
    }

    /// Block until an established or deleted event arrives.
    pub fn receive_one(&mut self) -> io::Result<FlowEvent> {
        let mut address = Address::default();
        // SAFETY: FLOW events have no packet payload. The address remains live
        // for the synchronous receive call.
        let received = unsafe {
            (self.recv)(
                self.handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut address,
            )
        };
        if received == 0 {
            return Err(io::Error::last_os_error());
        }
        parse(&address)
    }
}

impl Drop for FlowEvents {
    fn drop(&mut self) {
        // SAFETY: this handle belongs to the loaded WinDivert DLL.
        unsafe { (self.close)(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        ffi::{c_char, c_int, c_void},
        sync::atomic::{AtomicU32, AtomicU64, Ordering},
    };

    static OPEN_LAYER: AtomicU32 = AtomicU32::new(0);
    static OPEN_FLAGS: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn open(_: *const c_char, layer: u32, _: i16, flags: u64) -> Handle {
        OPEN_LAYER.store(layer, Ordering::Relaxed);
        OPEN_FLAGS.store(flags, Ordering::Relaxed);
        1usize as Handle
    }

    struct FakeEvents(VecDeque<Address>);

    unsafe extern "C" fn recv(
        handle: Handle,
        packet: *mut c_void,
        capacity: u32,
        length: *mut u32,
        address: *mut Address,
    ) -> c_int {
        assert!(packet.is_null());
        assert_eq!(capacity, 0);
        assert!(length.is_null());
        // SAFETY: the fixture owns this state and address through the call.
        unsafe { *address = (*handle.cast::<FakeEvents>()).0.pop_front().unwrap() };
        1
    }

    unsafe extern "C" fn close(_: Handle) -> c_int {
        1
    }

    fn put_ip(data: &mut [u8], ip: Ipv6Addr) {
        for (index, chunk) in ip.octets().as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_be_bytes(*chunk);
            data[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
    }

    fn event(kind: FlowKind, local: Ipv6Addr, remote: Ipv6Addr) -> Address {
        let mut address = Address {
            flags: LAYER_FLOW
                | ((match kind {
                    FlowKind::Established => 1,
                    FlowKind::Deleted => 2,
                }) << 8)
                | (1 << 17),
            ..Address::default()
        };
        address.data[..8].copy_from_slice(&42u64.to_ne_bytes());
        address.data[8..16].copy_from_slice(&7u64.to_ne_bytes());
        address.data[16..20].copy_from_slice(&123u32.to_ne_bytes());
        put_ip(&mut address.data[20..36], local);
        put_ip(&mut address.data[36..52], remote);
        address.data[52..54].copy_from_slice(&12345u16.to_ne_bytes());
        address.data[54..56].copy_from_slice(&443u16.to_ne_bytes());
        address.data[56] = 6;
        address
    }

    #[test]
    fn opens_sniff_only_flow_handle_and_reads_lifecycle() {
        assert_eq!(open_handle(open).unwrap(), 1usize as Handle);
        assert_eq!(OPEN_LAYER.load(Ordering::Relaxed), LAYER_FLOW);
        assert_eq!(
            OPEN_FLAGS.load(Ordering::Relaxed),
            FLAG_SNIFF | FLAG_RECV_ONLY
        );
        let local = "::ffff:192.0.2.1".parse().unwrap();
        let remote = "::ffff:198.51.100.2".parse().unwrap();
        let mut state = Box::new(FakeEvents(
            [
                event(FlowKind::Established, local, remote),
                event(FlowKind::Deleted, local, remote),
            ]
            .into(),
        ));
        let mut events = FlowEvents {
            // SAFETY: kernel32 stays loaded while fake functions are used.
            _library: unsafe { Library::new("kernel32.dll") }.unwrap(),
            handle: state.as_mut() as *mut FakeEvents as Handle,
            recv,
            close,
        };
        let established = events.receive_one().unwrap();
        assert_eq!(established.kind, FlowKind::Established);
        assert_eq!(established.endpoint_id, 42);
        assert_eq!(established.parent_endpoint_id, 7);
        assert_eq!(established.process_id, 123);
        assert_eq!(established.local, "192.0.2.1:12345".parse().unwrap());
        assert_eq!(established.remote, "198.51.100.2:443".parse().unwrap());
        assert_eq!(established.protocol, 6);
        assert!(established.outbound);
        assert_eq!(events.receive_one().unwrap().kind, FlowKind::Deleted);
    }

    #[test]
    fn reads_ipv6_and_rejects_other_layers() {
        let mut address = event(
            FlowKind::Established,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        );
        assert_eq!(
            parse(&address).unwrap().local,
            "[2001:db8::1]:12345".parse().unwrap()
        );
        address.flags = 0;
        assert_eq!(
            parse(&address).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
