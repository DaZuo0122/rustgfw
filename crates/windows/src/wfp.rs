//! User-mode WFP management for exact local flows. No callout driver is needed.
use rustgfw_core::{
    KernelPolicy,
    offload::{self, Action},
    packet::Protocol,
    rules::Rule,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    ptr,
};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{IpHelper, Ndis, WindowsFilteringPlatform as wfp},
        System::Rpc::{RPC_C_AUTHN_WINNT, RPC_S_UUID_LOCAL_ONLY, UuidCreate},
    },
    core::GUID,
};

pub struct LocalFlow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: Protocol,
    pub scope: LocalScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalScope {
    Compartment(u32),
    /// LUID of the interface associated with the local IP address.
    InterfaceLuid(u64),
}

impl LocalFlow {
    pub fn on_interface(
        local: SocketAddr,
        remote: SocketAddr,
        protocol: Protocol,
        interface_index: u32,
    ) -> io::Result<Self> {
        let mut luid = Ndis::NET_LUID_LH::default();
        // SAFETY: the API writes one NET_LUID into the live output value.
        let status = unsafe { IpHelper::ConvertInterfaceIndexToLuid(interface_index, &mut luid) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            local,
            remote,
            protocol,
            scope: LocalScope::InterfaceLuid(unsafe { luid.Value }),
        })
    }
}

pub struct FlowBlock {
    filters: [u64; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StaticBlock {
    protocol: Protocol,
    port: Option<u16>,
}

/// Only a leading run of drop rules is safe to enforce before user-space
/// inspection. An accept rule may shadow every later drop rule.
fn static_blocks(rules: &[Rule]) -> Vec<StaticBlock> {
    offload::compile(rules)
        .into_iter()
        .take_while(|rule| rule.action == Action::Drop)
        .map(|rule| StaticBlock {
            protocol: rule.protocol,
            port: rule.port,
        })
        .collect()
}

pub struct WfpPolicy {
    engine: HANDLE,
    sublayer: GUID,
}

fn check(status: u32, operation: &str) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{operation} failed with WFP status 0x{status:08x}"
        )))
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

impl WfpPolicy {
    /// A dynamic BFE session owns every filter and its private sublayer.
    pub fn open() -> io::Result<Self> {
        let mut sublayer = GUID::default();
        // SAFETY: UuidCreate writes one initialized GUID.
        let uuid_status = unsafe { UuidCreate(&mut sublayer) };
        if uuid_status != 0 && uuid_status != RPC_S_UUID_LOCAL_ONLY {
            check(uuid_status as u32, "UuidCreate")?;
        }
        let name = wide("rustgfw dynamic flow blocks");
        let session = wfp::FWPM_SESSION0 {
            flags: wfp::FWPM_SESSION_FLAG_DYNAMIC,
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut engine = ptr::null_mut();
        // SAFETY: session and engine pointers remain valid through the call.
        check(
            unsafe {
                wfp::FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    &session,
                    &mut engine,
                )
            },
            "FwpmEngineOpen0",
        )?;
        let policy = Self { engine, sublayer };
        let layer = wfp::FWPM_SUBLAYER0 {
            subLayerKey: sublayer,
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                ..Default::default()
            },
            weight: 0x8000,
            ..Default::default()
        };
        // SAFETY: BFE copies the sublayer description before returning.
        check(
            unsafe { wfp::FwpmSubLayerAdd0(engine, &layer, ptr::null_mut()) },
            "FwpmSubLayerAdd0",
        )?;
        Ok(policy)
    }

    /// Install provably terminal transport drops in the dynamic session.
    /// The session removes all filters when it closes.
    pub fn install_static(&mut self, rules: &[Rule]) -> io::Result<usize> {
        let blocks = static_blocks(rules);
        if blocks.is_empty() {
            return Ok(0);
        }
        let name = wide("rustgfw static transport block");
        check(
            unsafe { wfp::FwpmTransactionBegin0(self.engine, 0) },
            "FwpmTransactionBegin0",
        )?;
        let result = (|| {
            let mut count = 0;
            for block in blocks {
                let layers = [
                    wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                ];
                let mut conditions = [wfp::FWPM_FILTER_CONDITION0::default(); 2];
                conditions[0].fieldKey = wfp::FWPM_CONDITION_IP_PROTOCOL;
                conditions[0].matchType = wfp::FWP_MATCH_EQUAL;
                conditions[0].conditionValue.r#type = wfp::FWP_UINT8;
                conditions[0].conditionValue.Anonymous.uint8 = match block.protocol {
                    Protocol::Tcp => 6,
                    Protocol::Udp => 17,
                };
                conditions[1].matchType = wfp::FWP_MATCH_EQUAL;
                conditions[1].conditionValue.r#type = wfp::FWP_UINT16;
                if let Some(port) = block.port {
                    conditions[1].conditionValue.Anonymous.uint16 = port;
                }
                let mut filter = wfp::FWPM_FILTER0::default();
                filter.displayData.name = name.as_ptr().cast_mut();
                filter.subLayerKey = self.sublayer;
                filter.action.r#type = wfp::FWP_ACTION_BLOCK;
                filter.filterCondition = conditions.as_mut_ptr();
                let port_fields = [
                    Some(wfp::FWPM_CONDITION_IP_LOCAL_PORT),
                    Some(wfp::FWPM_CONDITION_IP_REMOTE_PORT),
                ];
                let any_port = [None];
                let fields = if block.port.is_some() {
                    &port_fields[..]
                } else {
                    &any_port[..]
                };
                for layer in layers {
                    filter.layerKey = layer;
                    for field in fields {
                        filter.numFilterConditions = if block.port.is_some() { 2 } else { 1 };
                        if let Some(field) = field {
                            conditions[1].fieldKey = *field;
                        }
                        let mut id = 0;
                        check(
                            unsafe {
                                wfp::FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), &mut id)
                            },
                            "FwpmFilterAdd0",
                        )?;
                        count += 1;
                    }
                }
            }
            check(
                unsafe { wfp::FwpmTransactionCommit0(self.engine) },
                "FwpmTransactionCommit0",
            )?;
            Ok(count)
        })();
        if result.is_err() {
            unsafe { wfp::FwpmTransactionAbort0(self.engine) };
        }
        result
    }
}

fn conditions(
    flow: &LocalFlow,
    items: &mut [wfp::FWPM_FILTER_CONDITION0; 6],
    ipv6: &mut [wfp::FWP_BYTE_ARRAY16; 2],
    interface_luid: &mut u64,
) -> io::Result<[GUID; 2]> {
    let layers = match (flow.local.ip(), flow.remote.ip()) {
        (IpAddr::V4(local), IpAddr::V4(remote)) => {
            items[0].conditionValue.r#type = wfp::FWP_UINT32;
            items[0].conditionValue.Anonymous.uint32 = u32::from_be_bytes(local.octets());
            items[1].conditionValue.r#type = wfp::FWP_UINT32;
            items[1].conditionValue.Anonymous.uint32 = u32::from_be_bytes(remote.octets());
            [
                wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            ]
        }
        (IpAddr::V6(local), IpAddr::V6(remote)) => {
            ipv6[0].byteArray16 = local.octets();
            ipv6[1].byteArray16 = remote.octets();
            items[0].conditionValue.r#type = wfp::FWP_BYTE_ARRAY16_TYPE;
            items[0].conditionValue.Anonymous.byteArray16 = &mut ipv6[0];
            items[1].conditionValue.r#type = wfp::FWP_BYTE_ARRAY16_TYPE;
            items[1].conditionValue.Anonymous.byteArray16 = &mut ipv6[1];
            [
                wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ]
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mixed IP families",
            ));
        }
    };
    for item in items.iter_mut() {
        item.matchType = wfp::FWP_MATCH_EQUAL;
    }
    items[0].fieldKey = wfp::FWPM_CONDITION_IP_LOCAL_ADDRESS;
    items[1].fieldKey = wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS;
    items[2].fieldKey = wfp::FWPM_CONDITION_IP_LOCAL_PORT;
    items[2].conditionValue.r#type = wfp::FWP_UINT16;
    items[2].conditionValue.Anonymous.uint16 = flow.local.port();
    items[3].fieldKey = wfp::FWPM_CONDITION_IP_REMOTE_PORT;
    items[3].conditionValue.r#type = wfp::FWP_UINT16;
    items[3].conditionValue.Anonymous.uint16 = flow.remote.port();
    items[4].fieldKey = wfp::FWPM_CONDITION_IP_PROTOCOL;
    items[4].conditionValue.r#type = wfp::FWP_UINT8;
    items[4].conditionValue.Anonymous.uint8 = match flow.protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
    };
    match flow.scope {
        LocalScope::Compartment(id) => {
            items[5].fieldKey = wfp::FWPM_CONDITION_COMPARTMENT_ID;
            items[5].conditionValue.r#type = wfp::FWP_UINT32;
            items[5].conditionValue.Anonymous.uint32 = id;
        }
        LocalScope::InterfaceLuid(luid) => {
            *interface_luid = luid;
            items[5].fieldKey = wfp::FWPM_CONDITION_IP_LOCAL_INTERFACE;
            items[5].conditionValue.r#type = wfp::FWP_UINT64;
            items[5].conditionValue.Anonymous.uint64 = interface_luid;
        }
    }
    Ok(layers)
}

impl KernelPolicy for WfpPolicy {
    type Rule = LocalFlow;
    type Handle = FlowBlock;

    fn install(&mut self, flow: &LocalFlow) -> io::Result<FlowBlock> {
        let mut items = [wfp::FWPM_FILTER_CONDITION0::default(); 6];
        let mut ipv6 = [wfp::FWP_BYTE_ARRAY16::default(); 2];
        let mut interface_luid = 0;
        let layers = conditions(flow, &mut items, &mut ipv6, &mut interface_luid)?;
        let name = wide("rustgfw blocked flow");
        let mut filter = wfp::FWPM_FILTER0::default();
        filter.displayData.name = name.as_ptr().cast_mut();
        filter.subLayerKey = self.sublayer;
        filter.numFilterConditions = items.len() as u32;
        filter.filterCondition = items.as_mut_ptr();
        filter.action.r#type = wfp::FWP_ACTION_BLOCK;
        // SAFETY: the engine session remains open and BFE copies filter data.
        check(
            unsafe { wfp::FwpmTransactionBegin0(self.engine, 0) },
            "FwpmTransactionBegin0",
        )?;
        let mut ids = [0; 2];
        let result = (|| {
            for (index, layer) in layers.into_iter().enumerate() {
                filter.layerKey = layer;
                check(
                    unsafe {
                        wfp::FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), &mut ids[index])
                    },
                    "FwpmFilterAdd0",
                )?;
            }
            check(
                unsafe { wfp::FwpmTransactionCommit0(self.engine) },
                "FwpmTransactionCommit0",
            )
        })();
        if result.is_err() {
            unsafe { wfp::FwpmTransactionAbort0(self.engine) };
        }
        result?;
        Ok(FlowBlock { filters: ids })
    }

    fn revoke(&mut self, block: &FlowBlock) -> io::Result<()> {
        check(
            unsafe { wfp::FwpmTransactionBegin0(self.engine, 0) },
            "FwpmTransactionBegin0",
        )?;
        let result = (|| {
            for id in block.filters {
                check(
                    unsafe { wfp::FwpmFilterDeleteById0(self.engine, id) },
                    "FwpmFilterDeleteById0",
                )?;
            }
            check(
                unsafe { wfp::FwpmTransactionCommit0(self.engine) },
                "FwpmTransactionCommit0",
            )
        })();
        if result.is_err() {
            unsafe { wfp::FwpmTransactionAbort0(self.engine) };
        }
        result
    }
}

impl Drop for WfpPolicy {
    fn drop(&mut self) {
        // SAFETY: this handle came from FwpmEngineOpen0 and is still open.
        unsafe { wfp::FwpmEngineClose0(self.engine) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustgfw_core::Verdict;

    #[test]
    fn static_offload_stops_at_first_accept_rule() {
        let rules = [
            Rule {
                protocol: Some(Protocol::Tcp),
                port: Some(443),
                verdict: Verdict::Drop,
            },
            Rule {
                protocol: None,
                port: Some(53),
                verdict: Verdict::Drop,
            },
            Rule {
                protocol: None,
                port: None,
                verdict: Verdict::Accept,
            },
            Rule {
                protocol: Some(Protocol::Udp),
                port: Some(500),
                verdict: Verdict::Drop,
            },
        ];
        assert_eq!(
            static_blocks(&rules),
            [
                StaticBlock {
                    protocol: Protocol::Tcp,
                    port: Some(443),
                },
                StaticBlock {
                    protocol: Protocol::Tcp,
                    port: Some(53),
                },
                StaticBlock {
                    protocol: Protocol::Udp,
                    port: Some(53),
                },
            ]
        );
    }

    fn same_guid(a: GUID, b: GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    #[test]
    fn exact_ipv4_flow_uses_host_order_values() {
        let flow = LocalFlow {
            local: "192.0.2.1:1234".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            scope: LocalScope::Compartment(7),
        };
        let mut items = [wfp::FWPM_FILTER_CONDITION0::default(); 6];
        let mut ipv6 = [wfp::FWP_BYTE_ARRAY16::default(); 2];
        let mut interface_luid = 0;
        let layers = conditions(&flow, &mut items, &mut ipv6, &mut interface_luid).unwrap();
        assert!(same_guid(layers[0], wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4));
        assert!(same_guid(
            layers[1],
            wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        ));
        // SAFETY: the selected condition variants are FWP_UINT32/UINT16/UINT8.
        unsafe {
            assert_eq!(items[0].conditionValue.Anonymous.uint32, 0xc000_0201);
            assert_eq!(items[1].conditionValue.Anonymous.uint32, 0xc633_6402);
            assert_eq!(items[2].conditionValue.Anonymous.uint16, 1234);
            assert_eq!(items[3].conditionValue.Anonymous.uint16, 443);
            assert_eq!(items[4].conditionValue.Anonymous.uint8, 6);
            assert_eq!(items[5].conditionValue.Anonymous.uint32, 7);
        }
        assert!(same_guid(
            items[5].fieldKey,
            wfp::FWPM_CONDITION_COMPARTMENT_ID
        ));
        assert_eq!(items[5].conditionValue.r#type, wfp::FWP_UINT32);
    }

    #[test]
    fn exact_ipv6_flow_keeps_address_bytes() {
        let flow = LocalFlow {
            local: "[2001:db8::1]:1234".parse().unwrap(),
            remote: "[2001:db8::2]:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            scope: LocalScope::Compartment(9),
        };
        let mut items = [wfp::FWPM_FILTER_CONDITION0::default(); 6];
        let mut ipv6 = [wfp::FWP_BYTE_ARRAY16::default(); 2];
        let mut interface_luid = 0;
        let layers = conditions(&flow, &mut items, &mut ipv6, &mut interface_luid).unwrap();
        assert!(same_guid(layers[0], wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6));
        assert!(same_guid(
            layers[1],
            wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        ));
        assert_eq!(
            ipv6[0].byteArray16,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(
            ipv6[1].byteArray16,
            "2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert!(same_guid(
            items[5].fieldKey,
            wfp::FWPM_CONDITION_COMPARTMENT_ID
        ));
        unsafe { assert_eq!(items[5].conditionValue.Anonymous.uint32, 9) };
    }

    #[test]
    fn exact_flow_can_use_local_interface_luid() {
        let flow = LocalFlow {
            local: "192.0.2.1:1234".parse().unwrap(),
            remote: "198.51.100.2:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            scope: LocalScope::InterfaceLuid(0x1234_5678_9abc_def0),
        };
        let mut items = [wfp::FWPM_FILTER_CONDITION0::default(); 6];
        let mut ipv6 = [wfp::FWP_BYTE_ARRAY16::default(); 2];
        let mut interface_luid = 0;
        conditions(&flow, &mut items, &mut ipv6, &mut interface_luid).unwrap();
        assert!(same_guid(
            items[5].fieldKey,
            wfp::FWPM_CONDITION_IP_LOCAL_INTERFACE
        ));
        assert_eq!(items[5].conditionValue.r#type, wfp::FWP_UINT64);
        assert_eq!(interface_luid, 0x1234_5678_9abc_def0);
        unsafe {
            assert_eq!(*items[5].conditionValue.Anonymous.uint64, interface_luid);
        }
    }
}
