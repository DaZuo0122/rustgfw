//! The request at the start of a sing-mux logical stream.
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::inspect::Observation;

const MAX_REQUEST: usize = 261;

#[derive(Debug)]
pub struct InvalidStreamRequest;

#[derive(Clone)]
pub struct StreamTarget {
    pub network: &'static str,
    pub host: String,
    pub port: u16,
}

impl StreamTarget {
    pub fn observations(&self) -> Vec<Observation> {
        vec![
            Observation {
                field: "sing_mux.network",
                value: self.network.into(),
            },
            Observation {
                field: "sing_mux.host",
                value: self.host.clone(),
            },
            Observation {
                field: "sing_mux.port",
                value: self.port.to_string(),
            },
        ]
    }
}

#[derive(Default)]
pub struct StreamRequest {
    bytes: Vec<u8>,
    target: Option<StreamTarget>,
}

impl StreamRequest {
    pub fn target(&self) -> Option<&StreamTarget> {
        self.target.as_ref()
    }

    /// Returns the target exactly once, when enough stream bytes have arrived.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Option<StreamTarget>, InvalidStreamRequest> {
        if self.target.is_some() {
            return Ok(None);
        }
        let remaining = MAX_REQUEST.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        let Some(target) = parse(&self.bytes)? else {
            return Ok(None);
        };
        self.target = Some(target.clone());
        self.bytes.clear();
        Ok(Some(target))
    }
}

fn parse(bytes: &[u8]) -> Result<Option<StreamTarget>, InvalidStreamRequest> {
    if bytes.len() < 3 {
        return Ok(None);
    }
    let flags = u16::from_be_bytes([bytes[0], bytes[1]]);
    let (host, end) = match bytes[2] {
        1 if bytes.len() >= 7 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[3..7]).unwrap()).to_string(),
            7,
        ),
        4 if bytes.len() >= 19 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[3..19]).unwrap()).to_string(),
            19,
        ),
        3 if bytes.len() >= 4 && bytes.len() >= 4 + bytes[3] as usize => {
            let end = 4 + bytes[3] as usize;
            (String::from_utf8_lossy(&bytes[4..end]).into_owned(), end)
        }
        1 | 3 | 4 => return Ok(None),
        _ => return Err(InvalidStreamRequest),
    };
    if bytes.len() < end + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
    Ok(Some(StreamTarget {
        network: if flags & 1 == 0 { "tcp" } else { "udp" },
        host,
        port,
    }))
}
