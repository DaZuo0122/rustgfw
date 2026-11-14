//! Borrowed IP transport views. Fragment reassembly belongs before this parser.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    Fragment,
    Unsupported,
}

#[derive(Debug)]
pub struct Transport<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: Protocol,
    pub payload: &'a [u8],
    pub tcp_flags: u8,
    pub tcp_sequence: Option<u32>,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub fn parse(bytes: &[u8]) -> Result<Transport<'_>, ParseError> {
    use ParseError::*;
    let (source, destination, mut next, mut offset, end) = match bytes.first().map(|b| b >> 4) {
        Some(4) => {
            if bytes.len() < 20 {
                return Err(Malformed);
            }
            let offset = usize::from(bytes[0] & 15) * 4;
            let end = usize::from(word(bytes, 2));
            if offset < 20 || end < offset || end > bytes.len() {
                return Err(Malformed);
            }
            if word(bytes, 6) & 0x3fff != 0 {
                return Err(Fragment);
            }
            (
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                bytes[9],
                offset,
                end,
            )
        }
        Some(6) => {
            if bytes.len() < 40 {
                return Err(Malformed);
            }
            let end = 40 + usize::from(word(bytes, 4));
            if end > bytes.len() {
                return Err(Malformed);
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap())),
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&bytes[24..40]).unwrap(),
                )),
                bytes[6],
                40,
                end,
            )
        }
        _ => return Err(Malformed),
    };
    if bytes[0] >> 4 == 6 {
        loop {
            let length = match next {
                0 | 43 | 60 | 51 => {
                    if offset + 2 > end {
                        return Err(Malformed);
                    }
                    if next == 51 {
                        (usize::from(bytes[offset + 1]) + 2) * 4
                    } else {
                        (usize::from(bytes[offset + 1]) + 1) * 8
                    }
                }
                44 => {
                    if offset + 8 > end {
                        return Err(Malformed);
                    }
                    if word(bytes, offset + 2) & 0xfff9 != 0 {
                        return Err(Fragment);
                    }
                    8 // Atomic IPv6 fragment.
                }
                _ => break,
            };
            if offset + length > end {
                return Err(Malformed);
            }
            next = bytes[offset];
            offset += length;
        }
    }
    let data = &bytes[offset..end];
    let (protocol, header, length, tcp_flags) = match next {
        6 => {
            if data.len() < 20 {
                return Err(Malformed);
            }
            let header = usize::from(data[12] >> 4) * 4;
            if header < 20 || header > data.len() {
                return Err(Malformed);
            }
            (Protocol::Tcp, header, data.len(), data[13])
        }
        17 => {
            if data.len() < 8 {
                return Err(Malformed);
            }
            let length = usize::from(word(data, 4));
            if length < 8 || length > data.len() {
                return Err(Malformed);
            }
            (Protocol::Udp, 8, length, 0)
        }
        _ => return Err(Unsupported),
    };
    Ok(Transport {
        source: SocketAddr::new(source, word(data, 0)),
        destination: SocketAddr::new(destination, word(data, 2)),
        protocol,
        payload: &data[header..length],
        tcp_flags,
        tcp_sequence: (protocol == Protocol::Tcp)
            .then(|| u32::from_be_bytes(data[4..8].try_into().unwrap())),
    })
}

#[cfg(test)]
pub(crate) fn udp(reverse: bool) -> Vec<u8> {
    let mut p = vec![0; 31];
    p[0] = 0x45;
    p[3] = 31;
    p[9] = 17;
    p[12] = 10;
    p[16] = 20;
    p[20..22].copy_from_slice(&12345u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[25] = 11;
    p[28..].copy_from_slice(b"dns");
    if reverse {
        p.swap(12, 16);
        p.swap(20, 22);
        p.swap(21, 23);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lengths_fragments_and_payload() {
        let mut p = udp(false);
        assert_eq!(parse(&p).unwrap().payload, b"dns");
        for len in 0..p.len() {
            assert!(parse(&p[..len]).is_err());
        }
        p[6] = 0x20;
        assert_eq!(parse(&p).unwrap_err(), ParseError::Fragment);
        p[6] = 0;
        p[25] = 7;
        assert_eq!(parse(&p).unwrap_err(), ParseError::Malformed);
    }
    #[test]
    fn ipv6_extension_header() {
        let mut p = vec![0; 56];
        p[0] = 0x60;
        p[5] = 16;
        p[6] = 0;
        p[40] = 17;
        p[53] = 8;
        assert_eq!(parse(&p).unwrap().protocol, Protocol::Udp);
        p[41] = 2;
        assert_eq!(parse(&p).unwrap_err(), ParseError::Malformed);
    }
}
