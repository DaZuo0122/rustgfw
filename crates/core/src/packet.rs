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
    pub payload_offset: usize,
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
        payload_offset: offset + header,
        tcp_flags,
        tcp_sequence: (protocol == Protocol::Tcp)
            .then(|| u32::from_be_bytes(data[4..8].try_into().unwrap())),
    })
}

fn checksum_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let Some(&last) = remainder.first() {
        sum += u32::from(last) << 8;
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Replace one UDP datagram's payload and rebuild the complete IP packet.
/// IPv4 fragments, non-atomic IPv6 fragments, and oversized results are
/// rejected by the same parser and length limits used for inspection.
pub fn replace_udp_payload(bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, ParseError> {
    let transport = parse(bytes)?;
    if transport.protocol != Protocol::Udp {
        return Err(ParseError::Unsupported);
    }
    let udp_start = transport.payload_offset - 8;
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or(ParseError::Malformed)?;
    let total = udp_start
        .checked_add(udp_len)
        .ok_or(ParseError::Malformed)?;
    if udp_len > u16::MAX as usize
        || match bytes[0] >> 4 {
            4 => total > u16::MAX as usize,
            6 => total - 40 > u16::MAX as usize,
            _ => true,
        }
    {
        return Err(ParseError::Malformed);
    }

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&bytes[..transport.payload_offset]);
    output.extend_from_slice(payload);
    output[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    output[udp_start + 6..udp_start + 8].fill(0);

    let pseudo = match bytes[0] >> 4 {
        4 => {
            output[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            output[10..12].fill(0);
            let header_len = usize::from(bytes[0] & 15) * 4;
            let ip_sum = checksum_finish(checksum_add(0, &output[..header_len]));
            output[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            let sum = checksum_add(0, &output[12..20]);
            checksum_add(sum, &[0, 17, (udp_len >> 8) as u8, udp_len as u8])
        }
        6 => {
            output[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
            let sum = checksum_add(0, &output[8..40]);
            checksum_add(sum, &(udp_len as u32).to_be_bytes()) + 17
        }
        _ => unreachable!(), // parse() already checked the IP version.
    };
    let udp_sum = checksum_finish(checksum_add(pseudo, &output[udp_start..]));
    output[udp_start + 6..udp_start + 8]
        .copy_from_slice(&if udp_sum == 0 { 0xffff } else { udp_sum }.to_be_bytes());
    Ok(output)
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

    #[test]
    fn udp_payload_replacement_updates_ipv4_lengths_and_checksums() {
        let original = udp(false);
        let output = replace_udp_payload(&original, b"replacement").unwrap();
        let transport = parse(&output).unwrap();
        assert_eq!(transport.payload, b"replacement");
        assert_eq!(output.len(), usize::from(word(&output, 2)));
        assert_eq!(word(&output, 24), 8 + b"replacement".len() as u16);
        assert_eq!(checksum_finish(checksum_add(0, &output[..20])), 0);
        let pseudo = checksum_add(0, &output[12..20]);
        let pseudo = checksum_add(pseudo, &[0, 17, 0, word(&output, 24) as u8]);
        assert_eq!(checksum_finish(checksum_add(pseudo, &output[20..])), 0);
    }

    #[test]
    fn udp_payload_replacement_preserves_ipv6_extension_and_checksum() {
        let mut original = vec![0; 60];
        original[0] = 0x60;
        original[4..6].copy_from_slice(&20u16.to_be_bytes());
        original[6] = 0; // Hop-by-Hop extension header.
        original[23] = 1;
        original[39] = 2;
        original[40] = 17;
        original[48..50].copy_from_slice(&12345u16.to_be_bytes());
        original[50..52].copy_from_slice(&53u16.to_be_bytes());
        original[52..54].copy_from_slice(&12u16.to_be_bytes());
        original[56..60].copy_from_slice(b"old!");

        let output = replace_udp_payload(&original, b"new payload").unwrap();
        let transport = parse(&output).unwrap();
        assert_eq!(transport.payload, b"new payload");
        assert_eq!(transport.payload_offset, 56);
        assert_eq!(output[40], 17);
        assert_eq!(usize::from(word(&output, 4)) + 40, output.len());
        let pseudo = checksum_add(0, &output[8..40]);
        let pseudo = checksum_add(pseudo, &u32::from(word(&output, 52)).to_be_bytes()) + 17;
        assert_eq!(checksum_finish(checksum_add(pseudo, &output[48..])), 0);
        assert_eq!(
            replace_udp_payload(&original, &vec![0; 65528]),
            Err(ParseError::Malformed)
        );
    }
}
