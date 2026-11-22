//! Structural observations from an unprotected VLESS v0 TCP request header.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const FIELDS: &[&str] = &[
    "vless.candidate",
    "vless.command",
    "vless.target_type",
    "vless.target_host",
    "vless.target_port",
    "vless.addons_length",
];

// Version, UUID, addons length and bytes, command, port, address type and domain.
const MAX_HEADER_BYTES: usize = 1 + 16 + 1 + 255 + 1 + 2 + 1 + 1 + 255;

#[derive(Default)]
pub struct VlessRequest {
    pending: Vec<u8>,
    done: bool,
}

impl VlessRequest {
    pub fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if self.done {
            return Analysis::Finished;
        }
        let room = MAX_HEADER_BYTES - self.pending.len();
        self.pending
            .extend_from_slice(&bytes[..bytes.len().min(room)]);
        let result = self.parse();
        if !matches!(result, Analysis::Pending) || self.pending.len() == MAX_HEADER_BYTES {
            self.done = true;
        }
        result
    }

    fn parse(&self) -> Analysis {
        let bytes = &self.pending;
        let Some(&version) = bytes.first() else {
            return Analysis::Pending;
        };
        if version != 0 {
            return Analysis::Finished;
        }
        let Some(&addons_length) = bytes.get(17) else {
            return Analysis::Pending;
        };
        let command_offset = 18 + usize::from(addons_length);
        let Some(&command) = bytes.get(command_offset) else {
            return Analysis::Pending;
        };
        if !valid_addons(&bytes[18..command_offset]) {
            return Analysis::Finished;
        }
        let mut observations = vec![
            Observation {
                field: "vless.candidate",
                value: "true".into(),
            },
            Observation {
                field: "vless.addons_length",
                value: addons_length.to_string(),
            },
        ];
        let command_name = match command {
            1 => "tcp",
            2 => "udp",
            3 => "mux",
            4 => "rvs",
            _ => return Analysis::Finished,
        };
        observations.push(Observation {
            field: "vless.command",
            value: command_name.into(),
        });
        if command >= 3 {
            return Analysis::FinalObservations(observations);
        }
        let port_offset = command_offset + 1;
        let Some(port_bytes) = bytes.get(port_offset..port_offset + 2) else {
            return Analysis::Pending;
        };
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        let address_offset = port_offset + 2;
        let Some(&address_type) = bytes.get(address_offset) else {
            return Analysis::Pending;
        };
        let (address_type, host) = match address_type {
            1 => {
                let Some(ip) = bytes.get(address_offset + 1..address_offset + 5) else {
                    return Analysis::Pending;
                };
                (
                    "ipv4",
                    Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
                )
            }
            2 => {
                let Some(&length) = bytes.get(address_offset + 1) else {
                    return Analysis::Pending;
                };
                if length == 0 {
                    return Analysis::Finished;
                }
                let start = address_offset + 2;
                let Some(domain) = bytes.get(start..start + usize::from(length)) else {
                    return Analysis::Pending;
                };
                let Ok(domain) = std::str::from_utf8(domain) else {
                    return Analysis::Finished;
                };
                if !domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
                {
                    return Analysis::Finished;
                }
                ("domain", domain.to_ascii_lowercase())
            }
            3 => {
                let Some(ip) = bytes.get(address_offset + 1..address_offset + 17) else {
                    return Analysis::Pending;
                };
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(ip).unwrap());
                ("ipv6", ip.to_string())
            }
            _ => return Analysis::Finished,
        };
        observations.extend([
            Observation {
                field: "vless.target_type",
                value: address_type.into(),
            },
            Observation {
                field: "vless.target_host",
                value: host,
            },
            Observation {
                field: "vless.target_port",
                value: port.to_string(),
            },
        ]);
        Analysis::FinalObservations(observations)
    }
}

// Current VLESS Addons protobuf contains length-delimited Flow (1) and Seed (2).
fn valid_addons(mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        let field = bytes[0];
        if !matches!(field, 0x0a | 0x12) {
            return false;
        }
        let Some(&first) = bytes.get(1) else {
            return false;
        };
        let (length, length_bytes) = if first & 0x80 == 0 {
            (usize::from(first), 1)
        } else {
            let Some(&second) = bytes.get(2) else {
                return false;
            };
            if second > 1 {
                return false;
            }
            (usize::from(first & 0x7f) | usize::from(second) << 7, 2)
        };
        let start = 1 + length_bytes;
        let Some(value) = bytes.get(start..start + length) else {
            return false;
        };
        if field == 0x0a && std::str::from_utf8(value).is_err() {
            return false;
        }
        bytes = &bytes[start + length..];
    }
    true
}

impl BidirectionalStreamAnalyzer for VlessRequest {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if reverse {
            Analysis::Pending
        } else {
            self.feed(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(result: Analysis) -> Vec<Observation> {
        let Analysis::FinalObservations(values) = result else {
            panic!("expected a VLESS candidate");
        };
        values
    }

    fn value<'a>(values: &'a [Observation], field: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|item| item.field == field)
            .map(|item| item.value.as_str())
    }

    fn prefix(addons: &[u8], command: u8) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend([0x42; 16]);
        bytes.push(addons.len() as u8);
        bytes.extend(addons);
        bytes.push(command);
        bytes
    }

    #[test]
    fn domain_request_is_reassembled_across_every_boundary() {
        let mut request = prefix(&[0x0a, 0x01, b'x'], 1);
        request.extend([0x01, 0xbb, 2, 12]);
        request.extend(b"Blocked.Test");
        for split in 0..request.len() {
            let mut analyzer = VlessRequest::default();
            assert!(matches!(
                analyzer.feed(&request[..split]),
                Analysis::Pending
            ));
            let fields = values(analyzer.feed(&request[split..]));
            assert_eq!(value(&fields, "vless.candidate"), Some("true"));
            assert_eq!(value(&fields, "vless.command"), Some("tcp"));
            assert_eq!(value(&fields, "vless.target_type"), Some("domain"));
            assert_eq!(value(&fields, "vless.target_host"), Some("blocked.test"));
            assert_eq!(value(&fields, "vless.target_port"), Some("443"));
            assert_eq!(value(&fields, "vless.addons_length"), Some("3"));
        }
        let mut analyzer = VlessRequest::default();
        for &byte in &request[..request.len() - 1] {
            assert!(matches!(analyzer.feed(&[byte]), Analysis::Pending));
        }
        assert_eq!(
            value(
                &values(analyzer.feed(&request[request.len() - 1..])),
                "vless.target_host"
            ),
            Some("blocked.test")
        );
    }

    #[test]
    fn ip_targets_and_addressless_commands() {
        let mut ipv4 = prefix(&[], 2);
        ipv4.extend([0, 53, 1, 192, 0, 2, 1]);
        let fields = values(VlessRequest::default().feed(&ipv4));
        assert_eq!(value(&fields, "vless.command"), Some("udp"));
        assert_eq!(value(&fields, "vless.target_host"), Some("192.0.2.1"));

        let mut ipv6 = prefix(&[], 1);
        ipv6.extend([1, 0xbb, 3]);
        ipv6.extend(Ipv6Addr::LOCALHOST.octets());
        let fields = values(VlessRequest::default().feed(&ipv6));
        assert_eq!(value(&fields, "vless.target_host"), Some("::1"));

        for (command, expected) in [(3, "mux"), (4, "rvs")] {
            let fields = values(VlessRequest::default().feed(&prefix(&[], command)));
            assert_eq!(value(&fields, "vless.command"), Some(expected));
            assert_eq!(value(&fields, "vless.target_host"), None);
        }
        let mut addons = vec![0x12, 0x80, 0x01];
        addons.extend([0x42; 128]);
        let fields = values(VlessRequest::default().feed(&prefix(&addons, 3)));
        assert_eq!(value(&fields, "vless.addons_length"), Some("131"));
    }

    #[test]
    fn invalid_or_reverse_data_does_not_match() {
        for bytes in [
            b"\x16\x03\x03".as_slice(),
            prefix(&[], 9).as_slice(),
            prefix(&[0xff], 3).as_slice(),
            {
                let mut bytes = prefix(&[], 1);
                bytes.extend([1, 187, 9]);
                bytes
            }
            .as_slice(),
        ] {
            assert!(matches!(
                VlessRequest::default().feed(bytes),
                Analysis::Finished
            ));
        }
        let mut analyzer = VlessRequest::default();
        assert!(matches!(
            BidirectionalStreamAnalyzer::feed(&mut analyzer, &prefix(&[], 3), true),
            Analysis::Pending
        ));
        assert_eq!(
            value(&values(analyzer.feed(&prefix(&[], 3))), "vless.command"),
            Some("mux")
        );
    }
}
