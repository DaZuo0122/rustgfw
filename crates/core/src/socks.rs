//! Client-side SOCKS4/4a and SOCKS5 request observations.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const FIELDS: &[&str] = &[
    "socks.version",
    "socks.command",
    "socks.target_type",
    "socks.target_host",
    "socks.target_port",
    "socks.auth",
];

const MAX_REQUEST_BYTES: usize = 16384;

#[derive(Default)]
enum Stage {
    #[default]
    Start,
    Socks4,
    Socks5Greeting,
    Socks5RequestOrAuth,
    Socks5Request,
    Done,
}

pub struct SocksRequest {
    pending: Vec<u8>,
    stage: Stage,
    auth: &'static str,
}

impl Default for SocksRequest {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            stage: Stage::Start,
            auth: "none",
        }
    }
}

impl SocksRequest {
    fn parse_socks4(&mut self) -> Option<Analysis> {
        if self.pending.len() < 9 {
            return None;
        }
        let Some(command) = command(self.pending[1], false) else {
            return Some(Analysis::Finished);
        };
        let port = u16::from_be_bytes([self.pending[2], self.pending[3]]);
        let ip = Ipv4Addr::new(
            self.pending[4],
            self.pending[5],
            self.pending[6],
            self.pending[7],
        );
        let user_end = self.pending[8..].iter().position(|&byte| byte == 0)? + 8;
        let socks4a = self.pending[4..7] == [0, 0, 0] && self.pending[7] != 0;
        let (version, target_type, target_host) = if socks4a {
            let start = user_end + 1;
            let end = self.pending[start..].iter().position(|&byte| byte == 0)? + start;
            let Ok(host) = std::str::from_utf8(&self.pending[start..end]) else {
                return Some(Analysis::Finished);
            };
            if host.is_empty() {
                return Some(Analysis::Finished);
            }
            ("4a", "domain", host.to_ascii_lowercase())
        } else {
            ("4", "ipv4", ip.to_string())
        };
        Some(Analysis::FinalObservations(observations(
            version,
            command,
            target_type,
            target_host,
            port,
            None,
        )))
    }

    fn parse_socks5_greeting(&mut self) -> Option<Analysis> {
        if self.pending.len() < 2 {
            return None;
        }
        let count = usize::from(self.pending[1]);
        if count == 0 {
            return Some(Analysis::Finished);
        }
        if self.pending.len() < count + 2 {
            return None;
        }
        self.pending.drain(..count + 2);
        self.stage = Stage::Socks5RequestOrAuth;
        Some(Analysis::Pending)
    }

    fn parse_socks5_auth(&mut self) -> Option<Analysis> {
        if self.pending.len() < 2 {
            return None;
        }
        let user_len = usize::from(self.pending[1]);
        if user_len == 0 {
            return Some(Analysis::Finished);
        }
        let password_len_offset = user_len + 2;
        let &password_len = self.pending.get(password_len_offset)?;
        let total = password_len_offset + 1 + usize::from(password_len);
        if self.pending.len() < total {
            return None;
        }
        self.pending.drain(..total);
        self.auth = "userpass";
        self.stage = Stage::Socks5Request;
        Some(Analysis::Pending)
    }

    fn parse_socks5_request(&self) -> Option<Analysis> {
        if self.pending.len() < 4 {
            return None;
        }
        let Some(command) = command(self.pending[1], true) else {
            return Some(Analysis::Finished);
        };
        if self.pending[0] != 5 || self.pending[2] != 0 {
            return Some(Analysis::Finished);
        }
        let (target_type, target_host, port_offset) = match self.pending[3] {
            1 => {
                if self.pending.len() < 10 {
                    return None;
                }
                let ip = Ipv4Addr::new(
                    self.pending[4],
                    self.pending[5],
                    self.pending[6],
                    self.pending[7],
                );
                ("ipv4", ip.to_string(), 8)
            }
            3 => {
                let &length = self.pending.get(4)?;
                if length == 0 {
                    return Some(Analysis::Finished);
                }
                let end = 5 + usize::from(length);
                if self.pending.len() < end + 2 {
                    return None;
                }
                let Ok(host) = std::str::from_utf8(&self.pending[5..end]) else {
                    return Some(Analysis::Finished);
                };
                ("domain", host.to_ascii_lowercase(), end)
            }
            4 => {
                if self.pending.len() < 22 {
                    return None;
                }
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&self.pending[4..20]).unwrap());
                ("ipv6", ip.to_string(), 20)
            }
            _ => return Some(Analysis::Finished),
        };
        let port = u16::from_be_bytes([self.pending[port_offset], self.pending[port_offset + 1]]);
        Some(Analysis::FinalObservations(observations(
            "5",
            command,
            target_type,
            target_host,
            port,
            Some(self.auth),
        )))
    }
}

impl SocksRequest {
    pub fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if matches!(self.stage, Stage::Done) {
            return Analysis::Finished;
        }
        self.pending.extend_from_slice(bytes);
        loop {
            let result = match self.stage {
                Stage::Start => {
                    let Some(&version) = self.pending.first() else {
                        return Analysis::Pending;
                    };
                    self.stage = match version {
                        4 => Stage::Socks4,
                        5 => Stage::Socks5Greeting,
                        _ => Stage::Done,
                    };
                    if matches!(self.stage, Stage::Done) {
                        return Analysis::Finished;
                    }
                    continue;
                }
                Stage::Socks4 => self.parse_socks4(),
                Stage::Socks5Greeting => self.parse_socks5_greeting(),
                Stage::Socks5RequestOrAuth => {
                    let Some(&version) = self.pending.first() else {
                        return Analysis::Pending;
                    };
                    match version {
                        1 => self.parse_socks5_auth(),
                        5 => {
                            self.stage = Stage::Socks5Request;
                            continue;
                        }
                        _ => Some(Analysis::Finished),
                    }
                }
                Stage::Socks5Request => self.parse_socks5_request(),
                Stage::Done => unreachable!(),
            };
            match result {
                Some(Analysis::Pending) => continue,
                Some(result) => {
                    self.stage = Stage::Done;
                    return result;
                }
                None if self.pending.len() > MAX_REQUEST_BYTES => {
                    self.stage = Stage::Done;
                    return Analysis::Finished;
                }
                None => return Analysis::Pending,
            }
        }
    }
}

impl BidirectionalStreamAnalyzer for SocksRequest {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if reverse {
            Analysis::Pending
        } else {
            self.feed(bytes)
        }
    }
}

fn command(value: u8, socks5: bool) -> Option<&'static str> {
    match value {
        1 => Some("connect"),
        2 => Some("bind"),
        3 if socks5 => Some("udp_associate"),
        _ => None,
    }
}

fn observations(
    version: &str,
    command: &str,
    target_type: &str,
    target_host: String,
    target_port: u16,
    auth: Option<&str>,
) -> Vec<Observation> {
    let mut result = vec![
        Observation {
            field: "socks.version",
            value: version.into(),
        },
        Observation {
            field: "socks.command",
            value: command.into(),
        },
        Observation {
            field: "socks.target_type",
            value: target_type.into(),
        },
        Observation {
            field: "socks.target_host",
            value: target_host,
        },
        Observation {
            field: "socks.target_port",
            value: target_port.to_string(),
        },
    ];
    if let Some(auth) = auth {
        result.push(Observation {
            field: "socks.auth",
            value: auth.into(),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(result: Analysis, name: &str) -> Option<String> {
        match result {
            Analysis::FinalObservations(values) => values
                .into_iter()
                .find(|item| item.field == name)
                .map(|item| item.value),
            _ => None,
        }
    }

    #[test]
    fn socks4a_domain_and_socks4_ip_are_extracted() {
        let mut parser = SocksRequest::default();
        let request = b"\x04\x01\x01\xbb\x00\x00\x00\x01user\0Blocked.Test\0";
        for &byte in &request[..request.len() - 1] {
            assert!(matches!(parser.feed(&[byte]), Analysis::Pending));
        }
        assert_eq!(
            field(
                parser.feed(&request[request.len() - 1..]),
                "socks.target_host"
            ),
            Some("blocked.test".into())
        );
        let mut parser = SocksRequest::default();
        assert_eq!(
            field(
                parser.feed(b"\x04\x01\x00\x50\xc0\x00\x02\x01user\0"),
                "socks.target_host"
            ),
            Some("192.0.2.1".into())
        );
    }

    #[test]
    fn socks5_method_auth_and_domain_request_can_share_one_chunk() {
        let wire = b"\x05\x01\x02\x01\x04user\x04pass\x05\x01\x00\x03\x0cblocked.test\x01\xbb";
        for chunk_size in [wire.len(), 1] {
            let mut parser = SocksRequest::default();
            let mut result = Analysis::Pending;
            for chunk in wire.chunks(chunk_size) {
                result = parser.feed(chunk);
            }
            let Analysis::FinalObservations(values) = result else {
                panic!("expected a SOCKS5 request");
            };
            let value = |name| {
                values
                    .iter()
                    .find(|item| item.field == name)
                    .map(|item| item.value.as_str())
            };
            assert_eq!(value("socks.target_host"), Some("blocked.test"));
            assert_eq!(value("socks.target_port"), Some("443"));
            assert_eq!(value("socks.auth"), Some("userpass"));
        }

        let mut parser = SocksRequest::default();
        let greeting = b"\x05\x01\x00";
        assert!(matches!(parser.feed(greeting), Analysis::Pending));
        let request = b"\x05\x03\x00\x01\x0a\x00\x00\x01\x00\x35";
        assert_eq!(
            field(parser.feed(request), "socks.command"),
            Some("udp_associate".into())
        );
    }

    #[test]
    fn socks5_ipv6_target_and_invalid_command() {
        let mut parser = SocksRequest::default();
        assert!(matches!(parser.feed(b"\x05\x01\x00"), Analysis::Pending));
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            field(parser.feed(&request), "socks.target_host"),
            Some("::1".into())
        );

        let mut invalid = SocksRequest::default();
        assert!(matches!(invalid.feed(b"\x05\x01\x00"), Analysis::Pending));
        assert!(matches!(
            invalid.feed(b"\x05\x09\x00\x01\x7f\x00\x00\x01\x00\x50"),
            Analysis::Finished
        ));
    }

    #[test]
    fn reverse_direction_is_not_parsed_as_a_client_request() {
        let mut parser = SocksRequest::default();
        let fake_server_bytes = b"\x05\x01\x00\x05\x01\x00\x03\x0cblocked.test\x01\xbb";
        assert!(matches!(
            BidirectionalStreamAnalyzer::feed(&mut parser, fake_server_bytes, true),
            Analysis::Pending
        ));
        assert!(matches!(
            BidirectionalStreamAnalyzer::feed(&mut parser, b"\x05\x01\x00", false),
            Analysis::Pending
        ));
        assert!(matches!(
            BidirectionalStreamAnalyzer::feed(
                &mut parser,
                b"\x05\x01\x00\x03\x0cblocked.test\x01\xbb",
                false
            ),
            Analysis::FinalObservations(_)
        ));
    }
}
