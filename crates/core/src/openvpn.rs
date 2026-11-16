//! OpenVPN UDP control handshake observations.
use crate::inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer};

pub const FIELDS: &[&str] = &[
    "openvpn.stage",
    "openvpn.opcode",
    "openvpn.client_reset",
    "openvpn.server_reset",
    "openvpn.tx_packets",
    "openvpn.rx_packets",
];

#[derive(Default)]
pub struct OpenVpnUdp {
    client_reset: Option<u8>,
    server_reset: Option<u8>,
    tx_packets: u64,
    rx_packets: u64,
}

fn client_reset(opcode: u8) -> bool {
    matches!(opcode, 1 | 7 | 10)
}

fn server_reset(opcode: u8) -> bool {
    matches!(opcode, 2 | 8)
}

fn data_or_control(opcode: u8) -> bool {
    matches!(opcode, 3 | 4 | 5 | 6 | 9 | 11)
}

impl UdpStreamAnalyzer for OpenVpnUdp {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        let Some(&first) = payload.first() else {
            return UdpStreamAnalysis::ClearFields(FIELDS.to_vec());
        };
        if payload.len() < 6 {
            return UdpStreamAnalysis::ClearFields(FIELDS.to_vec());
        }
        let opcode = first >> 3;
        if self.server_reset.is_none() && (payload.len() < 9 || first & 7 != 0) {
            return UdpStreamAnalysis::ClearFields(FIELDS.to_vec());
        }
        let stage = match (self.client_reset, self.server_reset) {
            (None, _) if !reverse && client_reset(opcode) => {
                self.client_reset = Some(opcode);
                "client_reset"
            }
            (Some(_), None) if reverse && server_reset(opcode) => {
                self.server_reset = Some(opcode);
                "handshake"
            }
            (Some(_), None) if !reverse && client_reset(opcode) => "client_reset",
            (Some(_), Some(_)) if data_or_control(opcode) => {
                if reverse {
                    self.rx_packets += 1;
                } else {
                    self.tx_packets += 1;
                }
                "data"
            }
            _ => return UdpStreamAnalysis::ClearFields(FIELDS.to_vec()),
        };
        let mut observations = vec![
            Observation {
                field: "openvpn.stage",
                value: stage.into(),
            },
            Observation {
                field: "openvpn.opcode",
                value: opcode.to_string(),
            },
            Observation {
                field: "openvpn.client_reset",
                value: self.client_reset.unwrap().to_string(),
            },
        ];
        if let Some(server_reset) = self.server_reset {
            observations.extend([
                Observation {
                    field: "openvpn.server_reset",
                    value: server_reset.to_string(),
                },
                Observation {
                    field: "openvpn.tx_packets",
                    value: self.tx_packets.to_string(),
                },
                Observation {
                    field: "openvpn.rx_packets",
                    value: self.rx_packets.to_string(),
                },
            ]);
        }
        UdpStreamAnalysis::ReplaceFields {
            fields: FIELDS.to_vec(),
            observations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(result: &'a UdpStreamAnalysis, name: &str) -> Option<&'a str> {
        match result {
            UdpStreamAnalysis::ReplaceFields { observations, .. } => observations
                .iter()
                .find(|item| item.field == name)
                .map(|item| item.value.as_str()),
            _ => None,
        }
    }

    #[test]
    fn confirms_reverse_reset_before_reporting_handshake() {
        let mut analyzer = OpenVpnUdp::default();
        let client = [7 << 3, 1, 2, 3, 4, 5, 6, 7, 8];
        let server = [8 << 3, 6, 7, 8, 9, 10, 11, 12, 13];
        let data = [6 << 3, 0, 0, 0, 0, 0];

        let first = analyzer.feed(&client, false);
        assert_eq!(field(&first, "openvpn.stage"), Some("client_reset"));
        assert_eq!(field(&first, "openvpn.server_reset"), None);
        assert!(matches!(
            analyzer.feed(&server, false),
            UdpStreamAnalysis::ClearFields(_)
        ));
        let second = analyzer.feed(&server, true);
        assert_eq!(field(&second, "openvpn.stage"), Some("handshake"));
        assert_eq!(field(&second, "openvpn.server_reset"), Some("8"));
        let third = analyzer.feed(&data, false);
        assert_eq!(field(&third, "openvpn.stage"), Some("data"));
        assert_eq!(field(&third, "openvpn.tx_packets"), Some("1"));
        assert_eq!(field(&third, "openvpn.rx_packets"), Some("0"));
        let fourth = analyzer.feed(&data, true);
        assert_eq!(field(&fourth, "openvpn.rx_packets"), Some("1"));
        assert!(matches!(
            analyzer.feed(&[0xff; 6], true),
            UdpStreamAnalysis::ClearFields(_)
        ));
    }
}
