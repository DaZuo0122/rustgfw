//! WireGuard UDP packet shape and cross-direction index observations.
use crate::inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer};
use std::collections::VecDeque;

pub const FIELDS: &[&str] = &[
    "wireguard.type",
    "wireguard.sender_index",
    "wireguard.receiver_index",
    "wireguard.receiver_matched",
    "wireguard.counter",
];

#[derive(Default)]
pub struct WireGuard {
    sender_indexes: VecDeque<(u32, bool)>,
}

impl WireGuard {
    fn remember(&mut self, index: u32, reverse: bool) {
        if self.sender_indexes.len() == 6 {
            self.sender_indexes.pop_front();
        }
        self.sender_indexes.push_back((index, reverse));
    }

    fn matches_receiver(&self, index: u32, reverse: bool) -> bool {
        self.sender_indexes
            .iter()
            .any(|&(sender, sender_reverse)| sender == index && sender_reverse != reverse)
    }

    fn parse(&mut self, payload: &[u8], reverse: bool) -> Option<Vec<Observation>> {
        if payload.len() < 4 || payload[1..4] != [0, 0, 0] {
            return None;
        }
        let mut values = Vec::new();
        let mut put = |field, value: String| values.push(Observation { field, value });
        match payload[0] {
            1 if payload.len() == 148 => {
                put("wireguard.type", "initiation".into());
                let sender = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                put("wireguard.sender_index", sender.to_string());
                self.remember(sender, reverse);
            }
            2 if payload.len() == 92 => {
                put("wireguard.type", "response".into());
                let sender = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                let receiver = u32::from_le_bytes(payload[8..12].try_into().unwrap());
                put("wireguard.sender_index", sender.to_string());
                put("wireguard.receiver_index", receiver.to_string());
                put(
                    "wireguard.receiver_matched",
                    self.matches_receiver(receiver, reverse).to_string(),
                );
                self.remember(sender, reverse);
            }
            3 if payload.len() == 64 => {
                put("wireguard.type", "cookie".into());
                let receiver = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                put("wireguard.receiver_index", receiver.to_string());
                put(
                    "wireguard.receiver_matched",
                    self.matches_receiver(receiver, reverse).to_string(),
                );
            }
            4 if payload.len() >= 32 && payload.len().is_multiple_of(16) => {
                put("wireguard.type", "data".into());
                let receiver = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                let counter = u64::from_le_bytes(payload[8..16].try_into().unwrap());
                put("wireguard.receiver_index", receiver.to_string());
                put(
                    "wireguard.receiver_matched",
                    self.matches_receiver(receiver, reverse).to_string(),
                );
                put("wireguard.counter", counter.to_string());
            }
            _ => return None,
        }
        Some(values)
    }
}

impl UdpStreamAnalyzer for WireGuard {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        match self.parse(payload, reverse) {
            Some(observations) => UdpStreamAnalysis::ReplaceFields {
                fields: FIELDS.to_vec(),
                observations,
            },
            None => UdpStreamAnalysis::ClearFields(FIELDS.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(analysis: &'a UdpStreamAnalysis, name: &str) -> Option<&'a str> {
        match analysis {
            UdpStreamAnalysis::ReplaceFields { observations, .. } => observations
                .iter()
                .find(|observation| observation.field == name)
                .map(|observation| observation.value.as_str()),
            _ => None,
        }
    }

    #[test]
    fn correlates_sender_and_receiver_indexes_across_directions() {
        let mut analyzer = WireGuard::default();
        let mut initiation = vec![0; 148];
        initiation[0] = 1;
        initiation[4..8].copy_from_slice(&42u32.to_le_bytes());
        let first = analyzer.feed(&initiation, false);
        assert_eq!(field(&first, "wireguard.type"), Some("initiation"));
        assert_eq!(field(&first, "wireguard.sender_index"), Some("42"));

        let mut response = vec![0; 92];
        response[0] = 2;
        response[4..8].copy_from_slice(&99u32.to_le_bytes());
        response[8..12].copy_from_slice(&42u32.to_le_bytes());
        let second = analyzer.feed(&response, true);
        assert_eq!(field(&second, "wireguard.type"), Some("response"));
        assert_eq!(field(&second, "wireguard.receiver_matched"), Some("true"));

        let mut data = vec![0; 32];
        data[0] = 4;
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        data[8..16].copy_from_slice(&7u64.to_le_bytes());
        let third = analyzer.feed(&data, false);
        assert_eq!(field(&third, "wireguard.type"), Some("data"));
        assert_eq!(field(&third, "wireguard.receiver_matched"), Some("true"));
        assert_eq!(field(&third, "wireguard.counter"), Some("7"));
        assert_eq!(field(&third, "wireguard.sender_index"), None);

        data[4..8].copy_from_slice(&123u32.to_le_bytes());
        assert_eq!(
            field(&analyzer.feed(&data, false), "wireguard.receiver_matched"),
            Some("false")
        );
        data[1] = 1;
        assert!(matches!(
            analyzer.feed(&data, false),
            UdpStreamAnalysis::ClearFields(_)
        ));
    }
}
