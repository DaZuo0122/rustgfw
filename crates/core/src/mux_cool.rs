//! Visible Xray Mux.Cool frames on an ordered reliable carrier.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation, ObservationBatch};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub const FIELDS: &[&str] = &[
    "mux_cool.session_id",
    "mux_cool.status",
    "mux_cool.network",
    "mux_cool.host",
    "mux_cool.port",
];
const MAX_METADATA: usize = 512;
const MAX_SESSIONS: usize = 256;

#[derive(Default)]
struct Direction {
    bytes: Vec<u8>,
}

#[derive(Default)]
pub struct MuxCool {
    directions: [Direction; 2],
    client: Option<usize>,
    sessions: HashMap<u16, Vec<Observation>>,
    finished: bool,
}

fn observation(field: &'static str, value: impl Into<String>) -> Observation {
    Observation {
        field,
        value: value.into(),
    }
}

fn target(bytes: &[u8]) -> Option<Vec<Observation>> {
    let network = match *bytes.first()? {
        1 => "tcp",
        2 => "udp",
        _ => return None,
    };
    let port = u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?);
    let (host, _) = match *bytes.get(3)? {
        1 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?).to_string(),
            8,
        ),
        2 => {
            let len = usize::from(*bytes.get(4)?);
            let host = std::str::from_utf8(bytes.get(5..5 + len)?)
                .ok()?
                .to_ascii_lowercase();
            (host, 5 + len)
        }
        3 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(4..20)?).ok()?).to_string(),
            20,
        ),
        _ => return None,
    };
    Some(vec![
        observation("mux_cool.network", network),
        observation("mux_cool.host", host),
        observation("mux_cool.port", port.to_string()),
    ])
}

impl MuxCool {
    fn frame(&mut self, direction: usize, meta: &[u8]) -> Result<Option<ObservationBatch>, ()> {
        let id = u16::from_be_bytes(meta[..2].try_into().map_err(|_| ())?);
        let status = match meta[2] {
            1 => "new",
            2 => "keep",
            3 => "end",
            4 => "keepalive",
            _ => return Err(()),
        };
        if meta[3] & !3 != 0 {
            return Err(());
        }
        if status == "keepalive" {
            return Ok(None);
        }
        let mut values = vec![
            observation("mux_cool.session_id", id.to_string()),
            observation("mux_cool.status", status),
        ];
        if status == "new" {
            if self.client.is_some_and(|client| client != direction) {
                return Err(());
            }
            let address = target(meta.get(4..).ok_or(())?).ok_or(())?;
            if !self.sessions.contains_key(&id) && self.sessions.len() >= MAX_SESSIONS {
                return Err(());
            }
            self.client = Some(direction);
            values.extend(address);
            self.sessions.insert(id, values.clone());
        } else if status == "keep" && meta.get(4) == Some(&2) {
            values.extend(target(&meta[4..]).ok_or(())?);
        }
        let context = if status != "new" {
            self.sessions.get(&id).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };
        if status == "end" {
            self.sessions.remove(&id);
        }
        Ok(Some(ObservationBatch {
            clear_fields: FIELDS,
            context,
            observations: values,
        }))
    }

    fn parse(&mut self, direction: usize, batches: &mut Vec<ObservationBatch>) -> Result<(), ()> {
        loop {
            let bytes = &self.directions[direction].bytes;
            if bytes.len() < 2 {
                return Ok(());
            }
            let metadata_len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            if !(4..=MAX_METADATA).contains(&metadata_len) {
                return Err(());
            }
            if bytes.len() < 2 + metadata_len {
                return Ok(());
            }
            let metadata = bytes[2..2 + metadata_len].to_vec();
            let extra = if metadata[3] & 1 != 0 {
                if bytes.len() < 4 + metadata_len {
                    return Ok(());
                }
                let length = usize::from(u16::from_be_bytes([
                    bytes[2 + metadata_len],
                    bytes[3 + metadata_len],
                ]));
                if bytes.len() < 4 + metadata_len + length {
                    return Ok(());
                }
                2 + length
            } else {
                0
            };
            self.directions[direction]
                .bytes
                .drain(..2 + metadata_len + extra);
            if let Some(batch) = self.frame(direction, &metadata)? {
                batches.push(batch);
            }
        }
    }
}

impl BidirectionalStreamAnalyzer for MuxCool {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        let direction = usize::from(reverse);
        self.directions[direction].bytes.extend_from_slice(bytes);
        let mut batches = Vec::new();
        if self.parse(direction, &mut batches).is_err() {
            tracing::debug!(reverse, "Mux.Cool carrier parsing stopped");
            self.finished = true;
        }
        if batches.is_empty() {
            if self.finished {
                Analysis::Finished
            } else {
                Analysis::Pending
            }
        } else {
            Analysis::Batches {
                batches,
                finished: self.finished,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u16, status: u8, target: Option<(&str, u16)>, data: &[u8]) -> Vec<u8> {
        let mut meta = id.to_be_bytes().to_vec();
        meta.push(status);
        meta.push(u8::from(!data.is_empty()));
        if let Some((host, port)) = target {
            meta.push(1);
            meta.extend(port.to_be_bytes());
            meta.push(2);
            meta.push(host.len() as u8);
            meta.extend(host.as_bytes());
        }
        let mut bytes = (meta.len() as u16).to_be_bytes().to_vec();
        bytes.extend(meta);
        if !data.is_empty() {
            bytes.extend((data.len() as u16).to_be_bytes());
            bytes.extend(data);
        }
        bytes
    }

    fn batch(result: Analysis) -> ObservationBatch {
        match result {
            Analysis::Batches { mut batches, .. } if batches.len() == 1 => batches.remove(0),
            other => panic!("expected one Mux.Cool frame, got {other:?}"),
        }
    }

    fn value<'a>(values: &'a [Observation], field: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|item| item.field == field)
            .map(|item| item.value.as_str())
    }

    #[test]
    fn fragmented_new_with_data_preserves_frame_boundaries() {
        let mut mux = MuxCool::default();
        let first = frame(1, 1, Some(("First.Test", 443)), b"hello");
        assert!(matches!(mux.feed(&first[..7], false), Analysis::Pending));
        let second = frame(2, 1, Some(("second.test", 80)), &[]);
        let Analysis::Batches { batches, .. } =
            mux.feed(&[first[7..].to_vec(), second].concat(), false)
        else {
            panic!("missing sessions")
        };
        assert_eq!(batches.len(), 2);
        assert_eq!(
            value(&batches[0].observations, "mux_cool.host"),
            Some("first.test")
        );
        assert_eq!(
            value(&batches[1].observations, "mux_cool.host"),
            Some("second.test")
        );
    }

    #[test]
    fn response_uses_its_own_session_target_and_end_releases_it() {
        let mut mux = MuxCool::default();
        let mut requests = frame(1, 1, Some(("first.test", 443)), b"hello");
        requests.extend(frame(2, 1, Some(("second.test", 80)), &[]));
        let Analysis::Batches { batches, .. } = mux.feed(&requests, false) else {
            panic!("missing sessions")
        };
        assert_eq!(batches.len(), 2);
        let response = batch(mux.feed(&frame(2, 2, None, b"reply"), true));
        assert_eq!(
            value(&response.context, "mux_cool.host"),
            Some("second.test")
        );
        assert_eq!(
            value(&response.observations, "mux_cool.status"),
            Some("keep")
        );
        let end = batch(mux.feed(&frame(2, 3, None, &[]), true));
        assert_eq!(value(&end.context, "mux_cool.host"), Some("second.test"));
        assert!(!mux.sessions.contains_key(&2));
        assert!(mux.sessions.contains_key(&1));
    }
}
