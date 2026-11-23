//! Early raw TCP packet lengths, directions, bursts, and first-payload statistics.
use crate::{
    inspect::{Analysis, Observation, TcpPacketAnalyzer},
    wire_stats::PrefixStats,
};

pub const FIELDS: &[&str] = &[
    "tcp_shape.first_len",
    "tcp_shape.first_prefix_len",
    "tcp_shape.first_popcount_milli",
    "tcp_shape.first_printable_per_mille",
    "tcp_shape.first_entropy_milli",
    "tcp_shape.first_random_like",
    "tcp_shape.signed_lengths",
    "tcp_shape.signed_bursts",
    "tcp_shape.packet_count",
    "tcp_shape.origin_first_run",
    "tcp_shape.origin_first_bytes",
    "tcp_shape.reply_seen",
];

const MAX_PACKETS: usize = 16;

#[derive(Default)]
pub struct TcpShape {
    seen: Vec<(bool, u32, usize)>,
    lengths: Vec<i64>,
    bursts: Vec<i64>,
    origin_first_run: usize,
    origin_first_bytes: usize,
    reply_seen: bool,
}

impl TcpPacketAnalyzer for TcpShape {
    fn feed(&mut self, sequence: u32, payload: &[u8], reverse: bool) -> Analysis {
        if self.lengths.len() == MAX_PACKETS {
            return Analysis::Finished;
        }
        if payload.is_empty() {
            return Analysis::Pending;
        }
        let identity = (reverse, sequence, payload.len());
        if self.seen.contains(&identity) {
            return Analysis::Pending;
        }
        self.seen.push(identity);
        let first = self.lengths.is_empty();
        let mut observations = Vec::new();
        if first {
            let stats = PrefixStats::sample(payload);
            for (field, value) in [
                ("tcp_shape.first_len", payload.len().to_string()),
                ("tcp_shape.first_prefix_len", stats.len.to_string()),
                (
                    "tcp_shape.first_popcount_milli",
                    stats.popcount_milli.to_string(),
                ),
                (
                    "tcp_shape.first_printable_per_mille",
                    stats.printable_per_mille.to_string(),
                ),
                (
                    "tcp_shape.first_entropy_milli",
                    stats.entropy_milli.to_string(),
                ),
                (
                    "tcp_shape.first_random_like",
                    stats.random_like().to_string(),
                ),
            ] {
                observations.push(Observation { field, value });
            }
        }
        if reverse {
            self.reply_seen = true;
        } else if !self.reply_seen {
            self.origin_first_run += 1;
            self.origin_first_bytes += payload.len();
        }
        let signed = if reverse {
            -(payload.len() as i64)
        } else {
            payload.len() as i64
        };
        self.lengths.push(signed);
        if let Some(last) = self.bursts.last_mut()
            && last.signum() == signed.signum()
        {
            *last += signed;
        } else {
            self.bursts.push(signed);
        }
        for (field, value) in [
            ("tcp_shape.signed_lengths", signed_values(&self.lengths)),
            ("tcp_shape.signed_bursts", signed_values(&self.bursts)),
            ("tcp_shape.packet_count", self.lengths.len().to_string()),
            (
                "tcp_shape.origin_first_run",
                self.origin_first_run.to_string(),
            ),
            (
                "tcp_shape.origin_first_bytes",
                self.origin_first_bytes.to_string(),
            ),
            ("tcp_shape.reply_seen", self.reply_seen.to_string()),
        ] {
            observations.push(Observation { field, value });
        }
        if self.lengths.len() == MAX_PACKETS {
            Analysis::FinalObservations(observations)
        } else {
            Analysis::Observations(observations)
        }
    }
}

fn signed_values(values: &[i64]) -> String {
    values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observations(result: Analysis) -> Vec<Observation> {
        match result {
            Analysis::Observations(values) | Analysis::FinalObservations(values) => values,
            _ => panic!("expected packet observations"),
        }
    }

    fn field<'a>(values: &'a [Observation], name: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|value| value.field == name)
            .map(|value| value.value.as_str())
    }

    #[test]
    fn records_packet_boundaries_and_directional_bursts() {
        let mut shape = TcpShape::default();
        let first = (0..100)
            .map(|index| (index * 73 + 151) as u8)
            .collect::<Vec<_>>();
        let values = observations(shape.feed(100, &first, false));
        assert_eq!(field(&values, "tcp_shape.first_len"), Some("100"));
        assert_eq!(field(&values, "tcp_shape.first_random_like"), Some("true"));
        assert_eq!(field(&values, "tcp_shape.signed_lengths"), Some("100"));
        assert!(matches!(shape.feed(100, &first, false), Analysis::Pending));
        let values = observations(shape.feed(500, &[0; 200], true));
        assert_eq!(field(&values, "tcp_shape.signed_lengths"), Some("100,-200"));
        let values = observations(shape.feed(700, &[0; 300], true));
        assert_eq!(field(&values, "tcp_shape.signed_bursts"), Some("100,-500"));
        let values = observations(shape.feed(200, &[0; 50], false));
        assert_eq!(
            field(&values, "tcp_shape.signed_bursts"),
            Some("100,-500,50")
        );
        assert_eq!(field(&values, "tcp_shape.origin_first_bytes"), Some("100"));
        assert_eq!(field(&values, "tcp_shape.reply_seen"), Some("true"));
    }
}
