//! Early raw TCP packet lengths, directions, bursts, and first-payload statistics.
use crate::{
    CaptureTime,
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
    "tcp_shape.time_source",
    "tcp_shape.last_gap_us",
    "tcp_shape.gaps_us",
    "tcp_shape.origin_first_span_us",
    "tcp_shape.first_reply_delay_us",
    "tcp_shape.handshake_rtt_us",
    "tcp_shape.timed_bursts",
    "tcp_shape.size_trigram",
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
    first_time: Option<CaptureTime>,
    last_time: Option<CaptureTime>,
    gaps: Vec<Option<u64>>,
    syn_time: Option<CaptureTime>,
    saw_syn_ack: bool,
    handshake_rtt_us: Option<u64>,
}

impl TcpPacketAnalyzer for TcpShape {
    fn feed(&mut self, sequence: u32, payload: &[u8], reverse: bool) -> Analysis {
        self.feed_timed(sequence, payload, reverse, None)
    }

    fn observe_header(
        &mut self,
        flags: u8,
        reverse: bool,
        capture_time: Option<CaptureTime>,
    ) -> Analysis {
        if !reverse && flags & 0x12 == 0x02 && self.syn_time.is_none() {
            self.syn_time = capture_time;
        }
        if reverse && flags & 0x12 == 0x12 {
            self.saw_syn_ack = true;
        }
        if !reverse
            && flags & 0x12 == 0x10
            && self.saw_syn_ack
            && self.handshake_rtt_us.is_none()
            && let Some(rtt) = capture_time
                .zip(self.syn_time)
                .and_then(|(now, before)| now.elapsed_us_since(before))
                .filter(|rtt| *rtt > 0)
        {
            self.handshake_rtt_us = Some(rtt);
            return Analysis::Observations(vec![Observation {
                field: "tcp_shape.handshake_rtt_us",
                value: rtt.to_string(),
            }]);
        }
        Analysis::Pending
    }

    fn feed_timed(
        &mut self,
        sequence: u32,
        payload: &[u8],
        reverse: bool,
        capture_time: Option<CaptureTime>,
    ) -> Analysis {
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
            self.first_time = capture_time;
        } else {
            let gap = capture_time
                .zip(self.last_time)
                .and_then(|(now, before)| now.elapsed_us_since(before));
            self.gaps.push(gap);
            observations.push(Observation {
                field: "tcp_shape.last_gap_us",
                value: gap.map_or_else(|| "?".to_owned(), |value| value.to_string()),
            });
        }
        self.last_time = capture_time;
        observations.push(Observation {
            field: "tcp_shape.time_source",
            value: capture_time.map_or("none", CaptureTime::source).to_owned(),
        });
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
            if !self.reply_seen {
                let delay = capture_time
                    .zip(self.first_time)
                    .and_then(|(now, before)| now.elapsed_us_since(before));
                observations.push(Observation {
                    field: "tcp_shape.first_reply_delay_us",
                    value: delay.map_or_else(|| "?".to_owned(), |value| value.to_string()),
                });
            }
            self.reply_seen = true;
        } else if !self.reply_seen {
            self.origin_first_run += 1;
            self.origin_first_bytes += payload.len();
            let span = capture_time
                .zip(self.first_time)
                .and_then(|(now, before)| now.elapsed_us_since(before));
            observations.push(Observation {
                field: "tcp_shape.origin_first_span_us",
                value: span.map_or_else(|| "?".to_owned(), |value| value.to_string()),
            });
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
        for triple in self.lengths.windows(3) {
            observations.push(Observation {
                field: "tcp_shape.size_trigram",
                value: triple
                    .iter()
                    .map(|length| size_class(*length).to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            });
        }
        for (field, value) in [
            ("tcp_shape.gaps_us", format_gaps(&self.gaps)),
            ("tcp_shape.signed_lengths", signed_values(&self.lengths)),
            ("tcp_shape.signed_bursts", signed_values(&self.bursts)),
            (
                "tcp_shape.timed_bursts",
                self.timed_bursts().unwrap_or_else(|| "?".to_owned()),
            ),
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

impl TcpShape {
    fn timed_bursts(&self) -> Option<String> {
        let threshold = self.handshake_rtt_us?.saturating_mul(3);
        if self.first_time.map(CaptureTime::source) != self.syn_time.map(CaptureTime::source) {
            return None;
        }
        let mut bursts = Vec::<i64>::new();
        for (index, &length) in self.lengths.iter().enumerate() {
            if index > 0 {
                let gap = self.gaps.get(index - 1).copied().flatten()?;
                if gap < threshold
                    && let Some(last) = bursts.last_mut()
                    && last.signum() == length.signum()
                {
                    *last += length;
                    continue;
                }
            }
            bursts.push(length);
        }
        Some(signed_values(&bursts))
    }
}

fn format_gaps(gaps: &[Option<u64>]) -> String {
    gaps.iter()
        .map(|gap| gap.map_or_else(|| "?".to_owned(), |value| value.to_string()))
        .collect::<Vec<_>>()
        .join(",")
}

fn size_class(length: i64) -> i8 {
    let magnitude = match length.unsigned_abs() {
        0..=160 => 1,
        161..=600 => 2,
        601..=1210 => 3,
        _ => 4,
    };
    if length < 0 { -magnitude } else { magnitude }
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
    use std::time::{Duration, SystemTime};

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

    #[test]
    fn uses_capture_time_and_does_not_advance_on_retransmission() {
        let mut shape = TcpShape::default();
        let at =
            |micros| CaptureTime::Kernel(SystemTime::UNIX_EPOCH + Duration::from_micros(micros));
        let first = [0x91; 64];
        observations(shape.feed_timed(10, &first, false, Some(at(100_000))));
        assert!(matches!(
            shape.feed_timed(10, &first, false, Some(at(105_000))),
            Analysis::Pending
        ));
        let values = observations(shape.feed_timed(74, &[0; 32], false, Some(at(110_000))));
        assert_eq!(field(&values, "tcp_shape.last_gap_us"), Some("10000"));
        assert_eq!(field(&values, "tcp_shape.timed_bursts"), Some("?"));
        assert_eq!(
            field(&values, "tcp_shape.origin_first_span_us"),
            Some("10000")
        );
        let values = observations(shape.feed_timed(400, &[0; 50], true, Some(at(140_000))));
        assert_eq!(
            field(&values, "tcp_shape.first_reply_delay_us"),
            Some("40000")
        );
        assert_eq!(field(&values, "tcp_shape.gaps_us"), Some("10000,30000"));
        assert_eq!(field(&values, "tcp_shape.time_source"), Some("kernel"));
        let values = observations(shape.feed_timed(450, &[0; 10], true, None));
        assert_eq!(field(&values, "tcp_shape.last_gap_us"), Some("?"));
        assert_eq!(field(&values, "tcp_shape.time_source"), Some("none"));
    }

    #[test]
    fn handshake_rtt_splits_same_direction_bursts_and_bins_trigrams() {
        let mut shape = TcpShape::default();
        let at =
            |micros| CaptureTime::Kernel(SystemTime::UNIX_EPOCH + Duration::from_micros(micros));
        assert!(matches!(
            shape.observe_header(0x02, false, Some(at(0))),
            Analysis::Pending
        ));
        assert!(matches!(
            shape.observe_header(0x12, true, Some(at(5_000))),
            Analysis::Pending
        ));
        let rtt = observations(shape.observe_header(0x10, false, Some(at(10_000))));
        assert_eq!(field(&rtt, "tcp_shape.handshake_rtt_us"), Some("10000"));
        observations(shape.feed_timed(10, &[1; 100], false, Some(at(12_000))));
        let values = observations(shape.feed_timed(110, &[2; 200], false, Some(at(15_000))));
        assert_eq!(field(&values, "tcp_shape.timed_bursts"), Some("300"));
        let values = observations(shape.feed_timed(310, &[3; 300], false, Some(at(70_000))));
        assert_eq!(field(&values, "tcp_shape.signed_bursts"), Some("600"));
        assert_eq!(field(&values, "tcp_shape.timed_bursts"), Some("300,300"));
        assert_eq!(field(&values, "tcp_shape.size_trigram"), Some("1,2,2"));
        let values = observations(shape.feed_timed(500, &[4; 400], true, Some(at(75_000))));
        assert_eq!(
            field(&values, "tcp_shape.timed_bursts"),
            Some("300,300,-400")
        );
        assert!(
            values
                .iter()
                .any(|value| value.field == "tcp_shape.size_trigram" && value.value == "2,2,-2")
        );
    }
}
