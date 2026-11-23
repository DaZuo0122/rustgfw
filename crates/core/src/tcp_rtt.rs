//! Passive transport/application RTT discrepancy from early TCP packet timing.
use crate::{
    CaptureTime,
    inspect::{Analysis, Observation, TcpPacketAnalyzer},
};

pub const FIELDS: &[&str] = &[
    "tcp_rtt.transport_median_us",
    "tcp_rtt.application_estimate_us",
    "tcp_rtt.diff_us",
    "tcp_rtt.completed_pairs",
    "tcp_rtt.transport_samples",
    "tcp_rtt.correlation_peak_milli",
];

const MAX_PACKETS: usize = 64;
const WINDOW_PAIRS: usize = 3;
const MAX_SHIFT_MS: u64 = 1000;

#[derive(Clone, Copy)]
struct SentPacket {
    sequence: u32,
    end_sequence: u32,
    time: CaptureTime,
    event_index: usize,
    retransmitted: bool,
}

#[derive(Clone, Copy)]
struct TimedPacket {
    reverse: bool,
    elapsed_us: u64,
}

#[derive(Default)]
pub struct TcpRtt {
    seen: Vec<(bool, u32, usize)>,
    first_time: Option<CaptureTime>,
    packets: Vec<TimedPacket>,
    pending: Vec<SentPacket>,
    rtt_samples: Vec<(usize, u64)>,
}

impl TcpRtt {
    fn reset_timing(&mut self) {
        self.first_time = None;
        self.packets.clear();
        self.pending.clear();
        self.rtt_samples.clear();
    }

    fn estimate(&self) -> Option<Vec<Observation>> {
        let mut pair_starts = Vec::new();
        for index in 1..self.packets.len() {
            if self.packets[index].reverse && !self.packets[index - 1].reverse {
                let mut start = index - 1;
                while start > 0 && !self.packets[start - 1].reverse {
                    start -= 1;
                }
                pair_starts.push(start);
            }
        }
        if pair_starts.len() < WINDOW_PAIRS {
            return None;
        }
        let window_start = pair_starts[pair_starts.len() - WINDOW_PAIRS];
        let mut rtts = self
            .rtt_samples
            .iter()
            .filter(|(index, _)| *index >= window_start)
            .map(|(_, rtt)| *rtt)
            .collect::<Vec<_>>();
        if rtts.is_empty() {
            return None;
        }
        rtts.sort_unstable();
        let middle = rtts.len() / 2;
        let transport_rtt = if rtts.len().is_multiple_of(2) {
            ((u128::from(rtts[middle - 1]) + u128::from(rtts[middle])) / 2) as u64
        } else {
            rtts[middle]
        };
        let window = &self.packets[window_start..];
        let outgoing = window
            .iter()
            .filter(|packet| !packet.reverse)
            .map(|packet| packet.elapsed_us)
            .collect::<Vec<_>>();
        let incoming = window
            .iter()
            .filter(|packet| packet.reverse)
            .map(|packet| packet.elapsed_us)
            .collect::<Vec<_>>();
        let max_delay = incoming.last()?.checked_sub(*outgoing.first()?)?;
        let min_shift_ms = transport_rtt.div_ceil(1000);
        let max_shift_ms = (max_delay / 1000).min(MAX_SHIFT_MS);
        if min_shift_ms > max_shift_ms {
            return None;
        }
        // Laplace weighting tolerates jitter around a common response delay.
        let jitter_us = (transport_rtt / 4).clamp(1000, 20_000) as f64;
        let mut best_shift_ms = min_shift_ms;
        let mut best_score = -1.0;
        for shift_ms in min_shift_ms..=max_shift_ms {
            let shift_us = shift_ms * 1000;
            let mut score = 0.0;
            for &sent in &outgoing {
                for &received in &incoming {
                    if let Some(delay) = received.checked_sub(sent)
                        && delay > 0
                    {
                        score += (-(delay.abs_diff(shift_us) as f64) / jitter_us).exp();
                    }
                }
            }
            if score > best_score {
                best_score = score;
                best_shift_ms = shift_ms;
            }
        }
        let application_rtt = best_shift_ms * 1000;
        let peak_milli =
            (best_score * 1000.0 / (outgoing.len() * incoming.len()) as f64).round() as u64;
        Some(
            [
                ("tcp_rtt.transport_median_us", transport_rtt),
                ("tcp_rtt.application_estimate_us", application_rtt),
                ("tcp_rtt.diff_us", application_rtt - transport_rtt),
                ("tcp_rtt.completed_pairs", pair_starts.len() as u64),
                ("tcp_rtt.transport_samples", rtts.len() as u64),
                ("tcp_rtt.correlation_peak_milli", peak_milli),
            ]
            .into_iter()
            .map(|(field, value)| Observation {
                field,
                value: value.to_string(),
            })
            .collect(),
        )
    }
}

impl TcpPacketAnalyzer for TcpRtt {
    fn feed(&mut self, sequence: u32, payload: &[u8], reverse: bool) -> Analysis {
        self.feed_timed(sequence, payload, reverse, None)
    }

    fn observe_header(
        &mut self,
        flags: u8,
        _sequence: u32,
        acknowledgment: u32,
        reverse: bool,
        capture_time: Option<CaptureTime>,
    ) -> Analysis {
        if !reverse || flags & 0x10 == 0 || flags & 0x04 != 0 {
            return Analysis::Pending;
        }
        let Some(last) = self
            .pending
            .iter()
            .rposition(|sent| acknowledgment.wrapping_sub(sent.end_sequence) < 0x8000_0000)
        else {
            return Analysis::Pending;
        };
        let sent = self.pending[last];
        self.pending.drain(..=last);
        if sent.end_sequence == acknowledgment
            && !sent.retransmitted
            && let Some(rtt) = capture_time
                .and_then(|time| time.elapsed_us_since(sent.time))
                .filter(|rtt| *rtt > 0)
        {
            self.rtt_samples.push((sent.event_index, rtt));
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
        if self.seen.len() == MAX_PACKETS {
            return Analysis::Finished;
        }
        if payload.is_empty() {
            return Analysis::Pending;
        }
        let identity = (reverse, sequence, payload.len());
        if self.seen.contains(&identity) {
            if !reverse
                && let Some(sent) = self.pending.iter_mut().find(|sent| {
                    sent.sequence == sequence
                        && sent.end_sequence == sequence.wrapping_add(payload.len() as u32)
                })
            {
                sent.retransmitted = true;
            }
            return Analysis::Pending;
        }
        self.seen.push(identity);
        let Some(time) = capture_time else {
            self.reset_timing();
            return Analysis::Pending;
        };
        let elapsed_us = if let Some(first) = self.first_time {
            if let Some(elapsed) = time.elapsed_us_since(first).filter(|elapsed| {
                self.packets
                    .last()
                    .is_none_or(|last| *elapsed >= last.elapsed_us)
            }) {
                elapsed
            } else {
                self.reset_timing();
                self.first_time = Some(time);
                0
            }
        } else {
            self.first_time = Some(time);
            0
        };
        let event_index = self.packets.len();
        self.packets.push(TimedPacket {
            reverse,
            elapsed_us,
        });
        if !reverse {
            self.pending.push(SentPacket {
                sequence,
                end_sequence: sequence.wrapping_add(payload.len() as u32),
                time,
                event_index,
                retransmitted: false,
            });
        }
        let observations = reverse.then(|| self.estimate()).flatten();
        match (observations, self.seen.len() == MAX_PACKETS) {
            (Some(values), true) => Analysis::FinalObservations(values),
            (Some(values), false) => Analysis::Observations(values),
            (None, true) => Analysis::Finished,
            (None, false) => Analysis::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn at(us: u64) -> CaptureTime {
        CaptureTime::Kernel(SystemTime::UNIX_EPOCH + Duration::from_micros(us))
    }

    fn value<'a>(analysis: &'a Analysis, field: &str) -> Option<&'a str> {
        match analysis {
            Analysis::Observations(values) | Analysis::FinalObservations(values) => values
                .iter()
                .find(|item| item.field == field)
                .map(|item| item.value.as_str()),
            _ => None,
        }
    }

    fn three_pairs(response_delay_us: u64) -> Analysis {
        let mut analyzer = TcpRtt::default();
        let mut result = Analysis::Pending;
        for index in 0..3 {
            let start = index * 100_000;
            let sequence = 100 + index as u32 * 40;
            assert!(matches!(
                analyzer.feed_timed(sequence, &[1; 40], false, Some(at(start))),
                Analysis::Pending
            ));
            analyzer.observe_header(0x10, 0, sequence + 40, true, Some(at(start + 10_000)));
            result = analyzer.feed_timed(
                500 + index as u32 * 40,
                &[2; 40],
                true,
                Some(at(start + response_delay_us)),
            );
        }
        result
    }

    #[test]
    fn separates_transport_and_application_delay_across_three_pairs() {
        let proxied = three_pairs(50_000);
        assert_eq!(
            value(&proxied, "tcp_rtt.transport_median_us"),
            Some("10000")
        );
        assert_eq!(
            value(&proxied, "tcp_rtt.application_estimate_us"),
            Some("50000")
        );
        assert_eq!(value(&proxied, "tcp_rtt.diff_us"), Some("40000"));
        assert_eq!(value(&proxied, "tcp_rtt.completed_pairs"), Some("3"));
        assert_eq!(value(&proxied, "tcp_rtt.transport_samples"), Some("3"));
        let direct = three_pairs(15_000);
        assert_eq!(value(&direct, "tcp_rtt.diff_us"), Some("5000"));
    }

    #[test]
    fn correlates_multi_packet_request_and_response_bursts() {
        let mut analyzer = TcpRtt::default();
        let mut result = Analysis::Pending;
        for index in 0..3u32 {
            let start = u64::from(index) * 100_000;
            let sequence = 100 + index * 80;
            analyzer.feed_timed(sequence, &[1; 40], false, Some(at(start)));
            analyzer.feed_timed(sequence + 40, &[2; 40], false, Some(at(start + 1_000)));
            analyzer.observe_header(0x10, 0, sequence + 80, true, Some(at(start + 10_000)));
            analyzer.feed_timed(500 + index * 80, &[3; 40], true, Some(at(start + 50_000)));
            result =
                analyzer.feed_timed(540 + index * 80, &[4; 40], true, Some(at(start + 51_000)));
        }
        assert_eq!(value(&result, "tcp_rtt.transport_median_us"), Some("9000"));
        assert_eq!(
            value(&result, "tcp_rtt.application_estimate_us"),
            Some("50000")
        );
        assert_eq!(value(&result, "tcp_rtt.diff_us"), Some("41000"));
    }

    #[test]
    fn retransmission_and_missing_time_do_not_supply_false_rtt_samples() {
        let mut analyzer = TcpRtt::default();
        analyzer.feed_timed(100, &[1; 40], false, Some(at(0)));
        analyzer.feed_timed(100, &[1; 40], false, Some(at(5_000)));
        analyzer.observe_header(0x10, 0, 140, true, Some(at(10_000)));
        analyzer.feed_timed(500, &[2; 40], true, Some(at(50_000)));
        assert!(analyzer.rtt_samples.is_empty());
        analyzer.feed_timed(140, &[1; 40], false, None);
        assert!(analyzer.packets.is_empty());
        assert!(analyzer.pending.is_empty());
    }
}
