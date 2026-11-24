//! Early UDP wire shape for opaque QUIC and randomized proxy traffic.
use crate::wire_stats::PrefixStats;
use crate::{
    CaptureTime,
    inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer},
};

pub const FIELDS: &[&str] = &[
    "udp_shape.first_len",
    "udp_shape.first_prefix_len",
    "udp_shape.first_popcount_milli",
    "udp_shape.first_printable_per_mille",
    "udp_shape.first_entropy_milli",
    "udp_shape.first_quic_initial_shape",
    "udp_shape.signed_lengths",
    "udp_shape.packet_count",
    "udp_shape.origin_first_run",
    "udp_shape.origin_first_bytes",
    "udp_shape.reply_seen",
    "udp_shape.fragmented_random_candidate",
    "udp_shape.time_source",
    "udp_shape.last_gap_us",
    "udp_shape.gaps_us",
    "udp_shape.origin_first_span_us",
    "udp_shape.first_reply_delay_us",
];

const MAX_PACKETS: usize = 8;

#[derive(Default)]
pub struct UdpShape {
    lengths: Vec<i64>,
    first_quic: bool,
    origin_first_run: usize,
    origin_first_bytes: usize,
    origin_first_random_like: bool,
    reply_seen: bool,
    candidate: bool,
    first_time: Option<CaptureTime>,
    last_time: Option<CaptureTime>,
    gaps: Vec<String>,
}

impl UdpStreamAnalyzer for UdpShape {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        self.feed_timed(payload, reverse, None)
    }

    fn feed_timed(
        &mut self,
        payload: &[u8],
        reverse: bool,
        capture_time: Option<CaptureTime>,
    ) -> UdpStreamAnalysis {
        if self.lengths.len() == MAX_PACKETS {
            return UdpStreamAnalysis::Finished;
        }
        let first = self.lengths.is_empty();
        let mut observations = Vec::new();
        if first {
            self.first_time = capture_time;
        } else {
            let gap = capture_time
                .zip(self.last_time)
                .and_then(|(now, before)| now.elapsed_us_since(before));
            let gap = gap.map_or_else(|| "?".to_owned(), |value| value.to_string());
            self.gaps.push(gap.clone());
            observations.push(Observation {
                field: "udp_shape.last_gap_us",
                value: gap,
            });
        }
        self.last_time = capture_time;
        observations.push(Observation {
            field: "udp_shape.time_source",
            value: capture_time.map_or("none", CaptureTime::source).to_owned(),
        });
        if first {
            let stats = PrefixStats::sample(payload);
            self.first_quic = quic_initial_shape(payload);
            self.origin_first_random_like = true;
            for (field, value) in [
                ("udp_shape.first_len", payload.len().to_string()),
                ("udp_shape.first_prefix_len", stats.len.to_string()),
                (
                    "udp_shape.first_popcount_milli",
                    stats.popcount_milli.to_string(),
                ),
                (
                    "udp_shape.first_printable_per_mille",
                    stats.printable_per_mille.to_string(),
                ),
                (
                    "udp_shape.first_entropy_milli",
                    stats.entropy_milli.to_string(),
                ),
                (
                    "udp_shape.first_quic_initial_shape",
                    self.first_quic.to_string(),
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
                    field: "udp_shape.first_reply_delay_us",
                    value: delay.map_or_else(|| "?".to_owned(), |value| value.to_string()),
                });
            }
            self.reply_seen = true;
        } else if !self.reply_seen {
            self.origin_first_run += 1;
            self.origin_first_bytes += payload.len();
            self.origin_first_random_like &= random_like(payload);
            let span = capture_time
                .zip(self.first_time)
                .and_then(|(now, before)| now.elapsed_us_since(before));
            observations.push(Observation {
                field: "udp_shape.origin_first_span_us",
                value: span.map_or_else(|| "?".to_owned(), |value| value.to_string()),
            });
            if self.origin_first_run >= 2
                && self.origin_first_bytes >= 1200
                && self.origin_first_random_like
                && !self.first_quic
            {
                self.candidate = true;
            }
        }
        let length = payload.len() as i64;
        self.lengths.push(if reverse { -length } else { length });
        for (field, value) in [
            ("udp_shape.gaps_us", self.gaps.join(",")),
            (
                "udp_shape.signed_lengths",
                self.lengths
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("udp_shape.packet_count", self.lengths.len().to_string()),
            (
                "udp_shape.origin_first_run",
                self.origin_first_run.to_string(),
            ),
            (
                "udp_shape.origin_first_bytes",
                self.origin_first_bytes.to_string(),
            ),
            ("udp_shape.reply_seen", self.reply_seen.to_string()),
            (
                "udp_shape.fragmented_random_candidate",
                self.candidate.to_string(),
            ),
        ] {
            observations.push(Observation { field, value });
        }
        if self.lengths.len() == MAX_PACKETS {
            UdpStreamAnalysis::FinalObservations(observations)
        } else {
            UdpStreamAnalysis::Observations(observations)
        }
    }
}

fn random_like(payload: &[u8]) -> bool {
    !quic_initial_shape(payload) && PrefixStats::sample(payload).random_like()
}

fn quic_initial_shape(payload: &[u8]) -> bool {
    let Some(header) = payload.get(..5) else {
        return false;
    };
    let version = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    match version {
        1 => header[0] & 0xf0 == 0xc0,
        0x6b33_43cf => header[0] & 0xf0 == 0xd0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn values(result: UdpStreamAnalysis) -> Vec<Observation> {
        match result {
            UdpStreamAnalysis::Observations(values)
            | UdpStreamAnalysis::FinalObservations(values) => values,
            _ => panic!("expected wire observations"),
        }
    }

    fn field<'a>(values: &'a [Observation], name: &str) -> Option<&'a str> {
        values
            .iter()
            .find(|value| value.field == name)
            .map(|value| value.value.as_str())
    }

    #[test]
    fn early_random_fragments_produce_a_candidate() {
        let mut shape = UdpShape::default();
        let first = (0..700)
            .map(|index| (index * 73 + 151) as u8)
            .collect::<Vec<_>>();
        let observed = values(shape.feed(&first, false));
        assert_eq!(field(&observed, "udp_shape.first_len"), Some("700"));
        assert_eq!(
            field(&observed, "udp_shape.first_popcount_milli"),
            Some("3984")
        );
        assert_eq!(
            field(&observed, "udp_shape.first_printable_per_mille"),
            Some("421")
        );
        assert_eq!(
            field(&observed, "udp_shape.first_entropy_milli"),
            Some("6000")
        );
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("false")
        );
        let observed = values(shape.feed(&first, false));
        assert_eq!(
            field(&observed, "udp_shape.signed_lengths"),
            Some("700,700")
        );
        assert_eq!(
            field(&observed, "udp_shape.origin_first_bytes"),
            Some("1400")
        );
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("true")
        );
        let observed = values(shape.feed(&first[..120], true));
        assert_eq!(
            field(&observed, "udp_shape.signed_lengths"),
            Some("700,700,-120")
        );
        assert_eq!(field(&observed, "udp_shape.reply_seen"), Some("true"));
    }

    #[test]
    fn reports_first_flight_and_reply_timing() {
        let mut shape = UdpShape::default();
        let at =
            |micros| CaptureTime::Kernel(SystemTime::UNIX_EPOCH + Duration::from_micros(micros));
        values(shape.feed_timed(&[1; 600], false, Some(at(1_000))));
        let observed = values(shape.feed_timed(&[2; 600], false, Some(at(4_000))));
        assert_eq!(field(&observed, "udp_shape.last_gap_us"), Some("3000"));
        assert_eq!(
            field(&observed, "udp_shape.origin_first_span_us"),
            Some("3000")
        );
        let observed = values(shape.feed_timed(&[3; 50], true, Some(at(20_000))));
        assert_eq!(
            field(&observed, "udp_shape.first_reply_delay_us"),
            Some("19000")
        );
        assert_eq!(field(&observed, "udp_shape.gaps_us"), Some("3000,16000"));
        assert_eq!(field(&observed, "udp_shape.time_source"), Some("kernel"));
    }

    #[test]
    fn standard_quic_initial_and_short_dns_do_not_match_fragment_candidate() {
        let mut quic = vec![0xc0, 0, 0, 0, 1];
        quic.extend([0x96, 0xa5].repeat(350));
        let mut shape = UdpShape::default();
        let observed = values(shape.feed(&quic, false));
        assert_eq!(
            field(&observed, "udp_shape.first_quic_initial_shape"),
            Some("true")
        );
        let observed = values(shape.feed(&quic, false));
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("false")
        );

        let patterned = [0x96, 0xa5].repeat(350);
        let mut low_entropy = UdpShape::default();
        values(low_entropy.feed(&patterned, false));
        let observed = values(low_entropy.feed(&patterned, false));
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("false")
        );

        let mut dns = UdpShape::default();
        let observed = values(dns.feed(&[0; 12], false));
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("false")
        );
        let observed = values(dns.feed(&[0; 12], false));
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("false")
        );
    }

    #[test]
    #[ignore = "requires the locally generated Hysteria2 obfuscation sample"]
    fn official_hysteria2_obfuscation_samples() {
        // Hysteria extras/v2 v2.14.0 wraps an ngtcp2 QUIC Initial from the
        // read-only OpenGFW fixtures. Each mode contains 16 independent runs.
        let fixture = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/hy2-capture/hy2-obfs-v2.14.bin"),
        )
        .unwrap();
        let mut cursor = 0;
        let mut take = |length: usize| {
            let bytes = &fixture[cursor..cursor + length];
            cursor += length;
            bytes
        };
        assert_eq!(take(4), b"HY2O");
        assert_eq!(take(1), [1]);
        assert_eq!(take(1), [16]);
        for mode in [1, 2] {
            assert_eq!(take(1), [mode]);
            let mut candidates = 0;
            for _ in 0..16 {
                let count = usize::from(take(1)[0]);
                assert!(if mode == 1 {
                    (2..=8).contains(&count)
                } else {
                    count == 1
                });
                let mut shape = UdpShape::default();
                let mut candidate = false;
                for index in 0..count {
                    let length = u16::from_be_bytes(take(2).try_into().unwrap()) as usize;
                    let packet = take(length);
                    let observed = values(shape.feed(packet, false));
                    if index == 0 {
                        assert_eq!(
                            field(&observed, "udp_shape.first_quic_initial_shape"),
                            Some("false")
                        );
                    }
                    candidate |=
                        field(&observed, "udp_shape.fragmented_random_candidate") == Some("true");
                }
                candidates += usize::from(candidate);
            }
            assert_eq!(candidates, if mode == 1 { 16 } else { 0 });
        }
        assert_eq!(cursor, fixture.len());
    }

    #[test]
    #[ignore = "requires the read-only OpenGFW QUIC capture fixtures"]
    fn real_quic_initials_do_not_trigger_fragment_candidate() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../references/opengfw/analyzer/udp/testdata");
        for client in [
            "chrome153",
            "firefox153esr",
            "curl8.14-openssl3.5",
            "quiche",
            "ngtcp2-1.11",
            "aioquic1.2",
        ] {
            let payload = std::fs::read(base.join(format!("quic-{client}-0.bin"))).unwrap();
            let mut shape = UdpShape::default();
            let observations = values(shape.feed(&payload, false));
            assert_eq!(
                field(&observations, "udp_shape.first_quic_initial_shape"),
                Some("true"),
                "{client}"
            );
            assert_eq!(
                field(&observations, "udp_shape.fragmented_random_candidate"),
                Some("false"),
                "{client}"
            );
        }
    }
}
