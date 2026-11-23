//! Early UDP wire shape for opaque QUIC and randomized proxy traffic.
use crate::inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer};
use crate::wire_stats::PrefixStats;

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
}

impl UdpStreamAnalyzer for UdpShape {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        if self.lengths.len() == MAX_PACKETS {
            return UdpStreamAnalysis::Finished;
        }
        let first = self.lengths.is_empty();
        let mut observations = Vec::new();
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
            self.reply_seen = true;
        } else if !self.reply_seen {
            self.origin_first_run += 1;
            self.origin_first_bytes += payload.len();
            self.origin_first_random_like &= random_like(payload);
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
