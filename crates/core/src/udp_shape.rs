//! Early UDP wire shape for opaque QUIC and randomized proxy traffic.
use crate::inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer};

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
const PREFIX_BYTES: usize = 64;

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
            let prefix = &payload[..payload.len().min(PREFIX_BYTES)];
            let bits = prefix.iter().map(|byte| byte.count_ones()).sum::<u32>();
            let popcount = if prefix.is_empty() {
                0
            } else {
                1000 * bits as usize / prefix.len()
            };
            let printable = prefix
                .iter()
                .filter(|&&byte| (0x20..=0x7e).contains(&byte))
                .count();
            let printable = if prefix.is_empty() {
                0
            } else {
                1000 * printable / prefix.len()
            };
            self.first_quic = quic_initial_shape(payload);
            self.origin_first_random_like = true;
            for (field, value) in [
                ("udp_shape.first_len", payload.len().to_string()),
                ("udp_shape.first_prefix_len", prefix.len().to_string()),
                ("udp_shape.first_popcount_milli", popcount.to_string()),
                ("udp_shape.first_printable_per_mille", printable.to_string()),
                (
                    "udp_shape.first_entropy_milli",
                    entropy_milli(prefix).to_string(),
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
    let prefix = &payload[..payload.len().min(PREFIX_BYTES)];
    if prefix.len() < 32 || quic_initial_shape(payload) {
        return false;
    }
    let bits = prefix.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
    let printable = prefix
        .iter()
        .filter(|&&byte| (0x20..=0x7e).contains(&byte))
        .count();
    (3400..=4600).contains(&(1000 * bits / prefix.len()))
        && 1000 * printable / prefix.len() < 500
        && entropy_milli(prefix) >= 4500
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

fn entropy_milli(prefix: &[u8]) -> usize {
    if prefix.is_empty() {
        return 0;
    }
    let mut counts = [0usize; 256];
    for &byte in prefix {
        counts[usize::from(byte)] += 1;
    }
    let n = prefix.len() as f64;
    let bits = counts
        .into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let probability = count as f64 / n;
            -probability * probability.log2()
        })
        .sum::<f64>();
    (bits * 1000.0).round() as usize
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
