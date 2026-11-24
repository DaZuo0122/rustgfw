//! Early UDP wire shape for opaque QUIC and randomized proxy traffic.
use crate::wire_stats::PrefixStats;
use crate::{
    CaptureTime,
    inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer},
    quic,
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
    "udp_shape.short_header_form_packets",
    "udp_shape.short_header_fixed_bit_packets",
    "udp_shape.short_header_initial_cid_matches",
    "udp_shape.short_header_initial_cid_match_bytes",
    "udp_shape.quic_zero_rtt_shape_datagrams",
    "udp_shape.quic_handshake_shape_datagrams",
    "udp_shape.quic_coalesced_long_header_datagrams",
    "udp_shape.origin_first_run",
    "udp_shape.origin_first_bytes",
    "udp_shape.origin_first_varied_lengths",
    "udp_shape.origin_first_random_like",
    "udp_shape.origin_first_random_like_packets",
    "udp_shape.reply_seen",
    "udp_shape.fragmented_random_candidate",
    "udp_shape.time_source",
    "udp_shape.last_gap_us",
    "udp_shape.gaps_us",
    "udp_shape.origin_first_span_us",
    "udp_shape.first_reply_delay_us",
];

const MAX_PACKETS: usize = 16;

#[derive(Default)]
pub struct UdpShape {
    lengths: Vec<i64>,
    short_header_form_packets: usize,
    short_header_fixed_bit_packets: usize,
    short_header_initial_cid_matches: usize,
    short_header_initial_cid_match_bytes: usize,
    initial_scids: [Option<Vec<u8>>; 2],
    quic_zero_rtt_shape_datagrams: usize,
    quic_handshake_shape_datagrams: usize,
    quic_coalesced_long_header_datagrams: usize,
    first_quic: bool,
    origin_first_run: usize,
    origin_first_bytes: usize,
    origin_first_varied_lengths: bool,
    origin_first_random_like: bool,
    origin_first_random_like_packets: usize,
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
            self.origin_first_varied_lengths |= self
                .lengths
                .first()
                .is_some_and(|&first_len| first_len != payload.len() as i64);
            let packet_random_like = random_like(payload);
            self.origin_first_random_like &= packet_random_like;
            self.origin_first_random_like_packets += usize::from(packet_random_like);
            let span = capture_time
                .zip(self.first_time)
                .and_then(|(now, before)| now.elapsed_us_since(before));
            observations.push(Observation {
                field: "udp_shape.origin_first_span_us",
                value: span.map_or_else(|| "?".to_owned(), |value| value.to_string()),
            });
            if self.origin_first_run >= 2
                && self.origin_first_bytes >= 1200
                && self.origin_first_varied_lengths
                && self.origin_first_random_like
                && !self.first_quic
            {
                self.candidate = true;
            }
        }
        let length = payload.len() as i64;
        let quic_shape = quic::wire_shape(payload);
        let direction = usize::from(reverse);
        if let Some(scid) = quic_shape.initial_scid.filter(|scid| !scid.is_empty()) {
            self.initial_scids[direction].get_or_insert_with(|| scid.to_vec());
        }
        if payload.len() >= 18 {
            let first_byte = payload[0];
            if first_byte & 0x80 == 0 {
                self.short_header_form_packets += 1;
                if first_byte & 0x40 != 0 {
                    self.short_header_fixed_bit_packets += 1;
                }
                if let Some(scid) = self.initial_scids[1 - direction].as_deref()
                    && payload[1..].starts_with(scid)
                {
                    self.short_header_initial_cid_matches += 1;
                    self.short_header_initial_cid_match_bytes =
                        self.short_header_initial_cid_match_bytes.max(scid.len());
                }
            }
        }
        self.quic_zero_rtt_shape_datagrams += usize::from(quic_shape.zero_rtt);
        self.quic_handshake_shape_datagrams += usize::from(quic_shape.handshake);
        self.quic_coalesced_long_header_datagrams += usize::from(quic_shape.coalesced);
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
                "udp_shape.short_header_form_packets",
                self.short_header_form_packets.to_string(),
            ),
            (
                "udp_shape.short_header_fixed_bit_packets",
                self.short_header_fixed_bit_packets.to_string(),
            ),
            (
                "udp_shape.short_header_initial_cid_matches",
                self.short_header_initial_cid_matches.to_string(),
            ),
            (
                "udp_shape.short_header_initial_cid_match_bytes",
                self.short_header_initial_cid_match_bytes.to_string(),
            ),
            (
                "udp_shape.quic_zero_rtt_shape_datagrams",
                self.quic_zero_rtt_shape_datagrams.to_string(),
            ),
            (
                "udp_shape.quic_handshake_shape_datagrams",
                self.quic_handshake_shape_datagrams.to_string(),
            ),
            (
                "udp_shape.quic_coalesced_long_header_datagrams",
                self.quic_coalesced_long_header_datagrams.to_string(),
            ),
            (
                "udp_shape.origin_first_run",
                self.origin_first_run.to_string(),
            ),
            (
                "udp_shape.origin_first_bytes",
                self.origin_first_bytes.to_string(),
            ),
            (
                "udp_shape.origin_first_varied_lengths",
                self.origin_first_varied_lengths.to_string(),
            ),
            (
                "udp_shape.origin_first_random_like",
                self.origin_first_random_like.to_string(),
            ),
            (
                "udp_shape.origin_first_random_like_packets",
                self.origin_first_random_like_packets.to_string(),
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
        let mut second = first.clone();
        second.push(0x67);
        let observed = values(shape.feed(&second, false));
        assert_eq!(
            field(&observed, "udp_shape.signed_lengths"),
            Some("700,701")
        );
        assert_eq!(
            field(&observed, "udp_shape.origin_first_bytes"),
            Some("1401")
        );
        assert_eq!(
            field(&observed, "udp_shape.origin_first_varied_lengths"),
            Some("true")
        );
        assert_eq!(
            field(&observed, "udp_shape.fragmented_random_candidate"),
            Some("true")
        );
        assert_eq!(
            field(&observed, "udp_shape.origin_first_random_like"),
            Some("true")
        );
        assert_eq!(
            field(&observed, "udp_shape.origin_first_random_like_packets"),
            Some("2")
        );
        let observed = values(shape.feed(&first[..120], true));
        assert_eq!(
            field(&observed, "udp_shape.signed_lengths"),
            Some("700,701,-120")
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
    fn short_header_form_and_greased_fixed_bit_are_separate() {
        let mut shape = UdpShape::default();
        let packet = |first, length| {
            let mut bytes = vec![0x5a; length];
            bytes[0] = first;
            bytes
        };
        let observed = values(shape.feed(&packet(0x43, 40), false));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("1")
        );
        assert_eq!(
            field(&observed, "udp_shape.short_header_fixed_bit_packets"),
            Some("1")
        );
        let observed = values(shape.feed(&packet(0x03, 40), false));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("2")
        );
        assert_eq!(
            field(&observed, "udp_shape.short_header_fixed_bit_packets"),
            Some("1")
        );
        let observed = values(shape.feed(&packet(0xc3, 40), false));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("2")
        );
        assert_eq!(
            field(&observed, "udp_shape.short_header_fixed_bit_packets"),
            Some("1")
        );
        let observed = values(shape.feed(&packet(0x43, 17), false));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("2")
        );
        let observed = values(shape.feed(&packet(0x43, 40), true));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("3")
        );
        assert_eq!(
            field(&observed, "udp_shape.short_header_fixed_bit_packets"),
            Some("2")
        );
    }

    #[test]
    fn observes_v1_and_v2_coalesced_long_header_shapes() {
        fn long_packet(first: u8, version: u32, initial: bool) -> Vec<u8> {
            let mut packet = vec![first];
            packet.extend_from_slice(&version.to_be_bytes());
            packet.extend_from_slice(&[0, 0]); // empty destination and source connection IDs
            if initial {
                packet.push(0); // empty Initial token
            }
            packet.push(17); // packet number plus protected payload
            packet.extend_from_slice(&[0; 17]);
            packet
        }

        let mut shape = UdpShape::default();
        let mut v1 = long_packet(0xc0, 1, true);
        v1.extend(long_packet(0xd0, 1, false));
        v1.extend(long_packet(0xe0, 1, false));
        let observed = values(shape.feed(&v1, false));
        assert_eq!(
            field(&observed, "udp_shape.quic_zero_rtt_shape_datagrams"),
            Some("1")
        );
        assert_eq!(
            field(&observed, "udp_shape.quic_handshake_shape_datagrams"),
            Some("1")
        );
        assert_eq!(
            field(&observed, "udp_shape.quic_coalesced_long_header_datagrams"),
            Some("1")
        );

        let mut v2 = long_packet(0xd0, 0x6b33_43cf, true);
        v2.extend(long_packet(0xe0, 0x6b33_43cf, false));
        v2.extend(long_packet(0xf0, 0x6b33_43cf, false));
        let observed = values(shape.feed(&v2, true));
        assert_eq!(
            field(&observed, "udp_shape.quic_zero_rtt_shape_datagrams"),
            Some("2")
        );
        assert_eq!(
            field(&observed, "udp_shape.quic_handshake_shape_datagrams"),
            Some("2")
        );
        assert_eq!(
            field(&observed, "udp_shape.quic_coalesced_long_header_datagrams"),
            Some("2")
        );
        let observed = values(shape.feed(&v1[..10], false));
        assert_eq!(
            field(&observed, "udp_shape.quic_zero_rtt_shape_datagrams"),
            Some("2")
        );
    }

    #[test]
    fn short_headers_match_opposite_initial_source_cid_after_handshake() {
        fn initial(first: u8, version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
            let mut bytes = vec![first];
            bytes.extend(version.to_be_bytes());
            bytes.push(dcid.len() as u8);
            bytes.extend(dcid);
            bytes.push(scid.len() as u8);
            bytes.extend(scid);
            bytes.extend([0, 17]);
            bytes.extend([0; 17]);
            bytes
        }
        for (first, version) in [(0xc0, 1), (0xd0, 0x6b33_43cf)] {
            let mut shape = UdpShape::default();
            let client_scid = [1, 2, 3, 4];
            let server_scid = [5, 6, 7, 8, 9, 10];
            values(shape.feed(&[0x40; 24], false));
            values(shape.feed(&initial(first, version, &[11; 8], &client_scid), false));
            values(shape.feed(&initial(first, version, &client_scid, &server_scid), true));

            let mut client_short = vec![0x40];
            client_short.extend(server_scid);
            client_short.extend([0xaa; 20]);
            let observed = values(shape.feed(&client_short, false));
            assert_eq!(
                field(&observed, "udp_shape.short_header_initial_cid_matches"),
                Some("1")
            );
            assert_eq!(
                field(&observed, "udp_shape.short_header_initial_cid_match_bytes"),
                Some("6")
            );

            let mut wrong = client_short.clone();
            wrong[1] ^= 1;
            let observed = values(shape.feed(&wrong, false));
            assert_eq!(
                field(&observed, "udp_shape.short_header_initial_cid_matches"),
                Some("1")
            );

            let mut server_short = vec![0x40];
            server_short.extend(client_scid);
            server_short.extend([0xbb; 20]);
            let observed = values(shape.feed(&server_short, true));
            assert_eq!(
                field(&observed, "udp_shape.short_header_initial_cid_matches"),
                Some("2")
            );
        }
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
        assert_eq!(
            field(&observed, "udp_shape.origin_first_random_like"),
            Some("false")
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

        let random = (0..1258)
            .map(|index| (index * 73 + 151) as u8)
            .collect::<Vec<_>>();
        let mut equal_lengths = UdpShape::default();
        values(equal_lengths.feed(&random, false));
        let observed = values(equal_lengths.feed(&random, false));
        assert_eq!(
            field(&observed, "udp_shape.origin_first_varied_lengths"),
            Some("false")
        );
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
    #[ignore = "requires local captures from the official Hysteria2 client"]
    fn official_hysteria2_client_first_flights() {
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hy2-capture");
        for run in 0..16 {
            for (mode, expected) in [("plain", false), ("salamander", false), ("gecko", true)] {
                let capture = std::fs::read(base.join(format!("client-{mode}-{run}.bin"))).unwrap();
                assert_eq!(&capture[..4], b"HY2C");
                assert_eq!(capture[4], 1);
                let mut cursor = 6;
                let mut shape = UdpShape::default();
                let mut candidate = false;
                for index in 0..capture[5] {
                    let length = u16::from_be_bytes(capture[cursor..cursor + 2].try_into().unwrap())
                        as usize;
                    cursor += 2;
                    if index < MAX_PACKETS as u8 {
                        let observed = values(shape.feed(&capture[cursor..cursor + length], false));
                        if index == 1 && mode == "salamander" {
                            let random_packets =
                                field(&observed, "udp_shape.origin_first_random_like_packets")
                                    .unwrap()
                                    .parse::<usize>()
                                    .unwrap();
                            assert!(random_packets >= 1, "{mode} run {run}");
                            assert_eq!(
                                field(&observed, "udp_shape.origin_first_varied_lengths"),
                                Some("false"),
                                "{mode} run {run}"
                            );
                        }
                        if index == 1 && mode == "plain" {
                            assert_eq!(
                                field(&observed, "udp_shape.origin_first_random_like_packets"),
                                Some("0"),
                                "{mode} run {run}"
                            );
                        }
                        candidate |= field(&observed, "udp_shape.fragmented_random_candidate")
                            == Some("true");
                    }
                    cursor += length;
                }
                assert_eq!(cursor, capture.len(), "{mode} run {run}");
                assert_eq!(candidate, expected, "{mode} run {run}");
            }
        }
    }

    #[test]
    #[ignore = "requires a local official Hysteria2 client/server session capture"]
    fn official_hysteria2_session_exposes_short_header_run() {
        let capture = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/hy2-capture/local-session.bin"),
        )
        .unwrap();
        assert_eq!(&capture[..5], b"HY2S\x01");
        let count = u16::from_be_bytes(capture[5..7].try_into().unwrap());
        let mut cursor = 7;
        let mut packets = Vec::new();
        for _ in 0..count {
            let reverse = capture[cursor] != 0;
            cursor += 1;
            let length =
                u16::from_be_bytes(capture[cursor..cursor + 2].try_into().unwrap()) as usize;
            cursor += 2;
            packets.push((reverse, &capture[cursor..cursor + length]));
            cursor += length;
        }
        assert_eq!(cursor, capture.len());
        let window = packets
            .windows(8)
            .find(|window| {
                window
                    .iter()
                    .all(|(_, packet)| packet.len() >= 18 && packet[0] & 0xc0 == 0x40)
            })
            .unwrap();
        let first_direction = window[0].0;
        let mut shape = UdpShape::default();
        let mut observed = Vec::new();
        for (index, &(direction, packet)) in window.iter().enumerate() {
            observed = values(shape.feed(packet, direction != first_direction));
            if index == 0 {
                assert_eq!(
                    field(&observed, "udp_shape.first_quic_initial_shape"),
                    Some("false")
                );
            }
        }
        assert_eq!(field(&observed, "udp_shape.packet_count"), Some("8"));
        assert_eq!(
            field(&observed, "udp_shape.short_header_form_packets"),
            Some("8")
        );
        assert_eq!(
            field(&observed, "udp_shape.short_header_fixed_bit_packets"),
            Some("8")
        );
    }

    #[test]
    #[ignore = "requires locally captured ordinary HTTP/3 and resumed 0-RTT sessions"]
    fn local_http3_resumption_exposes_zero_rtt_shape() {
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hy2-capture");
        let count_zero_rtt = |name| {
            let capture = std::fs::read(base.join(name)).unwrap();
            assert_eq!(&capture[..4], b"H3B1");
            let count = u16::from_be_bytes(capture[4..6].try_into().unwrap());
            let mut cursor = 6;
            let mut shape = UdpShape::default();
            let mut observed = Vec::new();
            for index in 0..count {
                let reverse = capture[cursor] == 1;
                let length =
                    u16::from_be_bytes(capture[cursor + 9..cursor + 11].try_into().unwrap())
                        as usize;
                cursor += 11;
                if index < MAX_PACKETS as u16 {
                    observed = values(shape.feed(&capture[cursor..cursor + length], reverse));
                }
                cursor += length;
            }
            assert_eq!(cursor, capture.len());
            (
                field(&observed, "udp_shape.quic_zero_rtt_shape_datagrams")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
                field(&observed, "udp_shape.short_header_initial_cid_matches")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap(),
            )
        };
        let baseline = count_zero_rtt("h3-baseline.bin");
        let resumed = count_zero_rtt("h3-zero-rtt.bin");
        assert_eq!(baseline.0, 0);
        assert!(resumed.0 >= 1);
        assert!(baseline.1 >= 4);
        assert!(resumed.1 >= 4);
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
