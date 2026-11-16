//! First client TCP payload measurements used by OpenGFW's FET heuristic.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation};

pub const FIELDS: &[&str] = &[
    "fet.candidate",
    "fet.sample_len",
    "fet.average_popcount_milli",
    "fet.printable_per_mille",
    "fet.first_six_printable",
    "fet.longest_printable_run",
    "fet.tls_http_prefix",
];
const SAMPLE_LIMIT: usize = 8192;
const HTTP_PREFIXES: &[&[u8]] = &[
    b"GET", b"HEA", b"POS", b"PUT", b"DEL", b"CON", b"OPT", b"TRA", b"PAT",
];

#[derive(Default)]
pub struct FullyEncryptedTraffic {
    finished: bool,
}

impl BidirectionalStreamAnalyzer for FullyEncryptedTraffic {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        if reverse || bytes.is_empty() {
            return Analysis::Pending;
        }
        self.finished = true;
        let bytes = &bytes[..bytes.len().min(SAMPLE_LIMIT)];
        let len = bytes.len();
        let set_bits: usize = bytes.iter().map(|byte| byte.count_ones() as usize).sum();
        let printable_count = bytes.iter().filter(|&&byte| printable(byte)).count();
        let first_six_printable = bytes
            .get(..6)
            .is_some_and(|first| first.iter().all(|&byte| printable(byte)));
        let longest_printable_run = bytes
            .iter()
            .fold((0usize, 0usize), |(longest, current), &byte| {
                let current = if printable(byte) { current + 1 } else { 0 };
                (longest.max(current), current)
            })
            .0;
        let tls_http_prefix = bytes.get(..3).is_some_and(|first| {
            ((0x16..=0x17).contains(&first[0]) && first[1] == 3 && first[2] <= 9)
                || HTTP_PREFIXES.contains(&first)
        });
        let candidate = set_bits * 10 > len * 34
            && set_bits * 10 < len * 46
            && !first_six_printable
            && printable_count * 2 <= len
            && longest_printable_run <= 20
            && !tls_http_prefix;
        let observation = |field, value: String| Observation { field, value };
        Analysis::FinalObservations(vec![
            observation("fet.candidate", candidate.to_string()),
            observation("fet.sample_len", len.to_string()),
            observation(
                "fet.average_popcount_milli",
                (set_bits * 1000 / len).to_string(),
            ),
            observation(
                "fet.printable_per_mille",
                (printable_count * 1000 / len).to_string(),
            ),
            observation("fet.first_six_printable", first_six_printable.to_string()),
            observation(
                "fet.longest_printable_run",
                longest_printable_run.to_string(),
            ),
            observation("fet.tls_http_prefix", tls_http_prefix.to_string()),
        ])
    }
}

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(result: &'a Analysis, name: &str) -> Option<&'a str> {
        let Analysis::FinalObservations(values) = result else {
            return None;
        };
        values
            .iter()
            .find(|value| value.field == name)
            .map(|value| value.value.as_str())
    }

    #[test]
    fn measures_first_client_sample_only() {
        let mut analyzer = FullyEncryptedTraffic::default();
        assert_eq!(analyzer.feed(&[0x0f; 64], true), Analysis::Pending);
        assert_eq!(analyzer.feed(b"", false), Analysis::Pending);
        let result = analyzer.feed(&[0x0f; 64], false);
        assert_eq!(field(&result, "fet.candidate"), Some("true"));
        assert_eq!(field(&result, "fet.sample_len"), Some("64"));
        assert_eq!(field(&result, "fet.average_popcount_milli"), Some("4000"));
        assert_eq!(field(&result, "fet.printable_per_mille"), Some("0"));
        assert_eq!(field(&result, "fet.longest_printable_run"), Some("0"));
        assert_eq!(analyzer.feed(b"GET /", false), Analysis::Finished);
    }

    #[test]
    fn plaintext_and_tls_prefix_are_exempt() {
        for sample in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"\x16\x03\x03\x00\x20\x01".as_slice(),
        ] {
            let result = FullyEncryptedTraffic::default().feed(sample, false);
            assert_eq!(field(&result, "fet.candidate"), Some("false"));
            assert_eq!(field(&result, "fet.tls_http_prefix"), Some("true"));
        }
    }

    #[test]
    fn reports_exact_printability_boundaries() {
        let result = FullyEncryptedTraffic::default().feed(b"abcde0\x00\x00", false);
        assert_eq!(field(&result, "fet.first_six_printable"), Some("true"));
        assert_eq!(field(&result, "fet.longest_printable_run"), Some("6"));
        assert_eq!(field(&result, "fet.printable_per_mille"), Some("750"));
    }

    #[test]
    fn each_non_prefix_exemption_prevents_a_candidate() {
        let mut first_six = vec![b'?'; 6];
        first_six.extend([0x0f; 58]);
        let mut majority_printable = Vec::new();
        for _ in 0..32 {
            majority_printable.extend([0x02, b'?']);
        }
        majority_printable.push(b'?');
        let mut long_run = vec![0x07; 43];
        long_run.extend([b'?'; 21]);
        for sample in [
            vec![0; 64],
            vec![0xff; 64],
            first_six,
            majority_printable,
            long_run,
        ] {
            let result = FullyEncryptedTraffic::default().feed(&sample, false);
            assert_eq!(field(&result, "fet.candidate"), Some("false"), "{sample:?}");
        }
    }
}
