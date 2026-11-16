//! TLS-in-TLS length-sequence heuristic. A positive result is only a candidate.
use crate::inspect::{Analysis, BidirectionalStreamAnalyzer, Observation};

#[path = "trojan_tree.rs"]
mod tree;

pub const FIELDS: &[&str] = &[
    "trojan.candidate",
    "trojan.seq1",
    "trojan.seq2",
    "trojan.seq3",
    "trojan.seq4",
];
const CCS: [u8; 6] = [20, 3, 3, 0, 1, 1];
const BYTE_LIMIT: usize = 512_000;

#[derive(Default)]
pub struct TrojanSequence {
    first_client: Vec<u8>,
    recent_client: [u8; 6],
    recent_len: usize,
    sequence: [usize; 4],
    sequence_index: usize,
    last_reverse: bool,
    counting: bool,
    seen_bytes: usize,
    finished: bool,
}

impl TrojanSequence {
    fn observations(&self) -> Vec<Observation> {
        let observation = |field, value: String| Observation { field, value };
        vec![
            observation(
                "trojan.candidate",
                tree::classify(self.sequence).to_string(),
            ),
            observation("trojan.seq1", self.sequence[0].to_string()),
            observation("trojan.seq2", self.sequence[1].to_string()),
            observation("trojan.seq3", self.sequence[2].to_string()),
            observation("trojan.seq4", self.sequence[3].to_string()),
        ]
    }
}

impl BidirectionalStreamAnalyzer for TrojanSequence {
    fn feed(&mut self, bytes: &[u8], reverse: bool) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        self.seen_bytes += bytes.len();
        if self.seen_bytes > BYTE_LIMIT {
            self.finished = true;
            return Analysis::Finished;
        }
        if bytes.is_empty() {
            return Analysis::Pending;
        }
        if !reverse && self.first_client.len() < 3 {
            let needed = 3 - self.first_client.len();
            self.first_client
                .extend_from_slice(&bytes[..bytes.len().min(needed)]);
            if self.first_client.len() == 3
                && (!(0x16..=0x17).contains(&self.first_client[0])
                    || self.first_client[1] != 3
                    || self.first_client[2] > 9)
            {
                self.finished = true;
                return Analysis::Finished;
            }
        }
        if !self.counting {
            if reverse {
                return Analysis::Pending;
            }
            for (index, &byte) in bytes.iter().enumerate() {
                if self.recent_len == CCS.len() {
                    self.recent_client.copy_within(1..CCS.len(), 0);
                    self.recent_len -= 1;
                }
                self.recent_client[self.recent_len] = byte;
                self.recent_len += 1;
                if self.recent_len == CCS.len() && self.recent_client == CCS {
                    self.counting = true;
                    self.sequence[0] = bytes.len() - index.saturating_sub(CCS.len() - 1);
                    break;
                }
            }
            return Analysis::Pending;
        }
        if reverse != self.last_reverse {
            self.sequence_index += 1;
            if self.sequence_index == self.sequence.len() {
                self.finished = true;
                return Analysis::FinalObservations(self.observations());
            }
            self.last_reverse = reverse;
        }
        self.sequence[self.sequence_index] += bytes.len();
        Analysis::Pending
    }
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
            .find(|item| item.field == name)
            .map(|item| item.value.as_str())
    }

    fn classify_sequence(lengths: [usize; 4]) -> Analysis {
        let mut analyzer = TrojanSequence::default();
        assert_eq!(analyzer.feed(b"\x16\x03\x03", false), Analysis::Pending);
        let mut ccs = CCS.to_vec();
        ccs.resize(lengths[0], 0);
        assert_eq!(analyzer.feed(&ccs, false), Analysis::Pending);
        assert_eq!(analyzer.feed(&vec![0; lengths[1]], true), Analysis::Pending);
        assert_eq!(
            analyzer.feed(&vec![0; lengths[2]], false),
            Analysis::Pending
        );
        assert_eq!(analyzer.feed(&vec![0; lengths[3]], true), Analysis::Pending);
        let result = analyzer.feed(b"x", false);
        assert_eq!(analyzer.feed(b"later", true), Analysis::Finished);
        result
    }

    #[test]
    fn reports_positive_and_negative_model_paths_with_lengths() {
        let positive = classify_sequence([200, 100, 100, 100]);
        assert_eq!(field(&positive, "trojan.candidate"), Some("true"));
        assert_eq!(field(&positive, "trojan.seq1"), Some("200"));
        assert_eq!(field(&positive, "trojan.seq2"), Some("100"));
        assert_eq!(field(&positive, "trojan.seq3"), Some("100"));
        assert_eq!(field(&positive, "trojan.seq4"), Some("100"));
        assert_eq!(
            field(&classify_sequence([100, 100, 100, 100]), "trojan.candidate"),
            Some("false")
        );
    }

    #[test]
    fn finds_fragmented_ccs_and_rejects_non_tls_prefix() {
        let mut analyzer = TrojanSequence::default();
        assert_eq!(analyzer.feed(b"\x16", false), Analysis::Pending);
        assert_eq!(
            analyzer.feed(b"\x03\x03hello\x14\x03", false),
            Analysis::Pending
        );
        let mut remainder = vec![3, 0, 1, 1];
        remainder.extend([0; 96]);
        assert_eq!(analyzer.feed(&remainder, false), Analysis::Pending);
        assert_eq!(analyzer.feed(&[0; 100], true), Analysis::Pending);
        assert_eq!(analyzer.feed(&[0; 100], false), Analysis::Pending);
        assert_eq!(analyzer.feed(&[0; 100], true), Analysis::Pending);
        let result = analyzer.feed(b"x", false);
        assert_eq!(field(&result, "trojan.seq1"), Some("100"));

        let mut non_tls = TrojanSequence::default();
        assert_eq!(non_tls.feed(b"GET /", false), Analysis::Finished);
        assert_eq!(non_tls.feed(&CCS, false), Analysis::Finished);
    }
}
