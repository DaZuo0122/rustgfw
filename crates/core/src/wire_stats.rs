//! Small prefix sample used by both TCP and UDP outer-shape analyzers.

pub(crate) struct PrefixStats {
    pub len: usize,
    pub popcount_milli: usize,
    pub printable_per_mille: usize,
    pub entropy_milli: usize,
}

impl PrefixStats {
    pub fn sample(payload: &[u8]) -> Self {
        let prefix = &payload[..payload.len().min(64)];
        if prefix.is_empty() {
            return Self {
                len: 0,
                popcount_milli: 0,
                printable_per_mille: 0,
                entropy_milli: 0,
            };
        }
        let bits = prefix.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
        let printable = prefix
            .iter()
            .filter(|&&byte| (0x20..=0x7e).contains(&byte))
            .count();
        let mut counts = [0usize; 256];
        for &byte in prefix {
            counts[usize::from(byte)] += 1;
        }
        let n = prefix.len() as f64;
        let entropy = counts
            .into_iter()
            .filter(|&count| count > 0)
            .map(|count| {
                let probability = count as f64 / n;
                -probability * probability.log2()
            })
            .sum::<f64>();
        Self {
            len: prefix.len(),
            popcount_milli: 1000 * bits / prefix.len(),
            printable_per_mille: 1000 * printable / prefix.len(),
            entropy_milli: (entropy * 1000.0).round() as usize,
        }
    }

    pub fn random_like(&self) -> bool {
        self.len >= 32
            && (3400..=4600).contains(&self.popcount_milli)
            && self.printable_per_mille <= 500
            && self.entropy_milli >= 4500
    }
}
