//! Per-direction TCP byte reassembly, independent of packet I/O and analyzers.
//! The caller owns flow lifetime, FIN/RST handling, and the opposite direction.

#[derive(Debug, PartialEq, Eq)]
pub enum ReassemblyError {
    BufferLimit,
    ConflictingOverlap,
}

struct Segment {
    sequence: u32,
    bytes: Vec<u8>,
}

pub struct Reassembler {
    next: Option<u32>,
    pending: Vec<Segment>,
    buffered: usize,
    limit: usize,
}

impl Reassembler {
    pub fn new(limit: usize) -> Self {
        Self {
            next: None,
            pending: Vec::new(),
            buffered: 0,
            limit,
        }
    }
    pub fn buffered_bytes(&self) -> usize {
        self.buffered
    }

    /// SYN occupies one sequence number. Without SYN, capture starts at the
    /// first observed byte; callers must mark such streams as midstream.
    /// Returns only newly contiguous bytes, never retransmitted bytes.
    pub fn feed(
        &mut self,
        sequence: u32,
        syn: bool,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ReassemblyError> {
        let mut sequence = sequence.wrapping_add(u32::from(syn));
        let next = *self.next.get_or_insert(sequence);
        let mut bytes = bytes;
        let distance = sequence.wrapping_sub(next) as i32;
        if distance < 0 {
            let skip = (next.wrapping_sub(sequence) as usize).min(bytes.len());
            bytes = &bytes[skip..];
            sequence = sequence.wrapping_add(skip as u32);
        }
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        // Reject contradictory buffered overlaps rather than presenting an
        // invented byte stream to an analyzer. Already delivered data is ignored.
        let start = sequence.wrapping_sub(next) as usize;
        for segment in &self.pending {
            let other = segment.sequence.wrapping_sub(next) as usize;
            let lo = start.max(other);
            let hi = (start + bytes.len()).min(other + segment.bytes.len());
            if lo < hi && bytes[lo - start..hi - start] != segment.bytes[lo - other..hi - other] {
                return Err(ReassemblyError::ConflictingOverlap);
            }
            if other <= start && other + segment.bytes.len() >= start + bytes.len() {
                return Ok(Vec::new());
            }
        }
        if start != 0 && self.buffered + bytes.len() > self.limit {
            return Err(ReassemblyError::BufferLimit);
        }
        self.buffered += bytes.len();
        self.pending.push(Segment {
            sequence,
            bytes: bytes.to_vec(),
        });
        self.pending.sort_by_key(|s| s.sequence.wrapping_sub(next));
        let mut output = Vec::new();
        let mut cursor = next;
        while let Some(segment) = self.pending.first() {
            if (segment.sequence.wrapping_sub(cursor) as i32) > 0 {
                break;
            }
            let segment = self.pending.remove(0);
            self.buffered -= segment.bytes.len();
            let skip = (cursor.wrapping_sub(segment.sequence) as usize).min(segment.bytes.len());
            output.extend_from_slice(&segment.bytes[skip..]);
            cursor = cursor.wrapping_add((segment.bytes.len() - skip) as u32);
        }
        self.next = Some(cursor);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn out_of_order_retransmission_and_wrap() {
        let mut r = Reassembler::new(1024);
        assert!(r.feed(u32::MAX - 2, true, b"").unwrap().is_empty());
        assert!(r.feed(1, false, b"def").unwrap().is_empty());
        assert_eq!(r.feed(u32::MAX - 1, false, b"abc").unwrap(), b"abcdef");
        assert!(r.feed(1, false, b"def").unwrap().is_empty());
        assert_eq!(r.buffered_bytes(), 0);
    }
    #[test]
    fn overlap_and_budget() {
        let mut r = Reassembler::new(4);
        r.feed(0, true, b"").unwrap();
        r.feed(3, false, b"cd").unwrap();
        assert_eq!(
            r.feed(4, false, b"X"),
            Err(ReassemblyError::ConflictingOverlap)
        );
        assert_eq!(r.feed(6, false, b"xyz"), Err(ReassemblyError::BufferLimit));
        assert_eq!(r.feed(1, false, b"abc").unwrap(), b"abcd");
    }
}
