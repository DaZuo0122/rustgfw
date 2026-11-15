//! Plaintext TLS ClientHello inspection; ECH inner names are not visible.
use crate::inspect::{Analysis, Observation, StreamAnalyzer};

pub struct TlsSni {
    records: Vec<u8>,
    handshake: Vec<u8>,
    finished: bool,
    buffer_limit: usize,
}
impl Default for TlsSni {
    fn default() -> Self {
        Self::with_buffer_limit(131072)
    }
}
impl TlsSni {
    pub fn with_buffer_limit(buffer_limit: usize) -> Self {
        Self {
            records: Vec::new(),
            handshake: Vec::new(),
            finished: false,
            buffer_limit,
        }
    }
}
impl StreamAnalyzer for TlsSni {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        if self.records.len() + self.handshake.len() + bytes.len() > self.buffer_limit {
            self.finished = true;
            return Analysis::Finished;
        }
        self.records.extend_from_slice(bytes);
        loop {
            if self.records.len() < 5 {
                return Analysis::Pending;
            }
            if self.records[0] != 22 || self.records[1] != 3 {
                self.finished = true;
                return Analysis::Finished;
            }
            let len = usize::from(u16::from_be_bytes([self.records[3], self.records[4]]));
            if len > 16384 {
                self.finished = true;
                return Analysis::Finished;
            }
            if self.records.len() < 5 + len {
                return Analysis::Pending;
            }
            self.handshake.extend_from_slice(&self.records[5..5 + len]);
            self.records.drain(..5 + len);
            if self.handshake.len() < 4 {
                continue;
            }
            let h = &self.handshake;
            let length = (usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3]);
            if h[0] != 1 || length > 65536 {
                self.finished = true;
                return Analysis::Finished;
            }
            if h.len() < 4 + length {
                continue;
            }
            self.finished = true;
            return client_hello_name(&h[4..4 + length]).map_or(Analysis::Finished, |value| {
                Analysis::FinalObservations(vec![Observation {
                    field: "tls.sni",
                    value,
                }])
            });
        }
    }
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn byte(&mut self) -> Option<usize> {
        Some(usize::from(self.take(1)?[0]))
    }
    fn word(&mut self) -> Option<usize> {
        Some(usize::from(u16::from_be_bytes(
            self.take(2)?.try_into().ok()?,
        )))
    }
    fn vector(&mut self) -> Option<&'a [u8]> {
        let len = self.word()?;
        self.take(len)
    }
}
fn client_hello_name(body: &[u8]) -> Option<String> {
    let mut c = Cursor(body);
    c.take(34)?;
    let session = c.byte()?;
    if session > 32 {
        return None;
    }
    c.take(session)?;
    let suites = c.vector()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    let compression = c.byte()?;
    if compression == 0 {
        return None;
    }
    c.take(compression)?;
    let mut extensions = Cursor(c.vector()?);
    if !c.0.is_empty() {
        return None;
    }
    let mut name = None;
    while !extensions.0.is_empty() {
        let kind = extensions.word()?;
        let data = extensions.vector()?;
        if kind != 0 {
            continue;
        }
        if name.is_some() {
            return None;
        }
        let mut ext = Cursor(data);
        let mut names = Cursor(ext.vector()?);
        if !ext.0.is_empty() {
            return None;
        }
        while !names.0.is_empty() {
            let kind = names.byte()?;
            let bytes = names.vector()?;
            if kind == 0 {
                if name.is_some() || bytes.is_empty() || !bytes.is_ascii() {
                    return None;
                }
                name = Some(std::str::from_utf8(bytes).ok()?.to_ascii_lowercase());
            }
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector(bytes: &[u8]) -> Vec<u8> {
        let mut v = (bytes.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(bytes);
        v
    }
    fn hello() -> Vec<u8> {
        let mut name = vec![0];
        name.extend(vector(b"Example.COM"));
        let mut extension = vec![0, 0];
        extension.extend(vector(&vector(&name)));
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 1, 1, 0]);
        body.extend(vector(&extension));
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        handshake
    }
    fn record(body: &[u8]) -> Vec<u8> {
        let mut v = vec![22, 3, 1];
        v.extend(vector(body));
        v
    }
    #[test]
    fn tcp_and_record_fragmentation() {
        let h = hello();
        for split in 0..h.len() {
            let mut wire = record(&h[..split]);
            wire.extend(record(&h[split..]));
            let mut analyzer = TlsSni::default();
            let mut result = Analysis::Pending;
            for byte in wire {
                result = analyzer.feed(&[byte]);
            }
            assert_eq!(
                result,
                Analysis::FinalObservations(vec![Observation {
                    field: "tls.sni",
                    value: "example.com".into(),
                }])
            );
        }
    }
    #[test]
    fn truncation_and_malformed_lengths() {
        let h = hello();
        for len in 0..h.len() {
            assert_eq!(
                TlsSni::default().feed(&record(&h[..len])),
                Analysis::Pending
            );
        }
        let mut h = hello();
        h[38] = 255;
        assert_eq!(TlsSni::default().feed(&record(&h)), Analysis::Finished);
        assert_eq!(TlsSni::default().feed(b"GET /"), Analysis::Finished);
    }
    #[test]
    fn configured_buffer_limit_ends_large_client_hello() {
        let wire = record(&hello());
        assert_eq!(
            TlsSni::with_buffer_limit(32).feed(&wire),
            Analysis::Finished
        );
        assert!(matches!(
            TlsSni::with_buffer_limit(wire.len()).feed(&wire),
            Analysis::FinalObservations(_)
        ));
    }
}
