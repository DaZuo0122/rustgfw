//! SSH identification line observation over a reassembled TCP direction.
use crate::inspect::{Analysis, Observation, StreamAnalyzer};

pub struct SshBanner {
    line: Vec<u8>,
    consumed: usize,
    limit: usize,
    finished: bool,
}

impl Default for SshBanner {
    fn default() -> Self {
        Self::with_limit(1024)
    }
}

impl SshBanner {
    pub fn with_limit(limit: usize) -> Self {
        Self {
            line: Vec::new(),
            consumed: 0,
            limit,
            finished: false,
        }
    }
}

fn observations(line: &[u8]) -> Option<Vec<Observation>> {
    let line = std::str::from_utf8(line).ok()?;
    let identification = line.split_once(' ').map_or(line, |(head, _)| head);
    let (protocol, software) = identification.strip_prefix("SSH-")?.split_once('-')?;
    if protocol.is_empty()
        || !protocol
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || software.is_empty()
        || !software.is_ascii()
        || software.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }
    Some(vec![
        Observation {
            field: "ssh.protocol",
            value: protocol.to_owned(),
        },
        Observation {
            field: "ssh.software",
            value: software.to_owned(),
        },
        Observation {
            field: "ssh.banner",
            value: line.to_owned(),
        },
    ])
}

impl StreamAnalyzer for SshBanner {
    fn feed(&mut self, bytes: &[u8]) -> Analysis {
        if self.finished {
            return Analysis::Finished;
        }
        for &byte in bytes {
            if self.consumed == self.limit {
                self.finished = true;
                return Analysis::Finished;
            }
            self.consumed += 1;
            if byte == b'\n' {
                let line = self.line.strip_suffix(b"\r").unwrap_or(&self.line);
                if line.starts_with(b"SSH-") {
                    self.finished = true;
                    return observations(line)
                        .map(Analysis::FinalObservations)
                        .unwrap_or(Analysis::Finished);
                }
                self.line.clear();
            } else {
                self.line.push(byte);
            }
        }
        Analysis::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fragmented_identification_after_pre_banner() {
        let mut analyzer = SshBanner::default();
        assert_eq!(analyzer.feed(b"notice\r\nSSH-2."), Analysis::Pending);
        assert_eq!(
            analyzer.feed(b"0-OpenSSH_9.9 test comment\r\nbytes"),
            Analysis::FinalObservations(vec![
                Observation {
                    field: "ssh.protocol",
                    value: "2.0".into(),
                },
                Observation {
                    field: "ssh.software",
                    value: "OpenSSH_9.9".into(),
                },
                Observation {
                    field: "ssh.banner",
                    value: "SSH-2.0-OpenSSH_9.9 test comment".into(),
                },
            ])
        );
        assert_eq!(analyzer.feed(b"anything"), Analysis::Finished);
    }

    #[test]
    fn rejects_invalid_identification_and_bounded_preamble() {
        assert_eq!(
            SshBanner::default().feed(b"SSH-2.0-\r\n"),
            Analysis::Finished
        );
        assert_eq!(
            SshBanner::default().feed(b"SSH-x-impl\r\n"),
            Analysis::Finished
        );
        let mut analyzer = SshBanner::with_limit(8);
        assert_eq!(analyzer.feed(b"notice\r\n"), Analysis::Pending);
        assert_eq!(analyzer.feed(b"S"), Analysis::Finished);
    }
}
