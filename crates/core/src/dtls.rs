//! DTLS 1.2/1.3 plaintext handshake observations across UDP datagrams.
use crate::{
    inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer},
    tls::{
        ClientFingerprintFields, client_fingerprint_observations, client_hello_metadata,
        server_hello_metadata,
    },
};

pub const FIELDS: &[&str] = &[
    "dtls.sni",
    "dtls.alpn",
    "dtls.supported_version",
    "dtls.ech_extension",
    "dtls.client_cookie_present",
    "dtls.hello_verify",
    "dtls.server_version",
    "dtls.server_cipher",
    "dtls.server_alpn",
    "dtls.client_legacy_version",
    "dtls.client_cipher_suite",
    "dtls.client_cipher_suites",
    "dtls.client_cipher_suites_no_grease",
    "dtls.client_extension",
    "dtls.client_extensions",
    "dtls.client_extensions_no_grease",
    "dtls.client_supported_group",
    "dtls.client_supported_groups",
    "dtls.client_supported_groups_no_grease",
    "dtls.client_signature_algorithm",
    "dtls.client_signature_algorithms",
    "dtls.client_signature_algorithms_no_grease",
    "dtls.client_key_share_group",
    "dtls.client_key_share_groups",
    "dtls.client_key_share_groups_no_grease",
];

const FINGERPRINT_FIELDS: ClientFingerprintFields = ClientFingerprintFields {
    legacy_version: "dtls.client_legacy_version",
    cipher_suite: "dtls.client_cipher_suite",
    cipher_suites: "dtls.client_cipher_suites",
    cipher_suites_no_grease: "dtls.client_cipher_suites_no_grease",
    extension: "dtls.client_extension",
    extensions: "dtls.client_extensions",
    extensions_no_grease: "dtls.client_extensions_no_grease",
    supported_group: "dtls.client_supported_group",
    supported_groups: "dtls.client_supported_groups",
    supported_groups_no_grease: "dtls.client_supported_groups_no_grease",
    signature_algorithm: "dtls.client_signature_algorithm",
    signature_algorithms: "dtls.client_signature_algorithms",
    signature_algorithms_no_grease: "dtls.client_signature_algorithms_no_grease",
    key_share_group: "dtls.client_key_share_group",
    key_share_groups: "dtls.client_key_share_groups",
    key_share_groups_no_grease: "dtls.client_key_share_groups_no_grease",
};

const MAX_MESSAGE: usize = 65536;
const MAX_DATAGRAMS: usize = 16;

fn u24(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
}

struct HandshakeFragment<'a> {
    kind: u8,
    sequence: u16,
    length: usize,
    offset: usize,
    data: &'a [u8],
}

struct Message {
    sequence: u16,
    body: Vec<u8>,
    received: Vec<bool>,
    received_count: usize,
}

impl Message {
    fn insert(&mut self, offset: usize, fragment: &[u8]) -> bool {
        for (index, &byte) in fragment.iter().enumerate() {
            let at = offset + index;
            if self.received[at] && self.body[at] != byte {
                return false;
            }
            if !self.received[at] {
                self.body[at] = byte;
                self.received[at] = true;
                self.received_count += 1;
            }
        }
        true
    }

    fn complete(&self) -> bool {
        self.received_count == self.body.len()
    }
}

fn add_fragment(
    slot: &mut Option<Message>,
    sequence: u16,
    length: usize,
    offset: usize,
    fragment: &[u8],
) -> Option<Option<Vec<u8>>> {
    if slot
        .as_ref()
        .is_some_and(|message| message.sequence > sequence)
    {
        return Some(None);
    }
    if slot
        .as_ref()
        .is_some_and(|message| message.sequence == sequence && message.body.len() != length)
    {
        return None;
    }
    if slot
        .as_ref()
        .is_none_or(|message| message.sequence != sequence)
    {
        *slot = Some(Message {
            sequence,
            body: vec![0; length],
            received: vec![false; length],
            received_count: 0,
        });
    }
    let message = slot.as_mut()?;
    if !message.insert(offset, fragment) {
        return None;
    }
    if message.complete() {
        Some(Some(slot.take()?.body))
    } else {
        Some(None)
    }
}

fn client_hello(body: &[u8]) -> Option<(crate::tls::ClientHelloMetadata, bool)> {
    let session_len = usize::from(*body.get(34)?);
    if session_len > 32 {
        return None;
    }
    let cookie_at = 35usize.checked_add(session_len)?;
    let cookie_len = usize::from(*body.get(cookie_at)?);
    let after_cookie = cookie_at.checked_add(1 + cookie_len)?;
    body.get(cookie_at..after_cookie)?;
    let mut normalized = Vec::with_capacity(body.len() - 1 - cookie_len);
    normalized.extend_from_slice(&body[..cookie_at]);
    normalized.extend_from_slice(&body[after_cookie..]);
    let mut cursor = cookie_at;
    let suites = normalized.get(cursor..cursor + 2)?;
    cursor += 2 + usize::from(u16::from_be_bytes([suites[0], suites[1]]));
    let compression = usize::from(*normalized.get(cursor)?);
    cursor += 1 + compression;
    if cursor == normalized.len() {
        // DTLS 1.2 can omit the extensions vector entirely.
        normalized.extend([0, 0]);
    }
    Some((client_hello_metadata(&normalized)?, cookie_len != 0))
}

#[derive(Default)]
pub struct DtlsHello {
    client_direction: Option<bool>,
    client: Option<Message>,
    verify: Option<Message>,
    server: Option<Message>,
    last_client_sequence: Option<u16>,
    verify_reported: bool,
    datagrams: usize,
    finished: bool,
}

impl DtlsHello {
    fn handshake(
        &mut self,
        fragment: HandshakeFragment<'_>,
        reverse: bool,
        observations: &mut Vec<Observation>,
    ) {
        let HandshakeFragment {
            kind,
            sequence,
            length,
            offset,
            data,
        } = fragment;
        if kind == 1 {
            if self
                .client_direction
                .is_some_and(|direction| direction != reverse)
            {
                return;
            }
            self.client_direction.get_or_insert(reverse);
            let Some(Some(body)) = add_fragment(&mut self.client, sequence, length, offset, data)
            else {
                return;
            };
            let Some((hello, cookie_present)) = client_hello(&body) else {
                return;
            };
            if self.last_client_sequence == Some(sequence) {
                return;
            }
            self.last_client_sequence = Some(sequence);
            observations.extend(client_fingerprint_observations(&hello, FINGERPRINT_FIELDS));
            observations.extend(hello.sni.into_iter().map(|value| Observation {
                field: "dtls.sni",
                value,
            }));
            observations.extend(hello.alpn.into_iter().map(|value| Observation {
                field: "dtls.alpn",
                value,
            }));
            observations.extend(
                hello
                    .supported_versions
                    .into_iter()
                    .map(|version| Observation {
                        field: "dtls.supported_version",
                        value: format!("0x{version:04x}"),
                    }),
            );
            observations.push(Observation {
                field: "dtls.ech_extension",
                value: hello.ech_extension.to_string(),
            });
            observations.push(Observation {
                field: "dtls.client_cookie_present",
                value: cookie_present.to_string(),
            });
        } else if kind == 3 && !self.verify_reported && self.client_direction == Some(!reverse) {
            let Some(Some(body)) = add_fragment(&mut self.verify, sequence, length, offset, data)
            else {
                return;
            };
            if body.len() >= 3 && body.len() == 3 + usize::from(body[2]) && body[2] != 0 {
                self.verify_reported = true;
                observations.push(Observation {
                    field: "dtls.hello_verify",
                    value: "true".into(),
                });
            }
        } else if kind == 2 && self.client_direction == Some(!reverse) {
            let Some(Some(body)) = add_fragment(&mut self.server, sequence, length, offset, data)
            else {
                return;
            };
            let Some(hello) = server_hello_metadata(&body) else {
                return;
            };
            if hello.retry {
                return;
            }
            observations.push(Observation {
                field: "dtls.server_version",
                value: format!("0x{:04x}", hello.version),
            });
            observations.push(Observation {
                field: "dtls.server_cipher",
                value: format!("0x{:04x}", hello.cipher),
            });
            if let Some(value) = hello.alpn {
                observations.push(Observation {
                    field: "dtls.server_alpn",
                    value,
                });
            }
            self.finished = true;
        }
    }
}

impl UdpStreamAnalyzer for DtlsHello {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        if self.finished {
            return UdpStreamAnalysis::Finished;
        }
        self.datagrams += 1;
        if self.datagrams > MAX_DATAGRAMS {
            self.finished = true;
            return UdpStreamAnalysis::Finished;
        }
        let mut observations = Vec::new();
        let mut datagram = payload;
        while !self.finished
            && datagram.len() >= 13
            && (20..=26).contains(&datagram[0])
            && datagram[1] == 0xfe
            && matches!(datagram[2], 0xff | 0xfd)
        {
            let content_type = datagram[0];
            let length = usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
            let Some(record) = datagram.get(13..13 + length) else {
                break;
            };
            let epoch = u16::from_be_bytes([datagram[3], datagram[4]]);
            datagram = &datagram[13 + length..];
            if content_type != 22 || epoch != 0 {
                continue;
            }
            let mut cursor = 0;
            while let Some(header) = record.get(cursor..cursor + 12) {
                let kind = header[0];
                let length = u24(&header[1..4]);
                let sequence = u16::from_be_bytes([header[4], header[5]]);
                let offset = u24(&header[6..9]);
                let fragment_len = u24(&header[9..12]);
                cursor += 12;
                if length > MAX_MESSAGE
                    || offset
                        .checked_add(fragment_len)
                        .is_none_or(|end| end > length)
                {
                    break;
                }
                let Some(fragment) = record.get(cursor..cursor + fragment_len) else {
                    break;
                };
                cursor += fragment_len;
                self.handshake(
                    HandshakeFragment {
                        kind,
                        sequence,
                        length,
                        offset,
                        data: fragment,
                    },
                    reverse,
                    &mut observations,
                );
                if self.finished {
                    break;
                }
            }
        }
        if observations.is_empty() {
            UdpStreamAnalysis::Pending
        } else if self.finished {
            UdpStreamAnalysis::FinalObservations(observations)
        } else {
            UdpStreamAnalysis::Observations(observations)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(bytes: &[u8]) -> Vec<u8> {
        let mut value = (bytes.len() as u16).to_be_bytes().to_vec();
        value.extend_from_slice(bytes);
        value
    }

    fn client_body(cookie: &[u8], version: u16) -> Vec<u8> {
        let name = b"dtls.example";
        let mut names = vec![0];
        names.extend(vector(name));
        let mut extensions = vec![0, 0];
        extensions.extend(vector(&vector(&names)));
        extensions.extend([0, 16]);
        extensions.extend(vector(&vector(&[2, b'h', b'2'])));
        if version == 0xfefc {
            extensions.extend([0, 43]);
            extensions.extend(vector(&[2, 0xfe, 0xfc]));
        }
        let mut body = vec![0xfe, 0xfd];
        body.extend([0x42; 32]);
        body.push(0);
        body.push(cookie.len() as u8);
        body.extend(cookie);
        body.extend(vector(&[0x13, 0x01]));
        body.extend([1, 0]);
        body.extend(vector(&extensions));
        body
    }

    fn server_body(version: u16) -> Vec<u8> {
        let mut body = vec![0xfe, 0xfd];
        body.extend([0x24; 32]);
        body.extend([0, 0x13, 0x01, 0]);
        let mut extensions = Vec::new();
        if version == 0xfefc {
            extensions.extend([0, 43, 0, 2, 0xfe, 0xfc]);
        } else {
            extensions.extend([0, 16]);
            extensions.extend(vector(&vector(&[2, b'h', b'2'])));
        }
        body.extend(vector(&extensions));
        body
    }

    fn fragment(kind: u8, sequence: u16, body: &[u8], offset: usize, length: usize) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend([
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        message.extend(sequence.to_be_bytes());
        message.extend([(offset >> 16) as u8, (offset >> 8) as u8, offset as u8]);
        message.extend([(length >> 16) as u8, (length >> 8) as u8, length as u8]);
        message.extend_from_slice(&body[offset..offset + length]);
        let mut record = vec![22, 0xfe, 0xfd];
        record.extend([0; 8]);
        record.extend((message.len() as u16).to_be_bytes());
        record.extend(message);
        record
    }

    fn field<'a>(result: &'a UdpStreamAnalysis, name: &str) -> Option<&'a str> {
        match result {
            UdpStreamAnalysis::Observations(values)
            | UdpStreamAnalysis::FinalObservations(values) => values
                .iter()
                .find(|value| value.field == name)
                .map(|value| value.value.as_str()),
            _ => None,
        }
    }

    #[test]
    fn reassembles_dtls12_hello_and_cookie_exchange() {
        let mut analyzer = DtlsHello::default();
        let hello = client_body(&[], 0xfefd);
        let split = hello.len() / 2;
        let later = fragment(1, 0, &hello, split, hello.len() - split);
        let earlier = fragment(1, 0, &hello, 0, split);
        assert!(matches!(
            analyzer.feed(&later, false),
            UdpStreamAnalysis::Pending
        ));
        let first = analyzer.feed(&earlier, false);
        assert_eq!(field(&first, "dtls.sni"), Some("dtls.example"));
        assert_eq!(field(&first, "dtls.alpn"), Some("h2"));
        assert_eq!(field(&first, "dtls.client_cookie_present"), Some("false"));
        assert_eq!(field(&first, "dtls.client_cipher_suites"), Some("0x1301"));

        let verify_body = [0xfe, 0xfd, 3, 1, 2, 3];
        let verify = fragment(3, 0, &verify_body, 0, verify_body.len());
        assert_eq!(
            field(&analyzer.feed(&verify, true), "dtls.hello_verify"),
            Some("true")
        );
        let cookie_hello = client_body(&[1, 2, 3], 0xfefd);
        let echoed = fragment(1, 1, &cookie_hello, 0, cookie_hello.len());
        assert_eq!(
            field(&analyzer.feed(&echoed, false), "dtls.client_cookie_present"),
            Some("true")
        );

        let server = server_body(0xfefd);
        let split = server.len() / 2;
        let later = fragment(2, 1, &server, split, server.len() - split);
        let earlier = fragment(2, 1, &server, 0, split);
        assert!(matches!(
            analyzer.feed(&later, true),
            UdpStreamAnalysis::Pending
        ));
        let result = analyzer.feed(&earlier, true);
        assert_eq!(field(&result, "dtls.server_version"), Some("0xfefd"));
        assert_eq!(field(&result, "dtls.server_cipher"), Some("0x1301"));
        assert_eq!(field(&result, "dtls.server_alpn"), Some("h2"));
    }

    #[test]
    fn dtls13_uses_supported_version_and_hides_server_alpn() {
        let mut analyzer = DtlsHello::default();
        let client = client_body(&[], 0xfefc);
        let result = analyzer.feed(&fragment(1, 0, &client, 0, client.len()), true);
        assert_eq!(field(&result, "dtls.supported_version"), Some("0xfefc"));
        let server = server_body(0xfefc);
        let result = analyzer.feed(&fragment(2, 0, &server, 0, server.len()), false);
        assert_eq!(field(&result, "dtls.server_version"), Some("0xfefc"));
        assert_eq!(field(&result, "dtls.server_alpn"), None);
    }

    #[test]
    fn ignores_wrong_direction_and_encrypted_epoch() {
        let mut analyzer = DtlsHello::default();
        let client = client_body(&[], 0xfefd);
        let packet = fragment(1, 0, &client, 0, client.len());
        assert_eq!(
            field(&analyzer.feed(&packet, false), "dtls.sni"),
            Some("dtls.example")
        );
        let server = server_body(0xfefd);
        let reply = fragment(2, 0, &server, 0, server.len());
        let mut encrypted = reply.clone();
        encrypted[4] = 1;
        assert!(matches!(
            analyzer.feed(&encrypted, true),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            analyzer.feed(&reply, false),
            UdpStreamAnalysis::Pending
        ));
        assert_eq!(
            field(&analyzer.feed(&reply, true), "dtls.server_cipher"),
            Some("0x1301")
        );
    }

    #[test]
    fn parses_openssl_dtls12_client_hello() {
        // Captured from OpenSSL 3.6.3 with -dtls1_2 -servername dtls.example -alpn h2.
        let first = include_bytes!("../../../tests/fixtures/dtls-openssl12-client-0.bin");
        let second = include_bytes!("../../../tests/fixtures/dtls-openssl12-client-1.bin");
        for packets in [[first.as_slice(), second.as_slice()], [second, first]] {
            let mut analyzer = DtlsHello::default();
            assert!(matches!(
                analyzer.feed(packets[0], false),
                UdpStreamAnalysis::Pending
            ));
            let result = analyzer.feed(packets[1], false);
            assert_eq!(field(&result, "dtls.sni"), Some("dtls.example"));
            assert_eq!(field(&result, "dtls.alpn"), Some("h2"));
            assert_eq!(field(&result, "dtls.client_legacy_version"), Some("0xfefd"));
        }
    }

    #[test]
    fn dtls12_client_hello_without_extensions_is_valid() {
        let mut body = vec![0xfe, 0xfd];
        body.extend([0; 32]);
        body.extend([0, 0]); // Empty session ID and cookie.
        body.extend(vector(&[0x00, 0x2f]));
        body.extend([1, 0]);
        let packet = fragment(1, 0, &body, 0, body.len());
        let result = DtlsHello::default().feed(&packet, false);
        assert_eq!(field(&result, "dtls.client_legacy_version"), Some("0xfefd"));
        assert_eq!(field(&result, "dtls.client_cipher_suites"), Some("0x002f"));
    }
}
