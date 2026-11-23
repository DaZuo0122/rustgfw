//! Plaintext TLS ClientHello and ServerHello inspection.
use crate::inspect::{Analysis, Observation, StreamAnalyzer};

pub const FIELDS: &[&str] = &[
    "tls.sni",
    "tls.alpn",
    "tls.supported_version",
    "tls.ech_extension",
    "tls.client_legacy_version",
    "tls.client_cipher_suite",
    "tls.client_cipher_suites",
    "tls.client_cipher_suites_no_grease",
    "tls.client_extension",
    "tls.client_extensions",
    "tls.client_extensions_no_grease",
    "tls.client_supported_group",
    "tls.client_supported_groups",
    "tls.client_supported_groups_no_grease",
    "tls.client_signature_algorithm",
    "tls.client_signature_algorithms",
    "tls.client_signature_algorithms_no_grease",
    "tls.client_key_share_group",
    "tls.client_key_share_groups",
    "tls.client_key_share_groups_no_grease",
    "tls.server_version",
    "tls.server_cipher",
    "tls.server_alpn",
];
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

pub struct TlsHello {
    records: Vec<u8>,
    handshake: Vec<u8>,
    seen_retry: bool,
    finished: bool,
    buffer_limit: usize,
}
pub type TlsClientHello = TlsHello;

impl Default for TlsHello {
    fn default() -> Self {
        Self::with_buffer_limit(131072)
    }
}
impl TlsHello {
    pub fn with_buffer_limit(buffer_limit: usize) -> Self {
        Self {
            records: Vec::new(),
            handshake: Vec::new(),
            seen_retry: false,
            finished: false,
            buffer_limit,
        }
    }
}
impl StreamAnalyzer for TlsHello {
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
            if self.handshake.len() >= 4 {
                let h = &self.handshake;
                let length =
                    (usize::from(h[1]) << 16) | (usize::from(h[2]) << 8) | usize::from(h[3]);
                if !matches!(h[0], 1 | 2) || length > 65536 || (self.seen_retry && h[0] != 2) {
                    self.finished = true;
                    return Analysis::Finished;
                }
                if h.len() >= 4 + length {
                    let mut observations = Vec::new();
                    if h[0] == 1 {
                        let Some(hello) = client_hello_metadata(&h[4..4 + length]) else {
                            self.finished = true;
                            return Analysis::Finished;
                        };
                        observations.extend(client_fingerprint_observations(
                            &hello,
                            TLS_FINGERPRINT_FIELDS,
                        ));
                        if let Some(value) = hello.sni {
                            observations.push(Observation {
                                field: "tls.sni",
                                value,
                            });
                        }
                        observations.extend(hello.alpn.into_iter().map(|value| Observation {
                            field: "tls.alpn",
                            value,
                        }));
                        observations.extend(hello.supported_versions.into_iter().map(|version| {
                            Observation {
                                field: "tls.supported_version",
                                value: format!("0x{version:04x}"),
                            }
                        }));
                        observations.push(Observation {
                            field: "tls.ech_extension",
                            value: hello.ech_extension.to_string(),
                        });
                    } else {
                        let Some(hello) = server_hello_metadata(&h[4..4 + length]) else {
                            self.finished = true;
                            return Analysis::Finished;
                        };
                        if hello.retry {
                            if self.seen_retry {
                                self.finished = true;
                                return Analysis::Finished;
                            }
                            self.seen_retry = true;
                            self.handshake.drain(..4 + length);
                            continue;
                        }
                        observations.push(Observation {
                            field: "tls.server_version",
                            value: format!("0x{:04x}", hello.version),
                        });
                        observations.push(Observation {
                            field: "tls.server_cipher",
                            value: format!("0x{:04x}", hello.cipher),
                        });
                        if let Some(value) = hello.alpn {
                            observations.push(Observation {
                                field: "tls.server_alpn",
                                value,
                            });
                        }
                    }
                    self.finished = true;
                    return if observations.is_empty() {
                        Analysis::Finished
                    } else {
                        Analysis::FinalObservations(observations)
                    };
                }
            }
            if self.records.len() < 5 {
                return Analysis::Pending;
            }
            if self.records[1] != 3
                || (self.records[0] != 22 && !(self.records[0] == 20 && self.seen_retry))
            {
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
            if self.records[0] == 20 && self.seen_retry && self.records[5..5 + len] == [1] {
                self.records.drain(..5 + len);
                continue;
            }
            if self.records[0] != 22 {
                self.finished = true;
                return Analysis::Finished;
            }
            self.handshake.extend_from_slice(&self.records[5..5 + len]);
            self.records.drain(..5 + len);
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
pub(crate) struct ClientHelloMetadata {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extension_types: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub ech_extension: bool,
    pub quic_transport_parameters: bool,
    pub quic_datagram_max_size: Option<u64>,
}

pub(crate) struct ClientFingerprintFields {
    pub legacy_version: &'static str,
    pub cipher_suite: &'static str,
    pub cipher_suites: &'static str,
    pub cipher_suites_no_grease: &'static str,
    pub extension: &'static str,
    pub extensions: &'static str,
    pub extensions_no_grease: &'static str,
    pub supported_group: &'static str,
    pub supported_groups: &'static str,
    pub supported_groups_no_grease: &'static str,
    pub signature_algorithm: &'static str,
    pub signature_algorithms: &'static str,
    pub signature_algorithms_no_grease: &'static str,
    pub key_share_group: &'static str,
    pub key_share_groups: &'static str,
    pub key_share_groups_no_grease: &'static str,
}

const TLS_FINGERPRINT_FIELDS: ClientFingerprintFields = ClientFingerprintFields {
    legacy_version: "tls.client_legacy_version",
    cipher_suite: "tls.client_cipher_suite",
    cipher_suites: "tls.client_cipher_suites",
    cipher_suites_no_grease: "tls.client_cipher_suites_no_grease",
    extension: "tls.client_extension",
    extensions: "tls.client_extensions",
    extensions_no_grease: "tls.client_extensions_no_grease",
    supported_group: "tls.client_supported_group",
    supported_groups: "tls.client_supported_groups",
    supported_groups_no_grease: "tls.client_supported_groups_no_grease",
    signature_algorithm: "tls.client_signature_algorithm",
    signature_algorithms: "tls.client_signature_algorithms",
    signature_algorithms_no_grease: "tls.client_signature_algorithms_no_grease",
    key_share_group: "tls.client_key_share_group",
    key_share_groups: "tls.client_key_share_groups",
    key_share_groups_no_grease: "tls.client_key_share_groups_no_grease",
};

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

fn append_ordered_codes(
    observations: &mut Vec<Observation>,
    codes: &[u16],
    item_field: &'static str,
    ordered_field: &'static str,
    without_grease_field: &'static str,
) {
    let mut ordered = Vec::with_capacity(codes.len());
    let mut without_grease = Vec::with_capacity(codes.len());
    for &code in codes {
        let value = format!("0x{code:04x}");
        observations.push(Observation {
            field: item_field,
            value: value.clone(),
        });
        if !is_grease(code) {
            without_grease.push(value.clone());
        }
        ordered.push(value);
    }
    observations.push(Observation {
        field: ordered_field,
        value: ordered.join(","),
    });
    observations.push(Observation {
        field: without_grease_field,
        value: without_grease.join(","),
    });
}

pub(crate) fn client_fingerprint_observations(
    hello: &ClientHelloMetadata,
    fields: ClientFingerprintFields,
) -> Vec<Observation> {
    let mut observations = vec![Observation {
        field: fields.legacy_version,
        value: format!("0x{:04x}", hello.legacy_version),
    }];
    append_ordered_codes(
        &mut observations,
        &hello.cipher_suites,
        fields.cipher_suite,
        fields.cipher_suites,
        fields.cipher_suites_no_grease,
    );
    append_ordered_codes(
        &mut observations,
        &hello.extension_types,
        fields.extension,
        fields.extensions,
        fields.extensions_no_grease,
    );
    for (codes, item, ordered, without_grease) in [
        (
            &hello.supported_groups,
            fields.supported_group,
            fields.supported_groups,
            fields.supported_groups_no_grease,
        ),
        (
            &hello.signature_algorithms,
            fields.signature_algorithm,
            fields.signature_algorithms,
            fields.signature_algorithms_no_grease,
        ),
        (
            &hello.key_share_groups,
            fields.key_share_group,
            fields.key_share_groups,
            fields.key_share_groups_no_grease,
        ),
    ] {
        if !codes.is_empty() {
            append_ordered_codes(&mut observations, codes, item, ordered, without_grease);
        }
    }
    observations
}

fn code_list(data: &[u8]) -> Option<Vec<u16>> {
    let mut c = Cursor(data);
    let bytes = c.vector()?;
    if !c.0.is_empty() || bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect(),
    )
}

fn key_share_groups(data: &[u8]) -> Option<Vec<u16>> {
    let mut c = Cursor(data);
    let mut shares = Cursor(c.vector()?);
    if !c.0.is_empty() || shares.0.is_empty() {
        return None;
    }
    let mut groups = Vec::new();
    while !shares.0.is_empty() {
        let group = shares.word()? as u16;
        if shares.vector()?.is_empty() {
            return None;
        }
        groups.push(group);
    }
    Some(groups)
}

fn quic_varint(cursor: &mut Cursor<'_>) -> Option<u64> {
    let first = cursor.byte()? as u8;
    let width = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for &byte in cursor.take(width - 1)? {
        value = value << 8 | u64::from(byte);
    }
    Some(value)
}

fn quic_datagram_max_size(bytes: &[u8]) -> Option<Option<u64>> {
    let mut parameters = Cursor(bytes);
    let mut max_size = None;
    while !parameters.0.is_empty() {
        let id = quic_varint(&mut parameters)?;
        let length = usize::try_from(quic_varint(&mut parameters)?).ok()?;
        let value = parameters.take(length)?;
        if id == 0x20 {
            if max_size.is_some() {
                return None;
            }
            let mut value = Cursor(value);
            max_size = Some(quic_varint(&mut value)?);
            if !value.0.is_empty() {
                return None;
            }
        }
    }
    Some(max_size)
}

pub(crate) fn client_hello_metadata(body: &[u8]) -> Option<ClientHelloMetadata> {
    let mut c = Cursor(body);
    let legacy_version = c.word()? as u16;
    c.take(32)?;
    let session = c.byte()?;
    if session > 32 {
        return None;
    }
    c.take(session)?;
    let suites = c.vector()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    let cipher_suites = suites
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
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
    let mut alpn = Vec::new();
    let mut seen_alpn = false;
    let mut supported_versions = Vec::new();
    let mut seen_versions = false;
    let mut supported_groups = None;
    let mut signature_algorithms = None;
    let mut key_shares = None;
    let mut ech_extension = false;
    let mut quic_transport_parameters = false;
    let mut quic_datagram_size = None;
    let mut extension_types = Vec::new();
    while !extensions.0.is_empty() {
        let kind = extensions.word()?;
        let data = extensions.vector()?;
        extension_types.push(kind as u16);
        match kind {
            0 => {
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
            16 => {
                if seen_alpn {
                    return None;
                }
                seen_alpn = true;
                let mut ext = Cursor(data);
                let mut protocols = Cursor(ext.vector()?);
                if !ext.0.is_empty() || protocols.0.is_empty() {
                    return None;
                }
                while !protocols.0.is_empty() {
                    let len = protocols.byte()?;
                    let bytes = protocols.take(len)?;
                    if bytes.is_empty() {
                        return None;
                    }
                    if bytes.iter().all(u8::is_ascii_graphic) {
                        alpn.push(std::str::from_utf8(bytes).ok()?.to_owned());
                    }
                }
            }
            10 => {
                if supported_groups.is_some() {
                    return None;
                }
                supported_groups = Some(code_list(data)?);
            }
            13 => {
                if signature_algorithms.is_some() {
                    return None;
                }
                signature_algorithms = Some(code_list(data)?);
            }
            51 => {
                if key_shares.is_some() {
                    return None;
                }
                key_shares = Some(key_share_groups(data)?);
            }
            43 => {
                if seen_versions {
                    return None;
                }
                seen_versions = true;
                let mut ext = Cursor(data);
                let len = ext.byte()?;
                let mut versions = Cursor(ext.take(len)?);
                if !ext.0.is_empty() || versions.0.is_empty() || versions.0.len() % 2 != 0 {
                    return None;
                }
                while !versions.0.is_empty() {
                    supported_versions.push(versions.word()? as u16);
                }
            }
            0xfe0d => ech_extension = true,
            0x0039 => {
                if quic_transport_parameters {
                    return None;
                }
                quic_transport_parameters = true;
                quic_datagram_size = quic_datagram_max_size(data)?;
            }
            _ => {}
        }
    }
    Some(ClientHelloMetadata {
        legacy_version,
        cipher_suites,
        extension_types,
        supported_groups: supported_groups.unwrap_or_default(),
        signature_algorithms: signature_algorithms.unwrap_or_default(),
        key_share_groups: key_shares.unwrap_or_default(),
        sni: name,
        alpn,
        supported_versions,
        ech_extension,
        quic_transport_parameters,
        quic_datagram_max_size: quic_datagram_size,
    })
}

pub(crate) struct ServerHelloMetadata {
    pub(crate) version: u16,
    pub(crate) cipher: u16,
    alpn: Option<String>,
    pub(crate) retry: bool,
}

pub(crate) fn server_hello_metadata(body: &[u8]) -> Option<ServerHelloMetadata> {
    let mut c = Cursor(body);
    let legacy_version = c.word()? as u16;
    let random = c.take(32)?;
    let retry = random == HELLO_RETRY_RANDOM;
    let session_len = c.byte()?;
    if session_len > 32 {
        return None;
    }
    c.take(session_len)?;
    let cipher = c.word()? as u16;
    c.byte()?; // Legacy compression method.
    let mut version = legacy_version;
    let mut alpn = None;
    let mut seen_version = false;
    let mut seen_alpn = false;
    if !c.0.is_empty() {
        let mut extensions = Cursor(c.vector()?);
        if !c.0.is_empty() {
            return None;
        }
        while !extensions.0.is_empty() {
            let kind = extensions.word()?;
            let data = extensions.vector()?;
            match kind {
                43 => {
                    if seen_version || data.len() != 2 {
                        return None;
                    }
                    seen_version = true;
                    version = u16::from_be_bytes(data.try_into().ok()?);
                }
                16 => {
                    if seen_alpn {
                        return None;
                    }
                    seen_alpn = true;
                    let mut ext = Cursor(data);
                    let mut protocols = Cursor(ext.vector()?);
                    if !ext.0.is_empty() {
                        return None;
                    }
                    let len = protocols.byte()?;
                    let bytes = protocols.take(len)?;
                    if bytes.is_empty() || !protocols.0.is_empty() {
                        return None;
                    }
                    if bytes.iter().all(u8::is_ascii_graphic) {
                        alpn = Some(std::str::from_utf8(bytes).ok()?.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    if version == 0x0304 {
        // TLS 1.3 sends its selected ALPN in encrypted EncryptedExtensions.
        alpn = None;
    }
    Some(ServerHelloMetadata {
        version,
        cipher,
        alpn,
        retry,
    })
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
    fn hello_with_alpn(include_sni: bool) -> Vec<u8> {
        let mut hello = hello();
        let mut body = hello.split_off(4);
        let mut extensions = body.split_off(41);
        let existing = extensions.split_off(2);
        extensions.clear();
        if include_sni {
            extensions.extend(existing);
        }
        let mut protocols = vec![2];
        protocols.extend(b"h2");
        protocols.push(8);
        protocols.extend(b"http/1.1");
        extensions.extend([0, 16]);
        extensions.extend(vector(&vector(&protocols)));
        body.extend(vector(&extensions));
        let len = body.len();
        let mut handshake = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        handshake.extend(body);
        handshake
    }
    fn hello_with_versions_and_ech() -> Vec<u8> {
        let mut handshake = hello();
        let mut body = handshake.split_off(4);
        let mut existing = body.split_off(41);
        let mut extensions = existing.split_off(2);
        extensions.extend([0, 43]);
        extensions.extend(vector(&[4, 3, 4, 3, 3]));
        extensions.extend([0xfe, 0x0d, 0, 1, 0]);
        body.extend(vector(&extensions));
        let len = body.len();
        let mut handshake = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        handshake.extend(body);
        handshake
    }
    fn server_hello(tls13: bool, retry: bool) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend(if retry { HELLO_RETRY_RANDOM } else { [0; 32] });
        body.push(0);
        body.extend(if tls13 { [0x13, 1] } else { [0xc0, 0x2f] });
        body.push(0);
        let mut extensions = Vec::new();
        if tls13 {
            extensions.extend([0, 43, 0, 2, 3, 4]);
        } else {
            extensions.extend([0, 16]);
            extensions.extend(vector(&vector(&[2, b'h', b'2'])));
        }
        body.extend(vector(&extensions));
        let len = body.len();
        let mut handshake = vec![2, (len >> 16) as u8, (len >> 8) as u8, len as u8];
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
            let mut analyzer = TlsClientHello::default();
            let mut result = Analysis::Pending;
            for byte in wire {
                result = analyzer.feed(&[byte]);
            }
            let Analysis::FinalObservations(values) = result else {
                panic!("expected ClientHello observations");
            };
            assert!(
                values
                    .iter()
                    .any(|item| item.field == "tls.sni" && item.value == "example.com")
            );
            assert!(
                values
                    .iter()
                    .any(|item| item.field == "tls.ech_extension" && item.value == "false")
            );
            assert!(
                values
                    .iter()
                    .any(|item| item.field == "tls.client_cipher_suites" && item.value == "0x1301")
            );
            assert!(
                values
                    .iter()
                    .any(|item| item.field == "tls.client_extensions" && item.value == "0x0000")
            );
        }
    }
    #[test]
    fn client_fingerprint_keeps_wire_order_and_exposes_grease_free_order() {
        let mut extensions = vec![0x1a, 0x1a, 0, 0, 0, 43, 0, 3, 2, 3, 4];
        extensions.extend([0, 10]);
        extensions.extend(vector(&vector(&[0x0a, 0x0a, 0, 29, 0, 23])));
        extensions.extend([0, 13]);
        extensions.extend(vector(&vector(&[0x08, 0x04, 0x08, 0x05])));
        let mut shares = vec![0, 29];
        shares.extend(vector(&[1, 2, 3]));
        shares.extend([0x2a, 0x2a]);
        shares.extend(vector(&[4]));
        extensions.extend([0, 51]);
        extensions.extend(vector(&vector(&shares)));
        extensions.extend([0x2a, 0x2a, 0, 0]);
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend(vector(&[0x0a, 0x0a, 0x13, 1, 0xc0, 0x2f]));
        body.extend([1, 0]);
        body.extend(vector(&extensions));
        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend(body);
        let Analysis::FinalObservations(values) = TlsHello::default().feed(&record(&handshake))
        else {
            panic!("expected ClientHello observations");
        };
        let field = |name| {
            values
                .iter()
                .find(|item| item.field == name)
                .map(|item| item.value.as_str())
        };
        assert_eq!(field("tls.client_legacy_version"), Some("0x0303"));
        assert_eq!(
            field("tls.client_cipher_suites"),
            Some("0x0a0a,0x1301,0xc02f")
        );
        assert_eq!(
            field("tls.client_cipher_suites_no_grease"),
            Some("0x1301,0xc02f")
        );
        assert_eq!(
            field("tls.client_extensions"),
            Some("0x1a1a,0x002b,0x000a,0x000d,0x0033,0x2a2a")
        );
        assert_eq!(
            field("tls.client_extensions_no_grease"),
            Some("0x002b,0x000a,0x000d,0x0033")
        );
        assert_eq!(
            field("tls.client_supported_groups"),
            Some("0x0a0a,0x001d,0x0017")
        );
        assert_eq!(
            field("tls.client_supported_groups_no_grease"),
            Some("0x001d,0x0017")
        );
        assert_eq!(
            field("tls.client_signature_algorithms"),
            Some("0x0804,0x0805")
        );
        assert_eq!(field("tls.client_key_share_groups"), Some("0x001d,0x2a2a"));
        assert_eq!(
            field("tls.client_key_share_groups_no_grease"),
            Some("0x001d")
        );
        assert_eq!(
            values
                .iter()
                .filter(|item| item.field == "tls.client_cipher_suite")
                .count(),
            3
        );
        assert_eq!(
            values
                .iter()
                .filter(|item| item.field == "tls.client_extension")
                .count(),
            6
        );
    }
    #[test]
    fn truncation_and_malformed_lengths() {
        let h = hello();
        for len in 0..h.len() {
            assert_eq!(
                TlsClientHello::default().feed(&record(&h[..len])),
                Analysis::Pending
            );
        }
        let mut h = hello();
        h[38] = 255;
        assert_eq!(
            TlsClientHello::default().feed(&record(&h)),
            Analysis::Finished
        );
        assert_eq!(TlsClientHello::default().feed(b"GET /"), Analysis::Finished);
    }
    #[test]
    fn configured_buffer_limit_ends_large_client_hello() {
        let wire = record(&hello());
        assert_eq!(
            TlsClientHello::with_buffer_limit(32).feed(&wire),
            Analysis::Finished
        );
        assert!(matches!(
            TlsClientHello::with_buffer_limit(wire.len()).feed(&wire),
            Analysis::FinalObservations(_)
        ));
    }
    #[test]
    fn reports_each_offered_alpn_with_or_without_sni() {
        for include_sni in [false, true] {
            let wire = record(&hello_with_alpn(include_sni));
            let mut analyzer = TlsClientHello::default();
            let result = analyzer.feed(&wire);
            let Analysis::FinalObservations(values) = result else {
                panic!("expected ClientHello observations");
            };
            assert_eq!(
                values
                    .iter()
                    .find(|item| item.field == "tls.sni")
                    .map(|item| item.value.as_str()),
                include_sni.then_some("example.com")
            );
            let alpn: Vec<_> = values
                .iter()
                .filter(|item| item.field == "tls.alpn")
                .map(|item| item.value.as_str())
                .collect();
            assert_eq!(alpn, ["h2", "http/1.1"]);
        }
    }
    #[test]
    fn client_hello_reports_offered_versions_and_ech_extension() {
        let hello = hello_with_versions_and_ech();
        let Analysis::FinalObservations(values) = TlsHello::default().feed(&record(&hello)) else {
            panic!("expected ClientHello observations");
        };
        let versions: Vec<_> = values
            .iter()
            .filter(|item| item.field == "tls.supported_version")
            .map(|item| item.value.as_str())
            .collect();
        assert_eq!(versions, ["0x0304", "0x0303"]);
        assert!(
            values
                .iter()
                .any(|item| item.field == "tls.ech_extension" && item.value == "true")
        );

        let mut malformed = hello;
        let version_extension = malformed
            .windows(8)
            .position(|bytes| bytes == [0, 43, 0, 5, 4, 3, 4, 3])
            .unwrap();
        malformed[version_extension + 4] = 3;
        assert_eq!(
            TlsHello::default().feed(&record(&malformed)),
            Analysis::Finished
        );
    }

    #[test]
    fn quic_datagram_parameter_requires_one_complete_varint() {
        assert_eq!(
            quic_datagram_max_size(&[0x0f, 0, 0x20, 2, 0x45, 0xb0]),
            Some(Some(1456))
        );
        assert_eq!(quic_datagram_max_size(&[0x0f, 0]), Some(None));
        assert_eq!(quic_datagram_max_size(&[0x20, 1, 0]), Some(Some(0)));
        assert_eq!(
            quic_datagram_max_size(&[0x20, 4, 0x80, 0, 0xff, 0xff]),
            Some(Some(65535))
        );
        assert_eq!(quic_datagram_max_size(&[0x20, 2, 0x45]), None);
        assert_eq!(
            quic_datagram_max_size(&[0x20, 2, 0x45, 0xb0, 0x20, 1, 0]),
            None
        );
    }
    #[test]
    fn server_hello_reports_selected_version_cipher_and_visible_alpn() {
        for tls13 in [false, true] {
            let hello = server_hello(tls13, false);
            let split = hello.len() / 2;
            let mut wire = record(&hello[..split]);
            wire.extend(record(&hello[split..]));
            let mut analyzer = TlsHello::default();
            let mut result = Analysis::Pending;
            for byte in wire {
                result = analyzer.feed(&[byte]);
            }
            let Analysis::FinalObservations(values) = result else {
                panic!("expected ServerHello observations");
            };
            let field = |name| {
                values
                    .iter()
                    .find(|item| item.field == name)
                    .map(|item| item.value.as_str())
            };
            assert_eq!(
                field("tls.server_version"),
                Some(if tls13 { "0x0304" } else { "0x0303" })
            );
            assert_eq!(
                field("tls.server_cipher"),
                Some(if tls13 { "0x1301" } else { "0xc02f" })
            );
            assert_eq!(
                field("tls.server_alpn"),
                if tls13 { None } else { Some("h2") }
            );
        }
    }
    #[test]
    fn hello_retry_request_waits_for_final_server_hello() {
        let mut analyzer = TlsHello::default();
        assert_eq!(
            analyzer.feed(&record(&server_hello(true, true))),
            Analysis::Pending
        );
        assert_eq!(analyzer.feed(&[20, 3, 3, 0, 1, 1]), Analysis::Pending);
        let result = analyzer.feed(&record(&server_hello(true, false)));
        let Analysis::FinalObservations(values) = result else {
            panic!("expected final ServerHello observations");
        };
        assert!(
            values
                .iter()
                .any(|item| item.field == "tls.server_version" && item.value == "0x0304")
        );

        let coalesced = [
            record(&server_hello(true, true)),
            record(&server_hello(true, false)),
        ]
        .concat();
        assert!(matches!(
            TlsHello::default().feed(&coalesced),
            Analysis::FinalObservations(_)
        ));
        let duplicate = [
            record(&server_hello(true, true)),
            record(&server_hello(true, true)),
        ]
        .concat();
        assert_eq!(TlsHello::default().feed(&duplicate), Analysis::Finished);
    }
}
