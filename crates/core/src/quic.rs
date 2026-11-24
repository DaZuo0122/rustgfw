//! QUIC v1/v2 Initial inspection. Initial keys are public by design.
use crate::{
    inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer},
    tls::{
        ClientFingerprintFields, client_fingerprint_observations, client_hello_metadata,
        server_hello_metadata,
    },
};
use ring::{
    aead::{self, quic},
    hkdf,
};

pub const FIELDS: &[&str] = &[
    "quic.version",
    "quic.sni",
    "quic.alpn",
    "quic.tls_supported_version",
    "quic.ech_extension",
    "quic.transport_parameters",
    "quic.transport_parameter_id",
    "quic.transport_parameter_ids",
    "quic.transport_parameter_ids_no_grease",
    "quic.datagram_max_size",
    "quic.max_idle_timeout_ms",
    "quic.max_udp_payload_size",
    "quic.initial_max_data",
    "quic.initial_max_stream_data_bidi_local",
    "quic.initial_max_stream_data_bidi_remote",
    "quic.initial_max_stream_data_uni",
    "quic.initial_max_streams_bidi",
    "quic.initial_max_streams_uni",
    "quic.ack_delay_exponent",
    "quic.max_ack_delay_ms",
    "quic.disable_active_migration",
    "quic.active_connection_id_limit",
    "quic.tls_client_legacy_version",
    "quic.tls_client_random",
    "quic.tls_client_session_id",
    "quic.tls_client_session_id_len",
    "quic.tls_client_compression_methods",
    "quic.tls_client_cipher_suite",
    "quic.tls_client_cipher_suites",
    "quic.tls_client_cipher_suites_no_grease",
    "quic.tls_client_extension",
    "quic.tls_client_extensions",
    "quic.tls_client_extensions_no_grease",
    "quic.tls_client_supported_group",
    "quic.tls_client_supported_groups",
    "quic.tls_client_supported_groups_no_grease",
    "quic.tls_client_signature_algorithm",
    "quic.tls_client_signature_algorithms",
    "quic.tls_client_signature_algorithms_no_grease",
    "quic.tls_client_key_share_group",
    "quic.tls_client_key_share_groups",
    "quic.tls_client_key_share_groups_no_grease",
    "quic.server_version",
    "quic.server_cipher",
    "quic.retry_integrity_valid",
];
pub const SERVER_FIELDS: &[&str] = &[
    "quic.server_version",
    "quic.server_cipher",
    "quic.retry_integrity_valid",
];
const QUIC_FINGERPRINT_FIELDS: ClientFingerprintFields = ClientFingerprintFields {
    legacy_version: "quic.tls_client_legacy_version",
    random: "quic.tls_client_random",
    session_id: "quic.tls_client_session_id",
    session_id_len: "quic.tls_client_session_id_len",
    compression_methods: "quic.tls_client_compression_methods",
    cipher_suite: "quic.tls_client_cipher_suite",
    cipher_suites: "quic.tls_client_cipher_suites",
    cipher_suites_no_grease: "quic.tls_client_cipher_suites_no_grease",
    extension: "quic.tls_client_extension",
    extensions: "quic.tls_client_extensions",
    extensions_no_grease: "quic.tls_client_extensions_no_grease",
    supported_group: "quic.tls_client_supported_group",
    supported_groups: "quic.tls_client_supported_groups",
    supported_groups_no_grease: "quic.tls_client_supported_groups_no_grease",
    signature_algorithm: "quic.tls_client_signature_algorithm",
    signature_algorithms: "quic.tls_client_signature_algorithms",
    signature_algorithms_no_grease: "quic.tls_client_signature_algorithms_no_grease",
    key_share_group: "quic.tls_client_key_share_group",
    key_share_groups: "quic.tls_client_key_share_groups",
    key_share_groups_no_grease: "quic.tls_client_key_share_groups_no_grease",
};
const V1: u32 = 1;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];
const MAX_CRYPTO_BYTES: usize = 65536;
const MAX_FRAMES: usize = 256;
const MAX_CLIENT_DATAGRAMS: usize = 8;
const MAX_COALESCED_PACKETS: usize = 16;

struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(prk: &hkdf::Prk, label: &str, len: usize) -> Option<Vec<u8>> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);
    let mut output = vec![0; len];
    prk.expand(&[&info], Length(len))
        .ok()?
        .fill(&mut output)
        .ok()?;
    Some(output)
}

struct InitialKeys {
    payload: aead::LessSafeKey,
    header: quic::HeaderProtectionKey,
    iv: [u8; 12],
}

fn initial_material_for(
    version: u32,
    dcid: &[u8],
    server: bool,
) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let (salt, key_label, iv_label, hp_label) = match version {
        V1 => (&SALT_V1[..], "quic key", "quic iv", "quic hp"),
        V2 => (&SALT_V2[..], "quicv2 key", "quicv2 iv", "quicv2 hp"),
        _ => return None,
    };
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let secret = expand_label(&initial, if server { "server in" } else { "client in" }, 32)?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
    let key = expand_label(&client, key_label, 16)?.try_into().ok()?;
    let iv: [u8; 12] = expand_label(&client, iv_label, 12)?.try_into().ok()?;
    let hp = expand_label(&client, hp_label, 16)?.try_into().ok()?;
    Some((key, iv, hp))
}

fn initial_keys_for(version: u32, dcid: &[u8], server: bool) -> Option<InitialKeys> {
    let (key, iv, hp) = initial_material_for(version, dcid, server)?;
    Some(InitialKeys {
        payload: aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).ok()?),
        header: quic::HeaderProtectionKey::new(&quic::AES_128, &hp).ok()?,
        iv,
    })
}

fn initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    initial_keys_for(version, dcid, false)
}

fn varint(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *bytes.get(*cursor)?;
    let width = 1usize << (first >> 6);
    let value = bytes.get(*cursor..*cursor + width)?;
    *cursor += width;
    let mut result = u64::from(first & 0x3f);
    for &byte in &value[1..] {
        result = result << 8 | u64::from(byte);
    }
    Some(result)
}

struct Header<'a> {
    version: u32,
    kind: u8,
    dcid: &'a [u8],
    scid: &'a [u8],
    token: &'a [u8],
    packet_len: usize,
    pn_offset: usize,
    initial: bool,
}

fn parse_header(bytes: &[u8]) -> Option<Header<'_>> {
    let first = *bytes.first()?;
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?);
    if !matches!(version, V1 | V2) {
        return None;
    }
    let kind = (first >> 4) & 3;
    let initial = kind == if version == V2 { 1 } else { 0 };
    if kind == if version == V2 { 0 } else { 3 } {
        return None;
    }
    let mut cursor = 5;
    let dcid_len = usize::from(*bytes.get(cursor)?);
    cursor += 1;
    if dcid_len > 20 {
        return None;
    }
    let dcid = bytes.get(cursor..cursor + dcid_len)?;
    cursor += dcid_len;
    let scid_len = usize::from(*bytes.get(cursor)?);
    cursor += 1;
    if scid_len > 20 {
        return None;
    }
    let scid = bytes.get(cursor..cursor + scid_len)?;
    cursor += scid_len;
    let token = if initial {
        let token_len = usize::try_from(varint(bytes, &mut cursor)?).ok()?;
        let token = bytes.get(cursor..cursor.checked_add(token_len)?)?;
        cursor += token_len;
        token
    } else {
        &[]
    };
    let length = usize::try_from(varint(bytes, &mut cursor)?).ok()?;
    let packet_len = cursor.checked_add(length)?;
    if length < 17 || packet_len > bytes.len() {
        return None;
    }
    Some(Header {
        version,
        kind,
        dcid,
        scid,
        token,
        packet_len,
        pn_offset: cursor,
        initial,
    })
}

/// Visible v1/v2 long-header packet types within one UDP datagram. These are
/// wire shapes only; the non-Initial packets cannot be authenticated here.
#[derive(Default)]
pub(crate) struct WireShape {
    pub zero_rtt: bool,
    pub handshake: bool,
    pub coalesced: bool,
}

pub(crate) fn wire_shape(mut datagram: &[u8]) -> WireShape {
    let mut shape = WireShape::default();
    let mut packets = 0;
    while let Some(header) = parse_header(datagram) {
        packets += 1;
        if packets > MAX_COALESCED_PACKETS {
            break;
        }
        let kind = header.kind;
        let version = header.version;
        datagram = &datagram[header.packet_len..];
        shape.zero_rtt |= kind == if version == V2 { 2 } else { 1 };
        shape.handshake |= kind == if version == V2 { 3 } else { 2 };
    }
    shape.coalesced = packets > 1;
    shape
}

struct VerifiedRetry<'a> {
    scid: &'a [u8],
    token: &'a [u8],
}

fn verified_retry<'a>(
    packet: &'a [u8],
    version: u32,
    original_dcid: &[u8],
    client_scid: &[u8],
) -> Option<VerifiedRetry<'a>> {
    let first = *packet.first()?;
    if first & 0xc0 != 0xc0
        || (first >> 4) & 3 != if version == V2 { 0 } else { 3 }
        || u32::from_be_bytes(packet.get(1..5)?.try_into().ok()?) != version
    {
        return None;
    }
    let mut cursor = 5;
    let dcid_len = usize::from(*packet.get(cursor)?);
    cursor += 1;
    if dcid_len > 20 || packet.get(cursor..cursor + dcid_len)? != client_scid {
        return None;
    }
    cursor += dcid_len;
    let scid_len = usize::from(*packet.get(cursor)?);
    cursor += 1;
    if scid_len > 20 {
        return None;
    }
    let scid = packet.get(cursor..cursor + scid_len)?;
    if scid == original_dcid {
        return None;
    }
    cursor += scid_len;
    let tag_offset = packet.len().checked_sub(16)?;
    let token = packet.get(cursor..tag_offset)?;
    if token.is_empty() {
        return None;
    }
    let (key, nonce) = if version == V2 {
        (&RETRY_KEY_V2, RETRY_NONCE_V2)
    } else {
        (&RETRY_KEY_V1, RETRY_NONCE_V1)
    };
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, key).ok()?);
    let mut pseudo = Vec::with_capacity(original_dcid.len() + 1 + tag_offset);
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid);
    pseudo.extend_from_slice(&packet[..tag_offset]);
    let mut tag = packet[tag_offset..].to_vec();
    key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(pseudo),
        &mut tag,
    )
    .ok()?;
    Some(VerifiedRetry { scid, token })
}

fn packet_number(truncated: u64, width: usize, largest: Option<u64>) -> u64 {
    let expected = largest.map_or(0, |number| number + 1);
    let window = 1u64 << (width * 8);
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half <= expected && candidate < (1u64 << 62) - window {
        candidate + window
    } else if candidate > expected + half && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn nonce(iv: [u8; 12], packet_number: u64) -> aead::Nonce {
    let mut bytes = iv;
    for (byte, number) in bytes[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *byte ^= number;
    }
    aead::Nonce::assume_unique_for_key(bytes)
}

fn open_initial(
    packet: &[u8],
    pn_offset: usize,
    keys: &InitialKeys,
    largest: Option<u64>,
) -> Option<(u64, Vec<u8>)> {
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let mask = keys.header.new_mask(sample).ok()?;
    let mut packet = packet.to_vec();
    packet[0] ^= mask[0] & 0x0f;
    if packet[0] & 0x0c != 0 {
        return None;
    }
    let width = usize::from(packet[0] & 3) + 1;
    let mut truncated = 0u64;
    for index in 0..width {
        packet[pn_offset + index] ^= mask[index + 1];
        truncated = truncated << 8 | u64::from(packet[pn_offset + index]);
    }
    let number = packet_number(truncated, width, largest);
    let (header, ciphertext) = packet.split_at(pn_offset + width);
    let mut ciphertext = ciphertext.to_vec();
    let plaintext = keys
        .payload
        .open_in_place(
            nonce(keys.iv, number),
            aead::Aad::from(header),
            &mut ciphertext,
        )
        .ok()?;
    Some((number, plaintext.to_vec()))
}

struct Fragment {
    offset: usize,
    data: Vec<u8>,
}

#[derive(Default)]
struct CryptoBuffer {
    fragments: Vec<Fragment>,
    retained_bytes: usize,
}

impl CryptoBuffer {
    fn insert(&mut self, frame: Fragment) -> bool {
        for existing in &self.fragments {
            let start = frame.offset.max(existing.offset);
            let end = (frame.offset + frame.data.len()).min(existing.offset + existing.data.len());
            if start < end
                && frame.data[start - frame.offset..end - frame.offset]
                    != existing.data[start - existing.offset..end - existing.offset]
            {
                return false;
            }
        }
        if self.fragments.len() == MAX_FRAMES
            || self.retained_bytes + frame.data.len() > MAX_CRYPTO_BYTES
        {
            return false;
        }
        self.retained_bytes += frame.data.len();
        self.fragments.push(frame);
        true
    }

    fn contiguous(&mut self) -> Vec<u8> {
        self.fragments.sort_by_key(|frame| frame.offset);
        let mut data = Vec::new();
        for frame in &self.fragments {
            if frame.offset > data.len() {
                break;
            }
            if frame.offset + frame.data.len() > data.len() {
                data.extend_from_slice(&frame.data[data.len() - frame.offset..]);
            }
        }
        data
    }
}

fn crypto_frames(plaintext: &[u8]) -> Option<Vec<Fragment>> {
    let mut cursor = 0;
    let mut fragments = Vec::new();
    while cursor < plaintext.len() {
        let frame_type = varint(plaintext, &mut cursor)?;
        match frame_type {
            0 | 1 => {}
            2 | 3 => {
                varint(plaintext, &mut cursor)?;
                varint(plaintext, &mut cursor)?;
                let ranges = varint(plaintext, &mut cursor)?;
                varint(plaintext, &mut cursor)?;
                for _ in 0..ranges {
                    varint(plaintext, &mut cursor)?;
                    varint(plaintext, &mut cursor)?;
                }
                if frame_type == 3 {
                    for _ in 0..3 {
                        varint(plaintext, &mut cursor)?;
                    }
                }
            }
            6 => {
                let offset = usize::try_from(varint(plaintext, &mut cursor)?).ok()?;
                let length = usize::try_from(varint(plaintext, &mut cursor)?).ok()?;
                if offset.checked_add(length)? > MAX_CRYPTO_BYTES || fragments.len() == MAX_FRAMES {
                    return None;
                }
                let data = plaintext.get(cursor..cursor.checked_add(length)?)?.to_vec();
                cursor += length;
                fragments.push(Fragment { offset, data });
            }
            _ => return None,
        }
    }
    Some(fragments)
}

#[derive(Default)]
pub struct QuicInitial {
    connection: Option<(u32, Vec<u8>)>,
    client_scid: Option<Vec<u8>>,
    retry_token: Option<Vec<u8>>,
    crypto: CryptoBuffer,
    largest_number: Option<u64>,
    client_direction: Option<bool>,
    client_datagrams: usize,
    finished: bool,
}

impl UdpStreamAnalyzer for QuicInitial {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        if self.finished {
            return UdpStreamAnalysis::Finished;
        }
        if self
            .client_direction
            .is_some_and(|direction| direction != reverse)
        {
            if self.retry_token.is_none()
                && let (Some((version, dcid)), Some(client_scid)) =
                    (&self.connection, &self.client_scid)
                && let Some(retry) = verified_retry(payload, *version, dcid, client_scid)
            {
                self.connection = Some((*version, retry.scid.to_vec()));
                self.retry_token = Some(retry.token.to_vec());
                self.crypto = CryptoBuffer::default();
            }
            return UdpStreamAnalysis::Pending;
        }
        self.client_datagrams += 1;
        if self.client_datagrams > MAX_CLIENT_DATAGRAMS {
            self.finished = true;
            return UdpStreamAnalysis::Finished;
        }
        let mut datagram = payload;
        let mut accepted = false;
        let mut packets = 0;
        while let Some(header) = parse_header(datagram) {
            packets += 1;
            if packets > MAX_COALESCED_PACKETS {
                break;
            }
            let packet = &datagram[..header.packet_len];
            datagram = &datagram[header.packet_len..];
            if !header.initial {
                continue;
            }
            if self.connection.as_ref().is_some_and(|(version, dcid)| {
                *version != header.version || dcid.as_slice() != header.dcid
            }) {
                continue;
            }
            if self.retry_token.as_ref().is_some_and(|token| {
                token.as_slice() != header.token || self.client_scid.as_deref() != Some(header.scid)
            }) {
                continue;
            }
            let Some(keys) = initial_keys(header.version, header.dcid) else {
                continue;
            };
            let Some((number, plaintext)) =
                open_initial(packet, header.pn_offset, &keys, self.largest_number)
            else {
                continue;
            };
            let Some(frames) = crypto_frames(&plaintext) else {
                continue;
            };
            if self.connection.is_none() {
                self.connection = Some((header.version, header.dcid.to_vec()));
                self.client_scid = Some(header.scid.to_vec());
                self.client_direction = Some(reverse);
            }
            self.largest_number = Some(self.largest_number.map_or(number, |old| old.max(number)));
            for frame in frames {
                if !self.crypto.insert(frame) {
                    self.finished = true;
                    return UdpStreamAnalysis::Finished;
                }
            }
            accepted = true;
        }
        if !accepted {
            return UdpStreamAnalysis::Pending;
        }
        let stream = self.crypto.contiguous();
        if stream.len() < 4 {
            return UdpStreamAnalysis::Pending;
        }
        let length =
            usize::from(stream[1]) << 16 | usize::from(stream[2]) << 8 | usize::from(stream[3]);
        if stream[0] != 1 || length > MAX_CRYPTO_BYTES - 4 {
            self.finished = true;
            return UdpStreamAnalysis::Finished;
        }
        if stream.len() < 4 + length {
            return UdpStreamAnalysis::Pending;
        }
        self.finished = true;
        let version = self.connection.as_ref().unwrap().0;
        let mut observations = vec![Observation {
            field: "quic.version",
            value: if version == V1 { "1" } else { "2" }.into(),
        }];
        if let Some(hello) = client_hello_metadata(&stream[4..4 + length]) {
            observations.extend(client_fingerprint_observations(
                &hello,
                QUIC_FINGERPRINT_FIELDS,
            ));
            if let Some(value) = hello.sni {
                observations.push(Observation {
                    field: "quic.sni",
                    value,
                });
            }
            observations.extend(hello.alpn.into_iter().map(|value| Observation {
                field: "quic.alpn",
                value,
            }));
            observations.extend(
                hello
                    .supported_versions
                    .into_iter()
                    .map(|version| Observation {
                        field: "quic.tls_supported_version",
                        value: format!("0x{version:04x}"),
                    }),
            );
            observations.push(Observation {
                field: "quic.ech_extension",
                value: hello.ech_extension.to_string(),
            });
            observations.push(Observation {
                field: "quic.transport_parameters",
                value: hello.quic_transport_parameters.to_string(),
            });
            if hello.quic_transport_parameters {
                let mut ordered = Vec::new();
                let mut without_grease = Vec::new();
                for id in hello.quic_transport_parameter_ids {
                    let value = format!("0x{id:x}");
                    observations.push(Observation {
                        field: "quic.transport_parameter_id",
                        value: value.clone(),
                    });
                    if id % 31 != 27 {
                        without_grease.push(value.clone());
                    }
                    ordered.push(value);
                }
                observations.push(Observation {
                    field: "quic.transport_parameter_ids",
                    value: ordered.join(","),
                });
                observations.push(Observation {
                    field: "quic.transport_parameter_ids_no_grease",
                    value: without_grease.join(","),
                });
                for (id, value) in hello.quic_transport_parameter_integers {
                    let field = match id {
                        0x01 => "quic.max_idle_timeout_ms",
                        0x03 => "quic.max_udp_payload_size",
                        0x04 => "quic.initial_max_data",
                        0x05 => "quic.initial_max_stream_data_bidi_local",
                        0x06 => "quic.initial_max_stream_data_bidi_remote",
                        0x07 => "quic.initial_max_stream_data_uni",
                        0x08 => "quic.initial_max_streams_bidi",
                        0x09 => "quic.initial_max_streams_uni",
                        0x0a => "quic.ack_delay_exponent",
                        0x0b => "quic.max_ack_delay_ms",
                        _ => continue,
                    };
                    observations.push(Observation {
                        field,
                        value: value.to_string(),
                    });
                }
                observations.push(Observation {
                    field: "quic.disable_active_migration",
                    value: hello.quic_disable_active_migration.to_string(),
                });
                if let Some(value) = hello.quic_active_connection_id_limit {
                    observations.push(Observation {
                        field: "quic.active_connection_id_limit",
                        value: value.to_string(),
                    });
                }
            }
            if let Some(value) = hello.quic_datagram_max_size {
                observations.push(Observation {
                    field: "quic.datagram_max_size",
                    value: value.to_string(),
                });
            }
        }
        UdpStreamAnalysis::FinalObservations(observations)
    }
}

struct ServerConnection {
    version: u32,
    initial_dcid: Vec<u8>,
    client_scid: Vec<u8>,
    client_direction: bool,
    retry_token: Option<Vec<u8>>,
}

/// Observes a server's first TLS ServerHello from the public QUIC Initial space.
#[derive(Default)]
pub struct QuicServerInitial {
    connection: Option<ServerConnection>,
    crypto: CryptoBuffer,
    largest_number: Option<u64>,
    server_datagrams: usize,
    finished: bool,
}

impl QuicServerInitial {
    fn server_hello(&mut self) -> UdpStreamAnalysis {
        let stream = self.crypto.contiguous();
        if stream.len() < 4 {
            return UdpStreamAnalysis::Pending;
        }
        let mut offset = 0;
        let mut seen_retry = false;
        loop {
            if stream.len() < offset + 4 {
                return UdpStreamAnalysis::Pending;
            }
            let length = usize::from(stream[offset + 1]) << 16
                | usize::from(stream[offset + 2]) << 8
                | usize::from(stream[offset + 3]);
            if stream[offset] != 2 || length > MAX_CRYPTO_BYTES - offset - 4 {
                self.finished = true;
                return UdpStreamAnalysis::Finished;
            }
            if stream.len() < offset + 4 + length {
                return UdpStreamAnalysis::Pending;
            }
            let Some(hello) = server_hello_metadata(&stream[offset + 4..offset + 4 + length])
            else {
                self.finished = true;
                return UdpStreamAnalysis::Finished;
            };
            if !hello.retry {
                self.finished = true;
                return UdpStreamAnalysis::FinalObservations(vec![
                    Observation {
                        field: "quic.server_version",
                        value: format!("0x{:04x}", hello.version),
                    },
                    Observation {
                        field: "quic.server_cipher",
                        value: format!("0x{:04x}", hello.cipher),
                    },
                ]);
            }
            if seen_retry {
                self.finished = true;
                return UdpStreamAnalysis::Finished;
            }
            seen_retry = true;
            offset += 4 + length;
        }
    }
}

impl UdpStreamAnalyzer for QuicServerInitial {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        if self.finished {
            return UdpStreamAnalysis::Finished;
        }
        if self
            .connection
            .as_ref()
            .is_some_and(|connection| connection.client_direction == reverse)
        {
            return UdpStreamAnalysis::Pending;
        }
        if let Some(connection) = &mut self.connection
            && connection.retry_token.is_none()
            && self.largest_number.is_none()
            && let Some(retry) = verified_retry(
                payload,
                connection.version,
                &connection.initial_dcid,
                &connection.client_scid,
            )
        {
            connection.initial_dcid = retry.scid.to_vec();
            connection.retry_token = Some(retry.token.to_vec());
            return UdpStreamAnalysis::Observations(vec![Observation {
                field: "quic.retry_integrity_valid",
                value: "true".into(),
            }]);
        }
        let mut datagram = payload;
        let mut packets = 0;
        let mut accepted = false;
        while let Some(header) = parse_header(datagram) {
            packets += 1;
            if packets > MAX_COALESCED_PACKETS {
                break;
            }
            let packet = &datagram[..header.packet_len];
            datagram = &datagram[header.packet_len..];
            if !header.initial {
                continue;
            }
            if let Some(connection) = &self.connection {
                if header.version != connection.version || header.dcid != connection.client_scid {
                    continue;
                }
                let Some(keys) =
                    initial_keys_for(connection.version, &connection.initial_dcid, true)
                else {
                    continue;
                };
                let Some((number, plaintext)) =
                    open_initial(packet, header.pn_offset, &keys, self.largest_number)
                else {
                    continue;
                };
                let Some(frames) = crypto_frames(&plaintext) else {
                    continue;
                };
                self.largest_number =
                    Some(self.largest_number.map_or(number, |old| old.max(number)));
                for frame in frames {
                    if !self.crypto.insert(frame) {
                        self.finished = true;
                        return UdpStreamAnalysis::Finished;
                    }
                }
                accepted = true;
            } else {
                let Some(keys) = initial_keys(header.version, header.dcid) else {
                    continue;
                };
                let Some((_, plaintext)) = open_initial(packet, header.pn_offset, &keys, None)
                else {
                    continue;
                };
                if crypto_frames(&plaintext).is_none() {
                    continue;
                }
                self.connection = Some(ServerConnection {
                    version: header.version,
                    initial_dcid: header.dcid.to_vec(),
                    client_scid: header.scid.to_vec(),
                    client_direction: reverse,
                    retry_token: None,
                });
            }
        }
        if self.connection.is_some()
            && self.connection.as_ref().unwrap().client_direction != reverse
        {
            self.server_datagrams += 1;
            if self.server_datagrams > MAX_CLIENT_DATAGRAMS {
                self.finished = true;
                return UdpStreamAnalysis::Finished;
            }
        }
        if accepted {
            self.server_hello()
        } else {
            UdpStreamAnalysis::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn vector(bytes: &[u8]) -> Vec<u8> {
        let mut output = (bytes.len() as u16).to_be_bytes().to_vec();
        output.extend_from_slice(bytes);
        output
    }

    fn client_hello(name: &str, with_transport_parameters: bool) -> Vec<u8> {
        let mut server_name = vec![0];
        server_name.extend(vector(name.as_bytes()));
        let mut extension = vec![0, 0];
        extension.extend(vector(&vector(&server_name)));
        let mut protocols = vec![2];
        protocols.extend(b"h3");
        protocols.push(5);
        protocols.extend(b"h3-29");
        extension.extend([0, 16]);
        extension.extend(vector(&vector(&protocols)));
        extension.extend([0, 43]);
        extension.extend(vector(&[4, 3, 4, 3, 3]));
        extension.extend([0, 10]);
        extension.extend(vector(&vector(&[0, 29])));
        extension.extend([0, 13]);
        extension.extend(vector(&vector(&[8, 4])));
        extension.extend([0, 51]);
        extension.extend(vector(&vector(&[0, 29, 0, 1, 1])));
        extension.extend([0xfe, 0x0d, 0, 1, 0]);
        if with_transport_parameters {
            extension.extend([
                0, 0x39, 0, 16, 0x0f, 0, 0x1b, 0, 0x0c, 0, 0x0e, 1, 4, 0x20, 2, 0x45, 0xb0, 0x01,
                1, 50,
            ]);
        }
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 1, 1, 0]);
        body.extend(vector(&extension));
        let len = body.len();
        let mut handshake = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        handshake.extend(body);
        handshake
    }

    fn encode_varint(value: usize) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else {
            vec![0x40 | (value >> 8) as u8, value as u8]
        }
    }

    fn initial_packet(
        version: u32,
        number: u8,
        offset: usize,
        data: &[u8],
        cids: (&[u8], &[u8], &[u8]),
        server: bool,
        token: &[u8],
    ) -> Vec<u8> {
        let (dcid, scid, key_dcid) = cids;
        let keys = initial_keys_for(version, key_dcid, server).unwrap();
        let mut plaintext = vec![6];
        plaintext.extend(encode_varint(offset));
        plaintext.extend(encode_varint(data.len()));
        plaintext.extend(data);
        plaintext.extend([0; 32]);

        let mut header = vec![if version == V2 { 0xd0 } else { 0xc0 }];
        header.extend(version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend(dcid);
        header.push(scid.len() as u8);
        header.extend(scid);
        header.extend(encode_varint(token.len()));
        header.extend(token);
        header.extend(encode_varint(1 + plaintext.len() + 16));
        let pn_offset = header.len();
        header.push(number);
        keys.payload
            .seal_in_place_append_tag(
                nonce(keys.iv, u64::from(number)),
                aead::Aad::from(header.as_slice()),
                &mut plaintext,
            )
            .unwrap();
        header.extend(plaintext);
        let mask = keys
            .header
            .new_mask(&header[pn_offset + 4..pn_offset + 20])
            .unwrap();
        header[0] ^= mask[0] & 0x0f;
        header[pn_offset] ^= mask[1];
        header
    }

    fn initial(version: u32, number: u8, offset: usize, data: &[u8]) -> Vec<u8> {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        initial_packet(
            version,
            number,
            offset,
            data,
            (&dcid, &[], &dcid),
            false,
            &[],
        )
    }

    fn server_hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0x42; 32]);
        body.extend([0, 0x13, 1, 0]);
        body.extend(vector(&[0, 43, 0, 2, 3, 4]));
        let len = body.len();
        let mut handshake = vec![2, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        handshake.extend(body);
        handshake
    }

    fn field<'a>(result: &'a UdpStreamAnalysis, name: &str) -> Option<&'a str> {
        match result {
            UdpStreamAnalysis::FinalObservations(values)
            | UdpStreamAnalysis::Observations(values) => values
                .iter()
                .find(|item| item.field == name)
                .map(|item| item.value.as_str()),
            _ => None,
        }
    }

    #[test]
    fn initial_material_matches_rfc_vectors() {
        // RFC 9001 A.1 and RFC 9369 A.1, DCID 8394c8f03e515708.
        let dcid = hex("8394c8f03e515708");
        for (version, key, iv, hp) in [
            (
                V1,
                "1f369613dd76d5467730efcbe3b1a22d",
                "fa044b2f42a3fd3b46fb255c",
                "9f50449e04a0e810283a1e9933adedd2",
            ),
            (
                V2,
                "8b1a0bc121284290a29e0971b5cd045d",
                "91f73e2351d8fa91660e909f",
                "45b95e15235d6f45a6b19cbcb0294ba9",
            ),
        ] {
            let actual = initial_material_for(version, &dcid, false).unwrap();
            assert_eq!(actual.0.as_slice(), hex(key));
            assert_eq!(actual.1.as_slice(), hex(iv));
            assert_eq!(actual.2.as_slice(), hex(hp));
        }
        for (version, key, iv, hp) in [
            (
                V1,
                "cf3a5331653c364c88f0f379b6067e37",
                "0ac1493ca1905853b0bba03e",
                "c206b8d9b9f0f37644430b490eeaa314",
            ),
            (
                V2,
                "82db637861d55e1d011f19ea71d5d2a7",
                "dd13c276499c0249d3310652",
                "edf6d05c83121201b436e16877593c3a",
            ),
        ] {
            let actual = initial_material_for(version, &dcid, true).unwrap();
            assert_eq!(actual.0.as_slice(), hex(key));
            assert_eq!(actual.1.as_slice(), hex(iv));
            assert_eq!(actual.2.as_slice(), hex(hp));
        }
    }

    #[test]
    fn validates_v1_v2_retry_integrity_vectors() {
        // RFC 9001 A.4 and RFC 9369 A.4 use the same original client DCID.
        let original_dcid = hex("8394c8f03e515708");
        for (version, wire) in [
            (
                V1,
                "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
            ),
            (
                V2,
                "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6",
            ),
        ] {
            let packet = hex(wire);
            let retry = verified_retry(&packet, version, &original_dcid, &[]).unwrap();
            assert_eq!(retry.scid, hex("f067a5502a4262b5"));
            assert_eq!(retry.token, b"token");
            let mut corrupt = packet.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(verified_retry(&corrupt, version, &original_dcid, &[]).is_none());
            assert!(verified_retry(&packet, version, &[0; 8], &[]).is_none());
        }
    }

    #[test]
    fn retry_rekeys_both_initial_analyzers() {
        let original_dcid = hex("8394c8f03e515708");
        let retry_dcid = hex("f067a5502a4262b5");
        for (version, wire) in [
            (
                V1,
                "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
            ),
            (
                V2,
                "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6",
            ),
        ] {
            let hello = client_hello("after-retry.test", true);
            let before = initial_packet(
                version,
                0,
                0,
                &hello[..8],
                (&original_dcid, &[], &original_dcid),
                false,
                &[],
            );
            let retry = hex(wire);
            let after = initial_packet(
                version,
                1,
                0,
                &hello,
                (&retry_dcid, &[], &retry_dcid),
                false,
                b"token",
            );
            let wrong_token = initial_packet(
                version,
                1,
                0,
                &hello,
                (&retry_dcid, &[], &retry_dcid),
                false,
                b"wrong",
            );
            let reply = initial_packet(
                version,
                0,
                0,
                &server_hello(),
                (&[], &[0xaa], &retry_dcid),
                true,
                &[],
            );
            let mut client = QuicInitial::default();
            assert!(matches!(
                client.feed(&before, false),
                UdpStreamAnalysis::Pending
            ));
            assert!(matches!(
                client.feed(&retry, true),
                UdpStreamAnalysis::Pending
            ));
            assert!(matches!(
                client.feed(&wrong_token, false),
                UdpStreamAnalysis::Pending
            ));
            assert_eq!(
                field(&client.feed(&after, false), "quic.sni"),
                Some("after-retry.test")
            );

            let mut server = QuicServerInitial::default();
            assert!(matches!(
                server.feed(&before, false),
                UdpStreamAnalysis::Pending
            ));
            assert_eq!(
                field(&server.feed(&retry, true), "quic.retry_integrity_valid"),
                Some("true")
            );
            assert!(matches!(
                server.feed(&after, false),
                UdpStreamAnalysis::Pending
            ));
            assert_eq!(
                field(&server.feed(&reply, true), "quic.server_cipher"),
                Some("0x1301")
            );
        }
    }

    #[test]
    fn corrupted_retry_does_not_change_initial_keys() {
        let original_dcid = hex("8394c8f03e515708");
        let hello = client_hello("no-retry.test", true);
        let before = initial_packet(
            V1,
            0,
            0,
            &hello[..8],
            (&original_dcid, &[], &original_dcid),
            false,
            &[],
        );
        let continued = initial_packet(
            V1,
            1,
            0,
            &hello,
            (&original_dcid, &[], &original_dcid),
            false,
            &[],
        );
        let reply = initial_packet(
            V1,
            0,
            0,
            &server_hello(),
            (&[], &[0xaa], &original_dcid),
            true,
            &[],
        );
        let mut corrupt =
            hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        *corrupt.last_mut().unwrap() ^= 1;
        let mut client = QuicInitial::default();
        let mut server = QuicServerInitial::default();
        assert!(matches!(
            client.feed(&before, false),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            server.feed(&before, false),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            client.feed(&corrupt, true),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            server.feed(&corrupt, true),
            UdpStreamAnalysis::Pending
        ));
        assert_eq!(
            field(&client.feed(&continued, false), "quic.sni"),
            Some("no-retry.test")
        );
        assert_eq!(
            field(&server.feed(&reply, true), "quic.server_cipher"),
            Some("0x1301")
        );
    }

    #[test]
    fn decrypts_and_reassembles_v1_v2_client_hello() {
        for version in [V1, V2] {
            let hello = client_hello("Blocked.Test", true);
            let split = hello.len() / 2;
            let later = initial(version, 1, split, &hello[split..]);
            let earlier = initial(version, 0, 0, &hello[..split]);
            let mut analyzer = QuicInitial::default();
            assert!(matches!(
                analyzer.feed(&later, false),
                UdpStreamAnalysis::Pending
            ));
            assert!(matches!(
                analyzer.feed(&[0xff; 64], true),
                UdpStreamAnalysis::Pending
            ));
            let result = analyzer.feed(&earlier, false);
            assert_eq!(field(&result, "quic.sni"), Some("blocked.test"));
            assert_eq!(field(&result, "quic.alpn"), Some("h3"));
            assert_eq!(field(&result, "quic.tls_supported_version"), Some("0x0304"));
            assert_eq!(field(&result, "quic.ech_extension"), Some("true"));
            assert_eq!(field(&result, "quic.transport_parameters"), Some("true"));
            assert_eq!(
                field(&result, "quic.transport_parameter_ids"),
                Some("0xf,0x1b,0xc,0xe,0x20,0x1")
            );
            assert_eq!(
                field(&result, "quic.transport_parameter_ids_no_grease"),
                Some("0xf,0xc,0xe,0x20,0x1")
            );
            assert_eq!(
                field(&result, "quic.disable_active_migration"),
                Some("true")
            );
            assert_eq!(field(&result, "quic.active_connection_id_limit"), Some("4"));
            assert_eq!(field(&result, "quic.datagram_max_size"), Some("1456"));
            assert_eq!(field(&result, "quic.max_idle_timeout_ms"), Some("50"));
            assert_eq!(
                field(&result, "quic.tls_client_legacy_version"),
                Some("0x0303")
            );
            assert_eq!(field(&result, "quic.tls_client_session_id_len"), Some("0"));
            assert_eq!(
                field(&result, "quic.tls_client_compression_methods"),
                Some("0x00")
            );
            assert_eq!(
                field(&result, "quic.tls_client_random").map(str::len),
                Some(64)
            );
            assert_eq!(
                field(&result, "quic.tls_client_cipher_suites"),
                Some("0x1301")
            );
            assert_eq!(
                field(&result, "quic.tls_client_extensions"),
                Some("0x0000,0x0010,0x002b,0x000a,0x000d,0x0033,0xfe0d,0x0039")
            );
            assert_eq!(
                field(&result, "quic.tls_client_supported_groups"),
                Some("0x001d")
            );
            assert_eq!(
                field(&result, "quic.tls_client_signature_algorithms"),
                Some("0x0804")
            );
            assert_eq!(
                field(&result, "quic.tls_client_key_share_groups"),
                Some("0x001d")
            );
            if let UdpStreamAnalysis::FinalObservations(values) = &result {
                assert!(
                    values
                        .iter()
                        .any(|value| value.field == "quic.alpn" && value.value == "h3-29")
                );
                assert!(values.iter().any(|value| {
                    value.field == "quic.tls_supported_version" && value.value == "0x0303"
                }));
            }
            assert_eq!(
                field(&result, "quic.version"),
                Some(if version == V1 { "1" } else { "2" })
            );
            let mut reversed = QuicInitial::default();
            assert!(matches!(
                reversed.feed(&later, true),
                UdpStreamAnalysis::Pending
            ));
            assert_eq!(
                field(&reversed.feed(&earlier, true), "quic.sni"),
                Some("blocked.test")
            );
        }
    }

    #[test]
    fn missing_transport_parameters_are_reported_separately_from_h3_alpn() {
        let hello = client_hello("example.test", false);
        let result = QuicInitial::default().feed(&initial(V1, 0, 0, &hello), false);
        assert_eq!(field(&result, "quic.alpn"), Some("h3"));
        assert_eq!(field(&result, "quic.transport_parameters"), Some("false"));
        assert_eq!(field(&result, "quic.datagram_max_size"), None);
    }

    #[test]
    fn rejects_corrupt_initial_before_binding_connection() {
        let hello = client_hello("blocked.test", true);
        let valid = initial(V1, 0, 0, &hello);
        let mut corrupt = valid.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut analyzer = QuicInitial::default();
        assert!(matches!(
            analyzer.feed(&corrupt, false),
            UdpStreamAnalysis::Pending
        ));
        assert_eq!(
            field(&analyzer.feed(&valid, false), "quic.sni"),
            Some("blocked.test")
        );
    }

    #[test]
    fn decrypts_and_reassembles_v1_v2_server_hello() {
        let initial_dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client_scid = [0x11, 0x22, 0x33, 0x44];
        let server_scid = [0xaa, 0xbb, 0xcc, 0xdd];
        for version in [V1, V2] {
            let client = initial_packet(
                version,
                0,
                0,
                &client_hello("example.test", true),
                (&initial_dcid, &client_scid, &initial_dcid),
                false,
                &[],
            );
            let hello = server_hello();
            let split = hello.len() / 2;
            let later = initial_packet(
                version,
                1,
                split,
                &hello[split..],
                (&client_scid, &server_scid, &initial_dcid),
                true,
                &[],
            );
            let earlier = initial_packet(
                version,
                0,
                0,
                &hello[..split],
                (&client_scid, &server_scid, &initial_dcid),
                true,
                &[],
            );
            let mut analyzer = QuicServerInitial::default();
            assert!(matches!(
                analyzer.feed(&client, false),
                UdpStreamAnalysis::Pending
            ));
            assert!(matches!(
                analyzer.feed(&later, true),
                UdpStreamAnalysis::Pending
            ));
            let result = analyzer.feed(&earlier, true);
            assert_eq!(field(&result, "quic.server_version"), Some("0x0304"));
            assert_eq!(field(&result, "quic.server_cipher"), Some("0x1301"));
            assert!(matches!(
                analyzer.feed(&earlier, true),
                UdpStreamAnalysis::Finished
            ));

            let mut reversed = QuicServerInitial::default();
            assert!(matches!(
                reversed.feed(&client, true),
                UdpStreamAnalysis::Pending
            ));
            assert_eq!(
                field(&reversed.feed(&earlier, false), "quic.server_cipher"),
                None
            );
            assert_eq!(
                field(&reversed.feed(&later, false), "quic.server_cipher"),
                Some("0x1301")
            );
        }
    }

    #[test]
    fn server_hello_requires_matching_cid_and_valid_initial_tag() {
        let initial_dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let client_scid = [0x11, 0x22, 0x33, 0x44];
        let client = initial_packet(
            V1,
            0,
            0,
            &client_hello("example.test", true),
            (&initial_dcid, &client_scid, &initial_dcid),
            false,
            &[],
        );
        let valid = initial_packet(
            V1,
            0,
            0,
            &server_hello(),
            (&client_scid, &[0xaa], &initial_dcid),
            true,
            &[],
        );
        let wrong_cid = initial_packet(
            V1,
            0,
            0,
            &server_hello(),
            (&[0xff], &[0xaa], &initial_dcid),
            true,
            &[],
        );
        let mut corrupt = valid.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut analyzer = QuicServerInitial::default();
        assert!(matches!(
            analyzer.feed(&client, false),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            analyzer.feed(&wrong_cid, true),
            UdpStreamAnalysis::Pending
        ));
        assert!(matches!(
            analyzer.feed(&corrupt, true),
            UdpStreamAnalysis::Pending
        ));
        assert_eq!(
            field(&analyzer.feed(&valid, true), "quic.server_cipher"),
            Some("0x1301")
        );
    }

    #[test]
    #[ignore = "requires the read-only OpenGFW reference fixtures"]
    fn decrypts_reference_client_initial_captures() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../references/opengfw/analyzer/udp/testdata");
        let mut numeric_signatures = std::collections::HashSet::new();
        for (name, count, expected, groups, shares) in [
            (
                "chrome153",
                2,
                "chrome.sniff.test",
                "0x11ec,0x001d,0x0017,0x0018",
                "0x11ec,0x001d",
            ),
            (
                "firefox153esr",
                2,
                "firefox.sniff.test",
                "0x11ec,0x001d,0x0017,0x0018,0x0019",
                "0x11ec,0x001d,0x0017",
            ),
            (
                "curl8.14-openssl3.5",
                2,
                "curl.sniff.test",
                "0x11ec,0x001d,0x0017,0x001e,0x0018,0x0019,0x0100,0x0101",
                "0x11ec,0x001d",
            ),
            (
                "quiche",
                3,
                "quiche.sniff.test",
                "0x11ec,0xfe32,0x001d,0x0017,0x0018",
                "0x11ec,0x001d",
            ),
            (
                "ngtcp2-1.11",
                1,
                "ngtcp2.sniff.test",
                "0x001d,0x0017,0x0018,0x0019",
                "0x001d,0x0017",
            ),
            (
                "aioquic1.2",
                1,
                "aioquic.sniff.test",
                "0x0017,0x0018,0x001d,0x001e",
                "0x0017,0x0018,0x001d,0x001e",
            ),
        ] {
            let mut analyzer = QuicInitial::default();
            let mut result = UdpStreamAnalysis::Pending;
            for index in 0..count {
                let bytes = std::fs::read(base.join(format!("quic-{name}-{index}.bin"))).unwrap();
                result = analyzer.feed(&bytes, false);
            }
            assert_eq!(field(&result, "quic.sni"), Some(expected), "{name}");
            numeric_signatures.insert(
                [
                    "quic.max_idle_timeout_ms",
                    "quic.max_udp_payload_size",
                    "quic.initial_max_data",
                    "quic.initial_max_streams_bidi",
                    "quic.initial_max_streams_uni",
                ]
                .map(|field_name| field(&result, field_name).unwrap_or("?"))
                .join(","),
            );
            assert!(
                field(&result, "quic.transport_parameter_ids")
                    .is_some_and(|ids| ids.split(',').any(|id| id == "0xf")),
                "{name}"
            );
            assert!(
                field(&result, "quic.transport_parameter_ids_no_grease").is_some(),
                "{name}"
            );
            assert_eq!(
                field(&result, "quic.tls_client_session_id_len"),
                Some("0"),
                "{name}"
            );
            assert_eq!(
                field(&result, "quic.tls_client_compression_methods"),
                Some("0x00"),
                "{name}"
            );
            assert_eq!(
                field(&result, "quic.tls_client_random").map(str::len),
                Some(64),
                "{name}"
            );
            assert_eq!(
                field(&result, "quic.tls_client_supported_groups"),
                Some(groups),
                "{name}"
            );
            assert_eq!(
                field(&result, "quic.tls_client_key_share_groups"),
                Some(shares),
                "{name}"
            );
            assert!(
                field(&result, "quic.tls_client_signature_algorithms")
                    .is_some_and(|value| value.starts_with("0x")),
                "{name}"
            );
        }
        assert_eq!(numeric_signatures.len(), 6);
        let read = |name: &str, index| {
            std::fs::read(base.join(format!("quic-{name}-{index}.bin"))).unwrap()
        };
        let chrome = [read("chrome153", 0), read("chrome153", 1)];
        let firefox = read("firefox153esr", 1);
        let curl = read("curl8.14-openssl3.5", 1);
        for (name, packets) in [
            ("reordered", vec![&chrome[1][..], &chrome[0][..]]),
            (
                "duplicates",
                vec![&chrome[0][..], &chrome[0][..], &chrome[1][..]],
            ),
            (
                "other connections",
                vec![&chrome[0][..], &firefox[..], &curl[..], &chrome[1][..]],
            ),
        ] {
            let mut analyzer = QuicInitial::default();
            let mut result = UdpStreamAnalysis::Pending;
            for packet in packets {
                result = analyzer.feed(packet, false);
            }
            assert_eq!(
                field(&result, "quic.sni"),
                Some("chrome.sniff.test"),
                "{name}"
            );
        }
        let mut analyzer = QuicInitial::default();
        let coalesced = [&chrome[0][..], &chrome[1][..]].concat();
        assert_eq!(
            field(&analyzer.feed(&coalesced, false), "quic.sni"),
            Some("chrome.sniff.test")
        );
    }

    #[test]
    #[ignore = "requires the locally captured official Hysteria2 client first flight"]
    fn decrypts_official_hysteria2_plain_client_initial() {
        use std::collections::{BTreeSet, HashSet};

        let ids = |value: &str| value.split(',').map(str::to_owned).collect::<BTreeSet<_>>();
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../references/opengfw/analyzer/udp/testdata");
        let mut chrome = QuicInitial::default();
        let mut comparison = UdpStreamAnalysis::Pending;
        for index in 0..2 {
            let packet = std::fs::read(base.join(format!("quic-chrome153-{index}.bin"))).unwrap();
            comparison = chrome.feed(&packet, false);
        }
        let numeric_fields = [
            "quic.max_idle_timeout_ms",
            "quic.max_udp_payload_size",
            "quic.initial_max_data",
            "quic.initial_max_stream_data_bidi_local",
            "quic.initial_max_stream_data_bidi_remote",
            "quic.initial_max_stream_data_uni",
            "quic.initial_max_streams_bidi",
            "quic.initial_max_streams_uni",
            "quic.ack_delay_exponent",
            "quic.max_ack_delay_ms",
            "quic.active_connection_id_limit",
            "quic.datagram_max_size",
        ];
        let capture_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hy2-capture");
        let mut extension_orders = HashSet::new();
        let mut parameter_orders = HashSet::new();
        for run in 0..16 {
            let capture =
                std::fs::read(capture_dir.join(format!("client-plain-{run}.bin"))).unwrap();
            assert_eq!(&capture[..4], b"HY2C");
            let mut cursor = 6;
            let mut analyzer = QuicInitial::default();
            let mut result = UdpStreamAnalysis::Pending;
            for _ in 0..capture[5] {
                let length =
                    u16::from_be_bytes(capture[cursor..cursor + 2].try_into().unwrap()) as usize;
                cursor += 2;
                result = analyzer.feed(&capture[cursor..cursor + length], false);
                cursor += length;
                if matches!(result, UdpStreamAnalysis::FinalObservations(_)) {
                    break;
                }
            }
            assert_eq!(field(&result, "quic.alpn"), Some("h3"), "run {run}");
            assert_eq!(field(&result, "quic.sni"), Some("example.com"), "run {run}");
            for name in numeric_fields {
                assert_eq!(
                    field(&result, name),
                    field(&comparison, name),
                    "{name} run {run}"
                );
            }
            for name in [
                "quic.datagram_max_size",
                "quic.tls_client_cipher_suites_no_grease",
                "quic.tls_client_supported_groups_no_grease",
            ] {
                assert_eq!(
                    field(&result, name),
                    field(&comparison, name),
                    "{name} run {run}"
                );
            }
            for (name, orders) in [
                (
                    "quic.tls_client_extensions_no_grease",
                    &mut extension_orders,
                ),
                (
                    "quic.transport_parameter_ids_no_grease",
                    &mut parameter_orders,
                ),
            ] {
                let value = field(&result, name).unwrap();
                assert_eq!(
                    ids(value),
                    ids(field(&comparison, name).unwrap()),
                    "{name} run {run}"
                );
                orders.insert(value.to_owned());
            }
        }
        assert!(extension_orders.len() > 1);
        assert!(parameter_orders.len() > 1);
    }
}
