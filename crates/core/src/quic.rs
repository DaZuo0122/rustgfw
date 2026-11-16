//! QUIC v1/v2 client Initial inspection. Initial keys are public by design.
use crate::{
    inspect::{Observation, UdpStreamAnalysis, UdpStreamAnalyzer},
    tls::client_hello_metadata,
};
use ring::{
    aead::{self, quic},
    hkdf,
};

pub const FIELDS: &[&str] = &["quic.version", "quic.sni", "quic.alpn"];
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

fn initial_material(version: u32, dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let (salt, key_label, iv_label, hp_label) = match version {
        V1 => (&SALT_V1[..], "quic key", "quic iv", "quic hp"),
        V2 => (&SALT_V2[..], "quicv2 key", "quicv2 iv", "quicv2 hp"),
        _ => return None,
    };
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let secret = expand_label(&initial, "client in", 32)?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
    let key = expand_label(&client, key_label, 16)?.try_into().ok()?;
    let iv: [u8; 12] = expand_label(&client, iv_label, 12)?.try_into().ok()?;
    let hp = expand_label(&client, hp_label, 16)?.try_into().ok()?;
    Some((key, iv, hp))
}

fn initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (key, iv, hp) = initial_material(version, dcid)?;
    Some(InitialKeys {
        payload: aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).ok()?),
        header: quic::HeaderProtectionKey::new(&quic::AES_128, &hp).ok()?,
        iv,
    })
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
    dcid: &'a [u8],
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
    bytes.get(cursor..cursor + scid_len)?;
    cursor += scid_len;
    if initial {
        let token_len = usize::try_from(varint(bytes, &mut cursor)?).ok()?;
        bytes.get(cursor..cursor.checked_add(token_len)?)?;
        cursor += token_len;
    }
    let length = usize::try_from(varint(bytes, &mut cursor)?).ok()?;
    let packet_len = cursor.checked_add(length)?;
    if length < 17 || packet_len > bytes.len() {
        return None;
    }
    Some(Header {
        version,
        dcid,
        packet_len,
        pn_offset: cursor,
        initial,
    })
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
    fragments: Vec<Fragment>,
    retained_bytes: usize,
    largest_number: Option<u64>,
    client_direction: Option<bool>,
    client_datagrams: usize,
    finished: bool,
}

impl QuicInitial {
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

impl UdpStreamAnalyzer for QuicInitial {
    fn feed(&mut self, payload: &[u8], reverse: bool) -> UdpStreamAnalysis {
        if self.finished {
            return UdpStreamAnalysis::Finished;
        }
        if self
            .client_direction
            .is_some_and(|direction| direction != reverse)
        {
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
                self.client_direction = Some(reverse);
            }
            self.largest_number = Some(self.largest_number.map_or(number, |old| old.max(number)));
            for frame in frames {
                if !self.insert(frame) {
                    self.finished = true;
                    return UdpStreamAnalysis::Finished;
                }
            }
            accepted = true;
        }
        if !accepted {
            return UdpStreamAnalysis::Pending;
        }
        let stream = self.contiguous();
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
        }
        UdpStreamAnalysis::FinalObservations(observations)
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

    fn client_hello(name: &str) -> Vec<u8> {
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

    fn initial(version: u32, number: u8, offset: usize, data: &[u8]) -> Vec<u8> {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = initial_keys(version, &dcid).unwrap();
        let mut plaintext = vec![6];
        plaintext.extend(encode_varint(offset));
        plaintext.extend(encode_varint(data.len()));
        plaintext.extend(data);
        plaintext.extend([0; 32]);

        let mut header = vec![if version == V2 { 0xd0 } else { 0xc0 }];
        header.extend(version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend(dcid);
        header.extend([0, 0]); // Empty source CID and token.
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

    fn field<'a>(result: &'a UdpStreamAnalysis, name: &str) -> Option<&'a str> {
        match result {
            UdpStreamAnalysis::FinalObservations(values) => values
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
            let actual = initial_material(version, &dcid).unwrap();
            assert_eq!(actual.0.as_slice(), hex(key));
            assert_eq!(actual.1.as_slice(), hex(iv));
            assert_eq!(actual.2.as_slice(), hex(hp));
        }
    }

    #[test]
    fn decrypts_and_reassembles_v1_v2_client_hello() {
        for version in [V1, V2] {
            let hello = client_hello("Blocked.Test");
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
            if let UdpStreamAnalysis::FinalObservations(values) = &result {
                assert!(
                    values
                        .iter()
                        .any(|value| value.field == "quic.alpn" && value.value == "h3-29")
                );
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
    fn rejects_corrupt_initial_before_binding_connection() {
        let hello = client_hello("blocked.test");
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
    #[ignore = "requires the read-only OpenGFW reference fixtures"]
    fn decrypts_reference_client_initial_captures() {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../references/opengfw/analyzer/udp/testdata");
        for (name, count, expected) in [
            ("chrome153", 2, "chrome.sniff.test"),
            ("firefox153esr", 2, "firefox.sniff.test"),
            ("curl8.14-openssl3.5", 2, "curl.sniff.test"),
            ("quiche", 3, "quiche.sniff.test"),
            ("ngtcp2-1.11", 1, "ngtcp2.sniff.test"),
            ("aioquic1.2", 1, "aioquic.sniff.test"),
        ] {
            let mut analyzer = QuicInitial::default();
            let mut result = UdpStreamAnalysis::Pending;
            for index in 0..count {
                let bytes = std::fs::read(base.join(format!("quic-{name}-{index}.bin"))).unwrap();
                result = analyzer.feed(&bytes, false);
            }
            assert_eq!(field(&result, "quic.sni"), Some(expected), "{name}");
        }
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
}
