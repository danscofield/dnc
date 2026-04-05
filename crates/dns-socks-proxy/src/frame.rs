// Frame protocol: types, encoder, and decoder.

use std::fmt;

use rand::Rng;
use thiserror::Error;

use crate::socks::{ConnectRequest, TargetAddr};

// ---------------------------------------------------------------------------
// Address type constants (SOCKS5 / SYN payload)
// ---------------------------------------------------------------------------

const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame too short: need at least 15 bytes, got {0}")]
    TooShort(usize),

    #[error("invalid frame type: 0x{0:02x}")]
    InvalidFrameType(u8),

    #[error("invalid session_id length: expected 8, got {0}")]
    InvalidSessionIdLen(u8),

    #[error("invalid address type in SYN payload: 0x{0:02x}")]
    InvalidAddressType(u8),

    #[error("SYN payload too short: need at least {expected} bytes, got {actual}")]
    PayloadTooShort { expected: usize, actual: usize },

    #[error("domain name too long: max 255 bytes, got {0}")]
    DomainTooLong(usize),
}

// ---------------------------------------------------------------------------
// FrameType
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x01,
    Ack = 0x02,
    Syn = 0x03,
    SynAck = 0x04,
    Fin = 0x05,
    Rst = 0x06,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self, FrameError> {
        match v {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Ack),
            0x03 => Ok(Self::Syn),
            0x04 => Ok(Self::SynAck),
            0x05 => Ok(Self::Fin),
            0x06 => Ok(Self::Rst),
            other => Err(FrameError::InvalidFrameType(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// FrameFlags
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub fn empty() -> Self {
        Self(0)
    }
}

// ---------------------------------------------------------------------------
// SessionId
// ---------------------------------------------------------------------------

const SESSION_ID_LEN: usize = 8;

/// Alphanumeric charset used for session ID generation.
const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

impl SessionId {
    /// Generate a random 8-character alphanumeric session ID.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; SESSION_ID_LEN];
        for b in buf.iter_mut() {
            *b = ALPHANUMERIC[rng.gen_range(0..ALPHANUMERIC.len())];
        }
        Self(buf)
    }

    /// Return the session ID as an ASCII string slice.
    pub fn as_str(&self) -> &str {
        // Safety: we only ever store ASCII alphanumeric bytes.
        std::str::from_utf8(&self.0).expect("SessionId contains only ASCII")
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    pub session_id: SessionId,
    pub seq: u32,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Header size: 1 (session_id_len) + 8 (session_id) + 4 (seq) + 1 (type) + 1 (flags) = 15
pub const FRAME_HEADER_SIZE: usize = 15;

/// Encode a `Frame` into its wire-format byte representation.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + frame.payload.len());

    // session_id_len (1 byte, always 8)
    buf.push(SESSION_ID_LEN as u8);

    // session_id (8 bytes)
    buf.extend_from_slice(&frame.session_id.0);

    // seq (4 bytes, big-endian)
    buf.extend_from_slice(&frame.seq.to_be_bytes());

    // type (1 byte)
    buf.push(frame.frame_type as u8);

    // flags (1 byte)
    buf.push(frame.flags.0);

    // payload (remaining)
    buf.extend_from_slice(&frame.payload);

    buf
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Decode a wire-format byte slice into a `Frame`.
pub fn decode_frame(data: &[u8]) -> Result<Frame, FrameError> {
    if data.len() < FRAME_HEADER_SIZE {
        return Err(FrameError::TooShort(data.len()));
    }

    let session_id_len = data[0];
    if session_id_len != SESSION_ID_LEN as u8 {
        return Err(FrameError::InvalidSessionIdLen(session_id_len));
    }

    let mut sid = [0u8; SESSION_ID_LEN];
    sid.copy_from_slice(&data[1..1 + SESSION_ID_LEN]);

    let seq = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

    let frame_type = FrameType::from_u8(data[13])?;

    let flags = FrameFlags(data[14]);

    let payload = data[FRAME_HEADER_SIZE..].to_vec();

    Ok(Frame {
        session_id: SessionId(sid),
        seq,
        frame_type,
        flags,
        payload,
    })
}

// ---------------------------------------------------------------------------
// SYN payload encoder / decoder
// ---------------------------------------------------------------------------

/// Encode a SYN frame payload: addr_type + address + port(BE) + x25519_pubkey + client_id_len(1) + client_id.
///
/// The MAC is NOT included here — it is appended separately by the crypto module.
pub fn encode_syn_payload(target: &ConnectRequest, pubkey: &[u8; 32], client_id: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    match &target.target_addr {
        TargetAddr::Ipv4(ip) => {
            buf.push(ADDR_TYPE_IPV4);
            buf.extend_from_slice(ip);
        }
        TargetAddr::Domain(domain) => {
            buf.push(ADDR_TYPE_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ipv6(ip) => {
            buf.push(ADDR_TYPE_IPV6);
            buf.extend_from_slice(ip);
        }
    }

    buf.extend_from_slice(&target.target_port.to_be_bytes());
    buf.extend_from_slice(pubkey);
    buf.push(client_id.len() as u8);
    buf.extend_from_slice(client_id.as_bytes());

    buf
}

/// Decode a SYN frame payload into (TargetAddr, port, x25519_pubkey, client_id).
///
/// Expected layout: addr_type(1) | address(var) | port(2,BE) | x25519_pubkey(32) | client_id_len(1) | client_id(var)
pub fn decode_syn_payload(data: &[u8]) -> Result<(TargetAddr, u16, [u8; 32], String), FrameError> {
    // Minimum: 1 (addr_type) + at least 4 (IPv4) + 2 (port) + 32 (pubkey) = 39
    if data.is_empty() {
        return Err(FrameError::PayloadTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let addr_type = data[0];
    let (addr, addr_end) = match addr_type {
        ADDR_TYPE_IPV4 => {
            let needed = 1 + 4 + 2 + 32; // 39
            if data.len() < needed {
                return Err(FrameError::PayloadTooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[1..5]);
            (TargetAddr::Ipv4(ip), 5)
        }
        ADDR_TYPE_DOMAIN => {
            // 1 (addr_type) + 1 (len) + domain_len + 2 (port) + 32 (pubkey)
            if data.len() < 2 {
                return Err(FrameError::PayloadTooShort {
                    expected: 2,
                    actual: data.len(),
                });
            }
            let domain_len = data[1] as usize;
            let needed = 1 + 1 + domain_len + 2 + 32;
            if data.len() < needed {
                return Err(FrameError::PayloadTooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let domain_bytes = &data[2..2 + domain_len];
            let domain = String::from_utf8(domain_bytes.to_vec()).map_err(|_| {
                FrameError::PayloadTooShort {
                    expected: needed,
                    actual: data.len(),
                }
            })?;
            (TargetAddr::Domain(domain), 2 + domain_len)
        }
        ADDR_TYPE_IPV6 => {
            let needed = 1 + 16 + 2 + 32; // 51
            if data.len() < needed {
                return Err(FrameError::PayloadTooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            (TargetAddr::Ipv6(ip), 17)
        }
        other => return Err(FrameError::InvalidAddressType(other)),
    };

    let port = u16::from_be_bytes([data[addr_end], data[addr_end + 1]]);

    let pubkey_start = addr_end + 2;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[pubkey_start..pubkey_start + 32]);

    // Extract client_id (optional for backward compat — if not present, return empty).
    let client_id_len_offset = pubkey_start + 32;
    let client_id = if client_id_len_offset < data.len() {
        let cid_len = data[client_id_len_offset] as usize;
        let cid_start = client_id_len_offset + 1;
        if cid_start + cid_len <= data.len() {
            String::from_utf8(data[cid_start..cid_start + cid_len].to_vec())
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Ok((addr, port, pubkey, client_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks::{ConnectRequest, TargetAddr};

    #[test]
    fn session_id_generate_format() {
        let id = SessionId::generate();
        assert_eq!(id.0.len(), 8);
        for &b in &id.0 {
            assert!(
                b.is_ascii_alphanumeric(),
                "byte {b} is not alphanumeric"
            );
        }
    }

    #[test]
    fn session_id_display() {
        let id = SessionId(*b"aBcD1234");
        assert_eq!(id.to_string(), "aBcD1234");
        assert_eq!(id.as_str(), "aBcD1234");
    }

    #[test]
    fn encode_decode_round_trip() {
        let frame = Frame {
            session_id: SessionId(*b"abcd1234"),
            seq: 42,
            frame_type: FrameType::Data,
            flags: FrameFlags::empty(),
            payload: vec![0xDE, 0xAD],
        };

        let encoded = encode_frame(&frame);
        assert_eq!(encoded.len(), FRAME_HEADER_SIZE + 2);

        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn encode_decode_all_frame_types() {
        let types = [
            FrameType::Data,
            FrameType::Ack,
            FrameType::Syn,
            FrameType::SynAck,
            FrameType::Fin,
            FrameType::Rst,
        ];

        for ft in types {
            let frame = Frame {
                session_id: SessionId(*b"XXXXXXXX"),
                seq: 0,
                frame_type: ft,
                flags: FrameFlags::empty(),
                payload: vec![],
            };
            let decoded = decode_frame(&encode_frame(&frame)).unwrap();
            assert_eq!(decoded.frame_type, ft);
        }
    }

    #[test]
    fn decode_too_short() {
        let result = decode_frame(&[0u8; 10]);
        assert!(matches!(result, Err(FrameError::TooShort(10))));
    }

    #[test]
    fn decode_invalid_frame_type() {
        let frame = Frame {
            session_id: SessionId(*b"abcd1234"),
            seq: 0,
            frame_type: FrameType::Data,
            flags: FrameFlags::empty(),
            payload: vec![],
        };
        let mut encoded = encode_frame(&frame);
        // Corrupt the type byte (offset 13)
        encoded[13] = 0xFF;
        let result = decode_frame(&encoded);
        assert!(matches!(result, Err(FrameError::InvalidFrameType(0xFF))));
    }

    #[test]
    fn decode_invalid_session_id_len() {
        let mut data = vec![0u8; FRAME_HEADER_SIZE];
        data[0] = 5; // wrong session_id_len
        data[13] = 0x01; // valid type
        let result = decode_frame(&data);
        assert!(matches!(result, Err(FrameError::InvalidSessionIdLen(5))));
    }

    // -----------------------------------------------------------------------
    // SYN payload encode/decode tests
    // -----------------------------------------------------------------------

    fn dummy_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn syn_payload_ipv4_round_trip() {
        let target = ConnectRequest {
            target_addr: TargetAddr::Ipv4([192, 168, 1, 1]),
            target_port: 8080,
        };
        let pubkey = dummy_pubkey();
        let encoded = encode_syn_payload(&target, &pubkey, "testclient");
        let (addr, port, pk, cid) = decode_syn_payload(&encoded).unwrap();
        assert_eq!(addr, target.target_addr);
        assert_eq!(port, 8080);
        assert_eq!(pk, pubkey);
        assert_eq!(cid, "testclient");
    }

    #[test]
    fn syn_payload_ipv6_round_trip() {
        let ipv6 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let target = ConnectRequest {
            target_addr: TargetAddr::Ipv6(ipv6),
            target_port: 443,
        };
        let pubkey = dummy_pubkey();
        let encoded = encode_syn_payload(&target, &pubkey, "c2");
        let (addr, port, pk, cid) = decode_syn_payload(&encoded).unwrap();
        assert_eq!(addr, target.target_addr);
        assert_eq!(port, 443);
        assert_eq!(pk, pubkey);
        assert_eq!(cid, "c2");
    }

    #[test]
    fn syn_payload_domain_round_trip() {
        let target = ConnectRequest {
            target_addr: TargetAddr::Domain("example.com".to_string()),
            target_port: 80,
        };
        let pubkey = dummy_pubkey();
        let encoded = encode_syn_payload(&target, &pubkey, "myclient");
        let (addr, port, pk, cid) = decode_syn_payload(&encoded).unwrap();
        assert_eq!(addr, target.target_addr);
        assert_eq!(port, 80);
        assert_eq!(pk, pubkey);
        assert_eq!(cid, "myclient");
    }

    #[test]
    fn syn_payload_empty_data_errors() {
        let result = decode_syn_payload(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn syn_payload_invalid_addr_type() {
        // addr_type 0x02 is invalid
        let mut data = vec![0x02];
        data.extend_from_slice(&[0u8; 38]); // pad to avoid TooShort
        let result = decode_syn_payload(&data);
        assert!(matches!(result, Err(FrameError::InvalidAddressType(0x02))));
    }

    #[test]
    fn syn_payload_truncated_ipv4() {
        // addr_type=0x01 but only 10 bytes total (need 39)
        let data = vec![0x01; 10];
        let result = decode_syn_payload(&data);
        assert!(matches!(
            result,
            Err(FrameError::PayloadTooShort { .. })
        ));
    }

    #[test]
    fn encode_preserves_payload() {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let frame = Frame {
            session_id: SessionId(*b"test0001"),
            seq: 1000,
            frame_type: FrameType::Syn,
            flags: FrameFlags(0x42),
            payload: payload.clone(),
        };
        let decoded = decode_frame(&encode_frame(&frame)).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.flags, FrameFlags(0x42));
        assert_eq!(decoded.seq, 1000);
    }
}
