// smol_frame: session initiation messages and encrypted IP packet framing
// for the smoltcp tunnel.

use crate::crypto::{decrypt_data, encrypt_data, Direction, SessionKey};
use crate::frame::SessionId;
use crate::socks::TargetAddr;

// ---------------------------------------------------------------------------
// Message type constants
// ---------------------------------------------------------------------------

/// Message type byte for smoltcp session initiation.
pub const SMOL_MSG_INIT: u8 = 0x10;
/// Message type byte for smoltcp session initiation acknowledgement.
pub const SMOL_MSG_INIT_ACK: u8 = 0x11;
/// Message type byte for smoltcp session teardown.
pub const SMOL_MSG_TEARDOWN: u8 = 0x12;

// Address type constants (same as SOCKS5)
const ADDR_TYPE_IPV4: u8 = 0x01;
const ADDR_TYPE_DOMAIN: u8 = 0x03;
const ADDR_TYPE_IPV6: u8 = 0x04;

// ---------------------------------------------------------------------------
// Error type (Task 3.1)
// ---------------------------------------------------------------------------

/// Errors from smol frame encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum SmolFrameError {
    #[error("frame too short: need at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("invalid address type: 0x{0:02x}")]
    InvalidAddressType(u8),

    #[error("decode failure: {0}")]
    DecodeFailure(String),

    #[error("decryption failed")]
    DecryptionFailed,
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Parsed Init message fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitMessage {
    pub session_id: SessionId,
    pub target_addr: TargetAddr,
    pub target_port: u16,
    pub pubkey: [u8; 32],
    pub client_id: String,
}

/// Parsed InitAck message fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitAckMessage {
    pub session_id: SessionId,
    pub pubkey: [u8; 32],
}

// ---------------------------------------------------------------------------
// Init message encode/decode (Task 3.2)
// Layout: msg_type(1) | session_id(8) | addr_type(1) | address(var) | port(2) | pubkey(32) | client_id_len(1) | client_id(var)
// ---------------------------------------------------------------------------

/// Encode an Init message into wire format.
pub fn encode_init_message(msg: &InitMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(SMOL_MSG_INIT);
    buf.extend_from_slice(&msg.session_id.0);

    match &msg.target_addr {
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

    buf.extend_from_slice(&msg.target_port.to_be_bytes());
    buf.extend_from_slice(&msg.pubkey);
    buf.push(msg.client_id.len() as u8);
    buf.extend_from_slice(msg.client_id.as_bytes());

    buf
}

/// Decode an Init message from wire format.
pub fn decode_init_message(data: &[u8]) -> Result<InitMessage, SmolFrameError> {
    // Minimum: msg_type(1) + session_id(8) + addr_type(1) + ipv4(4) + port(2) + pubkey(32) + client_id_len(1) = 49
    if data.len() < 10 {
        return Err(SmolFrameError::TooShort {
            expected: 10,
            actual: data.len(),
        });
    }

    if data[0] != SMOL_MSG_INIT {
        return Err(SmolFrameError::InvalidMessageType(data[0]));
    }

    let mut sid = [0u8; 8];
    sid.copy_from_slice(&data[1..9]);
    let session_id = SessionId(sid);

    let addr_type = data[9];
    let (target_addr, addr_end) = match addr_type {
        ADDR_TYPE_IPV4 => {
            let needed = 10 + 4; // through IPv4 address
            if data.len() < needed {
                return Err(SmolFrameError::TooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&data[10..14]);
            (TargetAddr::Ipv4(ip), 14)
        }
        ADDR_TYPE_DOMAIN => {
            if data.len() < 11 {
                return Err(SmolFrameError::TooShort {
                    expected: 11,
                    actual: data.len(),
                });
            }
            let domain_len = data[10] as usize;
            let needed = 11 + domain_len;
            if data.len() < needed {
                return Err(SmolFrameError::TooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let domain = String::from_utf8(data[11..11 + domain_len].to_vec())
                .map_err(|e| SmolFrameError::DecodeFailure(format!("invalid domain UTF-8: {e}")))?;
            (TargetAddr::Domain(domain), 11 + domain_len)
        }
        ADDR_TYPE_IPV6 => {
            let needed = 10 + 16;
            if data.len() < needed {
                return Err(SmolFrameError::TooShort {
                    expected: needed,
                    actual: data.len(),
                });
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[10..26]);
            (TargetAddr::Ipv6(ip), 26)
        }
        other => return Err(SmolFrameError::InvalidAddressType(other)),
    };

    // port(2) + pubkey(32) + client_id_len(1) = 35 more bytes minimum
    let remaining_start = addr_end;
    if data.len() < remaining_start + 35 {
        return Err(SmolFrameError::TooShort {
            expected: remaining_start + 35,
            actual: data.len(),
        });
    }

    let target_port = u16::from_be_bytes([data[remaining_start], data[remaining_start + 1]]);

    let pubkey_start = remaining_start + 2;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[pubkey_start..pubkey_start + 32]);

    let cid_len_offset = pubkey_start + 32;
    let cid_len = data[cid_len_offset] as usize;
    let cid_start = cid_len_offset + 1;

    if data.len() < cid_start + cid_len {
        return Err(SmolFrameError::TooShort {
            expected: cid_start + cid_len,
            actual: data.len(),
        });
    }

    let client_id = String::from_utf8(data[cid_start..cid_start + cid_len].to_vec())
        .map_err(|e| SmolFrameError::DecodeFailure(format!("invalid client_id UTF-8: {e}")))?;

    Ok(InitMessage {
        session_id,
        target_addr,
        target_port,
        pubkey,
        client_id,
    })
}

// ---------------------------------------------------------------------------
// InitAck message encode/decode (Task 3.3)
// Layout: msg_type(1) | session_id(8) | pubkey(32)
// ---------------------------------------------------------------------------

/// Encode an InitAck message into wire format.
pub fn encode_init_ack_message(msg: &InitAckMessage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 32);
    buf.push(SMOL_MSG_INIT_ACK);
    buf.extend_from_slice(&msg.session_id.0);
    buf.extend_from_slice(&msg.pubkey);
    buf
}

/// Decode an InitAck message from wire format.
pub fn decode_init_ack_message(data: &[u8]) -> Result<InitAckMessage, SmolFrameError> {
    // msg_type(1) + session_id(8) + pubkey(32) = 41
    if data.len() < 41 {
        return Err(SmolFrameError::TooShort {
            expected: 41,
            actual: data.len(),
        });
    }

    if data[0] != SMOL_MSG_INIT_ACK {
        return Err(SmolFrameError::InvalidMessageType(data[0]));
    }

    let mut sid = [0u8; 8];
    sid.copy_from_slice(&data[1..9]);

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[9..41]);

    Ok(InitAckMessage {
        session_id: SessionId(sid),
        pubkey,
    })
}

// ---------------------------------------------------------------------------
// Teardown message encode/decode (Task 3.4)
// Layout: msg_type(1) | session_id(8)
// ---------------------------------------------------------------------------

/// Encode a Teardown message into wire format.
pub fn encode_teardown_message(session_id: &SessionId) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8);
    buf.push(SMOL_MSG_TEARDOWN);
    buf.extend_from_slice(&session_id.0);
    buf
}

/// Decode a Teardown message from wire format, returning the session ID.
pub fn decode_teardown_message(data: &[u8]) -> Result<SessionId, SmolFrameError> {
    // msg_type(1) + session_id(8) = 9
    if data.len() < 9 {
        return Err(SmolFrameError::TooShort {
            expected: 9,
            actual: data.len(),
        });
    }

    if data[0] != SMOL_MSG_TEARDOWN {
        return Err(SmolFrameError::InvalidMessageType(data[0]));
    }

    let mut sid = [0u8; 8];
    sid.copy_from_slice(&data[1..9]);
    Ok(SessionId(sid))
}

// ---------------------------------------------------------------------------
// Encrypted IP packet framing (Task 3.5)
// Wire format: session_id(8) | seq(4, BE) | ChaCha20-Poly1305 ciphertext(IP packet + 16-byte tag)
// ---------------------------------------------------------------------------

/// Header size for encrypted IP packets: session_id(8) + seq(4) = 12 bytes.
pub const ENCRYPTED_HEADER_SIZE: usize = 12;

/// Encrypt an IP packet and prepend the session_id + seq header.
pub fn encrypt_ip_packet(
    session_id: &SessionId,
    seq: u32,
    direction: Direction,
    session_key: &SessionKey,
    ip_packet: &[u8],
) -> Vec<u8> {
    let ciphertext = encrypt_data(session_key, seq, direction, ip_packet);

    let mut buf = Vec::with_capacity(ENCRYPTED_HEADER_SIZE + ciphertext.len());
    buf.extend_from_slice(&session_id.0);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ciphertext);
    buf
}

/// Decrypt an encrypted IP packet, returning (session_id, seq, plaintext).
pub fn decrypt_ip_packet(
    data: &[u8],
    direction: Direction,
    session_key: &SessionKey,
) -> Result<(SessionId, u32, Vec<u8>), SmolFrameError> {
    if data.len() < ENCRYPTED_HEADER_SIZE {
        return Err(SmolFrameError::TooShort {
            expected: ENCRYPTED_HEADER_SIZE,
            actual: data.len(),
        });
    }

    let mut sid = [0u8; 8];
    sid.copy_from_slice(&data[..8]);
    let session_id = SessionId(sid);

    let seq = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let ciphertext = &data[ENCRYPTED_HEADER_SIZE..];
    let plaintext = decrypt_data(session_key, seq, direction, ciphertext)
        .map_err(|_| SmolFrameError::DecryptionFailed)?;

    Ok((session_id, seq, plaintext))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_session_key, Direction, Psk};

    fn test_psk() -> Psk {
        Psk::from_bytes(vec![0xAB; 32]).unwrap()
    }

    fn test_session_key() -> SessionKey {
        let shared_secret = [0x01u8; 32];
        derive_session_key(&shared_secret, &test_psk()).unwrap()
    }

    fn dummy_pubkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    // --- Init message tests ---

    #[test]
    fn init_ipv4_round_trip() {
        let msg = InitMessage {
            session_id: SessionId(*b"abcd1234"),
            target_addr: TargetAddr::Ipv4([192, 168, 1, 1]),
            target_port: 8080,
            pubkey: dummy_pubkey(),
            client_id: "testclient".to_string(),
        };
        let encoded = encode_init_message(&msg);
        let decoded = decode_init_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn init_ipv6_round_trip() {
        let msg = InitMessage {
            session_id: SessionId(*b"XXXXXXXX"),
            target_addr: TargetAddr::Ipv6([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            target_port: 443,
            pubkey: dummy_pubkey(),
            client_id: "c2".to_string(),
        };
        let encoded = encode_init_message(&msg);
        let decoded = decode_init_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn init_domain_round_trip() {
        let msg = InitMessage {
            session_id: SessionId(*b"test0001"),
            target_addr: TargetAddr::Domain("example.com".to_string()),
            target_port: 80,
            pubkey: dummy_pubkey(),
            client_id: "myclient".to_string(),
        };
        let encoded = encode_init_message(&msg);
        let decoded = decode_init_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn init_empty_client_id() {
        let msg = InitMessage {
            session_id: SessionId(*b"abcd1234"),
            target_addr: TargetAddr::Ipv4([10, 0, 0, 1]),
            target_port: 22,
            pubkey: dummy_pubkey(),
            client_id: String::new(),
        };
        let encoded = encode_init_message(&msg);
        let decoded = decode_init_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn init_decode_too_short() {
        let result = decode_init_message(&[SMOL_MSG_INIT; 5]);
        assert!(matches!(result, Err(SmolFrameError::TooShort { .. })));
    }

    #[test]
    fn init_decode_wrong_msg_type() {
        let msg = InitMessage {
            session_id: SessionId(*b"abcd1234"),
            target_addr: TargetAddr::Ipv4([1, 2, 3, 4]),
            target_port: 80,
            pubkey: dummy_pubkey(),
            client_id: "x".to_string(),
        };
        let mut encoded = encode_init_message(&msg);
        encoded[0] = 0xFF;
        let result = decode_init_message(&encoded);
        assert!(matches!(result, Err(SmolFrameError::InvalidMessageType(0xFF))));
    }

    #[test]
    fn init_decode_invalid_addr_type() {
        let mut data = vec![SMOL_MSG_INIT];
        data.extend_from_slice(b"abcd1234"); // session_id
        data.push(0x02); // invalid addr type
        data.extend_from_slice(&[0u8; 50]); // padding
        let result = decode_init_message(&data);
        assert!(matches!(result, Err(SmolFrameError::InvalidAddressType(0x02))));
    }

    // --- InitAck message tests ---

    #[test]
    fn init_ack_round_trip() {
        let msg = InitAckMessage {
            session_id: SessionId(*b"sess0001"),
            pubkey: dummy_pubkey(),
        };
        let encoded = encode_init_ack_message(&msg);
        assert_eq!(encoded.len(), 41);
        let decoded = decode_init_ack_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn init_ack_decode_too_short() {
        let result = decode_init_ack_message(&[SMOL_MSG_INIT_ACK; 10]);
        assert!(matches!(result, Err(SmolFrameError::TooShort { .. })));
    }

    #[test]
    fn init_ack_decode_wrong_msg_type() {
        let msg = InitAckMessage {
            session_id: SessionId(*b"sess0001"),
            pubkey: dummy_pubkey(),
        };
        let mut encoded = encode_init_ack_message(&msg);
        encoded[0] = SMOL_MSG_INIT;
        let result = decode_init_ack_message(&encoded);
        assert!(matches!(result, Err(SmolFrameError::InvalidMessageType(_))));
    }

    // --- Teardown message tests ---

    #[test]
    fn teardown_round_trip() {
        let sid = SessionId(*b"tear0001");
        let encoded = encode_teardown_message(&sid);
        assert_eq!(encoded.len(), 9);
        let decoded = decode_teardown_message(&encoded).unwrap();
        assert_eq!(decoded, sid);
    }

    #[test]
    fn teardown_decode_too_short() {
        let result = decode_teardown_message(&[SMOL_MSG_TEARDOWN; 4]);
        assert!(matches!(result, Err(SmolFrameError::TooShort { .. })));
    }

    #[test]
    fn teardown_decode_wrong_msg_type() {
        let mut data = vec![0xFF];
        data.extend_from_slice(b"abcd1234");
        let result = decode_teardown_message(&data);
        assert!(matches!(result, Err(SmolFrameError::InvalidMessageType(0xFF))));
    }

    // --- Encrypted IP packet tests ---

    #[test]
    fn encrypt_decrypt_ip_packet_round_trip() {
        let key = test_session_key();
        let sid = SessionId(*b"encr0001");
        let ip_packet = vec![0x45, 0x00, 0x00, 0x28, 0xDE, 0xAD]; // fake IP header

        let encrypted = encrypt_ip_packet(&sid, 42, Direction::Upstream, &key, &ip_packet);
        // Should have 12-byte header + ciphertext (payload + 16-byte tag)
        assert_eq!(encrypted.len(), 12 + ip_packet.len() + 16);

        let (dec_sid, dec_seq, dec_payload) =
            decrypt_ip_packet(&encrypted, Direction::Upstream, &key).unwrap();
        assert_eq!(dec_sid, sid);
        assert_eq!(dec_seq, 42);
        assert_eq!(dec_payload, ip_packet);
    }

    #[test]
    fn encrypt_decrypt_empty_ip_packet() {
        let key = test_session_key();
        let sid = SessionId(*b"empty001");

        let encrypted = encrypt_ip_packet(&sid, 0, Direction::Downstream, &key, &[]);
        let (dec_sid, dec_seq, dec_payload) =
            decrypt_ip_packet(&encrypted, Direction::Downstream, &key).unwrap();
        assert_eq!(dec_sid, sid);
        assert_eq!(dec_seq, 0);
        assert!(dec_payload.is_empty());
    }

    #[test]
    fn decrypt_ip_packet_too_short() {
        let result = decrypt_ip_packet(&[0u8; 5], Direction::Upstream, &test_session_key());
        assert!(matches!(result, Err(SmolFrameError::TooShort { .. })));
    }

    #[test]
    fn decrypt_ip_packet_wrong_direction() {
        let key = test_session_key();
        let sid = SessionId(*b"dir00001");
        let encrypted = encrypt_ip_packet(&sid, 1, Direction::Upstream, &key, b"data");
        let result = decrypt_ip_packet(&encrypted, Direction::Downstream, &key);
        assert!(matches!(result, Err(SmolFrameError::DecryptionFailed)));
    }

    #[test]
    fn decrypt_ip_packet_tampered() {
        let key = test_session_key();
        let sid = SessionId(*b"tamp0001");
        let mut encrypted = encrypt_ip_packet(&sid, 1, Direction::Upstream, &key, b"secret");
        // Flip a bit in the ciphertext (after the 12-byte header)
        if encrypted.len() > 12 {
            encrypted[12] ^= 0x01;
        }
        let result = decrypt_ip_packet(&encrypted, Direction::Upstream, &key);
        assert!(matches!(result, Err(SmolFrameError::DecryptionFailed)));
    }

    #[test]
    fn encrypt_ip_packet_header_contains_session_id_and_seq() {
        let key = test_session_key();
        let sid = SessionId(*b"hdr00001");
        let encrypted = encrypt_ip_packet(&sid, 0x12345678, Direction::Upstream, &key, b"x");

        // First 8 bytes = session_id
        assert_eq!(&encrypted[..8], b"hdr00001");
        // Next 4 bytes = seq in big-endian
        assert_eq!(&encrypted[8..12], &[0x12, 0x34, 0x56, 0x78]);
    }
}
