//! Message encoding/decoding module.
//!
//! Handles base32 encoding, envelope formatting, and send query parsing.

use crate::error::DecodeError;
use crate::store::StoredMessage;
use data_encoding::Encoding;
use hickory_proto::rr::Name;
use std::sync::LazyLock;

/// Components extracted from a decoded envelope string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeParts {
    /// Sender identifier.
    pub sender_id: String,
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Unix epoch seconds timestamp.
    pub timestamp: u64,
    /// Raw payload bytes (decoded from base32).
    pub payload: Vec<u8>,
}

/// Encode a stored message into a TXT envelope string.
/// Format: `<sender_id>|<seq>|<timestamp>|<base32_payload>`
pub fn encode_envelope(msg: &StoredMessage) -> String {
    let encoded_payload = base32_encode(&msg.payload);
    format!(
        "{}|{}|{}|{}",
        msg.sender_id, msg.sequence, msg.timestamp, encoded_payload
    )
}

/// Decode a TXT envelope string back into components.
pub fn decode_envelope(envelope: &str) -> Result<EnvelopeParts, DecodeError> {
    let parts: Vec<&str> = envelope.splitn(4, '|').collect();
    if parts.len() != 4 {
        return Err(DecodeError::EnvelopeError(format!(
            "expected 4 pipe-delimited fields, got {}",
            parts.len()
        )));
    }

    let sender_id = parts[0].to_string();

    let sequence = parts[1].parse::<u64>().map_err(|e| {
        DecodeError::EnvelopeError(format!("invalid sequence number '{}': {}", parts[1], e))
    })?;

    let timestamp = parts[2].parse::<u64>().map_err(|e| {
        DecodeError::EnvelopeError(format!("invalid timestamp '{}': {}", parts[2], e))
    })?;

    let payload = base32_decode(parts[3])?;

    Ok(EnvelopeParts {
        sender_id,
        sequence,
        timestamp,
        payload,
    })
}

/// Custom base32 encoding: RFC 4648 lowercase alphabet, no padding.
static BASE32_LOWER_NOPAD: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.padding = None;
    spec.encoding().expect("valid base32 specification")
});

/// Base32 encode raw bytes (RFC 4648, lowercase, no padding).
pub fn base32_encode(data: &[u8]) -> String {
    BASE32_LOWER_NOPAD.encode(data)
}

/// Base32 decode a string back to raw bytes.
pub fn base32_decode(encoded: &str) -> Result<Vec<u8>, DecodeError> {
    BASE32_LOWER_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|e| DecodeError::Base32Error(e.to_string()))
}

/// Decode a send query name into message components.
///
/// The full query name has the structure:
/// `<nonce>.<payload_0>...<payload_n>.<sender_id>.<channel>.<controlled_domain>`
///
/// This function strips the controlled domain labels from the right and the
/// nonce label from the left, then extracts channel, sender_id, and payload.
///
/// Returns `(sender_id, channel, payload_bytes)`.
pub fn decode_send_query(
    labels: &[&str],
    controlled_domain: &Name,
) -> Result<(String, String, Vec<u8>), DecodeError> {
    // Count how many labels the controlled domain has (excluding root).
    let domain_label_count = controlled_domain.iter().count();

    // We need at least: nonce + 1 payload label + sender_id + channel + domain labels
    let min_labels = 1 + 1 + 1 + 1 + domain_label_count;
    if labels.len() < min_labels {
        return Err(DecodeError::QueryError(format!(
            "not enough labels: got {}, need at least {}",
            labels.len(),
            min_labels
        )));
    }

    // Strip controlled domain labels from the right.
    let remaining = &labels[..labels.len() - domain_label_count];

    // Strip nonce (leftmost label).
    let remaining = &remaining[1..];

    // Need at least: 1 payload label + sender_id + channel
    if remaining.len() < 3 {
        return Err(DecodeError::QueryError(format!(
            "not enough labels after stripping nonce and domain: got {}, need at least 3",
            remaining.len()
        )));
    }

    // Rightmost remaining label is the channel.
    let channel = remaining[remaining.len() - 1].to_string();

    // Next-to-rightmost is the sender_id.
    let sender_id = remaining[remaining.len() - 2].to_string();

    // Everything left of sender_id is payload labels.
    let payload_labels = &remaining[..remaining.len() - 2];

    // Concatenate payload labels into a single base32 string.
    let base32_payload: String = payload_labels.iter().copied().collect();

    // Decode the base32 payload.
    let payload = base32_decode(&base32_payload)?;

    Ok((sender_id, channel, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_base32_empty() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_decode("").unwrap(), b"");
    }

    #[test]
    fn test_base32_known_vectors() {
        // RFC 4648 test vectors (lowercase, no padding)
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_base32_roundtrip_known() {
        let inputs: &[&[u8]] = &[b"", b"hello", b"\x00\xff", b"foobar"];
        for input in inputs {
            let encoded = base32_encode(input);
            let decoded = base32_decode(&encoded).unwrap();
            assert_eq!(&decoded, input);
        }
    }

    #[test]
    fn test_base32_decode_invalid() {
        // '1' is not in the base32 alphabet
        assert!(base32_decode("1234").is_err());
    }

    #[test]
    fn test_encode_envelope_basic() {
        let msg = StoredMessage {
            sender_id: "alice".to_string(),
            payload: b"foobar".to_vec(),
            sequence: 42,
            timestamp: 1718000000,
            expiry: Instant::now(),
        };
        let envelope = encode_envelope(&msg);
        assert_eq!(envelope, "alice|42|1718000000|mzxw6ytboi");
    }

    #[test]
    fn test_decode_envelope_basic() {
        let envelope = "alice|42|1718000000|mzxw6ytboi";
        let parts = decode_envelope(envelope).unwrap();
        assert_eq!(parts.sender_id, "alice");
        assert_eq!(parts.sequence, 42);
        assert_eq!(parts.timestamp, 1718000000);
        assert_eq!(parts.payload, b"foobar");
    }

    #[test]
    fn test_envelope_roundtrip() {
        let msg = StoredMessage {
            sender_id: "bob".to_string(),
            payload: b"hello".to_vec(),
            sequence: 1,
            timestamp: 1700000000,
            expiry: Instant::now(),
        };
        let envelope = encode_envelope(&msg);
        let parts = decode_envelope(&envelope).unwrap();
        assert_eq!(parts.sender_id, msg.sender_id);
        assert_eq!(parts.sequence, msg.sequence);
        assert_eq!(parts.timestamp, msg.timestamp);
        assert_eq!(parts.payload, msg.payload);
    }

    #[test]
    fn test_encode_envelope_empty_payload() {
        let msg = StoredMessage {
            sender_id: "x".to_string(),
            payload: vec![],
            sequence: 0,
            timestamp: 0,
            expiry: Instant::now(),
        };
        let envelope = encode_envelope(&msg);
        assert_eq!(envelope, "x|0|0|");
        let parts = decode_envelope(&envelope).unwrap();
        assert_eq!(parts.payload, b"");
    }

    #[test]
    fn test_decode_envelope_too_few_fields() {
        assert!(decode_envelope("alice|42").is_err());
    }

    #[test]
    fn test_decode_envelope_invalid_sequence() {
        assert!(decode_envelope("alice|notanumber|1718000000|mzxw6ytboi").is_err());
    }

    #[test]
    fn test_decode_envelope_invalid_timestamp() {
        assert!(decode_envelope("alice|42|notanumber|mzxw6ytboi").is_err());
    }

    #[test]
    fn test_decode_envelope_invalid_base32_payload() {
        assert!(decode_envelope("alice|42|1718000000|!!!invalid!!!").is_err());
    }

    #[test]
    fn test_decode_envelope_sender_with_pipe_in_payload() {
        // splitn(4, '|') means the 4th field captures everything after the 3rd pipe,
        // so a base32 payload won't contain pipes, but let's verify the split logic
        // with a payload that has no pipes
        let msg = StoredMessage {
            sender_id: "sender".to_string(),
            payload: b"\x00\xff".to_vec(),
            sequence: 99,
            timestamp: 12345,
            expiry: Instant::now(),
        };
        let envelope = encode_envelope(&msg);
        let parts = decode_envelope(&envelope).unwrap();
        assert_eq!(parts.payload, b"\x00\xff");
    }
}
