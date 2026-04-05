// Crypto module: PSK, key exchange, encryption, and HMAC.

use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

type HmacSha256 = Hmac<Sha256>;

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("PSK too short: got {got} bytes, need at least {min}")]
    PskTooShort { got: usize, min: usize },

    #[error("failed to read PSK file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HKDF expand failed")]
    HkdfExpandError,

    #[error("decryption failed")]
    DecryptionFailed,
}

/// Minimum PSK length in bytes.
const PSK_MIN_LEN: usize = 32;

/// Pre-shared key (minimum 32 bytes).
#[derive(Clone, Debug)]
pub struct Psk(Vec<u8>);

impl Psk {
    /// Create a PSK from raw bytes, enforcing ≥32 byte minimum.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() < PSK_MIN_LEN {
            return Err(CryptoError::PskTooShort {
                got: bytes.len(),
                min: PSK_MIN_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Read a PSK from a file (raw bytes).
    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(bytes)
    }

    /// Access the raw PSK bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Per-session symmetric key material derived from DH + PSK.
pub struct SessionKey {
    /// ChaCha20-Poly1305 key for DATA frame encryption.
    pub data_key: [u8; 32],
    /// HMAC-SHA256 key for control frame authentication.
    pub control_key: [u8; 32],
}

/// Direction of data flow, used in nonce construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// SOCKS Client → Exit Node
    Upstream,
    /// Exit Node → SOCKS Client
    Downstream,
}

impl Direction {
    fn byte(self) -> u8 {
        match self {
            Direction::Upstream => 0x00,
            Direction::Downstream => 0x01,
        }
    }
}

/// Generate an X25519 ephemeral keypair.
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Derive session keys from a DH shared secret and PSK using HKDF-SHA256.
///
/// `shared_secret` is the raw 32-byte X25519 output (caller passes `.as_bytes()`).
/// IKM = shared_secret || PSK, info = "dns-socks-v1", output = 64 bytes.
pub fn derive_session_key(shared_secret: &[u8], psk: &Psk) -> Result<SessionKey, CryptoError> {
    let mut ikm = Vec::with_capacity(shared_secret.len() + psk.as_bytes().len());
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(psk.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 64];
    hk.expand(b"dns-socks-v1", &mut okm)
        .map_err(|_| CryptoError::HkdfExpandError)?;

    let mut data_key = [0u8; 32];
    let mut control_key = [0u8; 32];
    data_key.copy_from_slice(&okm[..32]);
    control_key.copy_from_slice(&okm[32..64]);

    Ok(SessionKey {
        data_key,
        control_key,
    })
}

/// Build the 12-byte nonce for ChaCha20-Poly1305.
///
/// ```text
/// nonce[0]    = direction (0x00 = upstream, 0x01 = downstream)
/// nonce[1..4] = 0x00 0x00 0x00
/// nonce[4..8] = seq (big-endian u32)
/// nonce[8..12] = 0x00 0x00 0x00 0x00
/// ```
fn build_nonce(seq: u32, direction: Direction) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[0] = direction.byte();
    nonce[4..8].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&nonce)
}

/// Encrypt a DATA frame payload using ChaCha20-Poly1305.
///
/// Returns ciphertext with appended 16-byte Poly1305 tag.
pub fn encrypt_data(
    key: &SessionKey,
    seq: u32,
    direction: Direction,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.data_key)
        .expect("data_key is always 32 bytes");
    let nonce = build_nonce(seq, direction);
    cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption should not fail")
}

/// Decrypt a DATA frame payload using ChaCha20-Poly1305.
pub fn decrypt_data(
    key: &SessionKey,
    seq: u32,
    direction: Direction,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.data_key)
        .expect("data_key is always 32 bytes");
    let nonce = build_nonce(seq, direction);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Compute HMAC-SHA256 over control frame bytes, truncated to 16 bytes.
pub fn compute_control_mac(psk: &Psk, frame_bytes: &[u8]) -> [u8; 16] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(psk.as_bytes()).expect("HMAC accepts any key length");
    mac.update(frame_bytes);
    let result = mac.finalize().into_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&result[..16]);
    truncated
}

/// Verify HMAC-SHA256 on a control frame (constant-time comparison).
pub fn verify_control_mac(psk: &Psk, frame_bytes: &[u8], mac: &[u8; 16]) -> bool {
    let mut hmac =
        <HmacSha256 as Mac>::new_from_slice(psk.as_bytes()).expect("HMAC accepts any key length");
    hmac.update(frame_bytes);
    // verify_truncated_left does constant-time comparison on the first N bytes
    hmac.verify_truncated_left(mac).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_psk() -> Psk {
        Psk::from_bytes(vec![0xAB; 32]).unwrap()
    }

    fn test_session_key() -> SessionKey {
        let shared_secret = [0x01u8; 32];
        derive_session_key(&shared_secret, &test_psk()).unwrap()
    }

    // --- PSK tests ---

    #[test]
    fn psk_too_short() {
        let result = Psk::from_bytes(vec![0; 31]);
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::PskTooShort { got, min } => {
                assert_eq!(got, 31);
                assert_eq!(min, 32);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn psk_empty() {
        assert!(Psk::from_bytes(vec![]).is_err());
    }

    #[test]
    fn psk_exactly_32_bytes() {
        assert!(Psk::from_bytes(vec![0; 32]).is_ok());
    }

    #[test]
    fn psk_longer_than_32_bytes() {
        assert!(Psk::from_bytes(vec![0; 64]).is_ok());
    }

    #[test]
    fn psk_from_file_not_found() {
        let result = Psk::from_file(Path::new("/nonexistent/path/psk"));
        assert!(result.is_err());
    }

    // --- Key derivation tests ---

    #[test]
    fn derive_session_key_deterministic() {
        let shared = [0x42u8; 32];
        let psk = test_psk();
        let k1 = derive_session_key(&shared, &psk).unwrap();
        let k2 = derive_session_key(&shared, &psk).unwrap();
        assert_eq!(k1.data_key, k2.data_key);
        assert_eq!(k1.control_key, k2.control_key);
    }

    #[test]
    fn derive_session_key_different_secret_gives_different_keys() {
        let psk = test_psk();
        let k1 = derive_session_key(&[0x01; 32], &psk).unwrap();
        let k2 = derive_session_key(&[0x02; 32], &psk).unwrap();
        assert_ne!(k1.data_key, k2.data_key);
        assert_ne!(k1.control_key, k2.control_key);
    }

    #[test]
    fn derive_session_key_different_psk_gives_different_keys() {
        let shared = [0x01u8; 32];
        let psk1 = Psk::from_bytes(vec![0xAA; 32]).unwrap();
        let psk2 = Psk::from_bytes(vec![0xBB; 32]).unwrap();
        let k1 = derive_session_key(&shared, &psk1).unwrap();
        let k2 = derive_session_key(&shared, &psk2).unwrap();
        assert_ne!(k1.data_key, k2.data_key);
    }

    // --- Encrypt/decrypt round-trip ---

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_session_key();
        let plaintext = b"hello, tunnel!";
        let ciphertext = encrypt_data(&key, 1, Direction::Upstream, plaintext);
        let decrypted = decrypt_data(&key, 1, Direction::Upstream, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_payload() {
        let key = test_session_key();
        let ciphertext = encrypt_data(&key, 0, Direction::Downstream, b"");
        let decrypted = decrypt_data(&key, 0, Direction::Downstream, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = test_session_key();
        let shared2 = [0x99u8; 32];
        let key2 = derive_session_key(&shared2, &test_psk()).unwrap();

        let ciphertext = encrypt_data(&key1, 1, Direction::Upstream, b"secret");
        let result = decrypt_data(&key2, 1, Direction::Upstream, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_wrong_seq_fails() {
        let key = test_session_key();
        let ciphertext = encrypt_data(&key, 1, Direction::Upstream, b"data");
        let result = decrypt_data(&key, 2, Direction::Upstream, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_with_wrong_direction_fails() {
        let key = test_session_key();
        let ciphertext = encrypt_data(&key, 1, Direction::Upstream, b"data");
        let result = decrypt_data(&key, 1, Direction::Downstream, &ciphertext);
        assert!(result.is_err());
    }

    // --- HMAC compute/verify round-trip ---

    #[test]
    fn hmac_compute_verify_roundtrip() {
        let psk = test_psk();
        let frame = b"some frame bytes";
        let mac = compute_control_mac(&psk, frame);
        assert!(verify_control_mac(&psk, frame, &mac));
    }

    #[test]
    fn hmac_verify_wrong_psk_fails() {
        let psk1 = Psk::from_bytes(vec![0xAA; 32]).unwrap();
        let psk2 = Psk::from_bytes(vec![0xBB; 32]).unwrap();
        let frame = b"frame data";
        let mac = compute_control_mac(&psk1, frame);
        assert!(!verify_control_mac(&psk2, frame, &mac));
    }

    #[test]
    fn hmac_verify_modified_frame_fails() {
        let psk = test_psk();
        let mac = compute_control_mac(&psk, b"original");
        assert!(!verify_control_mac(&psk, b"modified", &mac));
    }

    #[test]
    fn hmac_mac_is_16_bytes() {
        let psk = test_psk();
        let mac = compute_control_mac(&psk, b"test");
        assert_eq!(mac.len(), 16);
    }
}
