use crate::error::{Result, RokError};
use sha2::{Digest, Sha256};

/// A key identifier: the first 8 bytes of SHA-256(public_key_bytes).
///
/// Used for matching access entries during decryption without revealing
/// the full public key. Compact enough for storage and display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 8]);

impl KeyId {
    /// Compute a KeyId from raw public key bytes.
    pub fn from_public_bytes(public_key: &[u8]) -> Self {
        let hash = Sha256::digest(public_key);
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[..8]);
        KeyId(id)
    }

    /// Access the raw 8-byte identifier.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Encode as a base58 string.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decode from a base58 string.
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| RokError::EncodingError(format!("invalid base58: {}", e)))?;
        if bytes.len() != 8 {
            return Err(RokError::EncodingError(format!(
                "expected 8 bytes for KeyId, got {}",
                bytes.len()
            )));
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&bytes);
        Ok(KeyId(id))
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        KeyId(bytes)
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Constant-time comparison for security-sensitive contexts.
impl subtle::ConstantTimeEq for KeyId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let key_bytes = b"some public key material here!!!";
        let id1 = KeyId::from_public_bytes(key_bytes);
        let id2 = KeyId::from_public_bytes(key_bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_keys_different_ids() {
        let id1 = KeyId::from_public_bytes(b"key1_material_aaaaaaaaaaaaaaaa");
        let id2 = KeyId::from_public_bytes(b"key2_material_aaaaaaaaaaaaaaaa");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_base58_roundtrip() {
        let id = KeyId::from_public_bytes(b"test key bytes for roundtrip!!");
        let encoded = id.to_base58();
        let decoded = KeyId::from_base58(&encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_invalid_base58() {
        assert!(KeyId::from_base58("!!!invalid!!!").is_err());
        // Valid base58 but wrong length
        assert!(KeyId::from_base58("1").is_err());
    }
}
