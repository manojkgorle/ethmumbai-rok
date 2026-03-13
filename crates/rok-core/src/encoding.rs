use ed25519_dalek::VerifyingKey;
use sha2::{Sha256, Digest};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::error::{RokError, Result};
use crate::keys::read::ExportedReadKey;
use crate::keys::scope::Scope;
use crate::keys::key_id::KeyId;

/// Type tags for encoded keys.
const TAG_SPEND_PUBLIC: u8 = 0x01;
const TAG_READ_PUBLIC: u8 = 0x02;
const TAG_READ_SECRET: u8 = 0x03;

/// Compute a 4-byte checksum: first 4 bytes of SHA-256(SHA-256(data)).
fn checksum(data: &[u8]) -> [u8; 4] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    let mut cs = [0u8; 4];
    cs.copy_from_slice(&hash2[..4]);
    cs
}

/// Encode raw bytes with a type tag and checksum, then base58.
fn encode_with_tag(tag: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(tag);
    data.extend_from_slice(payload);
    let cs = checksum(&data);
    data.extend_from_slice(&cs);
    bs58::encode(&data).into_string()
}

/// Decode base58, verify tag and checksum, return payload.
fn decode_with_tag(encoded: &str, expected_tag: u8) -> Result<Vec<u8>> {
    let data = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| RokError::EncodingError(format!("invalid base58: {}", e)))?;

    if data.len() < 5 {
        return Err(RokError::EncodingError("encoded data too short".into()));
    }

    let tag = data[0];
    if tag != expected_tag {
        return Err(RokError::InvalidTypeTag {
            expected: expected_tag,
            got: tag,
        });
    }

    let (content, cs_bytes) = data.split_at(data.len() - 4);
    let expected_cs = checksum(content);
    if cs_bytes != expected_cs {
        return Err(RokError::InvalidChecksum);
    }

    Ok(content[1..].to_vec())
}

/// Encode a spend (Ed25519) public key to a human-readable string.
pub fn encode_spend_public(key: &VerifyingKey) -> String {
    encode_with_tag(TAG_SPEND_PUBLIC, key.as_bytes())
}

/// Decode a spend public key from its encoded form.
pub fn decode_spend_public(encoded: &str) -> Result<VerifyingKey> {
    let bytes = decode_with_tag(encoded, TAG_SPEND_PUBLIC)?;
    if bytes.len() != 32 {
        return Err(RokError::EncodingError(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| RokError::InvalidKeyMaterial)
}

/// Encode a read (X25519) public key with its scope.
///
/// Format: [32-byte X25519 public][scope bytes]
pub fn encode_read_public(key: &X25519PublicKey, scope: &Scope) -> String {
    let scope_bytes = scope.as_str().as_bytes();
    let mut payload = Vec::with_capacity(32 + scope_bytes.len());
    payload.extend_from_slice(key.as_bytes());
    payload.extend_from_slice(scope_bytes);
    encode_with_tag(TAG_READ_PUBLIC, &payload)
}

/// Decode a read public key and its scope.
pub fn decode_read_public(encoded: &str) -> Result<(X25519PublicKey, Scope)> {
    let bytes = decode_with_tag(encoded, TAG_READ_PUBLIC)?;
    if bytes.len() < 33 {
        return Err(RokError::EncodingError("read public key too short".into()));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes[..32]);
    let key = X25519PublicKey::from(key_bytes);

    let scope_str = std::str::from_utf8(&bytes[32..])
        .map_err(|_| RokError::EncodingError("invalid scope utf8".into()))?;
    let scope = Scope::new(scope_str)?;

    Ok((key, scope))
}

/// Encode an exported read key (includes secret - handle with care!).
///
/// Format: [32-byte secret][32-byte public][8-byte parent_key_id or 0x00][scope bytes]
pub fn encode_exported_read_key(exported: &ExportedReadKey) -> String {
    let scope_bytes = exported.scope.as_str().as_bytes();
    let mut payload = Vec::with_capacity(32 + 32 + 1 + 8 + scope_bytes.len());
    payload.extend_from_slice(&exported.secret_bytes);
    payload.extend_from_slice(&exported.public_bytes);

    if let Some(parent_id) = &exported.parent_key_id {
        payload.push(1); // has parent
        payload.extend_from_slice(parent_id.as_bytes());
    } else {
        payload.push(0); // no parent
    }

    payload.extend_from_slice(scope_bytes);
    encode_with_tag(TAG_READ_SECRET, &payload)
}

/// Decode an exported read key.
pub fn decode_exported_read_key(encoded: &str) -> Result<ExportedReadKey> {
    let bytes = decode_with_tag(encoded, TAG_READ_SECRET)?;

    if bytes.len() < 65 {
        return Err(RokError::EncodingError("exported read key too short".into()));
    }

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&bytes[..32]);

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(&bytes[32..64]);

    let has_parent = bytes[64];
    let (parent_key_id, scope_start) = if has_parent == 1 {
        if bytes.len() < 73 {
            return Err(RokError::EncodingError("missing parent key id".into()));
        }
        let mut parent_bytes = [0u8; 8];
        parent_bytes.copy_from_slice(&bytes[65..73]);
        (Some(KeyId::from_bytes(parent_bytes)), 73)
    } else {
        (None, 65)
    };

    let scope_str = std::str::from_utf8(&bytes[scope_start..])
        .map_err(|_| RokError::EncodingError("invalid scope utf8".into()))?;
    let scope = Scope::new(scope_str)?;

    Ok(ExportedReadKey {
        secret_bytes,
        public_bytes,
        scope,
        parent_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::spend::SpendKeyPair;

    #[test]
    fn test_spend_public_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let encoded = encode_spend_public(&spend.verifying_key());
        let decoded = decode_spend_public(&encoded).unwrap();
        assert_eq!(spend.verifying_key(), decoded);
    }

    #[test]
    fn test_read_public_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let scope = Scope::new("/finance").unwrap();
        let finance = root.derive_child_segment("finance").unwrap();

        let encoded = encode_read_public(finance.public_key(), &scope);
        let (decoded_key, decoded_scope) = decode_read_public(&encoded).unwrap();
        assert_eq!(&decoded_key, finance.public_key());
        assert_eq!(decoded_scope, scope);
    }

    #[test]
    fn test_exported_read_key_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        let exported = finance.export();
        let encoded = encode_exported_read_key(&exported);
        let decoded = decode_exported_read_key(&encoded).unwrap();

        assert_eq!(decoded.secret_bytes, exported.secret_bytes);
        assert_eq!(decoded.public_bytes, exported.public_bytes);
        assert_eq!(decoded.scope, exported.scope);
        assert_eq!(decoded.parent_key_id.map(|k| *k.as_bytes()), exported.parent_key_id.map(|k| *k.as_bytes()));
    }

    #[test]
    fn test_invalid_checksum_rejected() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let mut encoded = encode_spend_public(&spend.verifying_key());
        // Corrupt the last character
        let bytes = unsafe { encoded.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'1' { b'2' } else { b'1' };

        assert!(decode_spend_public(&encoded).is_err());
    }

    #[test]
    fn test_wrong_type_tag_rejected() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let encoded = encode_spend_public(&spend.verifying_key());
        // Try to decode as read public
        assert!(decode_read_public(&encoded).is_err());
    }

    #[test]
    fn test_root_read_key_no_parent() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let exported = root.export();
        let encoded = encode_exported_read_key(&exported);
        let decoded = decode_exported_read_key(&encoded).unwrap();
        assert!(decoded.parent_key_id.is_none());
    }
}
