use crate::encrypt::Algorithm;
use crate::error::{Result, RokError};
use crate::keys::key_id::KeyId;
use crate::keys::scope::Scope;

/// An access entry: a wrapped data key for one recipient.
#[derive(Debug, Clone)]
pub struct AccessEntry {
    pub read_key_id: KeyId,
    pub wrapped_data_key: Vec<u8>,
    pub wrap_nonce: [u8; 12],
}

/// The encrypted envelope — the core data structure for encrypted data.
///
/// Contains the encrypted payload, per-recipient access entries,
/// ephemeral key material, and a spend key signature for authenticity.
#[derive(Debug, Clone)]
pub struct EncryptedEnvelope {
    pub version: u32,
    pub algorithm: Algorithm,
    pub scope: Scope,
    pub ephemeral_x25519_public: [u8; 32],
    pub ephemeral_mlkem_ciphertext: Option<Vec<u8>>,
    pub access_entries: Vec<AccessEntry>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
    pub signature: [u8; 64],
    pub spend_public_key: [u8; 32],
}

/// Non-secret metadata about an envelope (for inspection without decryption).
#[derive(Debug)]
pub struct EnvelopeMetadata {
    pub version: u32,
    pub algorithm: Algorithm,
    pub scope: Scope,
    pub recipient_count: usize,
    pub ciphertext_len: usize,
    pub recipient_key_ids: Vec<KeyId>,
}

impl EncryptedEnvelope {
    /// File extension for encrypted files.
    pub const FILE_EXTENSION: &'static str = "rok";

    /// Current envelope version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Compute the bytes that are signed (everything except the signature field).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.push(self.algorithm as u8);
        buf.extend_from_slice(self.scope.as_str().as_bytes());
        buf.extend_from_slice(&self.ephemeral_x25519_public);

        if let Some(ref mlkem_ct) = self.ephemeral_mlkem_ciphertext {
            buf.extend_from_slice(&(mlkem_ct.len() as u32).to_le_bytes());
            buf.extend_from_slice(mlkem_ct);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        buf.extend_from_slice(&(self.access_entries.len() as u32).to_le_bytes());
        for entry in &self.access_entries {
            buf.extend_from_slice(entry.read_key_id.as_bytes());
            buf.extend_from_slice(&(entry.wrapped_data_key.len() as u32).to_le_bytes());
            buf.extend_from_slice(&entry.wrapped_data_key);
            buf.extend_from_slice(&entry.wrap_nonce);
        }

        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.tag);
        buf.extend_from_slice(&self.spend_public_key);

        buf
    }

    /// Extract non-secret metadata for inspection.
    pub fn metadata(&self) -> EnvelopeMetadata {
        EnvelopeMetadata {
            version: self.version,
            algorithm: self.algorithm,
            scope: self.scope.clone(),
            recipient_count: self.access_entries.len(),
            ciphertext_len: self.ciphertext.len(),
            recipient_key_ids: self.access_entries.iter().map(|e| e.read_key_id).collect(),
        }
    }

    /// Serialize to binary format.
    ///
    /// Format: simple length-prefixed binary. Protobuf support will be
    /// added in Phase 3.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic bytes "ROK\x01"
        buf.extend_from_slice(b"ROK\x01");

        // Version
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Algorithm
        buf.push(self.algorithm as u8);

        // Scope (length-prefixed)
        let scope_bytes = self.scope.as_str().as_bytes();
        buf.extend_from_slice(&(scope_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(scope_bytes);

        // Ephemeral X25519 public
        buf.extend_from_slice(&self.ephemeral_x25519_public);

        // ML-KEM ciphertext (optional, length-prefixed)
        if let Some(ref ct) = self.ephemeral_mlkem_ciphertext {
            buf.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            buf.extend_from_slice(ct);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        // Access entries
        buf.extend_from_slice(&(self.access_entries.len() as u16).to_le_bytes());
        for entry in &self.access_entries {
            buf.extend_from_slice(entry.read_key_id.as_bytes());
            buf.extend_from_slice(&(entry.wrapped_data_key.len() as u16).to_le_bytes());
            buf.extend_from_slice(&entry.wrapped_data_key);
            buf.extend_from_slice(&entry.wrap_nonce);
        }

        // Nonce
        buf.extend_from_slice(&self.nonce);

        // Ciphertext (length-prefixed)
        buf.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);

        // Tag
        buf.extend_from_slice(&self.tag);

        // Spend public key
        buf.extend_from_slice(&self.spend_public_key);

        // Signature
        buf.extend_from_slice(&self.signature);

        buf
    }

    /// Deserialize from binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let read_bytes = |pos: &mut usize, n: usize| -> Result<&[u8]> {
            if *pos + n > data.len() {
                return Err(RokError::SerializationError(
                    "unexpected end of data".into(),
                ));
            }
            let slice = &data[*pos..*pos + n];
            *pos += n;
            Ok(slice)
        };

        // Magic
        let magic = read_bytes(&mut pos, 4)?;
        if magic != b"ROK\x01" {
            return Err(RokError::SerializationError("invalid magic bytes".into()));
        }

        // Version
        let version_bytes = read_bytes(&mut pos, 4)?;
        let version = u32::from_le_bytes(version_bytes.try_into().unwrap());

        // Algorithm
        let algo_byte = read_bytes(&mut pos, 1)?[0];
        let algorithm = Algorithm::from_u8(algo_byte)?;

        // Scope
        let scope_len = u16::from_le_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let scope_bytes = read_bytes(&mut pos, scope_len)?;
        let scope_str = std::str::from_utf8(scope_bytes)
            .map_err(|_| RokError::SerializationError("invalid scope utf8".into()))?;
        let scope = Scope::new(scope_str)?;

        // Ephemeral X25519
        let mut ephemeral_x25519_public = [0u8; 32];
        ephemeral_x25519_public.copy_from_slice(read_bytes(&mut pos, 32)?);

        // ML-KEM ciphertext
        let mlkem_len = u32::from_le_bytes(read_bytes(&mut pos, 4)?.try_into().unwrap()) as usize;
        let ephemeral_mlkem_ciphertext = if mlkem_len > 0 {
            Some(read_bytes(&mut pos, mlkem_len)?.to_vec())
        } else {
            None
        };

        // Access entries
        let entry_count = u16::from_le_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let mut access_entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let mut key_id_bytes = [0u8; 8];
            key_id_bytes.copy_from_slice(read_bytes(&mut pos, 8)?);
            let read_key_id = KeyId::from_bytes(key_id_bytes);

            let wdk_len = u16::from_le_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            let wrapped_data_key = read_bytes(&mut pos, wdk_len)?.to_vec();

            let mut wrap_nonce = [0u8; 12];
            wrap_nonce.copy_from_slice(read_bytes(&mut pos, 12)?);

            access_entries.push(AccessEntry {
                read_key_id,
                wrapped_data_key,
                wrap_nonce,
            });
        }

        // Nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(read_bytes(&mut pos, 12)?);

        // Ciphertext
        let ct_len = u64::from_le_bytes(read_bytes(&mut pos, 8)?.try_into().unwrap()) as usize;
        let ciphertext = read_bytes(&mut pos, ct_len)?.to_vec();

        // Tag
        let mut tag = [0u8; 16];
        tag.copy_from_slice(read_bytes(&mut pos, 16)?);

        // Spend public key
        let mut spend_public_key = [0u8; 32];
        spend_public_key.copy_from_slice(read_bytes(&mut pos, 32)?);

        // Signature
        let mut signature = [0u8; 64];
        signature.copy_from_slice(read_bytes(&mut pos, 64)?);

        Ok(EncryptedEnvelope {
            version,
            algorithm,
            scope,
            ephemeral_x25519_public,
            ephemeral_mlkem_ciphertext,
            access_entries,
            nonce,
            ciphertext,
            tag,
            signature,
            spend_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: 1,
            algorithm: Algorithm::EciesX25519ChaCha20,
            scope: Scope::new("/test").unwrap(),
            ephemeral_x25519_public: [1u8; 32],
            ephemeral_mlkem_ciphertext: None,
            access_entries: vec![AccessEntry {
                read_key_id: KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
                wrapped_data_key: vec![0u8; 48],
                wrap_nonce: [9u8; 12],
            }],
            nonce: [10u8; 12],
            ciphertext: vec![11u8; 64],
            tag: [12u8; 16],
            signature: [13u8; 64],
            spend_public_key: [14u8; 32],
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let envelope = make_test_envelope();
        let bytes = envelope.to_bytes();
        let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, envelope.version);
        assert_eq!(restored.algorithm, envelope.algorithm);
        assert_eq!(restored.scope, envelope.scope);
        assert_eq!(
            restored.ephemeral_x25519_public,
            envelope.ephemeral_x25519_public
        );
        assert_eq!(restored.access_entries.len(), 1);
        assert_eq!(restored.nonce, envelope.nonce);
        assert_eq!(restored.ciphertext, envelope.ciphertext);
        assert_eq!(restored.tag, envelope.tag);
        assert_eq!(restored.signature, envelope.signature);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = make_test_envelope().to_bytes();
        bytes[0] = b'X';
        assert!(EncryptedEnvelope::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_metadata() {
        let envelope = make_test_envelope();
        let meta = envelope.metadata();
        assert_eq!(meta.version, 1);
        assert_eq!(meta.recipient_count, 1);
        assert_eq!(meta.ciphertext_len, 64);
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let envelope = make_test_envelope();
        let b1 = envelope.signable_bytes();
        let b2 = envelope.signable_bytes();
        assert_eq!(b1, b2);
    }
}
