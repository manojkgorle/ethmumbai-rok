//! Protobuf types and conversions.
//!
//! Generated from `proto/rok/*.proto` via prost-build.
//! This module re-exports the generated types and provides
//! `From`/`TryFrom` conversions to/from the native domain types.

#[allow(clippy::all)]
pub mod rok {
    include!("generated/rok.rs");
}

use ed25519_dalek::VerifyingKey;
use prost::Message;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::encrypt::{AccessMode as NativeAccessMode, Algorithm as NativeAlgorithm};
use crate::envelope::{AccessEntry as NativeAccessEntry, EncryptedEnvelope as NativeEnvelope};
use crate::error::{Result, RokError};
use crate::keys::key_id::KeyId;
use crate::keys::read::ExportedReadKey as NativeExportedReadKey;
use crate::keys::scope::Scope;
use crate::sectioned::{Section as NativeSection, SectionedEnvelope as NativeSectionedEnvelope};

// --- Algorithm conversions ---

impl From<NativeAlgorithm> for rok::Algorithm {
    fn from(algo: NativeAlgorithm) -> Self {
        match algo {
            NativeAlgorithm::EciesX25519ChaCha20 => rok::Algorithm::EciesX25519Chacha20,
            NativeAlgorithm::HybridX25519MlKemChaCha20 => rok::Algorithm::HybridX25519MlkemChacha20,
        }
    }
}

impl TryFrom<rok::Algorithm> for NativeAlgorithm {
    type Error = RokError;

    fn try_from(algo: rok::Algorithm) -> Result<Self> {
        match algo {
            rok::Algorithm::EciesX25519Chacha20 => Ok(NativeAlgorithm::EciesX25519ChaCha20),
            rok::Algorithm::HybridX25519MlkemChacha20 => {
                Ok(NativeAlgorithm::HybridX25519MlKemChaCha20)
            }
            rok::Algorithm::Unspecified => {
                Err(RokError::SerializationError("unspecified algorithm".into()))
            }
        }
    }
}

// --- AccessMode conversions ---

impl From<NativeAccessMode> for rok::AccessMode {
    fn from(mode: NativeAccessMode) -> Self {
        match mode {
            NativeAccessMode::Recipient => rok::AccessMode::Recipient,
            NativeAccessMode::ScopeBased => rok::AccessMode::ScopeBased,
        }
    }
}

impl TryFrom<rok::AccessMode> for NativeAccessMode {
    type Error = RokError;

    fn try_from(mode: rok::AccessMode) -> Result<Self> {
        match mode {
            rok::AccessMode::Recipient => Ok(NativeAccessMode::Recipient),
            rok::AccessMode::ScopeBased => Ok(NativeAccessMode::ScopeBased),
        }
    }
}

// --- SpendPublicKey conversions ---

impl rok::SpendPublicKey {
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let key_id = KeyId::from_public_bytes(vk.as_bytes());
        rok::SpendPublicKey {
            key_bytes: vk.as_bytes().to_vec(),
            key_id: key_id.as_bytes().to_vec(),
        }
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey> {
        if self.key_bytes.len() != 32 {
            return Err(RokError::SerializationError(
                "spend public key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.key_bytes);
        VerifyingKey::from_bytes(&arr).map_err(|_| RokError::InvalidKeyMaterial)
    }
}

// --- ReadPublicKey conversions ---

impl rok::ReadPublicKey {
    pub fn from_parts(key: &X25519PublicKey, scope: &Scope, parent_key_id: Option<&KeyId>) -> Self {
        let key_id = KeyId::from_public_bytes(key.as_bytes());
        rok::ReadPublicKey {
            key_bytes: key.as_bytes().to_vec(),
            scope: scope.as_str().to_string(),
            key_id: key_id.as_bytes().to_vec(),
            parent_key_id: parent_key_id
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_default(),
        }
    }

    pub fn to_parts(&self) -> Result<(X25519PublicKey, Scope, Option<KeyId>)> {
        if self.key_bytes.len() != 32 {
            return Err(RokError::SerializationError(
                "read public key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.key_bytes);
        let key = X25519PublicKey::from(arr);
        let scope = Scope::new(&self.scope)?;
        let parent = if self.parent_key_id.len() == 8 {
            let mut pid = [0u8; 8];
            pid.copy_from_slice(&self.parent_key_id);
            Some(KeyId::from_bytes(pid))
        } else {
            None
        };
        Ok((key, scope, parent))
    }
}

// --- ExportedReadKey conversions ---

impl From<&NativeExportedReadKey> for rok::ExportedReadKey {
    fn from(key: &NativeExportedReadKey) -> Self {
        rok::ExportedReadKey {
            secret_bytes: key.secret_bytes.to_vec(),
            public_bytes: key.public_bytes.to_vec(),
            scope: key.scope.as_str().to_string(),
            parent_key_id: key
                .parent_key_id
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_default(),
        }
    }
}

impl TryFrom<&rok::ExportedReadKey> for NativeExportedReadKey {
    type Error = RokError;

    fn try_from(key: &rok::ExportedReadKey) -> Result<Self> {
        if key.secret_bytes.len() != 32 {
            return Err(RokError::SerializationError(
                "exported read key secret must be 32 bytes".into(),
            ));
        }
        if key.public_bytes.len() != 32 {
            return Err(RokError::SerializationError(
                "exported read key public must be 32 bytes".into(),
            ));
        }
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&key.secret_bytes);
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(&key.public_bytes);
        let scope = Scope::new(&key.scope)?;
        let parent_key_id = if key.parent_key_id.len() == 8 {
            let mut pid = [0u8; 8];
            pid.copy_from_slice(&key.parent_key_id);
            Some(KeyId::from_bytes(pid))
        } else {
            None
        };
        Ok(NativeExportedReadKey {
            secret_bytes,
            public_bytes,
            scope,
            parent_key_id,
        })
    }
}

// --- AccessEntry conversions ---

impl From<&NativeAccessEntry> for rok::AccessEntry {
    fn from(entry: &NativeAccessEntry) -> Self {
        rok::AccessEntry {
            read_key_id: entry.read_key_id.as_bytes().to_vec(),
            wrapped_data_key: entry.wrapped_data_key.clone(),
            wrap_nonce: entry.wrap_nonce.to_vec(),
        }
    }
}

impl TryFrom<&rok::AccessEntry> for NativeAccessEntry {
    type Error = RokError;

    fn try_from(entry: &rok::AccessEntry) -> Result<Self> {
        if entry.read_key_id.len() != 8 {
            return Err(RokError::SerializationError(format!(
                "expected 8-byte key_id, got {}",
                entry.read_key_id.len()
            )));
        }
        let mut key_id_bytes = [0u8; 8];
        key_id_bytes.copy_from_slice(&entry.read_key_id);

        if entry.wrap_nonce.len() != 12 {
            return Err(RokError::SerializationError(format!(
                "expected 12-byte wrap_nonce, got {}",
                entry.wrap_nonce.len()
            )));
        }
        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&entry.wrap_nonce);

        Ok(NativeAccessEntry {
            read_key_id: KeyId::from_bytes(key_id_bytes),
            wrapped_data_key: entry.wrapped_data_key.clone(),
            wrap_nonce,
        })
    }
}

// --- EncryptedEnvelope conversions ---

impl From<&NativeEnvelope> for rok::EncryptedEnvelope {
    fn from(env: &NativeEnvelope) -> Self {
        rok::EncryptedEnvelope {
            version: env.version,
            algorithm: rok::Algorithm::from(env.algorithm) as i32,
            scope: env.scope.as_str().to_string(),
            ephemeral_x25519_public: env.ephemeral_x25519_public.to_vec(),
            ephemeral_mlkem_ciphertext: env.ephemeral_mlkem_ciphertext.clone().unwrap_or_default(),
            access_entries: env
                .access_entries
                .iter()
                .map(rok::AccessEntry::from)
                .collect(),
            nonce: env.nonce.to_vec(),
            ciphertext: env.ciphertext.clone(),
            tag: env.tag.to_vec(),
            spend_public_key: env.spend_public_key.to_vec(),
            signature: env.signature.to_vec(),
            access_mode: rok::AccessMode::from(env.access_mode) as i32,
        }
    }
}

impl TryFrom<&rok::EncryptedEnvelope> for NativeEnvelope {
    type Error = RokError;

    fn try_from(env: &rok::EncryptedEnvelope) -> Result<Self> {
        let algorithm =
            NativeAlgorithm::try_from(rok::Algorithm::try_from(env.algorithm).map_err(|_| {
                RokError::SerializationError(format!("unknown algorithm value: {}", env.algorithm))
            })?)?;

        let scope = Scope::new(&env.scope)?;

        if env.ephemeral_x25519_public.len() != 32 {
            return Err(RokError::SerializationError(
                "ephemeral X25519 public key must be 32 bytes".into(),
            ));
        }
        let mut ephemeral_x25519_public = [0u8; 32];
        ephemeral_x25519_public.copy_from_slice(&env.ephemeral_x25519_public);

        let ephemeral_mlkem_ciphertext = if env.ephemeral_mlkem_ciphertext.is_empty() {
            None
        } else {
            Some(env.ephemeral_mlkem_ciphertext.clone())
        };

        let mut access_entries = Vec::with_capacity(env.access_entries.len());
        for entry in &env.access_entries {
            access_entries.push(NativeAccessEntry::try_from(entry)?);
        }

        if env.nonce.len() != 12 {
            return Err(RokError::SerializationError(
                "nonce must be 12 bytes".into(),
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&env.nonce);

        if env.tag.len() != 16 {
            return Err(RokError::SerializationError("tag must be 16 bytes".into()));
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&env.tag);

        if env.spend_public_key.len() != 32 {
            return Err(RokError::SerializationError(
                "spend public key must be 32 bytes".into(),
            ));
        }
        let mut spend_public_key = [0u8; 32];
        spend_public_key.copy_from_slice(&env.spend_public_key);

        if env.signature.len() != 64 {
            return Err(RokError::SerializationError(
                "signature must be 64 bytes".into(),
            ));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&env.signature);

        let access_mode = NativeAccessMode::try_from(
            rok::AccessMode::try_from(env.access_mode).map_err(|_| {
                RokError::SerializationError(format!(
                    "unknown access mode value: {}",
                    env.access_mode
                ))
            })?,
        )?;

        Ok(NativeEnvelope {
            version: env.version,
            algorithm,
            scope,
            ephemeral_x25519_public,
            ephemeral_mlkem_ciphertext,
            access_entries,
            nonce,
            ciphertext: env.ciphertext.clone(),
            tag,
            spend_public_key,
            signature,
            access_mode,
        })
    }
}

// --- AccessPolicy conversions ---

impl rok::AccessPolicy {
    /// Encode to protobuf bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decode from protobuf bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self> {
        rok::AccessPolicy::decode(bytes)
            .map_err(|e| RokError::SerializationError(format!("protobuf decode: {}", e)))
    }
}

impl rok::RevocationList {
    /// Encode to protobuf bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    /// Decode from protobuf bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self> {
        rok::RevocationList::decode(bytes)
            .map_err(|e| RokError::SerializationError(format!("protobuf decode: {}", e)))
    }
}

// --- EncryptedEnvelope convenience methods ---

impl NativeEnvelope {
    /// Serialize to protobuf bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        let proto_env = rok::EncryptedEnvelope::from(self);
        proto_env.encode_to_vec()
    }

    /// Deserialize from protobuf bytes.
    pub fn from_proto_bytes(bytes: &[u8]) -> Result<Self> {
        let proto_env = rok::EncryptedEnvelope::decode(bytes)
            .map_err(|e| RokError::SerializationError(format!("protobuf decode: {}", e)))?;
        NativeEnvelope::try_from(&proto_env)
    }
}

// --- SectionedSection conversions ---

impl From<&NativeSection> for rok::SectionedSection {
    fn from(section: &NativeSection) -> Self {
        rok::SectionedSection {
            name: section.name.clone(),
            envelope: Some(rok::EncryptedEnvelope::from(&section.envelope)),
        }
    }
}

impl TryFrom<&rok::SectionedSection> for NativeSection {
    type Error = RokError;

    fn try_from(section: &rok::SectionedSection) -> Result<Self> {
        let proto_env = section.envelope.as_ref().ok_or_else(|| {
            RokError::SerializationError("sectioned section missing envelope".into())
        })?;
        let envelope = NativeEnvelope::try_from(proto_env)?;
        Ok(NativeSection {
            name: section.name.clone(),
            envelope,
        })
    }
}

// --- SectionedEnvelope conversions ---

impl From<&NativeSectionedEnvelope> for rok::SectionedEnvelope {
    fn from(env: &NativeSectionedEnvelope) -> Self {
        rok::SectionedEnvelope {
            version: env.version,
            sections: env
                .sections
                .iter()
                .map(rok::SectionedSection::from)
                .collect(),
        }
    }
}

impl TryFrom<&rok::SectionedEnvelope> for NativeSectionedEnvelope {
    type Error = RokError;

    fn try_from(env: &rok::SectionedEnvelope) -> Result<Self> {
        let mut sections = Vec::with_capacity(env.sections.len());
        for section in &env.sections {
            sections.push(NativeSection::try_from(section)?);
        }
        Ok(NativeSectionedEnvelope {
            version: env.version,
            sections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::Algorithm;
    use crate::keys::spend::SpendKeyPair;

    fn make_test_envelope() -> NativeEnvelope {
        NativeEnvelope {
            version: 2,
            algorithm: Algorithm::EciesX25519ChaCha20,
            scope: Scope::new("/test").unwrap(),
            ephemeral_x25519_public: [1u8; 32],
            ephemeral_mlkem_ciphertext: None,
            access_entries: vec![NativeAccessEntry {
                read_key_id: KeyId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
                wrapped_data_key: vec![0u8; 48],
                wrap_nonce: [9u8; 12],
            }],
            nonce: [10u8; 12],
            ciphertext: vec![11u8; 64],
            tag: [12u8; 16],
            signature: [13u8; 64],
            spend_public_key: [14u8; 32],
            access_mode: NativeAccessMode::Recipient,
        }
    }

    #[test]
    fn test_protobuf_roundtrip() {
        let envelope = make_test_envelope();
        let bytes = envelope.to_proto_bytes();
        let restored = NativeEnvelope::from_proto_bytes(&bytes).unwrap();

        assert_eq!(restored.version, envelope.version);
        assert_eq!(restored.algorithm, envelope.algorithm);
        assert_eq!(restored.scope, envelope.scope);
        assert_eq!(
            restored.ephemeral_x25519_public,
            envelope.ephemeral_x25519_public
        );
        assert_eq!(restored.access_entries.len(), 1);
        assert_eq!(
            restored.access_entries[0].read_key_id,
            envelope.access_entries[0].read_key_id
        );
        assert_eq!(restored.nonce, envelope.nonce);
        assert_eq!(restored.ciphertext, envelope.ciphertext);
        assert_eq!(restored.tag, envelope.tag);
        assert_eq!(restored.signature, envelope.signature);
        assert_eq!(restored.spend_public_key, envelope.spend_public_key);
    }

    #[test]
    fn test_protobuf_with_mlkem_ciphertext() {
        let mut envelope = make_test_envelope();
        envelope.algorithm = Algorithm::HybridX25519MlKemChaCha20;
        envelope.ephemeral_mlkem_ciphertext = Some(vec![42u8; 1088]);

        let bytes = envelope.to_proto_bytes();
        let restored = NativeEnvelope::from_proto_bytes(&bytes).unwrap();

        assert_eq!(restored.algorithm, Algorithm::HybridX25519MlKemChaCha20);
        assert_eq!(restored.ephemeral_mlkem_ciphertext, Some(vec![42u8; 1088]));
    }

    #[test]
    fn test_algorithm_conversion_roundtrip() {
        let native = NativeAlgorithm::EciesX25519ChaCha20;
        let proto = rok::Algorithm::from(native);
        let back = NativeAlgorithm::try_from(proto).unwrap();
        assert_eq!(native, back);

        let native = NativeAlgorithm::HybridX25519MlKemChaCha20;
        let proto = rok::Algorithm::from(native);
        let back = NativeAlgorithm::try_from(proto).unwrap();
        assert_eq!(native, back);
    }

    #[test]
    fn test_invalid_protobuf_bytes_rejected() {
        assert!(NativeEnvelope::from_proto_bytes(b"garbage").is_err());
    }

    #[test]
    fn test_spend_public_key_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let proto = rok::SpendPublicKey::from_verifying_key(&spend.verifying_key());
        let restored = proto.to_verifying_key().unwrap();
        assert_eq!(spend.verifying_key(), restored);
    }

    #[test]
    fn test_read_public_key_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        let proto = rok::ReadPublicKey::from_parts(
            finance.public_key(),
            finance.scope(),
            finance.parent_key_id(),
        );
        let (key, scope, parent) = proto.to_parts().unwrap();
        assert_eq!(&key, finance.public_key());
        assert_eq!(scope, *finance.scope());
        assert!(parent.is_some());
    }

    #[test]
    fn test_exported_read_key_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let exported = finance.export();

        let proto = rok::ExportedReadKey::from(&exported);
        let restored = NativeExportedReadKey::try_from(&proto).unwrap();

        assert_eq!(restored.secret_bytes, exported.secret_bytes);
        assert_eq!(restored.public_bytes, exported.public_bytes);
        assert_eq!(restored.scope, exported.scope);
    }

    #[test]
    fn test_access_policy_proto_roundtrip() {
        let policy = rok::AccessPolicy {
            rules: vec![rok::AccessRule {
                scope: "/finance".into(),
                recipient_key_ids: vec![vec![1, 2, 3, 4, 5, 6, 7, 8]],
                expires_at: 0,
            }],
        };

        let bytes = policy.to_proto_bytes();
        let restored = rok::AccessPolicy::from_proto_bytes(&bytes).unwrap();
        assert_eq!(restored.rules.len(), 1);
        assert_eq!(restored.rules[0].scope, "/finance");
    }

    #[test]
    fn test_revocation_list_proto_roundtrip() {
        let list = rok::RevocationList {
            entries: vec![rok::RevocationEntry {
                key_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                revoked_at: 1700000000,
                reason: "compromised".into(),
            }],
        };

        let bytes = list.to_proto_bytes();
        let restored = rok::RevocationList::from_proto_bytes(&bytes).unwrap();
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].reason, "compromised");
    }
}
