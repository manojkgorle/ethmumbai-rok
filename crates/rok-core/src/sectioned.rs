//! Sectioned envelope: multiple independently encrypted sections in a single container.
//!
//! Each section is a complete `EncryptedEnvelope` with its own scope, ephemeral keys,
//! ciphertext, and signature. The `SectionedEnvelope` is a thin named container
//! with its own binary (`ROKS`) and protobuf wire formats.

use prost::Message;

use crate::envelope::EncryptedEnvelope;
use crate::error::{Result, RokError};
use crate::proto::rok;

/// Magic bytes for the sectioned binary format.
pub const SECTIONED_MAGIC: &[u8; 4] = b"ROKS";

/// Current sectioned envelope version.
pub const SECTIONED_VERSION: u32 = 1;

/// A named section containing a complete encrypted envelope.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub envelope: EncryptedEnvelope,
}

/// A container of multiple independently encrypted sections.
#[derive(Debug, Clone)]
pub struct SectionedEnvelope {
    pub version: u32,
    pub sections: Vec<Section>,
}

/// Non-secret metadata about a single section.
#[derive(Debug)]
pub struct SectionMetadataEntry {
    pub name: String,
    pub scope: String,
    pub algorithm: crate::encrypt::Algorithm,
    pub access_mode: crate::encrypt::AccessMode,
    pub ciphertext_len: usize,
    pub recipient_count: usize,
}

/// Non-secret metadata about a sectioned envelope.
#[derive(Debug)]
pub struct SectionedMetadata {
    pub version: u32,
    pub section_count: usize,
    pub sections: Vec<SectionMetadataEntry>,
}

impl SectionedEnvelope {
    /// Extract non-secret metadata for inspection.
    pub fn metadata(&self) -> SectionedMetadata {
        SectionedMetadata {
            version: self.version,
            section_count: self.sections.len(),
            sections: self
                .sections
                .iter()
                .map(|s| {
                    let meta = s.envelope.metadata();
                    SectionMetadataEntry {
                        name: s.name.clone(),
                        scope: meta.scope.to_string(),
                        algorithm: meta.algorithm,
                        access_mode: meta.access_mode,
                        ciphertext_len: meta.ciphertext_len,
                        recipient_count: meta.recipient_count,
                    }
                })
                .collect(),
        }
    }

    /// Serialize to binary format.
    ///
    /// Format:
    /// ```text
    /// ROKS (4 bytes)
    /// version (u32 LE)
    /// section_count (u16 LE)
    /// For each section:
    ///   name_len (u16 LE) + name (UTF-8)
    ///   envelope_len (u32 LE) + EncryptedEnvelope::to_bytes()
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(SECTIONED_MAGIC);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&(self.sections.len() as u16).to_le_bytes());

        for section in &self.sections {
            let name_bytes = section.name.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(name_bytes);

            let envelope_bytes = section.envelope.to_bytes();
            buf.extend_from_slice(&(envelope_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&envelope_bytes);
        }

        buf
    }

    /// Deserialize from binary format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let read_bytes = |pos: &mut usize, n: usize| -> Result<&[u8]> {
            if *pos + n > data.len() {
                return Err(RokError::SerializationError(
                    "unexpected end of sectioned data".into(),
                ));
            }
            let slice = &data[*pos..*pos + n];
            *pos += n;
            Ok(slice)
        };

        // Magic
        let magic = read_bytes(&mut pos, 4)?;
        if magic != SECTIONED_MAGIC {
            return Err(RokError::SerializationError(
                "invalid sectioned magic bytes (expected ROKS)".into(),
            ));
        }

        // Version
        let version = u32::from_le_bytes(read_bytes(&mut pos, 4)?.try_into().unwrap());

        // Section count
        let section_count =
            u16::from_le_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;

        let mut sections = Vec::with_capacity(section_count);
        for _ in 0..section_count {
            // Name
            let name_len =
                u16::from_le_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            let name_bytes = read_bytes(&mut pos, name_len)?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| RokError::SerializationError("invalid section name utf8".into()))?
                .to_string();

            // Envelope
            let envelope_len =
                u32::from_le_bytes(read_bytes(&mut pos, 4)?.try_into().unwrap()) as usize;
            let envelope_bytes = read_bytes(&mut pos, envelope_len)?;
            let envelope = EncryptedEnvelope::from_bytes(envelope_bytes)?;

            sections.push(Section { name, envelope });
        }

        Ok(SectionedEnvelope { version, sections })
    }

    /// Serialize to protobuf bytes.
    pub fn to_proto_bytes(&self) -> Vec<u8> {
        let proto = rok::SectionedEnvelope::from(self);
        proto.encode_to_vec()
    }

    /// Deserialize from protobuf bytes.
    pub fn from_proto_bytes(data: &[u8]) -> Result<Self> {
        let proto = rok::SectionedEnvelope::decode(data)
            .map_err(|e| RokError::SerializationError(format!("protobuf decode: {}", e)))?;
        SectionedEnvelope::try_from(&proto)
    }
}

/// Builder for constructing a `SectionedEnvelope` with validation.
pub struct SectionedEnvelopeBuilder {
    sections: Vec<Section>,
}

impl SectionedEnvelopeBuilder {
    pub fn new() -> Self {
        SectionedEnvelopeBuilder {
            sections: Vec::new(),
        }
    }

    /// Add a named section. Returns an error if the name is already used.
    pub fn add_section(&mut self, name: String, envelope: EncryptedEnvelope) -> Result<&mut Self> {
        if self.sections.iter().any(|s| s.name == name) {
            return Err(RokError::SerializationError(format!(
                "duplicate section name: {}",
                name
            )));
        }
        self.sections.push(Section { name, envelope });
        Ok(self)
    }

    /// Build the sectioned envelope. Fails if no sections were added.
    pub fn build(self) -> Result<SectionedEnvelope> {
        if self.sections.is_empty() {
            return Err(RokError::SerializationError(
                "sectioned envelope must have at least one section".into(),
            ));
        }
        Ok(SectionedEnvelope {
            version: SECTIONED_VERSION,
            sections: self.sections,
        })
    }
}

impl Default for SectionedEnvelopeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{AccessMode, Algorithm, EncryptBuilder};
    use crate::keys::scope::Scope;
    use crate::keys::spend::SpendKeyPair;

    fn make_test_section(
        spend: &SpendKeyPair,
        name: &str,
        scope_str: &str,
        data: &[u8],
    ) -> Section {
        let mut rng = rand::thread_rng();
        let scope = Scope::new(scope_str).unwrap();
        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope)
            .set_spend_key(spend)
            .set_scope_based()
            .encrypt(data, &mut rng)
            .unwrap();
        Section {
            name: name.to_string(),
            envelope,
        }
    }

    #[test]
    fn test_binary_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let s1 = make_test_section(&spend, "finance", "/finance", b"finance data");
        let s2 = make_test_section(&spend, "legal", "/legal", b"legal data");

        let mut builder = SectionedEnvelopeBuilder::new();
        builder
            .add_section(s1.name.clone(), s1.envelope.clone())
            .unwrap();
        builder
            .add_section(s2.name.clone(), s2.envelope.clone())
            .unwrap();
        let sectioned = builder.build().unwrap();

        let bytes = sectioned.to_bytes();
        let restored = SectionedEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, SECTIONED_VERSION);
        assert_eq!(restored.sections.len(), 2);
        assert_eq!(restored.sections[0].name, "finance");
        assert_eq!(restored.sections[1].name, "legal");
        assert_eq!(restored.sections[0].envelope.scope, s1.envelope.scope);
        assert_eq!(restored.sections[1].envelope.scope, s2.envelope.scope);
    }

    #[test]
    fn test_proto_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let s1 = make_test_section(&spend, "finance", "/finance", b"finance data");
        let s2 = make_test_section(&spend, "legal", "/legal", b"legal data");

        let mut builder = SectionedEnvelopeBuilder::new();
        builder
            .add_section(s1.name.clone(), s1.envelope.clone())
            .unwrap();
        builder
            .add_section(s2.name.clone(), s2.envelope.clone())
            .unwrap();
        let sectioned = builder.build().unwrap();

        let bytes = sectioned.to_proto_bytes();
        let restored = SectionedEnvelope::from_proto_bytes(&bytes).unwrap();

        assert_eq!(restored.version, SECTIONED_VERSION);
        assert_eq!(restored.sections.len(), 2);
        assert_eq!(restored.sections[0].name, "finance");
        assert_eq!(restored.sections[1].name, "legal");
    }

    #[test]
    fn test_invalid_magic() {
        // ROK\x01 data should be rejected by SectionedEnvelope::from_bytes
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let mut rng = rand::thread_rng();
        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .set_spend_key(&spend)
            .set_scope_based()
            .encrypt(b"test", &mut rng)
            .unwrap();

        let single_bytes = envelope.to_bytes();
        assert!(SectionedEnvelope::from_bytes(&single_bytes).is_err());
    }

    #[test]
    fn test_empty_sections_rejected() {
        let builder = SectionedEnvelopeBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_duplicate_names_rejected() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let s1 = make_test_section(&spend, "finance", "/finance", b"data1");
        let s2 = make_test_section(&spend, "finance", "/legal", b"data2");

        let mut builder = SectionedEnvelopeBuilder::new();
        builder.add_section(s1.name, s1.envelope).unwrap();
        assert!(builder.add_section(s2.name, s2.envelope).is_err());
    }

    #[test]
    fn test_metadata() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let s1 = make_test_section(&spend, "finance", "/finance", b"finance data");
        let s2 = make_test_section(&spend, "legal", "/legal", b"legal data");

        let mut builder = SectionedEnvelopeBuilder::new();
        builder.add_section(s1.name, s1.envelope).unwrap();
        builder.add_section(s2.name, s2.envelope).unwrap();
        let sectioned = builder.build().unwrap();

        let meta = sectioned.metadata();
        assert_eq!(meta.version, SECTIONED_VERSION);
        assert_eq!(meta.section_count, 2);
        assert_eq!(meta.sections[0].name, "finance");
        assert_eq!(meta.sections[0].scope, "/finance");
        assert_eq!(meta.sections[0].algorithm, Algorithm::EciesX25519ChaCha20);
        assert_eq!(meta.sections[0].access_mode, AccessMode::ScopeBased);
        assert_eq!(meta.sections[1].name, "legal");
        assert_eq!(meta.sections[1].scope, "/legal");
    }
}
