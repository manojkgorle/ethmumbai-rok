use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient, decrypt};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::error::Result;
use rok_core::keys::key_id::KeyId;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

/// Encrypted data pipeline with scope-based consumer access.
///
/// A pipeline encrypts data chunks (messages) for a set of consumers.
/// Each consumer holds a read key that can decrypt the stream.
/// Consumers can be added or removed dynamically.
pub struct Pipeline {
    scope: Scope,
    spend_key: SpendKeyPair,
    consumers: Vec<Recipient>,
}

impl Pipeline {
    /// Create a new pipeline for the given scope.
    pub fn new(scope: Scope, spend_key: SpendKeyPair) -> Self {
        Pipeline {
            scope,
            spend_key,
            consumers: Vec::new(),
        }
    }

    /// Add a consumer (read key) to the pipeline.
    pub fn add_consumer(&mut self, recipient: Recipient) {
        self.consumers.push(recipient);
    }

    /// Remove a consumer by key ID.
    pub fn remove_consumer(&mut self, key_id: &KeyId) {
        self.consumers.retain(|r| r.key_id != *key_id);
    }

    /// Number of current consumers.
    pub fn consumer_count(&self) -> usize {
        self.consumers.len()
    }

    /// Encrypt a data chunk for all current consumers.
    pub fn encrypt_chunk(&self, data: &[u8]) -> Result<EncryptedEnvelope> {
        let mut rng = rand::thread_rng();

        EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, self.scope.clone())
            .add_recipients(&self.consumers)
            .set_spend_key(&self.spend_key)
            .encrypt(data, &mut rng)
    }

    /// Decrypt a chunk using a consumer's read key.
    pub fn decrypt_chunk(
        envelope: &EncryptedEnvelope,
        read_key: &ReadKeyPair,
        spend_verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<Vec<u8>> {
        decrypt(envelope, read_key, spend_verifying_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_basic() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let vk = spend.verifying_key();
        let root = spend.derive_root_read_key();
        let consumer = root.derive_child_segment("stream").unwrap();

        let mut pipeline = Pipeline::new(
            Scope::new("/stream").unwrap(),
            SpendKeyPair::from_seed(&[42u8; 32]),
        );

        pipeline.add_consumer(Recipient {
            read_public_key: *consumer.public_key(),
            key_id: consumer.key_id(),
        });

        let envelope = pipeline.encrypt_chunk(b"chunk 1").unwrap();
        let decrypted = Pipeline::decrypt_chunk(&envelope, &consumer, &vk).unwrap();
        assert_eq!(decrypted, b"chunk 1");
    }

    #[test]
    fn test_pipeline_multiple_chunks() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let vk = spend.verifying_key();
        let root = spend.derive_root_read_key();

        let mut pipeline = Pipeline::new(
            Scope::root(),
            SpendKeyPair::from_seed(&[42u8; 32]),
        );

        pipeline.add_consumer(Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        });

        for i in 0..5 {
            let data = format!("chunk {}", i);
            let envelope = pipeline.encrypt_chunk(data.as_bytes()).unwrap();
            let decrypted = Pipeline::decrypt_chunk(&envelope, &root, &vk).unwrap();
            assert_eq!(decrypted, data.as_bytes());
        }
    }

    #[test]
    fn test_pipeline_remove_consumer() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let c1 = root.derive_child_segment("c1").unwrap();
        let c2 = root.derive_child_segment("c2").unwrap();

        let mut pipeline = Pipeline::new(
            Scope::root(),
            SpendKeyPair::from_seed(&[42u8; 32]),
        );

        pipeline.add_consumer(Recipient {
            read_public_key: *c1.public_key(),
            key_id: c1.key_id(),
        });
        pipeline.add_consumer(Recipient {
            read_public_key: *c2.public_key(),
            key_id: c2.key_id(),
        });

        assert_eq!(pipeline.consumer_count(), 2);

        pipeline.remove_consumer(&c1.key_id());
        assert_eq!(pipeline.consumer_count(), 1);
    }
}
