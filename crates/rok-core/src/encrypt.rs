use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::derive;
use crate::envelope::{AccessEntry, EncryptedEnvelope};
use crate::error::{Result, RokError};
use crate::keys::key_id::KeyId;
use crate::keys::read::ReadKeyPair;
use crate::keys::scope::Scope;
use crate::keys::spend::SpendKeyPair;

/// Encryption algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    /// Pure classical: X25519 ECDH + ChaCha20-Poly1305
    EciesX25519ChaCha20 = 1,
    /// Hybrid post-quantum: X25519 + ML-KEM-768 + ChaCha20-Poly1305
    HybridX25519MlKemChaCha20 = 2,
}

impl Algorithm {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Algorithm::EciesX25519ChaCha20),
            2 => Ok(Algorithm::HybridX25519MlKemChaCha20),
            _ => Err(RokError::SerializationError(format!(
                "unknown algorithm: {}",
                v
            ))),
        }
    }
}

/// Access mode for encrypted envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AccessMode {
    /// Per-recipient: each recipient gets an individual access entry.
    #[default]
    Recipient = 0,
    /// Scope-based: a single access entry for the scope's derived key.
    /// Any ancestor key holder can derive down to decrypt.
    ScopeBased = 1,
}

impl AccessMode {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(AccessMode::Recipient),
            1 => Ok(AccessMode::ScopeBased),
            _ => Err(RokError::SerializationError(format!(
                "unknown access mode: {}",
                v
            ))),
        }
    }
}

/// A recipient that will receive access to encrypted data.
#[derive(Debug, Clone)]
pub struct Recipient {
    pub read_public_key: X25519PublicKey,
    pub key_id: KeyId,
}

/// Builder for constructing encrypted envelopes (classical mode).
pub struct EncryptBuilder<'a> {
    algorithm: Algorithm,
    scope: Scope,
    recipients: Vec<Recipient>,
    spend_key: Option<&'a SpendKeyPair>,
    scope_based: bool,
}

impl<'a> EncryptBuilder<'a> {
    /// Create a new builder for the given algorithm and scope.
    pub fn new(algorithm: Algorithm, scope: Scope) -> Self {
        EncryptBuilder {
            algorithm,
            scope,
            recipients: Vec::new(),
            spend_key: None,
            scope_based: false,
        }
    }

    /// Add a recipient who should be able to decrypt.
    pub fn add_recipient(&mut self, recipient: Recipient) -> &mut Self {
        self.recipients.push(recipient);
        self
    }

    /// Add multiple recipients.
    pub fn add_recipients(&mut self, recipients: &[Recipient]) -> &mut Self {
        self.recipients.extend_from_slice(recipients);
        self
    }

    /// Set the spend key for signing the envelope.
    pub fn set_spend_key(&mut self, spend_key: &'a SpendKeyPair) -> &mut Self {
        self.spend_key = Some(spend_key);
        self
    }

    /// Enable scope-based group encryption.
    ///
    /// Instead of listing individual recipients, a single access entry is created
    /// for the scope's derived key. Any ancestor key holder can derive down to decrypt.
    pub fn set_scope_based(&mut self) -> &mut Self {
        self.scope_based = true;
        self
    }

    /// Encrypt the plaintext and produce a signed envelope.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<EncryptedEnvelope> {
        let spend_key = self
            .spend_key
            .ok_or_else(|| RokError::EncryptionError("spend key not set".into()))?;

        // In scope-based mode, auto-derive the scope's read key as the sole recipient
        let recipients: Vec<Recipient>;
        let access_mode: AccessMode;
        if self.scope_based {
            access_mode = AccessMode::ScopeBased;
            let root_read = spend_key.derive_root_read_key();
            let scope_key = if self.scope == Scope::root() {
                root_read
            } else {
                root_read.derive_child(&self.scope)?
            };
            recipients = vec![Recipient {
                read_public_key: *scope_key.public_key(),
                key_id: scope_key.key_id(),
            }];
        } else {
            access_mode = AccessMode::Recipient;
            if self.recipients.is_empty() {
                return Err(RokError::EncryptionError("no recipients".into()));
            }
            recipients = self.recipients.clone();
        }

        if self.algorithm == Algorithm::HybridX25519MlKemChaCha20 {
            return Err(RokError::EncryptionError(
                "hybrid mode not yet supported in EncryptBuilder; use rok-pq".into(),
            ));
        }

        // 1. Generate random 256-bit data key
        let mut data_key = [0u8; 32];
        rng.fill_bytes(&mut data_key);

        // 2. Generate ephemeral X25519 keypair (using StaticSecret for multi-recipient DH)
        let mut ephemeral_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_static = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_static);

        // 3. Encrypt plaintext with ChaCha20-Poly1305
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&data_key)
            .map_err(|e| RokError::EncryptionError(format!("ChaCha20 init: {}", e)))?;

        let nonce = ChaChaNonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RokError::EncryptionError(format!("ChaCha20 encrypt: {}", e)))?;

        // ChaCha20Poly1305 appends a 16-byte tag
        let (ciphertext, tag_bytes) = encrypted.split_at(encrypted.len() - 16);
        let ciphertext = ciphertext.to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        // 4. For each recipient, wrap the data key
        let mut access_entries = Vec::with_capacity(recipients.len());

        for recipient in &recipients {
            let shared_secret = ephemeral_static.diffie_hellman(&recipient.read_public_key);

            // Derive wrapping key
            let mut shared_bytes = [0u8; 32];
            shared_bytes.copy_from_slice(shared_secret.as_bytes());
            let wrapping_key = derive::derive_wrapping_key(&shared_bytes, &recipient.key_id);
            shared_bytes.zeroize();

            // Wrap data key with AES-256-GCM-SIV
            let mut wrap_nonce_bytes = [0u8; 12];
            rng.fill_bytes(&mut wrap_nonce_bytes);

            let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrapping_key)
                .map_err(|e| RokError::EncryptionError(format!("AES-GCM-SIV init: {}", e)))?;

            let wrap_nonce = AesNonce::from_slice(&wrap_nonce_bytes);
            let wrapped_data_key = wrap_cipher
                .encrypt(wrap_nonce, data_key.as_ref())
                .map_err(|e| RokError::EncryptionError(format!("key wrap: {}", e)))?;

            access_entries.push(AccessEntry {
                read_key_id: recipient.key_id,
                wrapped_data_key,
                wrap_nonce: wrap_nonce_bytes,
            });
        }

        ephemeral_secret_bytes.zeroize();
        data_key.zeroize();

        // 5. Assemble envelope (without signature)
        let mut envelope = EncryptedEnvelope {
            version: EncryptedEnvelope::CURRENT_VERSION,
            algorithm: self.algorithm,
            scope: self.scope.clone(),
            ephemeral_x25519_public: *ephemeral_public.as_bytes(),
            ephemeral_mlkem_ciphertext: None,
            access_entries,
            nonce: nonce_bytes,
            ciphertext,
            tag,
            signature: [0u8; 64],
            spend_public_key: *spend_key.verifying_key().as_bytes(),
            access_mode,
        };

        // 6. Sign
        let signable = envelope.signable_bytes();
        let signature: Signature = spend_key.signing_key().sign(&signable);
        envelope.signature = signature.to_bytes();

        Ok(envelope)
    }
}

/// Decrypt an envelope using a read key (classical mode).
pub fn decrypt(
    envelope: &EncryptedEnvelope,
    read_key: &ReadKeyPair,
    spend_verifying_key: &VerifyingKey,
) -> Result<Vec<u8>> {
    // 1. Verify signature
    let signable = envelope.signable_bytes();
    let signature = Signature::from_bytes(&envelope.signature);
    spend_verifying_key
        .verify(&signable, &signature)
        .map_err(|_| RokError::SignatureVerificationFailed)?;

    // 2. Check scope access
    if !read_key.can_access(&envelope.scope) {
        return Err(RokError::ScopeMismatch {
            key_scope: read_key.scope().to_string(),
            data_scope: envelope.scope.to_string(),
        });
    }

    // 3. In scope-based mode, auto-derive to the envelope's scope if needed
    let derived: Option<ReadKeyPair>;
    let decrypt_key: &ReadKeyPair;
    if envelope.access_mode == AccessMode::ScopeBased && read_key.scope() != &envelope.scope {
        derived = Some(read_key.derive_child(&envelope.scope)?);
        decrypt_key = derived.as_ref().unwrap();
    } else {
        derived = None;
        decrypt_key = read_key;
    }

    // 4. Find matching access entry
    let my_key_id = decrypt_key.key_id();
    let entry = envelope
        .access_entries
        .iter()
        .find(|e| e.read_key_id == my_key_id)
        .ok_or_else(|| RokError::NoMatchingAccessEntry(my_key_id.to_string()))?;

    // 5. ECDH: shared = X25519(read_secret, ephemeral_public)
    let ephemeral_public = X25519PublicKey::from(envelope.ephemeral_x25519_public);
    let shared_secret = decrypt_key.secret().diffie_hellman(&ephemeral_public);

    let mut shared_bytes = [0u8; 32];
    shared_bytes.copy_from_slice(shared_secret.as_bytes());

    // 6. Derive wrapping key
    let wrapping_key = derive::derive_wrapping_key(&shared_bytes, &my_key_id);
    shared_bytes.zeroize();

    drop(derived);

    // 7. Unwrap data key
    let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrapping_key)
        .map_err(|e| RokError::DecryptionError(format!("AES-GCM-SIV init: {}", e)))?;

    let wrap_nonce = AesNonce::from_slice(&entry.wrap_nonce);
    let mut data_key = wrap_cipher
        .decrypt(wrap_nonce, entry.wrapped_data_key.as_ref())
        .map_err(|_| RokError::DecryptionError("failed to unwrap data key".into()))?;

    // 8. Decrypt ciphertext
    let cipher = ChaCha20Poly1305::new_from_slice(&data_key)
        .map_err(|e| RokError::DecryptionError(format!("ChaCha20 init: {}", e)))?;

    // Reconstruct the authenticated ciphertext (ciphertext + tag)
    let mut authenticated = Vec::with_capacity(envelope.ciphertext.len() + 16);
    authenticated.extend_from_slice(&envelope.ciphertext);
    authenticated.extend_from_slice(&envelope.tag);

    let nonce = ChaChaNonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, authenticated.as_ref())
        .map_err(|_| RokError::DecryptionError("ciphertext authentication failed".into()))?;

    data_key.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_keys() -> (SpendKeyPair, ReadKeyPair) {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root_read = spend.derive_root_read_key();
        (spend, root_read)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (spend, root_read) = setup_keys();
        let mut rng = rand::thread_rng();

        let plaintext = b"Hello, World! This is a secret message.";

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .set_spend_key(&spend)
            .encrypt(plaintext, &mut rng)
            .unwrap();

        let decrypted = decrypt(&envelope, &root_read, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_recipients() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root_read = spend.derive_root_read_key();
        let finance_read = root_read.derive_child_segment("finance").unwrap();
        let mut rng = rand::thread_rng();

        let plaintext = b"Quarterly financial report";

        let recipients = vec![
            Recipient {
                read_public_key: *root_read.public_key(),
                key_id: root_read.key_id(),
            },
            Recipient {
                read_public_key: *finance_read.public_key(),
                key_id: finance_read.key_id(),
            },
        ];

        let envelope = EncryptBuilder::new(
            Algorithm::EciesX25519ChaCha20,
            Scope::new("/finance").unwrap(),
        )
        .add_recipients(&recipients)
        .set_spend_key(&spend)
        .encrypt(plaintext, &mut rng)
        .unwrap();

        // Both should be able to decrypt
        let d1 = decrypt(&envelope, &root_read, &spend.verifying_key()).unwrap();
        assert_eq!(d1, plaintext);

        let d2 = decrypt(&envelope, &finance_read, &spend.verifying_key()).unwrap();
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root_read = spend.derive_root_read_key();
        let legal_read = root_read.derive_child_segment("legal").unwrap();
        let mut rng = rand::thread_rng();

        let finance_read = root_read.derive_child_segment("finance").unwrap();

        let recipient = Recipient {
            read_public_key: *finance_read.public_key(),
            key_id: finance_read.key_id(),
        };

        let envelope = EncryptBuilder::new(
            Algorithm::EciesX25519ChaCha20,
            Scope::new("/finance").unwrap(),
        )
        .add_recipient(recipient)
        .set_spend_key(&spend)
        .encrypt(b"secret", &mut rng)
        .unwrap();

        // Legal key should fail (scope mismatch)
        let result = decrypt(&envelope, &legal_read, &spend.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let (spend, root_read) = setup_keys();
        let mut rng = rand::thread_rng();

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let mut envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .set_spend_key(&spend)
            .encrypt(b"secret", &mut rng)
            .unwrap();

        // Tamper with ciphertext — this should fail signature verification
        // since the signable bytes include the ciphertext
        envelope.ciphertext[0] ^= 0xff;
        let result = decrypt(&envelope, &root_read, &spend.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_spend_key_fails() {
        let spend1 = SpendKeyPair::from_seed(&[1u8; 32]);
        let spend2 = SpendKeyPair::from_seed(&[2u8; 32]);
        let root_read = spend1.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .set_spend_key(&spend1)
            .encrypt(b"secret", &mut rng)
            .unwrap();

        // Verify with wrong spend key
        let result = decrypt(&envelope, &root_read, &spend2.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let (spend, root_read) = setup_keys();
        let mut rng = rand::thread_rng();

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .set_spend_key(&spend)
            .encrypt(b"", &mut rng)
            .unwrap();

        let decrypted = decrypt(&envelope, &root_read, &spend.verifying_key()).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext_roundtrip() {
        let (spend, root_read) = setup_keys();
        let mut rng = rand::thread_rng();

        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .set_spend_key(&spend)
            .encrypt(&plaintext, &mut rng)
            .unwrap();

        let decrypted = decrypt(&envelope, &root_read, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_no_recipients_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let mut rng = rand::thread_rng();

        let result = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .set_spend_key(&spend)
            .encrypt(b"secret", &mut rng);

        assert!(result.is_err());
    }

    #[test]
    fn test_no_spend_key_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root_read = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        let recipient = Recipient {
            read_public_key: *root_read.public_key(),
            key_id: root_read.key_id(),
        };

        let result = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .add_recipient(recipient)
            .encrypt(b"secret", &mut rng);

        assert!(result.is_err());
    }

    #[test]
    fn test_scope_hierarchy_access() {
        // Encrypt at /finance/q1, decrypt with /finance key (ancestor) should work
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let finance_q1 = finance.derive_child_segment("q1").unwrap();
        let mut rng = rand::thread_rng();

        // Encrypt for both finance and finance_q1 at scope /finance/q1
        let recipients = vec![
            Recipient {
                read_public_key: *finance.public_key(),
                key_id: finance.key_id(),
            },
            Recipient {
                read_public_key: *finance_q1.public_key(),
                key_id: finance_q1.key_id(),
            },
        ];

        let envelope = EncryptBuilder::new(
            Algorithm::EciesX25519ChaCha20,
            Scope::new("/finance/q1").unwrap(),
        )
        .add_recipients(&recipients)
        .set_spend_key(&spend)
        .encrypt(b"Q1 report", &mut rng)
        .unwrap();

        // Finance key (ancestor of /finance/q1) should decrypt
        let d1 = decrypt(&envelope, &finance, &spend.verifying_key()).unwrap();
        assert_eq!(d1, b"Q1 report");

        // Finance Q1 key (exact scope) should decrypt
        let d2 = decrypt(&envelope, &finance_q1, &spend.verifying_key()).unwrap();
        assert_eq!(d2, b"Q1 report");
    }

    #[test]
    fn test_scope_based_no_recipients_ok() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let mut rng = rand::thread_rng();

        // Scope-based mode with no explicit recipients should succeed
        let envelope = EncryptBuilder::new(
            Algorithm::EciesX25519ChaCha20,
            Scope::new("/finance").unwrap(),
        )
        .set_spend_key(&spend)
        .set_scope_based()
        .encrypt(b"scope-based test", &mut rng)
        .unwrap();

        assert_eq!(envelope.access_mode, AccessMode::ScopeBased);
        assert_eq!(envelope.access_entries.len(), 1);
    }

    #[test]
    fn test_scope_based_root_scope() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let mut rng = rand::thread_rng();

        // Scope-based at root scope
        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::root())
            .set_spend_key(&spend)
            .set_scope_based()
            .encrypt(b"root scope-based", &mut rng)
            .unwrap();

        assert_eq!(envelope.access_mode, AccessMode::ScopeBased);

        // Root key can decrypt directly
        let decrypted = decrypt(&envelope, &root, &spend.verifying_key()).unwrap();
        assert_eq!(decrypted, b"root scope-based");
    }
}
