use std::collections::HashMap;

use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient, decrypt};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::error::{RokError, Result};
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

/// Metadata about a document stored in the vault.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub name: String,
    pub scope: Scope,
    pub size: usize,
    pub recipient_count: usize,
}

/// An in-memory encrypted document vault with scope-based access control.
///
/// The vault holds encrypted documents (as `EncryptedEnvelope`s) organized by name.
/// Each document is associated with a scope, and only read keys with access to
/// that scope (or an ancestor) can decrypt it.
pub struct Vault {
    spend_key: SpendKeyPair,
    documents: HashMap<String, EncryptedEnvelope>,
}

impl Vault {
    /// Create a new vault with the given spend key.
    pub fn new(spend_key: SpendKeyPair) -> Self {
        Vault {
            spend_key,
            documents: HashMap::new(),
        }
    }

    /// Encrypt and store a document under a scope.
    ///
    /// The document is encrypted for all specified recipients.
    pub fn store(
        &mut self,
        name: &str,
        scope: &Scope,
        data: &[u8],
        recipients: &[Recipient],
    ) -> Result<()> {
        let mut rng = rand::thread_rng();

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope.clone())
            .add_recipients(recipients)
            .set_spend_key(&self.spend_key)
            .encrypt(data, &mut rng)?;

        self.documents.insert(name.to_string(), envelope);
        Ok(())
    }

    /// Decrypt and retrieve a document using a read key.
    pub fn retrieve(&self, name: &str, read_key: &ReadKeyPair) -> Result<Vec<u8>> {
        let envelope = self
            .documents
            .get(name)
            .ok_or_else(|| RokError::KeyNotFound(format!("document '{}' not found", name)))?;

        decrypt(envelope, read_key, &self.spend_key.verifying_key())
    }

    /// List all documents, optionally filtered by scope.
    pub fn list(&self, scope_filter: Option<&Scope>) -> Vec<VaultEntry> {
        self.documents
            .iter()
            .filter(|(_, env)| {
                if let Some(filter) = scope_filter {
                    filter.is_ancestor_of(&env.scope)
                } else {
                    true
                }
            })
            .map(|(name, env)| VaultEntry {
                name: name.clone(),
                scope: env.scope.clone(),
                size: env.ciphertext.len(),
                recipient_count: env.access_entries.len(),
            })
            .collect()
    }

    /// Re-encrypt all documents at a scope with new recipients.
    ///
    /// This is used for key rotation/revocation. All matching documents
    /// are decrypted with the spend key (via root read key) and re-encrypted.
    pub fn rekey(
        &mut self,
        scope: &Scope,
        root_read_key: &ReadKeyPair,
        new_recipients: &[Recipient],
    ) -> Result<usize> {
        let mut rng = rand::thread_rng();
        let vk = self.spend_key.verifying_key();

        let names_to_rekey: Vec<String> = self
            .documents
            .iter()
            .filter(|(_, env)| scope.is_ancestor_of(&env.scope))
            .map(|(name, _)| name.clone())
            .collect();

        let count = names_to_rekey.len();

        for name in names_to_rekey {
            let envelope = self.documents.get(&name).unwrap();
            let plaintext = decrypt(envelope, root_read_key, &vk)?;

            let new_envelope = EncryptBuilder::new(
                Algorithm::EciesX25519ChaCha20,
                envelope.scope.clone(),
            )
            .add_recipients(new_recipients)
            .set_spend_key(&self.spend_key)
            .encrypt(&plaintext, &mut rng)?;

            self.documents.insert(name, new_envelope);
        }

        Ok(count)
    }

    /// Number of documents in the vault.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the vault is empty.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// The spend key's verifying (public) key.
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.spend_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SpendKeyPair, ReadKeyPair, ReadKeyPair, ReadKeyPair) {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let legal = root.derive_child_segment("legal").unwrap();
        (spend, root, finance, legal)
    }

    #[test]
    fn test_store_and_retrieve() {
        let (spend, root, finance, _) = setup();
        let mut vault = Vault::new(SpendKeyPair::from_seed(&[42u8; 32]));

        let recipients = vec![Recipient {
            read_public_key: *finance.public_key(),
            key_id: finance.key_id(),
        }];

        vault
            .store("report.pdf", &Scope::new("/finance").unwrap(), b"secret data", &recipients)
            .unwrap();

        let data = vault.retrieve("report.pdf", &finance).unwrap();
        assert_eq!(data, b"secret data");
    }

    #[test]
    fn test_wrong_scope_key_fails() {
        let (spend, _, finance, legal) = setup();
        let mut vault = Vault::new(SpendKeyPair::from_seed(&[42u8; 32]));

        let recipients = vec![Recipient {
            read_public_key: *finance.public_key(),
            key_id: finance.key_id(),
        }];

        vault
            .store("report.pdf", &Scope::new("/finance").unwrap(), b"secret", &recipients)
            .unwrap();

        // Legal key should not be able to decrypt finance document
        assert!(vault.retrieve("report.pdf", &legal).is_err());
    }

    #[test]
    fn test_list_documents() {
        let (spend, root, finance, legal) = setup();
        let mut vault = Vault::new(SpendKeyPair::from_seed(&[42u8; 32]));

        let fin_recipients = vec![Recipient {
            read_public_key: *finance.public_key(),
            key_id: finance.key_id(),
        }];
        let legal_recipients = vec![Recipient {
            read_public_key: *legal.public_key(),
            key_id: legal.key_id(),
        }];

        vault
            .store("fin.pdf", &Scope::new("/finance").unwrap(), b"data1", &fin_recipients)
            .unwrap();
        vault
            .store("contract.pdf", &Scope::new("/legal").unwrap(), b"data2", &legal_recipients)
            .unwrap();

        // All documents
        assert_eq!(vault.list(None).len(), 2);

        // Only finance
        let fin_scope = Scope::new("/finance").unwrap();
        let fin_docs = vault.list(Some(&fin_scope));
        assert_eq!(fin_docs.len(), 1);
        assert_eq!(fin_docs[0].name, "fin.pdf");
    }

    #[test]
    fn test_rekey() {
        let (_, root, finance, legal) = setup();
        let mut vault = Vault::new(SpendKeyPair::from_seed(&[42u8; 32]));

        // Store with finance key
        let recipients = vec![
            Recipient {
                read_public_key: *root.public_key(),
                key_id: root.key_id(),
            },
            Recipient {
                read_public_key: *finance.public_key(),
                key_id: finance.key_id(),
            },
        ];

        vault
            .store("report.pdf", &Scope::new("/finance").unwrap(), b"secret data", &recipients)
            .unwrap();

        // Rekey: remove finance, add legal
        let new_recipients = vec![
            Recipient {
                read_public_key: *root.public_key(),
                key_id: root.key_id(),
            },
            Recipient {
                read_public_key: *legal.public_key(),
                key_id: legal.key_id(),
            },
        ];

        let count = vault
            .rekey(&Scope::new("/finance").unwrap(), &root, &new_recipients)
            .unwrap();
        assert_eq!(count, 1);

        // Finance key should no longer work
        assert!(vault.retrieve("report.pdf", &finance).is_err());

        // Root and legal should work
        let data = vault.retrieve("report.pdf", &root).unwrap();
        assert_eq!(data, b"secret data");
    }
}
