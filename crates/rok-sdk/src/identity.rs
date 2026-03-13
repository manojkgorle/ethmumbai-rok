use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient, decrypt};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::error::{RokError, Result};
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

/// An encrypted attribute within a credential.
#[derive(Debug, Clone)]
pub struct EncryptedAttribute {
    pub name: String,
    pub scope: Scope,
    pub envelope: EncryptedEnvelope,
}

/// A credential with individually-encrypted attributes.
///
/// Each attribute is encrypted under its own scope, enabling selective
/// disclosure: a verifier with a read key for `/identity/name` can see
/// the name but not `/identity/dob` (date of birth).
pub struct Credential {
    pub issuer_verifying_key: ed25519_dalek::VerifyingKey,
    pub subject_id: String,
    pub attributes: Vec<EncryptedAttribute>,
}

impl Credential {
    /// Issue a credential: encrypt each attribute under its own scope.
    ///
    /// Each attribute gets its own scope (e.g., `/identity/name`, `/identity/dob`).
    /// All specified recipients can decrypt all attributes they have scope access to.
    pub fn issue(
        spend_key: &SpendKeyPair,
        subject_id: &str,
        attributes: &[(&str, &Scope, &[u8])],
        recipients: &[Recipient],
    ) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut encrypted_attrs = Vec::with_capacity(attributes.len());

        for (name, scope, value) in attributes {
            let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, (*scope).clone())
                .add_recipients(recipients)
                .set_spend_key(spend_key)
                .encrypt(value, &mut rng)?;

            encrypted_attrs.push(EncryptedAttribute {
                name: name.to_string(),
                scope: (*scope).clone(),
                envelope,
            });
        }

        Ok(Credential {
            issuer_verifying_key: spend_key.verifying_key(),
            subject_id: subject_id.to_string(),
            attributes: encrypted_attrs,
        })
    }

    /// Selective disclosure: decrypt only the attributes the read key can access.
    ///
    /// Returns a list of (attribute_name, plaintext_value) pairs for attributes
    /// the key has scope access to. Attributes outside the key's scope are silently skipped.
    pub fn disclose(
        &self,
        read_key: &ReadKeyPair,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut disclosed = Vec::new();

        for attr in &self.attributes {
            // Check if the read key has scope access
            if !read_key.can_access(&attr.scope) {
                continue;
            }

            // Try to decrypt
            match decrypt(&attr.envelope, read_key, &self.issuer_verifying_key) {
                Ok(plaintext) => {
                    disclosed.push((attr.name.clone(), plaintext));
                }
                Err(RokError::NoMatchingAccessEntry(_)) => {
                    // Key has scope access but wasn't in the recipient list
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(disclosed)
    }

    /// Number of attributes in the credential.
    pub fn attribute_count(&self) -> usize {
        self.attributes.len()
    }

    /// List attribute names and their scopes (without decrypting).
    pub fn attribute_names(&self) -> Vec<(&str, &Scope)> {
        self.attributes
            .iter()
            .map(|a| (a.name.as_str(), &a.scope))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rok_core::keys::key_id::KeyId;

    #[test]
    fn test_issue_and_full_disclosure() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();

        let recipients = vec![Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        }];

        let name_scope = Scope::new("/identity/name").unwrap();
        let dob_scope = Scope::new("/identity/dob").unwrap();

        let cred = Credential::issue(
            &spend,
            "user-123",
            &[
                ("name", &name_scope, b"Alice Smith"),
                ("dob", &dob_scope, b"1990-01-15"),
            ],
            &recipients,
        )
        .unwrap();

        assert_eq!(cred.attribute_count(), 2);

        // Root key can see everything
        let disclosed = cred.disclose(&root).unwrap();
        assert_eq!(disclosed.len(), 2);
    }

    #[test]
    fn test_selective_disclosure() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let identity = root.derive_child_segment("identity").unwrap();
        let name_key = identity.derive_child_segment("name").unwrap();

        // Issue credential with name_key as recipient for name, root for all
        let recipients = vec![
            Recipient {
                read_public_key: *root.public_key(),
                key_id: root.key_id(),
            },
            Recipient {
                read_public_key: *name_key.public_key(),
                key_id: name_key.key_id(),
            },
        ];

        let name_scope = Scope::new("/identity/name").unwrap();
        let dob_scope = Scope::new("/identity/dob").unwrap();

        let cred = Credential::issue(
            &spend,
            "user-123",
            &[
                ("name", &name_scope, b"Alice Smith"),
                ("dob", &dob_scope, b"1990-01-15"),
            ],
            &recipients,
        )
        .unwrap();

        // name_key can only see name (scope /identity/name), not dob
        let disclosed = cred.disclose(&name_key).unwrap();
        assert_eq!(disclosed.len(), 1);
        assert_eq!(disclosed[0].0, "name");
        assert_eq!(disclosed[0].1, b"Alice Smith");
    }

    #[test]
    fn test_attribute_names() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();

        let recipients = vec![Recipient {
            read_public_key: *root.public_key(),
            key_id: root.key_id(),
        }];

        let name_scope = Scope::new("/identity/name").unwrap();
        let dob_scope = Scope::new("/identity/dob").unwrap();

        let cred = Credential::issue(
            &spend,
            "user-123",
            &[
                ("name", &name_scope, b"Alice"),
                ("dob", &dob_scope, b"1990"),
            ],
            &recipients,
        )
        .unwrap();

        let names = cred.attribute_names();
        assert_eq!(names.len(), 2);
        assert!(names.iter().any(|(n, _)| *n == "name"));
        assert!(names.iter().any(|(n, _)| *n == "dob"));
    }
}
