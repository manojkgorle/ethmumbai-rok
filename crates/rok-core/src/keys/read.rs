use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::derive;
use crate::error::{Result, RokError};
use crate::keys::key_id::KeyId;
use crate::keys::scope::Scope;

/// A read key pair for viewing encrypted data at a specific scope.
///
/// Uses X25519 for ECDH key agreement. Each read key is bound to a scope
/// and can only decrypt data at that scope or descendant scopes.
///
/// Read keys can be delegated: a parent read key holder can derive
/// child read keys at narrower scopes without involving the spend key.
pub struct ReadKeyPair {
    secret: StaticSecret,
    public: PublicKey,
    scope: Scope,
    parent_key_id: Option<KeyId>,
}

impl Drop for ReadKeyPair {
    fn drop(&mut self) {
        // StaticSecret zeroizes on drop in x25519-dalek 2.x
    }
}

impl ReadKeyPair {
    /// Create from raw secret bytes, scope, and optional parent key ID.
    /// Used internally by derivation functions.
    pub(crate) fn from_secret_bytes(
        mut secret_bytes: [u8; 32],
        scope: Scope,
        parent_key_id: Option<KeyId>,
    ) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        secret_bytes.zeroize();

        ReadKeyPair {
            secret,
            public,
            scope,
            parent_key_id,
        }
    }

    /// The X25519 public key (shared with encryptors).
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The scope this key grants access to.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// The key ID of the parent read key (None for root).
    pub fn parent_key_id(&self) -> Option<&KeyId> {
        self.parent_key_id.as_ref()
    }

    /// Compute the KeyId for this read key.
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_bytes(self.public.as_bytes())
    }

    /// Can this key access the given target scope?
    ///
    /// A read key can access its own scope and any descendant scope.
    pub fn can_access(&self, target_scope: &Scope) -> bool {
        self.scope.is_ancestor_of(target_scope)
    }

    /// Derive a child read key at a sub-scope.
    ///
    /// The child scope must be a descendant of this key's scope.
    pub fn derive_child(&self, child_scope: &Scope) -> Result<ReadKeyPair> {
        if !self.scope.is_ancestor_of(child_scope) || &self.scope == child_scope {
            return Err(RokError::DerivationError(format!(
                "'{}' is not a proper descendant of '{}'",
                child_scope, self.scope
            )));
        }

        let parent_key_id = self.key_id();
        let secret_bytes = self.secret_bytes();
        let child_secret =
            derive::derive_child_read_secret(&secret_bytes, &self.scope, child_scope)?;

        Ok(ReadKeyPair::from_secret_bytes(
            child_secret,
            child_scope.clone(),
            Some(parent_key_id),
        ))
    }

    /// Derive a child for a single path segment (convenience).
    pub fn derive_child_segment(&self, segment: &str) -> Result<ReadKeyPair> {
        let child_scope = self.scope.child(segment)?;
        self.derive_child(&child_scope)
    }

    /// Reference to the X25519 static secret (for ECDH).
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Export the secret bytes for this key. Handle with care.
    pub fn secret_bytes(&self) -> [u8; 32] {
        // x25519-dalek StaticSecret stores clamped bytes.
        // We need to extract them for HKDF derivation.
        // StaticSecret's to_bytes() returns the internal representation.
        self.secret.to_bytes()
    }

    /// Export the read key for delegation.
    pub fn export(&self) -> ExportedReadKey {
        ExportedReadKey {
            secret_bytes: self.secret_bytes(),
            public_bytes: *self.public.as_bytes(),
            scope: self.scope.clone(),
            parent_key_id: self.parent_key_id,
        }
    }

    /// Import a previously exported read key.
    pub fn import(exported: &ExportedReadKey) -> Result<Self> {
        let secret = StaticSecret::from(exported.secret_bytes);
        let public = PublicKey::from(&secret);

        // Verify the public key matches
        if public.as_bytes() != &exported.public_bytes {
            return Err(RokError::InvalidKeyMaterial);
        }

        Ok(ReadKeyPair {
            secret,
            public,
            scope: exported.scope.clone(),
            parent_key_id: exported.parent_key_id,
        })
    }
}

/// A read key stripped to what is needed for delegation/serialization.
pub struct ExportedReadKey {
    pub secret_bytes: [u8; 32],
    pub public_bytes: [u8; 32],
    pub scope: Scope,
    pub parent_key_id: Option<KeyId>,
}

impl Drop for ExportedReadKey {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::spend::SpendKeyPair;

    #[test]
    fn test_derive_child() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();

        let finance = root.derive_child_segment("finance").unwrap();
        assert_eq!(finance.scope().as_str(), "/finance");
        assert_eq!(finance.parent_key_id(), Some(&root.key_id()));
    }

    #[test]
    fn test_derive_grandchild() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let q1 = finance.derive_child_segment("q1").unwrap();

        assert_eq!(q1.scope().as_str(), "/finance/q1");
        assert_eq!(q1.parent_key_id(), Some(&finance.key_id()));
    }

    #[test]
    fn test_can_access() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        let finance_scope = Scope::new("/finance").unwrap();
        let finance_q1 = Scope::new("/finance/q1").unwrap();
        let legal = Scope::new("/legal").unwrap();
        let root_scope = Scope::root();

        // Root can access everything
        assert!(root.can_access(&root_scope));
        assert!(root.can_access(&finance_scope));
        assert!(root.can_access(&finance_q1));
        assert!(root.can_access(&legal));

        // Finance can access /finance and descendants
        assert!(finance.can_access(&finance_scope));
        assert!(finance.can_access(&finance_q1));
        assert!(!finance.can_access(&root_scope));
        assert!(!finance.can_access(&legal));
    }

    #[test]
    fn test_derive_non_descendant_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        let legal = Scope::new("/legal").unwrap();
        assert!(finance.derive_child(&legal).is_err());
    }

    #[test]
    fn test_derive_same_scope_fails() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        assert!(root.derive_child(&Scope::root()).is_err());
    }

    #[test]
    fn test_export_import_roundtrip() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        let exported = finance.export();
        let imported = ReadKeyPair::import(&exported).unwrap();

        assert_eq!(finance.key_id(), imported.key_id());
        assert_eq!(finance.scope(), imported.scope());
        assert_eq!(finance.public_key(), imported.public_key());
    }

    #[test]
    fn test_derived_keys_are_deterministic() {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);

        let root1 = spend.derive_root_read_key();
        let finance1 = root1.derive_child_segment("finance").unwrap();

        let root2 = spend.derive_root_read_key();
        let finance2 = root2.derive_child_segment("finance").unwrap();

        assert_eq!(finance1.key_id(), finance2.key_id());
        assert_eq!(finance1.public_key(), finance2.public_key());
    }

    #[test]
    fn test_multi_step_equals_direct() {
        // Deriving /a/b/c directly from root should equal step-by-step
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();

        let abc_direct = root.derive_child(&Scope::new("/a/b/c").unwrap()).unwrap();

        let a = root.derive_child_segment("a").unwrap();
        let ab = a.derive_child_segment("b").unwrap();
        let abc_stepwise = ab.derive_child_segment("c").unwrap();

        assert_eq!(abc_direct.key_id(), abc_stepwise.key_id());
        assert_eq!(abc_direct.public_key(), abc_stepwise.public_key());
    }
}
