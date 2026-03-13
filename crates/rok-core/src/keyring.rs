use crate::error::Result;
use crate::keys::key_id::KeyId;
use crate::keys::read::ReadKeyPair;
use crate::keys::scope::Scope;
use crate::keys::spend::SpendKeyPair;

/// Trait for key storage backends.
///
/// Implementations handle persistence and encryption-at-rest
/// of key material. The SDK provides a file-based implementation.
pub trait KeyStore {
    /// Store a spend key pair (should be encrypted at rest).
    fn store_spend_key(&mut self, label: &str, key: &SpendKeyPair) -> Result<()>;

    /// Retrieve a spend key pair by label.
    fn load_spend_key(&self, label: &str) -> Result<SpendKeyPair>;

    /// Store a read key pair.
    fn store_read_key(&mut self, key: &ReadKeyPair) -> Result<()>;

    /// Retrieve a read key pair by KeyId.
    fn load_read_key(&self, key_id: &KeyId) -> Result<ReadKeyPair>;

    /// List all stored read keys (metadata only, no secrets).
    fn list_read_keys(&self) -> Result<Vec<ReadKeyInfo>>;

    /// Mark a key as revoked.
    fn revoke_key(&mut self, key_id: &KeyId) -> Result<()>;

    /// Check if a key is revoked.
    fn is_revoked(&self, key_id: &KeyId) -> Result<bool>;

    /// Delete a key from storage.
    fn delete_key(&mut self, key_id: &KeyId) -> Result<()>;
}

/// Metadata about a stored read key (no secrets).
#[derive(Debug, Clone)]
pub struct ReadKeyInfo {
    pub key_id: KeyId,
    pub scope: Scope,
    pub parent_key_id: Option<KeyId>,
    pub created_at: u64,
    pub revoked: bool,
    pub label: Option<String>,
}
