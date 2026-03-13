use std::collections::HashMap;

use rok_core::error::{RokError, Result};
use rok_core::keys::key_id::KeyId;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::spend::SpendKeyPair;
use rok_core::keyring::{KeyStore, ReadKeyInfo};

/// In-memory keyring for key management.
///
/// Stores spend keys and read keys in memory. For production use,
/// keys should be encrypted at rest (e.g., with Argon2id-derived master key).
/// This implementation provides the foundation for persistent storage.
pub struct MemoryKeyring {
    spend_keys: HashMap<String, SpendKeySeed>,
    read_keys: HashMap<[u8; 8], ReadKeyEntry>,
}

struct SpendKeySeed {
    seed: [u8; 32],
}

struct ReadKeyEntry {
    exported: rok_core::keys::read::ExportedReadKey,
    info: ReadKeyInfo,
}

impl MemoryKeyring {
    /// Create a new empty keyring.
    pub fn new() -> Self {
        MemoryKeyring {
            spend_keys: HashMap::new(),
            read_keys: HashMap::new(),
        }
    }
}

impl Default for MemoryKeyring {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemoryKeyring {
    fn store_spend_key(&mut self, label: &str, key: &SpendKeyPair) -> Result<()> {
        self.spend_keys.insert(
            label.to_string(),
            SpendKeySeed { seed: key.seed() },
        );
        Ok(())
    }

    fn load_spend_key(&self, label: &str) -> Result<SpendKeyPair> {
        let entry = self
            .spend_keys
            .get(label)
            .ok_or_else(|| RokError::KeyNotFound(label.to_string()))?;
        Ok(SpendKeyPair::from_seed(&entry.seed))
    }

    fn store_read_key(&mut self, key: &ReadKeyPair) -> Result<()> {
        let key_id = key.key_id();
        let exported = key.export();
        let info = ReadKeyInfo {
            key_id,
            scope: key.scope().clone(),
            parent_key_id: key.parent_key_id().copied(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            revoked: false,
            label: None,
        };
        self.read_keys.insert(*key_id.as_bytes(), ReadKeyEntry { exported, info });
        Ok(())
    }

    fn load_read_key(&self, key_id: &KeyId) -> Result<ReadKeyPair> {
        let entry = self
            .read_keys
            .get(key_id.as_bytes())
            .ok_or_else(|| RokError::KeyNotFound(key_id.to_string()))?;
        if entry.info.revoked {
            return Err(RokError::KeyRevoked(key_id.to_string()));
        }
        ReadKeyPair::import(&entry.exported)
    }

    fn list_read_keys(&self) -> Result<Vec<ReadKeyInfo>> {
        Ok(self.read_keys.values().map(|e| e.info.clone()).collect())
    }

    fn revoke_key(&mut self, key_id: &KeyId) -> Result<()> {
        let entry = self
            .read_keys
            .get_mut(key_id.as_bytes())
            .ok_or_else(|| RokError::KeyNotFound(key_id.to_string()))?;
        entry.info.revoked = true;
        Ok(())
    }

    fn is_revoked(&self, key_id: &KeyId) -> Result<bool> {
        let entry = self
            .read_keys
            .get(key_id.as_bytes())
            .ok_or_else(|| RokError::KeyNotFound(key_id.to_string()))?;
        Ok(entry.info.revoked)
    }

    fn delete_key(&mut self, key_id: &KeyId) -> Result<()> {
        self.read_keys
            .remove(key_id.as_bytes())
            .ok_or_else(|| RokError::KeyNotFound(key_id.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_key_store_load() {
        let mut kr = MemoryKeyring::new();
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        kr.store_spend_key("main", &spend).unwrap();

        let loaded = kr.load_spend_key("main").unwrap();
        assert_eq!(spend.verifying_key(), loaded.verifying_key());
    }

    #[test]
    fn test_read_key_store_load() {
        let mut kr = MemoryKeyring::new();
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        kr.store_read_key(&finance).unwrap();
        let loaded = kr.load_read_key(&finance.key_id()).unwrap();
        assert_eq!(finance.key_id(), loaded.key_id());
        assert_eq!(finance.scope(), loaded.scope());
    }

    #[test]
    fn test_list_read_keys() {
        let mut kr = MemoryKeyring::new();
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let legal = root.derive_child_segment("legal").unwrap();

        kr.store_read_key(&finance).unwrap();
        kr.store_read_key(&legal).unwrap();

        let keys = kr.list_read_keys().unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_revoke_key() {
        let mut kr = MemoryKeyring::new();
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        kr.store_read_key(&finance).unwrap();
        assert!(!kr.is_revoked(&finance.key_id()).unwrap());

        kr.revoke_key(&finance.key_id()).unwrap();
        assert!(kr.is_revoked(&finance.key_id()).unwrap());

        // Loading a revoked key should fail
        assert!(kr.load_read_key(&finance.key_id()).is_err());
    }

    #[test]
    fn test_delete_key() {
        let mut kr = MemoryKeyring::new();
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();

        kr.store_read_key(&finance).unwrap();
        kr.delete_key(&finance.key_id()).unwrap();
        assert!(kr.load_read_key(&finance.key_id()).is_err());
    }

    #[test]
    fn test_key_not_found() {
        let kr = MemoryKeyring::new();
        let fake_id = KeyId::from_bytes([0; 8]);
        assert!(kr.load_read_key(&fake_id).is_err());
    }
}
