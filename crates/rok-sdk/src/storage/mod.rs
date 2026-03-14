use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rok_core::error::{Result, RokError};

#[cfg(feature = "fileverse")]
pub mod fileverse;

/// Unique identifier for a stored item (backend-specific).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageId(pub String);

/// A single entry in the storage backend.
#[derive(Debug, Clone)]
pub struct StorageEntry {
    pub id: StorageId,
    /// Scope path, e.g. "/finance/q1"
    pub scope: String,
    /// Logical name, e.g. "2024-q1-report"
    pub key: String,
    /// Raw EncryptedEnvelope bytes
    pub data: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Backend trait for persistent encrypted memory storage.
///
/// Implementations store opaque ciphertext bytes (rok `EncryptedEnvelope`s).
/// The backend never sees plaintext or scope structure — it just stores blobs.
pub trait StorageBackend: Send + Sync {
    /// Store data at a scope/key, returning the backend-assigned ID.
    fn put(&self, scope: &str, key: &str, data: &[u8]) -> Result<StorageId>;

    /// Retrieve an entry by its storage ID.
    fn get(&self, id: &StorageId) -> Result<StorageEntry>;

    /// Retrieve an entry by scope + key.
    fn get_by_key(&self, scope: &str, key: &str) -> Result<StorageEntry>;

    /// List all entries whose scope starts with `scope_prefix`.
    fn list(&self, scope_prefix: &str) -> Result<Vec<StorageEntry>>;

    /// Delete an entry by its storage ID.
    fn delete(&self, id: &StorageId) -> Result<()>;
}

/// In-memory storage backend for testing and development.
pub struct MemoryStorage {
    entries: Mutex<HashMap<String, StorageEntry>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn composite_key(scope: &str, key: &str) -> String {
        format!("{}/{}", scope, key)
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryStorage {
    fn put(&self, scope: &str, key: &str, data: &[u8]) -> Result<StorageId> {
        let composite = Self::composite_key(scope, key);
        let id = StorageId(composite.clone());
        let now = now_unix();

        let mut entries = self.entries.lock().map_err(|e| {
            RokError::StorageError(format!("lock poisoned: {}", e))
        })?;

        let (created_at, updated_at) = if let Some(existing) = entries.get(&composite) {
            (existing.created_at, now)
        } else {
            (now, now)
        };

        entries.insert(
            composite,
            StorageEntry {
                id: id.clone(),
                scope: scope.to_string(),
                key: key.to_string(),
                data: data.to_vec(),
                created_at,
                updated_at,
            },
        );

        Ok(id)
    }

    fn get(&self, id: &StorageId) -> Result<StorageEntry> {
        let entries = self.entries.lock().map_err(|e| {
            RokError::StorageError(format!("lock poisoned: {}", e))
        })?;

        entries
            .get(&id.0)
            .cloned()
            .ok_or_else(|| RokError::StorageError(format!("entry not found: {}", id.0)))
    }

    fn get_by_key(&self, scope: &str, key: &str) -> Result<StorageEntry> {
        let composite = Self::composite_key(scope, key);
        self.get(&StorageId(composite))
    }

    fn list(&self, scope_prefix: &str) -> Result<Vec<StorageEntry>> {
        let entries = self.entries.lock().map_err(|e| {
            RokError::StorageError(format!("lock poisoned: {}", e))
        })?;

        let results: Vec<StorageEntry> = entries
            .values()
            .filter(|entry| {
                entry.scope == scope_prefix
                    || entry.scope.starts_with(&format!("{}/", scope_prefix))
                    // Root scope "/" is ancestor of everything
                    || scope_prefix == "/"
            })
            .cloned()
            .collect();

        Ok(results)
    }

    fn delete(&self, id: &StorageId) -> Result<()> {
        let mut entries = self.entries.lock().map_err(|e| {
            RokError::StorageError(format!("lock poisoned: {}", e))
        })?;

        entries
            .remove(&id.0)
            .map(|_| ())
            .ok_or_else(|| RokError::StorageError(format!("entry not found: {}", id.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_and_get() {
        let storage = MemoryStorage::new();
        let id = storage.put("/finance", "report", b"encrypted-data").unwrap();
        let entry = storage.get(&id).unwrap();
        assert_eq!(entry.scope, "/finance");
        assert_eq!(entry.key, "report");
        assert_eq!(entry.data, b"encrypted-data");
    }

    #[test]
    fn test_get_by_key() {
        let storage = MemoryStorage::new();
        storage.put("/finance", "report", b"data1").unwrap();
        let entry = storage.get_by_key("/finance", "report").unwrap();
        assert_eq!(entry.data, b"data1");
    }

    #[test]
    fn test_put_overwrites() {
        let storage = MemoryStorage::new();
        storage.put("/finance", "report", b"v1").unwrap();
        storage.put("/finance", "report", b"v2").unwrap();
        let entry = storage.get_by_key("/finance", "report").unwrap();
        assert_eq!(entry.data, b"v2");
    }

    #[test]
    fn test_list_by_scope_prefix() {
        let storage = MemoryStorage::new();
        storage.put("/finance", "report", b"d1").unwrap();
        storage.put("/finance/q1", "summary", b"d2").unwrap();
        storage.put("/engineering", "roadmap", b"d3").unwrap();

        let finance = storage.list("/finance").unwrap();
        assert_eq!(finance.len(), 2);

        let eng = storage.list("/engineering").unwrap();
        assert_eq!(eng.len(), 1);

        let all = storage.list("/").unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_delete() {
        let storage = MemoryStorage::new();
        let id = storage.put("/finance", "report", b"data").unwrap();
        storage.delete(&id).unwrap();
        assert!(storage.get(&id).is_err());
    }

    #[test]
    fn test_get_nonexistent() {
        let storage = MemoryStorage::new();
        assert!(storage.get(&StorageId("nope".to_string())).is_err());
    }

    #[test]
    fn test_delete_nonexistent() {
        let storage = MemoryStorage::new();
        assert!(storage.delete(&StorageId("nope".to_string())).is_err());
    }
}
