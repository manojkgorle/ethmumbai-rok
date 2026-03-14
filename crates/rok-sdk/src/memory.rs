use rok_core::encrypt::{decrypt, Algorithm, EncryptBuilder};
use rok_core::envelope::EncryptedEnvelope;
use rok_core::error::{Result, RokError};
use rok_core::keys::read::{ExportedReadKey, ReadKeyPair};
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;

use crate::storage::{StorageBackend, StorageId};

/// Metadata about a decrypted memory entry.
#[derive(Debug)]
pub struct MemoryEntry {
    pub scope: Scope,
    pub key: String,
    pub data: Vec<u8>,
}

/// A memory proposed by an agent (plaintext, needs user approval + encryption).
#[derive(Debug)]
pub struct Proposal {
    pub scope: Scope,
    pub key: String,
    pub plaintext: Vec<u8>,
    pub proposed_by: String,
}

/// High-level encrypted memory store backed by a pluggable `StorageBackend`.
///
/// The owner (with spend key) encrypts/stores memories.
/// Agents (with scoped read keys) can read memories at their scope and propose new ones.
pub struct MemoryStore<B: StorageBackend> {
    spend_key: SpendKeyPair,
    backend: B,
}

impl<B: StorageBackend> MemoryStore<B> {
    pub fn new(spend_key: SpendKeyPair, backend: B) -> Self {
        MemoryStore { spend_key, backend }
    }

    /// Encrypt and store a memory at a scope using scope-based encryption.
    ///
    /// Only the spend key holder can call this. The memory is encrypted so that
    /// any read key at the scope (or an ancestor) can decrypt it.
    pub fn write(&self, scope: &Scope, key: &str, content: &[u8]) -> Result<StorageId> {
        let mut rng = rand::thread_rng();

        let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, scope.clone())
            .set_spend_key(&self.spend_key)
            .set_scope_based()
            .encrypt(content, &mut rng)?;

        let envelope_bytes = envelope.to_bytes();
        self.backend.put(scope.as_str(), key, &envelope_bytes)
    }

    /// Read and decrypt a memory using a scoped read key.
    ///
    /// The read key must have access to the memory's scope (same scope or ancestor).
    pub fn read(&self, read_key: &ReadKeyPair, scope: &Scope, key: &str) -> Result<Vec<u8>> {
        let entry = self.backend.get_by_key(scope.as_str(), key)?;
        let envelope = EncryptedEnvelope::from_bytes(&entry.data)?;
        decrypt(&envelope, read_key, &self.spend_key.verifying_key())
    }

    /// List and decrypt all memories visible to a read key (scope + descendants).
    pub fn list(&self, read_key: &ReadKeyPair) -> Result<Vec<MemoryEntry>> {
        let scope = read_key.scope();
        let entries = self.backend.list(scope.as_str())?;
        let vk = self.spend_key.verifying_key();

        let mut memories = Vec::new();
        for entry in entries {
            let envelope = EncryptedEnvelope::from_bytes(&entry.data)?;
            match decrypt(&envelope, read_key, &vk) {
                Ok(data) => {
                    let entry_scope = Scope::new(&entry.scope)
                        .map_err(|e| RokError::StorageError(format!("bad scope in storage: {}", e)))?;
                    memories.push(MemoryEntry {
                        scope: entry_scope,
                        key: entry.key,
                        data,
                    });
                }
                Err(_) => {
                    // Skip entries we can't decrypt (shouldn't happen if storage is consistent)
                    continue;
                }
            }
        }

        Ok(memories)
    }

    /// Accept a proposed memory from an agent, encrypt and store it.
    ///
    /// The user reviews the proposal (plaintext) and decides to accept it.
    /// The spend key encrypts it at the proposed scope.
    pub fn accept_proposal(&self, proposal: &Proposal) -> Result<StorageId> {
        self.write(&proposal.scope, &proposal.key, &proposal.plaintext)
    }

    /// Export a scoped read key for delegation to an agent.
    ///
    /// The agent receives this key and can decrypt memories at the given scope
    /// and any descendant scopes.
    pub fn grant_access(&self, scope: &Scope) -> Result<ExportedReadKey> {
        let root = self.spend_key.derive_root_read_key();
        if scope == &Scope::root() {
            return Ok(root.export());
        }
        let scoped_key = root.derive_child(scope)?;
        Ok(scoped_key.export())
    }

    /// Reference to the underlying storage backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

/// Read-only view into the memory store for agents.
///
/// Agents receive a scoped read key and the spend public key (for signature
/// verification). They can list and decrypt memories but cannot write.
pub struct MemoryReader<B: StorageBackend> {
    spend_vk: ed25519_dalek::VerifyingKey,
    backend: B,
}

impl<B: StorageBackend> MemoryReader<B> {
    pub fn new(spend_vk: ed25519_dalek::VerifyingKey, backend: B) -> Self {
        MemoryReader { spend_vk, backend }
    }

    /// Read and decrypt a memory using a scoped read key.
    pub fn read(&self, read_key: &ReadKeyPair, scope: &Scope, key: &str) -> Result<Vec<u8>> {
        let entry = self.backend.get_by_key(scope.as_str(), key)?;
        let envelope = EncryptedEnvelope::from_bytes(&entry.data)?;
        decrypt(&envelope, read_key, &self.spend_vk)
    }

    /// List and decrypt all memories visible to a read key (scope + descendants).
    pub fn list(&self, read_key: &ReadKeyPair) -> Result<Vec<MemoryEntry>> {
        let scope = read_key.scope();
        let entries = self.backend.list(scope.as_str())?;

        let mut memories = Vec::new();
        for entry in entries {
            let envelope = EncryptedEnvelope::from_bytes(&entry.data)?;
            match decrypt(&envelope, read_key, &self.spend_vk) {
                Ok(data) => {
                    let entry_scope = Scope::new(&entry.scope)
                        .map_err(|e| RokError::StorageError(format!("bad scope in storage: {}", e)))?;
                    memories.push(MemoryEntry {
                        scope: entry_scope,
                        key: entry.key,
                        data,
                    });
                }
                Err(_) => continue,
            }
        }

        Ok(memories)
    }

    /// Reference to the underlying storage backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn setup() -> (MemoryStore<MemoryStorage>, ReadKeyPair, ReadKeyPair, ReadKeyPair) {
        let spend = SpendKeyPair::from_seed(&[42u8; 32]);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let engineering = root.derive_child_segment("engineering").unwrap();
        let store = MemoryStore::new(
            SpendKeyPair::from_seed(&[42u8; 32]),
            MemoryStorage::new(),
        );
        (store, root, finance, engineering)
    }

    #[test]
    fn test_write_and_read() {
        let (store, _root, finance, _) = setup();
        let scope = Scope::new("/finance").unwrap();

        store.write(&scope, "report", b"Q1 numbers").unwrap();
        let data = store.read(&finance, &scope, "report").unwrap();
        assert_eq!(data, b"Q1 numbers");
    }

    #[test]
    fn test_ancestor_key_reads_descendant() {
        let (store, root, _, _) = setup();
        let scope = Scope::new("/finance/q1").unwrap();

        store.write(&scope, "summary", b"deep data").unwrap();

        // Root key (ancestor of /finance/q1) should decrypt via auto-derivation
        let data = store.read(&root, &scope, "summary").unwrap();
        assert_eq!(data, b"deep data");
    }

    #[test]
    fn test_wrong_scope_cannot_read() {
        let (store, _, _, engineering) = setup();
        let scope = Scope::new("/finance").unwrap();

        store.write(&scope, "secret", b"finance only").unwrap();

        // Engineering key should NOT decrypt finance data
        assert!(store.read(&engineering, &scope, "secret").is_err());
    }

    #[test]
    fn test_list_memories() {
        let (store, root, _, _) = setup();

        store.write(&Scope::new("/finance").unwrap(), "report", b"r1").unwrap();
        store.write(&Scope::new("/finance/q1").unwrap(), "q1", b"q1data").unwrap();
        store.write(&Scope::new("/engineering").unwrap(), "roadmap", b"eng").unwrap();

        // Root sees everything
        let all = store.list(&root).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_list_scoped() {
        let (store, _, finance, _) = setup();

        store.write(&Scope::new("/finance").unwrap(), "report", b"r1").unwrap();
        store.write(&Scope::new("/finance/q1").unwrap(), "q1", b"q1data").unwrap();
        store.write(&Scope::new("/engineering").unwrap(), "roadmap", b"eng").unwrap();

        // Finance key should only see /finance and /finance/q1
        let finance_memories = store.list(&finance).unwrap();
        assert_eq!(finance_memories.len(), 2);
    }

    #[test]
    fn test_accept_proposal() {
        let (store, _, finance, _) = setup();
        let scope = Scope::new("/finance").unwrap();

        let proposal = Proposal {
            scope: scope.clone(),
            key: "agent-finding".to_string(),
            plaintext: b"interesting pattern found".to_vec(),
            proposed_by: "perplexity".to_string(),
        };

        store.accept_proposal(&proposal).unwrap();

        let data = store.read(&finance, &scope, "agent-finding").unwrap();
        assert_eq!(data, b"interesting pattern found");
    }

    #[test]
    fn test_grant_access() {
        let (store, _, _, _) = setup();
        let scope = Scope::new("/finance").unwrap();

        let exported = store.grant_access(&scope).unwrap();
        let read_key = ReadKeyPair::import(&exported).unwrap();

        assert_eq!(read_key.scope().as_str(), "/finance");
        assert!(read_key.can_access(&scope));
        assert!(!read_key.can_access(&Scope::new("/engineering").unwrap()));
    }

    #[test]
    fn test_grant_root_access() {
        let (store, _, _, _) = setup();
        let exported = store.grant_access(&Scope::root()).unwrap();
        let read_key = ReadKeyPair::import(&exported).unwrap();
        assert_eq!(read_key.scope().as_str(), "/");
    }
}
