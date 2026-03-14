use rok_core::encoding;
use rok_core::keys::read::ReadKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::keys::spend::SpendKeyPair;
use rok_sdk::memory::{MemoryReader, MemoryStore};
use rok_sdk::storage::fileverse::FileverseBackend;
use rok_sdk::storage::StorageBackend;
use zeroize::Zeroize;

/// Session role determines read/write capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Has spend seed — full read/write/grant.
    Owner,
    /// Has scoped read key + spend public — read-only + propose.
    Agent,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Owner => write!(f, "owner"),
            Role::Agent => write!(f, "agent"),
        }
    }
}

/// Credentials resolved from env, config file, or login tool.
pub struct Credentials {
    pub fileverse_url: String,
    pub api_key: String,
    pub spend_seed: Option<[u8; 32]>,
    pub read_key_encoded: Option<String>,
    pub spend_public_encoded: Option<String>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        if let Some(ref mut seed) = self.spend_seed {
            seed.zeroize();
        }
    }
}

/// Persisted config file at ~/.rok/session.json.
#[derive(serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub fileverse_url: Option<String>,
    #[serde(default)]
    pub spend_seed: Option<String>,
    #[serde(default)]
    pub read_key: Option<String>,
    #[serde(default)]
    pub spend_public: Option<String>,
}

impl SessionConfig {
    /// Try to load from ~/.rok/session.json. Returns None if missing or unreadable.
    pub fn load() -> Option<Self> {
        let home = std::env::var("HOME").ok()?;
        let path = std::path::Path::new(&home).join(".rok/session.json");
        let contents = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }
}

/// Active session state, created after successful login.
pub struct Session {
    pub role: Role,
    pub scope: Scope,
    pub credentials: Credentials,
    pub memory_count: usize,
}

impl Session {
    /// Create a new owner session from a spend seed.
    pub fn new_owner(
        spend_seed: [u8; 32],
        scope: Scope,
        fileverse_url: String,
        api_key: String,
    ) -> Self {
        Self {
            role: Role::Owner,
            scope,
            credentials: Credentials {
                fileverse_url,
                api_key,
                spend_seed: Some(spend_seed),
                read_key_encoded: None,
                spend_public_encoded: None,
            },
            memory_count: 0,
        }
    }

    /// Create a new agent session from a read key + spend public.
    pub fn new_agent(
        read_key_encoded: String,
        spend_public_encoded: String,
        scope: Scope,
        fileverse_url: String,
        api_key: String,
    ) -> Self {
        Self {
            role: Role::Agent,
            scope,
            credentials: Credentials {
                fileverse_url,
                api_key,
                spend_seed: None,
                read_key_encoded: Some(read_key_encoded),
                spend_public_encoded: Some(spend_public_encoded),
            },
            memory_count: 0,
        }
    }

    /// Build a FileverseBackend from session credentials.
    pub fn backend(&self) -> FileverseBackend {
        FileverseBackend::with_base_url(
            self.credentials.fileverse_url.clone(),
            self.credentials.api_key.clone(),
        )
    }

    /// Load the spend key (owner only).
    pub fn spend_key(&self) -> anyhow::Result<SpendKeyPair> {
        let seed = self
            .credentials
            .spend_seed
            .ok_or_else(|| anyhow::anyhow!("no spend seed — session is agent role"))?;
        Ok(SpendKeyPair::from_seed(&seed))
    }

    /// Load the read key (agent path, or derive from spend for owner).
    pub fn read_key(&self) -> anyhow::Result<ReadKeyPair> {
        match self.role {
            Role::Owner => {
                let spend = self.spend_key()?;
                let root = spend.derive_root_read_key();
                if self.scope == Scope::root() {
                    Ok(root)
                } else {
                    root.derive_child(&self.scope)
                        .map_err(|e| anyhow::anyhow!("{e}"))
                }
            }
            Role::Agent => {
                let encoded = self
                    .credentials
                    .read_key_encoded
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no read key in agent session"))?;
                let exported = encoding::decode_exported_read_key(encoded)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                ReadKeyPair::import(&exported).map_err(|e| anyhow::anyhow!("{e}"))
            }
        }
    }

    /// Get the spend verifying key for signature verification.
    pub fn spend_verifying_key(&self) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
        match self.role {
            Role::Owner => Ok(self.spend_key()?.verifying_key()),
            Role::Agent => {
                let encoded = self
                    .credentials
                    .spend_public_encoded
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no spend public in agent session"))?;
                encoding::decode_spend_public(encoded).map_err(|e| anyhow::anyhow!("{e}"))
            }
        }
    }

    /// Build a MemoryStore with a specific backend (for testing).
    pub fn memory_store_with<B: StorageBackend>(
        &self,
        backend: B,
    ) -> anyhow::Result<MemoryStore<B>> {
        let spend = self.spend_key()?;
        Ok(MemoryStore::new(spend, backend))
    }

    /// Build a MemoryReader with a specific backend (for testing).
    pub fn memory_reader_with<B: StorageBackend>(
        &self,
        backend: B,
    ) -> anyhow::Result<MemoryReader<B>> {
        let vk = self.spend_verifying_key()?;
        Ok(MemoryReader::new(vk, backend))
    }

    /// Build a MemoryStore backed by Fileverse.
    pub fn memory_store(&self) -> anyhow::Result<MemoryStore<FileverseBackend>> {
        self.memory_store_with(self.backend())
    }

    /// Build a MemoryReader backed by Fileverse.
    pub fn memory_reader(&self) -> anyhow::Result<MemoryReader<FileverseBackend>> {
        self.memory_reader_with(self.backend())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rok_core::error::Result as RokResult;
    use rok_core::keys::spend::SpendKeyPair;
    use rok_sdk::storage::{MemoryStorage, StorageEntry, StorageId};
    use std::sync::Arc;

    /// Shared in-memory storage that can be cloned across store/reader.
    /// Wraps MemoryStorage in Arc so multiple owners share the same data.
    #[derive(Clone)]
    struct SharedStorage(Arc<MemoryStorage>);

    impl SharedStorage {
        fn new() -> Self {
            Self(Arc::new(MemoryStorage::new()))
        }
    }

    impl StorageBackend for SharedStorage {
        fn put(&self, scope: &str, key: &str, data: &[u8]) -> RokResult<StorageId> {
            self.0.put(scope, key, data)
        }
        fn get(&self, id: &StorageId) -> RokResult<StorageEntry> {
            self.0.get(id)
        }
        fn get_by_key(&self, scope: &str, key: &str) -> RokResult<StorageEntry> {
            self.0.get_by_key(scope, key)
        }
        fn list(&self, scope_prefix: &str) -> RokResult<Vec<StorageEntry>> {
            self.0.list(scope_prefix)
        }
        fn delete(&self, id: &StorageId) -> RokResult<()> {
            self.0.delete(id)
        }
    }

    const TEST_SEED: [u8; 32] = [42u8; 32];

    fn owner_session() -> Session {
        Session::new_owner(
            TEST_SEED,
            Scope::root(),
            "http://localhost:8001".into(),
            "test-key".into(),
        )
    }

    fn agent_session() -> Session {
        let spend = SpendKeyPair::from_seed(&TEST_SEED);
        let root = spend.derive_root_read_key();
        let finance = root.derive_child_segment("finance").unwrap();
        let exported = finance.export();

        let read_key_encoded = encoding::encode_exported_read_key(&exported);
        let spend_public_encoded = encoding::encode_spend_public(&spend.verifying_key());

        Session::new_agent(
            read_key_encoded,
            spend_public_encoded,
            Scope::new("/finance").unwrap(),
            "http://localhost:8001".into(),
            "test-key".into(),
        )
    }

    #[test]
    fn owner_role_and_key_derivation() {
        let session = owner_session();
        assert_eq!(session.role, Role::Owner);
        assert_eq!(session.scope, Scope::root());

        let spend = session.spend_key().unwrap();
        assert_eq!(spend.seed(), TEST_SEED);

        let read = session.read_key().unwrap();
        assert_eq!(read.scope(), &Scope::root());

        let vk = session.spend_verifying_key().unwrap();
        assert_eq!(vk, spend.verifying_key());
    }

    #[test]
    fn owner_scoped_session_derives_child_key() {
        let session = Session::new_owner(
            TEST_SEED,
            Scope::new("/engineering").unwrap(),
            "http://localhost:8001".into(),
            "test-key".into(),
        );

        let read = session.read_key().unwrap();
        assert_eq!(read.scope().as_str(), "/engineering");
        assert!(read.can_access(&Scope::new("/engineering").unwrap()));
        assert!(read.can_access(&Scope::new("/engineering/frontend").unwrap()));
        assert!(!read.can_access(&Scope::new("/finance").unwrap()));
    }

    #[test]
    fn agent_role_and_key_import() {
        let session = agent_session();
        assert_eq!(session.role, Role::Agent);
        assert_eq!(session.scope, Scope::new("/finance").unwrap());

        assert!(session.spend_key().is_err());

        let read = session.read_key().unwrap();
        assert_eq!(read.scope().as_str(), "/finance");
        assert!(read.can_access(&Scope::new("/finance").unwrap()));
        assert!(!read.can_access(&Scope::new("/engineering").unwrap()));

        let vk = session.spend_verifying_key().unwrap();
        let spend = SpendKeyPair::from_seed(&TEST_SEED);
        assert_eq!(vk, spend.verifying_key());
    }

    #[test]
    fn agent_cannot_build_store() {
        let session = agent_session();
        assert!(session.memory_store_with(SharedStorage::new()).is_err());
    }

    #[test]
    fn owner_write_and_read_round_trip() {
        let session = owner_session();
        let storage = SharedStorage::new();

        let store = session.memory_store_with(storage.clone()).unwrap();
        let scope = Scope::new("/notes").unwrap();
        store.write(&scope, "hello", b"world").unwrap();

        let reader = session.memory_reader_with(storage).unwrap();
        let read_key = session.read_key().unwrap();
        let data = reader.read(&read_key, &scope, "hello").unwrap();
        assert_eq!(data, b"world");
    }

    #[test]
    fn owner_write_agent_read() {
        let storage = SharedStorage::new();

        let owner = owner_session();
        let store = owner.memory_store_with(storage.clone()).unwrap();
        let scope = Scope::new("/finance").unwrap();
        store.write(&scope, "report", b"Q1 revenue: $1M").unwrap();

        let agent = agent_session();
        let reader = agent.memory_reader_with(storage).unwrap();
        let read_key = agent.read_key().unwrap();
        let data = reader.read(&read_key, &scope, "report").unwrap();
        assert_eq!(data, b"Q1 revenue: $1M");
    }

    #[test]
    fn agent_cannot_read_sibling_scope() {
        let storage = SharedStorage::new();

        let owner = owner_session();
        let store = owner.memory_store_with(storage.clone()).unwrap();
        let scope = Scope::new("/engineering").unwrap();
        store.write(&scope, "roadmap", b"secret plans").unwrap();

        let agent = agent_session();
        let reader = agent.memory_reader_with(storage).unwrap();
        let read_key = agent.read_key().unwrap();
        assert!(reader.read(&read_key, &scope, "roadmap").is_err());
    }

    #[test]
    fn owner_list_memories() {
        let storage = SharedStorage::new();
        let owner = owner_session();
        let store = owner.memory_store_with(storage.clone()).unwrap();

        store
            .write(&Scope::new("/a").unwrap(), "x", b"1")
            .unwrap();
        store
            .write(&Scope::new("/b").unwrap(), "y", b"2")
            .unwrap();

        let reader = owner.memory_reader_with(storage).unwrap();
        let read_key = owner.read_key().unwrap();
        let entries = reader.list(&read_key).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn owner_grant_produces_valid_agent_key() {
        let storage = SharedStorage::new();
        let owner = owner_session();
        let store = owner.memory_store_with(storage.clone()).unwrap();

        // Write a memory at /finance
        let scope = Scope::new("/finance").unwrap();
        store.write(&scope, "secret", b"numbers").unwrap();

        // Grant access to /finance
        let exported = store.grant_access(&scope).unwrap();
        let encoded = encoding::encode_exported_read_key(&exported);
        let spend_pub = encoding::encode_spend_public(&owner.spend_key().unwrap().verifying_key());

        // Create an agent session from the granted key
        let agent = Session::new_agent(
            encoded,
            spend_pub,
            scope.clone(),
            "http://localhost:8001".into(),
            "test-key".into(),
        );

        let reader = agent.memory_reader_with(storage).unwrap();
        let read_key = agent.read_key().unwrap();
        let data = reader.read(&read_key, &scope, "secret").unwrap();
        assert_eq!(data, b"numbers");
    }

    #[test]
    fn role_display() {
        assert_eq!(Role::Owner.to_string(), "owner");
        assert_eq!(Role::Agent.to_string(), "agent");
    }

    #[test]
    fn config_load_missing_file() {
        // Should return None when file doesn't exist (not panic)
        let _ = std::env::set_var("HOME", "/tmp/rok-test-nonexistent");
        assert!(SessionConfig::load().is_none());
    }
}
