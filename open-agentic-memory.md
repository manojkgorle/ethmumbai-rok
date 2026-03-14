# Open Scope-Based Agentic Memory: rok + Fileverse Integration

## Context

**Problem**: AI memory is siloed. Users create traces across many AI providers (Claude, GPT, Perplexity, etc.), but no provider allows exporting/sharing memory. Users want *selective* sharing — finance data to Perplexity, engineering to Claude Code, basics to a trending agent — not all-or-nothing.

**What we have**: rok provides scope-based hierarchical encryption. A spend key derives a tree of read keys (`/`, `/finance`, `/engineering`, etc.). An agent with a `/finance` read key can decrypt `/finance` and descendants, but nothing at `/engineering`.

**What we lack**: Decentralized persistent storage + sync.

**Fileverse**: Decentralized collaboration platform — IPFS storage, on-chain content hashes (Gnosis), E2E encryption, `@fileverse/api` package with **local REST server on `127.0.0.1:8001`** and built-in **MCP server**.

---

## Analysis: Why rok Encryption + Fileverse Storage

Fileverse's encryption is per-file, per-user (flat ACLs). No hierarchical scope derivation — a `/finance` key can't unlock `/finance/q1`. Their ZK-permissions are about "who can access this file", not "this key hierarchy unlocks this scope tree."

**Verdict**: Use Fileverse as **dumb decentralized storage**. rok encrypts client-side, stores opaque ciphertext via Fileverse's local API. Fileverse never sees plaintext or scope structure.

**Bridge**: `@fileverse/api` runs locally on `:8001` with REST endpoints. From Rust, we just call `reqwest::post("http://127.0.0.1:8001/api/...")`. No JS bridge, no WASM, no FFI. It also has an MCP server (`fileverse-api-mcp`) for direct agent integration.

---

## Architecture

```
User (Spend Key)
  │
  ├── derive /finance read key  → give to Perplexity
  ├── derive /engineering key   → give to Claude Code
  ├── derive /life key          → give to ChatGPT
  └── derive /basic key         → give to trending agent

Each agent:
  1. Receives scoped read key
  2. Calls MemoryStore to sync memories at their scope
  3. Can propose new memories (user approves + encrypts)

MemoryStore<B: StorageBackend>
  │
  ├── MemoryStorage    (in-memory, for tests)
  ├── LocalFsStorage   (local filesystem)
  └── FileverseBackend (HTTP calls to 127.0.0.1:8001)
        └── stores rok EncryptedEnvelope bytes as dDocs
```

### Access Model: Read-only + Propose
- Agents receive a **scoped read key** (can decrypt their scope and descendants)
- Agents **cannot encrypt** (no spend key) — they propose plaintext memories
- User's master process approves proposals, encrypts with spend key, stores
- This limits blast radius: a compromised agent can't pollute the memory store

---

## Implementation Plan

### Phase 1: `StorageBackend` trait + in-memory impl (rok-sdk)

**New files:**
- `crates/rok-sdk/src/storage.rs` — trait + `MemoryStorage`

**Modify:**
- `crates/rok-sdk/src/lib.rs` — add `pub mod storage`

```rust
/// Unique identifier for a stored item (backend-specific)
pub struct StorageId(pub String);

pub struct StorageEntry {
    pub id: StorageId,
    pub scope: String,       // scope path, e.g. "/finance/q1"
    pub key: String,          // logical name, e.g. "2024-q1-report"
    pub data: Vec<u8>,        // raw EncryptedEnvelope bytes
    pub created_at: u64,
    pub updated_at: u64,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, scope: &str, key: &str, data: &[u8]) -> Result<StorageId>;
    async fn get(&self, id: &StorageId) -> Result<StorageEntry>;
    async fn get_by_key(&self, scope: &str, key: &str) -> Result<StorageEntry>;
    async fn list(&self, scope_prefix: &str) -> Result<Vec<StorageEntry>>;
    async fn delete(&self, id: &StorageId) -> Result<()>;
}
```

`MemoryStorage`: `HashMap<String, StorageEntry>` keyed by `"{scope}/{key}"`.

**Reuse:**
- `KeyStore` trait pattern from `crates/rok-core/src/keyring.rs`
- `Scope` validation from `crates/rok-core/src/keys/scope.rs`

### Phase 2: `MemoryStore` high-level API (rok-sdk)

**New files:**
- `crates/rok-sdk/src/memory.rs`

**Modify:**
- `crates/rok-sdk/src/lib.rs` — add `pub mod memory`

```rust
pub struct MemoryStore<B: StorageBackend> {
    spend_key: SpendKeyPair,
    backend: B,
}

impl<B: StorageBackend> MemoryStore<B> {
    /// Encrypt and store a memory at a scope
    pub async fn write(&self, scope: &Scope, key: &str, content: &[u8]) -> Result<StorageId>;

    /// Read and decrypt a memory using a scoped read key
    pub async fn read(&self, read_key: &ReadKeyPair, scope: &Scope, key: &str) -> Result<Vec<u8>>;

    /// List all memories visible to a read key (scope + descendants)
    pub async fn list(&self, read_key: &ReadKeyPair) -> Result<Vec<MemoryEntry>>;

    /// Accept a proposed memory from an agent, encrypt and store it
    pub async fn accept_proposal(&self, proposal: &Proposal) -> Result<StorageId>;

    /// Export a scoped read key for an agent
    pub fn grant_access(&self, scope: &Scope) -> Result<ExportedReadKey>;
}

pub struct Proposal {
    pub scope: Scope,
    pub key: String,
    pub plaintext: Vec<u8>,
    pub proposed_by: String,  // agent identifier
}
```

**Reuse:**
- `EncryptBuilder::new().set_scope_based()` from `crates/rok-core/src/encrypt.rs`
- `decrypt()` with auto-derivation from `crates/rok-core/src/encrypt.rs`
- `ReadKeyPair::derive_child()` from `crates/rok-core/src/keys/read.rs`

### Phase 3: Fileverse backend (rok-sdk, feature-gated)

**New files:**
- `crates/rok-sdk/src/storage/fileverse.rs`

**Dependencies** (feature-gated behind `fileverse`):
- `reqwest` (HTTP client, already likely in deps or easy to add)
- `serde_json`

```rust
pub struct FileverseBackend {
    base_url: String,   // default "http://127.0.0.1:8001"
    api_key: String,
}
```

Implementation:
- `put()` → `POST /api/documents` with rok envelope bytes (base64 in JSON body)
- `get()` → `GET /api/documents/{id}?apiKey=...`
- `list()` → `GET /api/documents?prefix={scope}&apiKey=...`
- `delete()` → `DELETE /api/documents/{id}?apiKey=...`
- Scope path encoded in document metadata/title for listing

**Note**: Exact Fileverse API endpoints need discovery (their docs only show event endpoints). We'll need to run the server and inspect routes, or check source.

### Phase 4: Agent protocol spec (documentation only)

Define how agents interact:
1. **Key handoff**: Agent receives `ExportedReadKey` (base58-encoded scope + secret + key_id)
2. **Discovery**: Agent calls `list()` with their read key's scope to find available memories
3. **Read**: Agent calls `read()` to decrypt individual memories
4. **Propose**: Agent submits `Proposal` (plaintext + scope + key) to user's approval queue
5. **Sync**: Periodic `list()` with `since` timestamp for incremental updates

---

## Critical Files Reference

| File | What to reuse |
|------|--------------|
| `crates/rok-core/src/encrypt.rs` | `EncryptBuilder::set_scope_based()`, `decrypt()` |
| `crates/rok-core/src/keys/scope.rs` | `Scope` type, validation, hierarchy |
| `crates/rok-core/src/keys/read.rs` | `ReadKeyPair::derive_child()`, `export()` |
| `crates/rok-core/src/envelope.rs` | `EncryptedEnvelope::to_bytes()` / `from_bytes()` |
| `crates/rok-core/src/keyring.rs` | `KeyStore` trait pattern |
| `crates/rok-core/src/sectioned.rs` | `SectionedEnvelope` for multi-scope docs |
| `crates/rok-sdk/src/vault.rs` | Existing document store pattern to align with |
| `crates/rok-sdk/src/policy.rs` | `AccessPolicy` for scope-level grant/revoke |

---

## Verification

1. **Unit tests** for `StorageBackend` trait with `MemoryStorage`
2. **Integration test**: write at `/finance/q1`, read with `/finance` key (ancestor auto-derives)
3. **Integration test**: `/engineering` key cannot read `/finance` memories → `ScopeMismatch`
4. **Round-trip**: encrypt → store → retrieve → decrypt
5. **Proposal flow**: agent proposes → user accepts → encrypted → stored → agent reads
6. **Existing 117 tests** must continue passing
7. **Fileverse backend** (Phase 3): manual test with local `@fileverse/api` server running
