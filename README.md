# rok — Read-Only Keys

A Rust cryptography library implementing a **dual-key system** with hierarchical read-key delegation, multi-recipient encryption, and post-quantum hybrid support.

The core idea: a **spend key** (Ed25519) acts as the root of trust—it signs data and derives **read keys** (X25519). Read keys are scope-bound and hierarchical, enabling fine-grained access delegation *without* exposing the spend key.

```
Spend Key (Ed25519)
  └── Root Read Key (scope: /)
        ├── /finance
        │     ├── /finance/q1
        │     └── /finance/q2
        └── /legal
              └── /legal/contracts
```

A key at `/finance` can decrypt anything at `/finance`, `/finance/q1`, `/finance/q2`—but **not** `/legal`. Read keys can be delegated (exported) to third parties who can then derive child keys further, without ever gaining access to parent scopes.

## Features

- **Hierarchical read keys** — scope-based derivation with ancestor/descendant access control
- **Multi-recipient encryption** — encrypt once, grant access to many; each recipient gets an independently wrapped data key
- **Scope-based group encryption** — encrypt to a scope and any ancestor key holder can automatically decrypt, no recipient listing required
- **Post-quantum hybrid** — X25519 + ML-KEM-768 combined via HKDF; secure if *either* algorithm holds
- **Dual serialization** — compact binary format (`ROK\x01` magic header) and Protocol Buffers
- **Authenticated envelopes** — every ciphertext is signed by the spend key (Ed25519)
- **Key export/import** — delegate read keys with Base58-encoded portable format
- **Sectioned envelopes** — bundle multiple encrypted sections (each at its own scope) into a single `.roks` file; a `/finance` key decrypts only the finance section while a root key decrypts everything
- **Selective disclosure credentials** — encrypt individual attributes under different scopes
- **Zero-copy zeroization** — secrets are zeroized on drop via the `zeroize` crate

## Architecture

```
┌─────────────────────────────────────────────────┐
│           rok-cli          │     rok-mcp        │
│     12 commands, clap CLI  │  MCP server for    │
│                            │  Claude Code       │
├──────────────────┬─────────┴────────────────────┤
│     rok-sdk      │                              │
│  Vault, Pipeline,│         rok-pq               │
│  Policy, Identity│    ML-KEM-768 hybrid         │
├──────────────────┴──────────────────────────────┤
│                  rok-core                       │
│  Keys, Derivation, Encryption, Envelope, Signing│
└─────────────────────────────────────────────────┘
```

| Crate | Description |
|---|---|
| **rok-core** | Cryptographic primitives: key types, HKDF derivation, encryption/decryption, envelope format, signing, Base58 encoding |
| **rok-pq** | Post-quantum module: ML-KEM-768 encapsulation, X25519+ML-KEM hybrid combiner, and end-to-end hybrid envelope encrypt/decrypt |
| **rok-sdk** | High-level abstractions: encrypted vault, data pipeline, access policy engine, selective disclosure credentials |
| **rok-cli** | Command-line interface with 12 commands for key management, encryption, signing, and delegation |
| **rok-mcp** | MCP server for Claude Code — encrypted memory backed by Fileverse with auto-sync, scoped access, and key delegation |

## Cryptographic Primitives

| Purpose | Algorithm | Details |
|---|---|---|
| Signing | Ed25519 | Spend key signs all envelopes |
| Key agreement | X25519 ECDH | Ephemeral-static for per-envelope shared secrets |
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203 lattice-based KEM |
| Data encryption | ChaCha20-Poly1305 | AEAD for payload encryption |
| Key wrapping | AES-256-GCM-SIV | Per-recipient data key wrapping |
| Key derivation | HKDF-SHA256 | Domain-separated derivation with unique tags |
| Key identifiers | SHA-256 truncated | First 8 bytes of SHA-256(public_key) |
| Key encoding | Base58Check | Tagged encoding with 4-byte checksums |

### Domain Separation Tags

Each HKDF derivation uses a unique domain tag to prevent cross-protocol attacks:

| Tag | Purpose |
|---|---|
| `rok-v1-spend-to-root-read` | Spend key to root read key |
| `rok-v1-read-child-derive` | Parent read key to child (step-wise per path component) |
| `rok-v1-key-wrap` | ECDH shared secret to wrapping key |
| `rok-v1-hybrid-combine` | Combine X25519 + ML-KEM shared secrets |
| `rok-v1-pq-key-derive` | Derive PQ key seed from read key secret + scope |

## Installation

### From source

```bash
git clone https://github.com/user/read-only-keys.git
cd read-only-keys
cargo build --release
```

The binary is at `target/release/rok`.

### Requirements

- Rust 1.75+
- protobuf compiler (`protoc`) for proto code generation

## CLI Usage

### Key Generation

Generate a spend keypair and its root read key:

```bash
rok keygen --label mykey
```

Output:
```
=== Key Generation ===
  Label: mykey
  Spend Seed (hex): a1b2c3...
  Spend Public (base58): rokS1...
  Root Read Key ID: 3kF9...
  Root Read Public (base58): rokR2...
```

> **Important**: Save the spend seed securely. It is the root of trust for all derived keys.

### Key Derivation

Derive a scope-bound child read key:

```bash
rok derive --spend_seed <hex> --scope /finance
rok derive --spend_seed <hex> --scope /finance/q1
```

### Encryption

Encrypt a file for one or more recipients:

```bash
# Single recipient, binary format (default)
rok encrypt \
  --file secret.pdf \
  --scope /finance \
  --spend_seed <hex> \
  --recipient <base58-read-public-key> \
  --output secret.pdf.rok

# Multiple recipients
rok encrypt \
  --file secret.pdf \
  --scope /finance \
  --spend_seed <hex> \
  --recipient <key1> \
  --recipient <key2> \
  --recipient <key3> \
  --output secret.pdf.rok

# Protocol Buffers format
rok encrypt \
  --file secret.pdf \
  --scope /finance \
  --spend_seed <hex> \
  --recipient <key> \
  --output secret.pdf.rok \
  --format proto

# Scope-based group encryption (no recipients needed)
rok encrypt \
  --file report.pdf \
  --scope /finance/q1 \
  --spend_seed <hex> \
  --scope-based

# Hybrid post-quantum encryption (scope-based only)
rok encrypt \
  --file report.pdf \
  --scope /finance \
  --spend_seed <hex> \
  --scope-based \
  --algorithm hybrid
```

With `--scope-based`, a single access entry is created for the scope's derived key. Anyone holding a key at `/finance/q1`, `/finance`, or `/` can automatically decrypt—no need to list them individually.

With `--algorithm hybrid`, the envelope uses X25519 + ML-KEM-768 combined via HKDF. PQ keys are derived deterministically from the read key, so no extra key distribution is needed. Hybrid mode requires `--scope-based`.

### Decryption

Decrypt with a read key:

```bash
rok decrypt \
  --file secret.pdf.rok \
  --key <base58-read-secret-key> \
  --spend_public <base58-spend-public-key> \
  --output secret.pdf
```

The read key must have a scope that is an ancestor of (or equal to) the envelope's scope. The algorithm is auto-detected from the envelope—no `--algorithm` flag needed for decryption.

### Sectioned Encryption

Encrypt multiple sections at different scopes into a single `.roks` file:

```bash
# Using --section flags (name:scope:file)
rok encrypt-sections \
  --section finance:/finance:finance_report.txt \
  --section legal:/legal:legal_brief.txt \
  --spend-seed <hex> \
  --scope-based \
  --output document.roks

# Using a JSON manifest
rok encrypt-sections \
  --manifest sections.json \
  --spend-seed <hex> \
  --scope-based \
  --output document.roks

# Hybrid post-quantum
rok encrypt-sections \
  --section finance:/finance:fin.txt \
  --section legal:/legal:legal.txt \
  --spend-seed <hex> \
  --algorithm hybrid \
  --output document.roks
```

Manifest JSON format:
```json
[
  {"name": "finance", "scope": "/finance", "file": "finance_report.txt"},
  {"name": "legal", "scope": "/legal", "file": "legal_brief.txt"}
]
```

### Sectioned Decryption

Decrypt accessible sections from a `.roks` file:

```bash
# Decrypt all accessible sections
rok decrypt-sections \
  --file document.roks \
  --key <base58-read-key> \
  --spend-public <base58-spend-public> \
  --output-dir ./out/

# Decrypt specific sections only
rok decrypt-sections \
  --file document.roks \
  --key <base58-read-key> \
  --spend-public <base58-spend-public> \
  --output-dir ./out/ \
  --section finance
```

Output:
```
  Decrypted: finance -> ./out/finance (1234 bytes)
  Skipped: legal (no access)

Summary: 1 decrypted, 1 skipped
```

A `/finance` key decrypts only the finance section. A root key decrypts everything. Inaccessible sections are silently skipped.

### Signing & Verification

Sign any file with the spend key:

```bash
rok sign --file document.pdf --spend_seed <hex> --output document.pdf.sig
```

Verify a signature:

```bash
rok verify --file document.pdf --sig document.pdf.sig --spend_public <base58>
```

### Key Delegation (Grant)

Export a derived read key for delegation to a third party:

```bash
rok grant --scope /finance/q1 --spend_seed <hex>
```

Output:
```
=== Granted Read Key ===
  Scope: /finance/q1
  Key ID: 7xQ2...
  Exported Key (base58): rokE3...
```

The recipient can import this key and derive further child keys (e.g., `/finance/q1/reports`) but **cannot** access parent scopes like `/finance`.

### Key Revocation

Mark a key as revoked in the local keyring:

```bash
rok revoke --key_id <base58> --spend_seed <hex>
rok revoke --key_id <base58> --spend_seed <hex> --scope /finance
```

### Envelope Inspection

Inspect metadata of an encrypted envelope without decrypting:

```bash
rok inspect --file secret.pdf.rok
rok inspect --file secret.pdf.rok --format proto
```

Output:
```
=== Envelope Metadata ===
  Version: 2
  Algorithm: EciesX25519ChaCha20
  Access mode: per-recipient
  Scope: /finance
  Recipients: 3
  Ciphertext Size: 4.2 KB
```

For hybrid envelopes, additional fields are shown:
```
  Hybrid PQ: yes
  ML-KEM ciphertext size: 1088 bytes
```

Sectioned envelopes (`.roks`) are auto-detected:

```bash
rok inspect --file document.roks
```

Output:
```
=== Sectioned Envelope: document.roks ===
  Version: 1
  Sections: 2
  Format: binary
  Total file size: 1234 bytes

  Section 1 - "finance":
    Scope: /finance
    Algorithm: EciesX25519ChaCha20
    Access mode: scope-based
    Recipients: 1
    Ciphertext size: 456 bytes

  Section 2 - "legal":
    Scope: /legal
    Algorithm: EciesX25519ChaCha20
    Access mode: scope-based
    Recipients: 1
    Ciphertext size: 389 bytes
```

### Keyring Management

```bash
# List all keys (optionally filtered by scope)
rok keyring list --spend_seed <hex>
rok keyring list --spend_seed <hex> --scopes /finance --scopes /legal

# Export a key
rok keyring export --key_id <base58> --spend_seed <hex>

# Import a previously exported key
rok keyring import --exported_key <base58>

# Delete a key from the keyring
rok keyring delete --key_id <base58>
```

## Library Usage

### rok-core

```rust
use rok_core::keys::spend::SpendKeyPair;
use rok_core::keys::scope::Scope;
use rok_core::encrypt::{Algorithm, EncryptBuilder, Recipient, decrypt};

// Generate a spend keypair
let spend = SpendKeyPair::generate(&mut rng);

// Derive a scoped read key
let root_read = spend.derive_root_read_key();
let finance_key = root_read.derive_child(&Scope::new("/finance")?)?;

// Encrypt for a recipient
let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::new("/finance")?)
    .add_recipient(Recipient {
        read_public_key: finance_key.public_key(),
        key_id: finance_key.key_id(),
    })
    .spend_key(&spend)
    .encrypt(&mut rng, b"secret data")?;

// Serialize (binary or protobuf)
let bytes = envelope.to_bytes();
let proto_bytes = envelope.to_proto_bytes()?;

// Decrypt
let plaintext = decrypt(&envelope, &finance_key, &spend.verifying_key())?;
assert_eq!(plaintext, b"secret data");
```

### Scope-Based Group Encryption

Instead of listing individual recipients, encrypt to a scope. Any ancestor key holder can derive down and decrypt automatically:

```rust
use rok_core::encrypt::{Algorithm, EncryptBuilder, decrypt};
use rok_core::keys::scope::Scope;

// Encrypt at /finance/q1 with scope-based mode — one access entry, no recipients needed
let envelope = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::new("/finance/q1")?)
    .set_spend_key(&spend)
    .set_scope_based()
    .encrypt(b"Q1 report", &mut rng)?;

// Anyone with /finance/q1, /finance, or root key can decrypt
let plaintext = decrypt(&envelope, &finance_key, &spend.verifying_key())?;
let plaintext = decrypt(&envelope, &root_read, &spend.verifying_key())?;
```

### Sectioned Envelopes

Bundle multiple encrypted sections into a single container. Each section has its own scope and is independently encrypted:

```rust
use rok_core::encrypt::{Algorithm, EncryptBuilder, decrypt};
use rok_core::keys::scope::Scope;
use rok_core::sectioned::SectionedEnvelopeBuilder;

// Encrypt sections at different scopes
let finance_env = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::new("/finance")?)
    .set_spend_key(&spend)
    .set_scope_based()
    .encrypt(b"finance data", &mut rng)?;

let legal_env = EncryptBuilder::new(Algorithm::EciesX25519ChaCha20, Scope::new("/legal")?)
    .set_spend_key(&spend)
    .set_scope_based()
    .encrypt(b"legal data", &mut rng)?;

// Bundle into a single sectioned envelope
let mut builder = SectionedEnvelopeBuilder::new();
builder.add_section("finance".into(), finance_env)?;
builder.add_section("legal".into(), legal_env)?;
let sectioned = builder.build()?;

// Serialize (binary ROKS format or protobuf)
let bytes = sectioned.to_bytes();
let proto_bytes = sectioned.to_proto_bytes();

// Root key decrypts all sections
for section in &sectioned.sections {
    let plaintext = decrypt(&section.envelope, &root_read, &spend.verifying_key())?;
}

// Finance key decrypts only the finance section
let finance_data = decrypt(&sectioned.sections[0].envelope, &finance_key, &spend.verifying_key())?;
```

### Key Hierarchy & Access Control

```rust
use rok_core::keys::scope::Scope;

let root = Scope::root();                     // /
let finance = Scope::new("/finance")?;        // /finance
let finance_q1 = Scope::new("/finance/q1")?;  // /finance/q1

// Ancestor check
assert!(root.is_ancestor_of(&finance));       // / is ancestor of /finance
assert!(finance.is_ancestor_of(&finance_q1)); // /finance is ancestor of /finance/q1
assert!(!finance_q1.is_ancestor_of(&finance)); // child cannot access parent

// A read key can access its own scope and all descendant scopes
let finance_read = root_read.derive_child(&finance)?;
assert!(finance_read.can_access(&finance));    // exact match
assert!(finance_read.can_access(&finance_q1)); // descendant
```

### Key Export & Import

```rust
use rok_core::encoding::{encode_exported_read_key, decode_exported_read_key};

// Export a read key for delegation
let exported = finance_key.export();
let encoded = encode_exported_read_key(&exported);
// encoded is a Base58 string like "rokE3..."

// Import on the recipient side
let (secret, public, scope, parent_id) = decode_exported_read_key(&encoded)?;
let imported = ReadKeyPair::import(secret, public, scope, parent_id)?;
```

### Signing

```rust
use rok_core::sign::{sign, verify};

let signature = sign(b"important document", &spend);
verify(b"important document", &signature, &spend.verifying_key())?;
```

### rok-sdk — Vault

```rust
use rok_sdk::vault::Vault;

let mut vault = Vault::new(spend_key, root_read_key);

// Store an encrypted document
vault.store("budget.xlsx", b"spreadsheet data", &Scope::new("/finance")?, &mut rng)?;

// Retrieve and decrypt
let data = vault.retrieve("budget.xlsx", &finance_read_key)?;

// List entries
for entry in vault.list() {
    println!("{}: {} ({} recipients)", entry.name, entry.scope, entry.recipient_count);
}
```

### rok-sdk — Pipeline

```rust
use rok_sdk::pipeline::Pipeline;

let mut pipeline = Pipeline::new(spend_key, Scope::new("/telemetry")?);
pipeline.add_consumer(consumer_read_key_public, consumer_key_id);

// Encrypt streaming chunks
let envelope = pipeline.encrypt_chunk(b"sensor reading 42", &mut rng)?;

// Consumer decrypts
let reading = pipeline.decrypt_chunk(&envelope, &consumer_read_key)?;
```

### rok-sdk — Access Policy

```rust
use rok_sdk::policy::AccessPolicy;

let mut policy = AccessPolicy::new();

// Grant access with optional expiry
policy.grant("/finance", vec![key_id_alice, key_id_bob], None);
policy.grant("/finance/q1", vec![key_id_charlie], Some(expiry_timestamp));

// Query authorized keys for a scope
let keys = policy.authorized_keys_for_scope(&Scope::new("/finance/q1")?);

// Revoke access
policy.revoke("/finance", &key_id_bob);
```

### rok-sdk — Selective Disclosure Credentials

```rust
use rok_sdk::identity::Credential;

// Issue a credential with attributes encrypted under different scopes
let credential = Credential::issue(
    &spend,
    &root_read,
    &[
        ("name", b"Alice", "/identity/public"),
        ("ssn", b"123-45-6789", "/identity/private"),
        ("age", b"30", "/identity/public"),
    ],
    &mut rng,
)?;

// Selectively reveal only public attributes
let revealed = credential.reveal(&["name", "age"], &public_read_key, &spend.verifying_key())?;
// "ssn" remains encrypted — the verifier never sees it
```

### rok-pq — Post-Quantum Hybrid Encryption

End-to-end hybrid encrypt/decrypt with scope-based access. PQ keys are derived deterministically from the read key—no extra key distribution needed:

```rust
use rok_pq::envelope::{hybrid_encrypt, hybrid_decrypt};
use rok_core::keys::scope::Scope;

// Hybrid encrypt: X25519 + ML-KEM-768 + ChaCha20-Poly1305
let scope = Scope::new("/finance")?;
let envelope = hybrid_encrypt(b"secret data", &scope, &spend, &mut rng)?;

// Any ancestor key holder can decrypt (auto-derives to envelope scope)
let plaintext = hybrid_decrypt(&envelope, &root_read, &spend.verifying_key())?;
let plaintext = hybrid_decrypt(&envelope, &finance_key, &spend.verifying_key())?;
```

The low-level primitives are also available for custom protocols:

```rust
use rok_pq::kem::PqKeyPair;
use rok_pq::hybrid::{hybrid_encapsulate, hybrid_decapsulate, HybridRecipient};
use rok_pq::pq_derive::derive_pq_keypair;

// Deterministic PQ key derivation from read key + scope
let pq_keypair = derive_pq_keypair(&read_secret_bytes, &scope);

// Or generate a random ML-KEM-768 keypair
let pq_keypair = PqKeyPair::generate(&mut rng);
```

## Serialization Formats

### Binary Format

Compact binary with a magic header:

```
ROK\x01 | version(4) | algorithm(1) | access_mode(1) | scope_len(2) | scope
       | ephemeral_x25519(32) | mlkem_ct_len(4) | mlkem_ct
       | entry_count(2) | [key_id(8) | wrapped_len(2) | wrapped(N) | nonce(12)] ...
       | nonce(12) | ct_len(8) | ciphertext | tag(16) | spend_pub(32) | signature(64)
```

Version 1 envelopes omit `access_mode` (implicitly `Recipient`). Version 2+ includes it.

### Sectioned Binary Format

Sectioned envelopes use a distinct `ROKS` magic header:

```
ROKS (4 bytes magic)
version (u32 LE)
section_count (u16 LE)
For each section:
  name_len (u16 LE) | name (UTF-8)
  envelope_len (u32 LE) | EncryptedEnvelope::to_bytes() (complete inner envelope with ROK\x01 header)
```

### Protocol Buffers

Defined in `proto/rok/`:

| File | Messages |
|---|---|
| `keys.proto` | `SpendPublicKey`, `ReadPublicKey`, `ExportedReadKey`, `PqPublicKey` |
| `envelope.proto` | `EncryptedEnvelope`, `AccessEntry`, `SectionedEnvelope`, `SectionedSection`, `Algorithm` enum, `AccessMode` enum |
| `keyring.proto` | `Keyring`, `KeyringEntry`, `EncryptedSpendKey`, `EncryptedReadKey` |
| `access.proto` | `AccessPolicy`, `AccessRule`, `RevocationList`, `RevocationEntry` |

## Security Model

### Threat Model

| Threat | Mitigation |
|---|---|
| Compromised read key | Only decrypts data at or below its scope — parent and sibling scopes remain safe |
| Quantum adversary (harvest-now, decrypt-later) | Hybrid X25519 + ML-KEM-768 mode; secure if either primitive holds |
| Ciphertext tampering | Ed25519 signature on every envelope; ChaCha20-Poly1305 AEAD on payload |
| Key ID collision | SHA-256 truncated to 8 bytes (birthday bound ~2^32); key IDs are convenience identifiers, not security-critical |
| Cross-protocol attacks | HKDF domain separation tags prevent key material reuse across derivation contexts |
| Secret leakage | All secrets implement `Zeroize` + `Drop`; sensitive memory is cleared automatically |
| Deterministic derivation | Same spend seed always produces the same key hierarchy — recoverable from seed alone |

### Scope Access Rules

1. A read key at scope `S` can decrypt data encrypted at scope `S`
2. A read key at scope `S` can decrypt data encrypted at any descendant of `S`
3. A read key **cannot** decrypt data at any ancestor or sibling scope
4. The root read key (scope `/`) can decrypt everything
5. Delegated keys can derive children but never escalate to parent access
6. In **scope-based mode**, ancestor keys auto-derive to the envelope's scope—only one access entry is needed regardless of how many key holders exist

## CI/CD

GitHub Actions runs on every push to `main` and on pull requests:

| Job | Command | Purpose |
|---|---|---|
| **check** | `cargo check --workspace` | Compilation check |
| **test** | `cargo test --workspace` | Run all 136 tests |
| **clippy** | `cargo clippy --workspace -- -D warnings` | Lint (warnings are errors) |
| **fmt** | `cargo fmt --all -- --check` | Formatting check |
| **deny** | `cargo deny check` | Supply chain audit (CVEs, licenses, sources) |

### Supply Chain Security

Enforced via `cargo-deny` (`deny.toml`):

- **Advisories**: Known vulnerabilities are denied; unmaintained crates warn
- **Licenses**: Only permissive licenses allowed (MIT, Apache-2.0, BSD-2/3, ISC)
- **Bans**: Wildcard dependencies denied; duplicate versions warn
- **Sources**: Only crates.io allowed; unknown registries and git sources denied

## Testing

```bash
# Run all tests
cargo test --workspace

# Run only core tests
cargo test -p rok-core

# Run integration tests
cargo test -p rok-core --test full_flow
```

### Integration Test Coverage

The `full_flow` test suite (`crates/rok-core/tests/full_flow.rs`) covers:

| Test | Scenario |
|---|---|
| `test_full_lifecycle` | Keygen, derive, encrypt, serialize (binary), decrypt |
| `test_full_lifecycle_protobuf` | Full lifecycle with protobuf serialization |
| `test_multi_level_delegation` | Three-level hierarchy with ancestor access and sibling isolation |
| `test_key_export_import_decrypt` | Export read key, re-import, decrypt successfully |
| `test_key_encoding_roundtrip` | Base58 round-trip for spend public, read public, exported keys |
| `test_sign_verify_flow` | Ed25519 sign and verify with tamper detection |
| `test_cross_scope_isolation` | `/finance` vs `/legal` — verifies scope boundary enforcement |
| `test_deterministic_derivation` | Same seed produces identical key hierarchy |
| `test_binary_serialization_preserves_all_fields` | Multi-recipient envelope round-trip integrity |
| `test_tampered_envelope_rejected` | Signature verification catches modified ciphertext |
| `test_scope_based_exact_scope_decrypts` | Scope-based encrypt at `/finance/q1`, decrypt with exact scope key |
| `test_scope_based_ancestor_decrypts` | Scope-based encrypt, ancestor keys (`/finance`, `/`) auto-derive to decrypt |
| `test_scope_based_sibling_rejected` | `/legal` key cannot decrypt scope-based `/finance/q1` envelope |
| `test_scope_based_child_rejected` | `/finance/q1` key cannot decrypt scope-based `/finance` envelope |
| `test_scope_based_single_access_entry` | Verifies exactly one access entry is created |
| `test_scope_based_binary_roundtrip` | Binary serialize/deserialize + decrypt with ancestor key |
| `test_scope_based_proto_roundtrip` | Proto serialize/deserialize + decrypt with root key |
| `test_scope_based_tamper_rejected` | Tampered ciphertext caught by signature verification |
| `test_sectioned_finance_legal` | Sectioned envelope with `/finance` + `/legal`; root decrypts both, scoped keys decrypt only their section |
| `test_sectioned_scope_based` | All sections scope-based; ancestor key decrypts accessible sections |
| `test_sectioned_binary_proto_roundtrip` | Serialize sectioned envelope both ways (binary + proto), decrypt from restored |
| `test_sectioned_mixed_algorithms` | One section classical, one hybrid; both decrypt correctly |

## Project Structure

```
read-only-keys/
├── Cargo.toml                    # Workspace root
├── deny.toml                     # Supply chain security policy
├── proto/rok/                    # Protocol Buffer definitions
│   ├── keys.proto
│   ├── envelope.proto
│   ├── keyring.proto
│   └── access.proto
├── .github/workflows/ci.yml     # CI pipeline
└── crates/
    ├── rok-core/                 # Core cryptographic primitives
    │   ├── build.rs              # Protobuf code generation
    │   ├── src/
    │   │   ├── lib.rs
    │   │   ├── derive.rs         # HKDF key derivation
    │   │   ├── encrypt.rs        # EncryptBuilder, decrypt
    │   │   ├── envelope.rs       # Wire format (binary + proto)
    │   │   ├── sign.rs           # Ed25519 signing
    │   │   ├── encoding.rs       # Base58 with checksums
    │   │   ├── proto.rs          # Protobuf conversions
    │   │   ├── sectioned.rs      # Sectioned envelope (multi-scope container)
    │   │   ├── keys/
    │   │   │   ├── spend.rs      # SpendKeyPair (Ed25519)
    │   │   │   ├── read.rs       # ReadKeyPair (X25519, hierarchical)
    │   │   │   ├── scope.rs      # Validated scope paths
    │   │   │   └── key_id.rs     # 8-byte key identifiers
    │   │   └── generated/rok.rs  # prost-generated types
    │   └── tests/full_flow.rs    # Integration tests
    ├── rok-pq/                   # Post-quantum module
    │   └── src/
    │       ├── kem.rs            # ML-KEM-768 wrapper
    │       ├── hybrid.rs         # X25519 + ML-KEM combiner
    │       ├── pq_derive.rs      # Deterministic PQ key derivation
    │       └── envelope.rs       # Hybrid encrypt/decrypt envelopes
    ├── rok-sdk/                  # High-level SDK
    │   └── src/
    │       ├── vault.rs          # Encrypted document vault
    │       ├── pipeline.rs       # Streaming encryption pipeline
    │       ├── policy.rs         # Declarative access policy
    │       ├── identity.rs       # Selective disclosure credentials
    │       └── keyring.rs        # MemoryKeyring implementation
    ├── rok-mcp/                  # MCP server for Claude Code
    │   └── src/
    │       ├── main.rs           # Entry point, --dump/--status CLI flags
    │       ├── tools.rs          # 9 MCP tools (login, write, sync, etc.)
    │       ├── session.rs        # Session state, role detection, config
    │       └── resources.rs      # MCP resource provider
    └── rok-cli/                  # Command-line tool
        └── src/
            ├── main.rs
            ├── cli.rs            # Clap command definitions
            ├── output.rs         # Output formatting (text/JSON)
            └── commands/
                ├── encrypt.rs
                ├── decrypt.rs
                ├── encrypt_sections.rs  # Sectioned encrypt
                ├── decrypt_sections.rs  # Sectioned decrypt
                ├── sign.rs
                ├── verify.rs
                ├── inspect.rs
                ├── keyring.rs
                └── revoke.rs
```

## License

MIT OR Apache-2.0
