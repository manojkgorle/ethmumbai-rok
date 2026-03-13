# Security Audit Report — rok (Read-Only Keys)

**Auditor**: Senior security engineer (cryptography focus)  
**Date**: March 2025  
**Scope**: Full repository — rok-core, rok-pq, rok-sdk, rok-cli

---

## Executive Summary

The codebase implements a coherent dual-key system with hierarchical read-key delegation, AEAD encryption, and post-quantum hybrid support. **No critical cryptographic flaws** were found in the core design (sign-then-encrypt order, scope checks, key derivation, or algorithm choices). Several **medium- and low-severity** issues were identified: denial-of-service via malicious envelopes, secret handling in the CLI and in-memory lifetime of sensitive structs, and minor robustness issues in parsing/encoding.

---

## 1. High / Critical

*None identified.* Signature verification is performed before any decryption; scope checks and key lookup occur after authentication; HKDF domain separation and algorithm usage are correct.

---

## 2. Medium Severity

### 2.1 Allocation bomb / DoS in binary envelope parsing

**Location**: `crates/rok-core/src/envelope.rs` — `EncryptedEnvelope::from_bytes`

**Issue**: The binary wire format does not enforce maximum limits on:

- `scope_len` (u16 → up to 65,535 bytes)
- `entry_count` (u16 → up to 65,535 access entries)
- `wdk_len` per entry (u16 → up to 65,535 bytes per wrapped key)
- `ct_len` (u64)
- `mlkem_len` (u32)

A small malicious file can declare large lengths and trigger huge allocations (e.g. 65,535 entries × 65,535-byte wrapped keys), leading to memory exhaustion and DoS.

**Recommendation**: Enforce reasonable maxima before allocating, e.g.:

- `scope_len`: e.g. 2048 bytes
- `entry_count`: e.g. 1024
- `wdk_len`: e.g. 256 (AES-GCM-SIV output for 32-byte key + 12-byte nonce is fixed; reject anything larger)
- `ct_len`: e.g. 512 MiB
- `mlkem_len`: e.g. 2 KiB (ML-KEM-768 ciphertext is fixed size)

Reject parsing with a clear error if any declared length exceeds the limit.

---

### 2.2 CLI secrets in process listing and argv

**Location**: `crates/rok-cli` — all commands that take `--spend_seed` or `--key` (exported read key)

**Issue**: Spend seed and exported read keys are passed as CLI arguments. On many systems these appear in:

- Process listings (`ps`, `pgrep`, `/proc/*/cmdline`)
- Audit logs and shell history
- Process dump and core files

There is no option to read the spend seed (or key) from a file or from an environment variable, which would allow safer handling (e.g. `ROK_SPEND_SEED`, or `--spend_seed @/path/to/seed.file`).

**Recommendation**:

- Add support for reading the spend seed from an environment variable (e.g. `ROK_SPEND_SEED`) and/or from a file (e.g. `--spend_seed @file` or `--spend_seed-file`).
- Document that passing secrets on the command line is unsafe on shared or untrusted systems.
- Where possible, avoid keeping secret strings in `String`/`Vec` longer than necessary and consider zeroizing after use (see 2.4).

---

### 2.3 Hybrid encapsulation shared secret not zeroized on drop

**Location**: `crates/rok-pq/src/hybrid.rs` — `HybridEncapsulation`

**Issue**: `HybridEncapsulation` holds `combined_shared_secret: [u8; 32]`. The struct does not implement `Zeroize` or `Drop`. When the value goes out of scope, the combined key material may remain in memory, increasing exposure to later cold-boot or memory-scraping attacks.

**Recommendation**: Implement `Zeroize` and `ZeroizeOnDrop` for `HybridEncapsulation` (and any similar structs that hold KEM/ECDH shared secrets), and zeroize the secret in `Drop` before release.

---

### 2.4 Secrets not zeroized in CLI flows

**Location**: `crates/rok-cli/src/commands/encrypt.rs`, `decrypt.rs`, `derive.rs`, `grant.rs`, `sign.rs`, `revoke.rs`, `keyring.rs`

**Issue**:

- **Encrypt**: Decoded spend seed (`seed_bytes`, `seed`) and file plaintext are never zeroized after use.
- **Decrypt**: Decrypted plaintext buffer is not zeroized after being written to disk.
- **Other commands**: Spend seed is decoded into local buffers that are not zeroized.

Sensitive data therefore remains in process memory for the lifetime of the process (and possibly in core dumps).

**Recommendation**: Use `zeroize` (or equivalent) to clear:

- Spend seed bytes and any copies (e.g. in encrypt, derive, grant, sign, revoke, keyring).
- Decrypted plaintext in the decrypt command after writing to file (and on error paths where applicable).
- Consider wrapping secret CLI args in a type that zeroizes on drop where feasible.

---

## 3. Low Severity / Hardening

### 3.1 KeyId comparison not constant-time in decrypt path

**Location**: `crates/rok-core/src/encrypt.rs` — `decrypt()`

**Issue**: The matching access entry is found with:

```rust
let entry = envelope.access_entries.iter().find(|e| e.read_key_id == my_key_id)
```

`KeyId` implements `subtle::ConstantTimeEq`, but `==` uses `PartialEq`, so the comparison is not guaranteed to be constant-time. In theory this could leak which entry matched (e.g. position in the list) via timing.

**Recommendation**: When looking up the entry by key ID, use constant-time comparison (e.g. iterate and compare with `key_id.ct_eq()`, then select the matching entry without short-circuiting on the first match in a way that changes control flow). Alternatively, keep a single recipient or document that constant-time lookup is not required for the threat model.

---

### 3.2 Invalid `has_parent` in exported read key encoding

**Location**: `crates/rok-core/src/encoding.rs` — `decode_exported_read_key`

**Issue**: The payload byte at index 64 is interpreted as `has_parent`. Only `1` is treated as “has parent”; any other value (e.g. `2`) is treated as “no parent”. For invalid values this can yield incorrect `parent_key_id` and wrong scope parsing (scope starting at byte 65), leading to a malformed or confusing key.

**Recommendation**: Explicitly require `has_parent` to be 0 or 1; return `Err(RokError::EncodingError(...))` for any other value.

---

### 3.3 Protobuf envelope decoding without size limits

**Location**: `crates/rok-core/src/proto.rs` and generated protobuf decode

**Issue**: Envelope decoding from protobuf uses the decoder’s default behavior for repeated and length-delimited fields. Very large repeated fields or large ciphertexts could cause large allocations and similar DoS to the binary parser.

**Recommendation**: Where the protobuf API allows (e.g. custom decode or options), enforce the same kind of maximum lengths as recommended for the binary format (scope length, recipient count, ciphertext size, etc.). If not easily configurable, consider a two-phase decode (read length fields first, reject if over limit) or a size-bounded wrapper.

---

## 4. Positive Findings

- **Signature before decryption**: `decrypt()` verifies the spend key signature before any key unwrapping or plaintext decryption, avoiding oracle or downgrade issues.
- **Scope enforcement**: Scope checks (`read_key.can_access(&envelope.scope)`) are applied after verification and before using key material; hierarchy rules are clear and tested.
- **Domain separation**: HKDF uses distinct domain tags for spend→root read, read→child, key wrap, and hybrid combine, reducing cross-context key reuse risks.
- **KeyId constant-time trait**: `KeyId` implements `ConstantTimeEq`; the remaining issue is use of `==` in the decrypt path (see 3.1).
- **Scope validation**: Scope strings are validated (leading `/`, no `//`, allowed character set, no empty segments), and ancestor checks avoid prefix confusion (e.g. `/fin` vs `/finance`).
- **Sensitive types**: `ExportedReadKey` and key derivation paths zeroize where appropriate; `ReadKeyPair` and key derivation use `StaticSecret` and zeroize intermediates in critical paths.
- **Algorithm and primitives**: ChaCha20-Poly1305, AES-256-GCM-SIV, HKDF-SHA256, Ed25519, X25519, and ML-KEM-768 are used in a consistent and standard way.

---

## 5. Recommendations Summary

| Priority | Action |
|----------|--------|
| High    | Add strict length limits in `EncryptedEnvelope::from_bytes` (and equivalent for proto) to prevent allocation DoS. |
| Medium  | Provide env var or file-based input for spend seed (and optionally for read key) in the CLI. |
| Medium  | Implement `Zeroize`/`ZeroizeOnDrop` for `HybridEncapsulation` and zeroize combined shared secret on drop. |
| Medium  | Zeroize spend seed buffers and decrypted plaintext in CLI commands after use. |
| Low     | Use constant-time comparison when resolving the recipient access entry by key ID in `decrypt()`. |
| Low     | Reject invalid `has_parent` values in `decode_exported_read_key`. |
| Low     | Apply size limits to protobuf envelope decoding where possible. |

---

## 6. Scope Not Audited

- **deny.toml / supply chain**: Not reviewed in depth; the presence of advisory and license checks is noted.
- **Fuzzing / property-based tests**: Not run; recommended for envelope parsing and encoding/decoding.
- **Side-channel**: Only timing of key ID comparison was considered; no formal constant-time or side-channel review of underlying crates (e.g. dalek, ml-kem) was performed.

This report reflects a static review of the codebase and the described design. Operational security (key storage, deployment, key rotation) is out of scope.
