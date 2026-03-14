# rok-memory

Claude Code plugin for encrypted decentralized memory backed by [Fileverse](https://fileverse.io).

End-to-end encrypted, hierarchically scoped, with key delegation — no plaintext ever leaves your machine.

## Install

### From the marketplace

```bash
# Add the marketplace
/plugin marketplace add manojkgorle/rok

# Install the plugin
/plugin install rok-memory@rok-plugins
```

### From local checkout

```bash
git clone https://github.com/manojkgorle/rok
claude --plugin-dir rok/plugin/rok-memory
```

### Manual

```bash
# Install the MCP server binary
cargo install --git https://github.com/manojkgorle/rok rok-mcp

# Add to your Claude Code MCP settings (~/.claude.json)
{
  "mcpServers": {
    "rok-memory": {
      "command": "rok-mcp"
    }
  }
}
```

## Setup

### Prerequisites

- Rust toolchain (`cargo`) — [install](https://rustup.rs)
- A running Fileverse API server (default: `http://127.0.0.1:8001`)

### Credentials

Create `~/.rok/session.json` for auto-login on startup:

```json
{
  "apiKey": "your-fileverse-api-key",
  "fileverseUrl": "http://127.0.0.1:8001",
  "spendSeed": "64-hex-char-spend-seed"
}
```

```bash
chmod 600 ~/.rok/session.json
```

Or skip this and call `rok_login` in conversation.

## Usage

Once installed, the plugin exposes 8 tools that Claude uses automatically when you interact with memories.

### Owner (has spend seed)

```
> store "ChaCha20 chosen over AES for performance" at /engineering/decisions
  → rok_write(scope="/engineering/decisions", key="chacha20-rationale", content="...")

> list my memories
  → rok_list()

> grant alice access to /engineering
  → rok_grant(scope="/engineering")
  → returns read_key + spend_public for alice
```

### Agent (has read key)

```
> what decisions were made about encryption?
  → rok_read(scope="/engineering/decisions", key="chacha20-rationale")

> remember that we benchmarked AES too
  → rok_propose(scope="/engineering/decisions", key="aes-benchmark", content="...")
  → staged as proposal — owner must accept
```

## Tools

| Tool | Role | Description |
|------|------|-------------|
| `rok_login` | any | Start session with spend_seed (owner) or read_key + spend_public (agent) |
| `rok_logout` | any | End session, zeroize credentials from memory |
| `rok_list` | any | List all memories accessible from session scope |
| `rok_read` | any | Decrypt and return a memory by scope + key |
| `rok_write` | owner | Encrypt and store a memory |
| `rok_grant` | owner | Export a scoped read key for delegation |
| `rok_propose` | any | Agent stages a write; owner accepts it |
| `rok_status` | any | Show session role, scope, memory count |

## How it works

```
You ──→ Claude Code ──→ rok-mcp (MCP server) ──→ Fileverse API
                              │
                    rok-core: encrypt/decrypt
                    rok-sdk:  MemoryStore/Reader
```

- **Encryption**: ChaCha20-Poly1305 (data) + AES-256-GCM-SIV (key wrapping) + X25519 ECDH
- **Key hierarchy**: A spend seed derives a root read key. Child keys are derived per scope via HKDF-SHA256. A key at `/finance` can read `/finance/q1` but not `/engineering`.
- **Scope-based access**: Memories are encrypted to a scope. Any ancestor key can decrypt via auto-derivation. Sibling scopes are cryptographically isolated.
- **Storage**: Fileverse stores opaque ciphertext blobs. The server never sees plaintext.

## Resources

Each memory is also exposed as an MCP resource at `rok://memory/{scope}/{key}`. Clients that support MCP resources can browse memories directly.

## License

MIT OR Apache-2.0
