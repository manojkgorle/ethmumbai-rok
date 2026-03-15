# rok-memory

Claude Code and Cursor plugin for encrypted decentralized memory backed by [Fileverse](https://fileverse.io).

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

### Cursor

All Cursor-related files live inside the plugin for easy installation:

| What | In plugin |
|------|-----------|
| Cursor manifest (rules, skills, MCP) | `.cursor-plugin/plugin.json` |
| MCP server config | `.cursor/mcp.json` |
| AutoLoad refresh script | `scripts/refresh-rok-memory-context.sh` |

To use it in Cursor:

- **From this repo:** Open the repo in Cursor; the plugin can be loaded from `plugin/rok-memory/`. Merge `plugin/rok-memory/.cursor/mcp.json` into your project's `.cursor/mcp.json` (or copy it if you have no other MCP servers).
- **MCP:** The plugin includes `.cursor/mcp.json`; merge it into your project's `.cursor/mcp.json`. Install the binary from the workspace (or from the repo that contains the plugin):

```bash
cargo install --path crates/rok-mcp
```

**Restart:** After adding or changing `.cursor/mcp.json`, fully quit and reopen Cursor so the rok-memory MCP server loads.

**Trigger / login:** You don’t “launch” the plugin — the MCP is available as soon as Cursor has loaded it. To start a session you can:

1. **Pre-configure (recommended):** Create `~/.rok/session.json` with `apiKey`, `fileverseUrl`, and `spendSeed` (see [Credentials](#credentials)). The server will use it when tools run; no in-chat login needed.
2. **In chat:** In a Cursor Composer or chat, say e.g. “Set up rok memory” or “Log me into rok memory” — the AI will call `rok_memory:setup` (first-time config) or `rok_memory:login` (spend seed or read key + spend public). After that, “remember this”, “list my memories”, “store at /scope” etc. will use the memory tools.

To get **autoLoad-style context** (memories injected at session start), Cursor has no SessionStart hooks, so use the refresh script:

1. Ensure `~/.rok/session.json` has `"autoLoad": true`.
2. Run **Tasks: Run Task** → **Refresh rok-memory context** (or run `WORKSPACE_ROOT=/path/to/project bash plugin/rok-memory/scripts/refresh-rok-memory-context.sh` from the project root).
3. The script writes the current memory dump into `.cursor/rules/rok-memory-context.mdc` with `alwaysApply: true`, so Cursor injects it at the start of each new chat.

Run the task when you start work or when you want to refresh context; new chats will include the latest memories until you run it again.

### How Cursor plugins are installed (and how this one fits)

Cursor installs plugins in two main ways:

1. **From the Cursor Marketplace** — Users open the marketplace in Cursor (or [cursor.com/marketplace](https://cursor.com/marketplace)), browse or search, and click Install. Plugins are Git repositories submitted to Cursor and reviewed before listing. They can be scoped to a project or installed at the user level.
2. **From a team marketplace** — On Teams/Enterprise, admins add a GitHub repo as a team marketplace; developers see it in the marketplace panel and install from there (required plugins install automatically for their group).

A valid Cursor plugin is a directory with a **`.cursor-plugin/plugin.json`** manifest and standard folders: **`rules/`**, **`skills/`**, **`.mcp.json`** (at plugin root), and optionally `hooks/`, `agents/`, `commands/`. Cursor discovers these automatically. Multi-plugin repos put a **`.cursor-plugin/marketplace.json`** at the **repository root** listing each plugin by `name` and `source` (path to the plugin directory).

**This plugin is compatible** with that model: it has `.cursor-plugin/plugin.json`, `rules/`, `skills/`, and `.mcp.json` in `plugin/rok-memory/`. This repo also has `.cursor-plugin/marketplace.json` at the repo root with `"source": "./plugin/rok-memory"`, so the whole repo can be added as a team marketplace and rok-memory installed from it. For the official Cursor Marketplace, the repo would need to be submitted at [cursor.com/marketplace/publish](https://cursor.com/marketplace/publish). The extra files (`.cursor/mcp.json` for copy-merge, `scripts/refresh-rok-memory-context.sh`) are for convenience and do not affect Cursor’s discovery.

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

Or skip this and call `rok_memory:login` in conversation.

## Usage

Once installed, the plugin exposes 10 tools that Claude uses automatically when you interact with memories.

### Owner (has spend seed)

```
> store "ChaCha20 chosen over AES for performance" at /engineering/decisions
  → rok_memory:write(scope="/engineering/decisions", key="chacha20-rationale", content="...")

> list my memories
  → rok_memory:list()

> grant alice access to /engineering
  → rok_memory:grant(scope="/engineering")
  → returns read_key + spend_public for alice
```

### Agent (has read key)

```
> what decisions were made about encryption?
  → rok_memory:read(scope="/engineering/decisions", key="chacha20-rationale")

> remember that we benchmarked AES too
  → rok_memory:propose(scope="/engineering/decisions", key="aes-benchmark", content="...")
  → staged as proposal — owner must accept
```

## Tools

| Tool | Role | Description |
|------|------|-------------|
| `rok_memory:setup` | any | Configure credentials, write `~/.rok/session.json`, and start a session |
| `rok_memory:login` | any | Start session with spend_seed (owner) or read_key + spend_public (agent) |
| `rok_memory:logout` | any | End session, zeroize credentials from memory |
| `rok_memory:list` | any | List all memories accessible from session scope |
| `rok_memory:read` | any | Decrypt and return a memory by scope + key |
| `rok_memory:write` | owner | Encrypt and store a memory |
| `rok_memory:grant` | owner | Export a scoped read key for delegation |
| `rok_memory:propose` | any | Agent stages a write; owner accepts it |
| `rok_memory:sync` | any | Batch upsert with dedup; owner writes, agent proposes |
| `rok_memory:status` | any | Show session role, scope, memory count |

## Auto-sync

When `autoLoad` is enabled in `~/.rok/session.json`, the plugin automatically syncs context at conversation end:

1. **SessionStart hook** loads all memories into Claude's context
2. During the conversation, Claude works normally (and can call `rok_write` explicitly)
3. **Stop hook** fires at conversation end — it dumps current memories, then prompts Claude to call `rok_memory:sync` with any new knowledge worth persisting

Enable it by adding `"autoLoad": true` to your session config:

```json
{
  "apiKey": "your-fileverse-api-key",
  "fileverseUrl": "http://127.0.0.1:8001",
  "spendSeed": "64-hex-char-spend-seed",
  "autoLoad": true
}
```

`rok_memory:sync` performs batch upsert with dedup — it reads each memory before writing and skips unchanged entries to avoid unnecessary re-encryption and Fileverse round-trips. For agents, changes are staged as proposals.

### CLI flags

The `rok-mcp` binary supports two flags used by hooks:

| Flag | Purpose |
|------|---------|
| `--dump` | Print all decrypted memories to stdout (SessionStart hook in Claude Code; in Cursor, used by the refresh-rok-memory-context script) |
| `--status` | Print session status as JSON (used by Stop hook to gate auto-sync) |

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

GPL-3.0 with an additional restriction: modified versions of this software may not be used for commercial purposes. See [LICENSE](LICENSE) for the full terms.
