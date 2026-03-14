---
name: rok-memory
description: Fetch, list, write, and manage encrypted scoped memories stored on Fileverse via the rok CLI. Use when the user wants to interact with rok's decentralized encrypted memory store — reading agent memories, writing new memories, granting scoped access to agents, or accepting agent proposals. Triggers on requests like "list my memories", "store this at /engineering", "grant finance access", or any rok memory CRUD operation.
---

# rok Memory

Manage encrypted hierarchical memories backed by Fileverse decentralized storage via the `rok` CLI.

## Prerequisites

Before running any command, verify:

1. `FILEVERSE_API_KEY` is set (or ask the user for it)
2. Fileverse server is running (`curl -s http://127.0.0.1:8001/ping` should return `{"reply":"pong"}`)
3. rok binary is built (`cargo build --bin rok` in the project root)

If the server isn't running, tell the user to start it with `fileverse-api`.

## Commands

All commands use this base:

```
cargo run --bin rok -- memory <subcommand> --api-key "$FILEVERSE_API_KEY"
```

### Write a memory

```bash
cargo run --bin rok -- memory write \
  --scope "/engineering" \
  --key "decision-log" \
  --data "We chose ChaCha20 for performance" \
  --spend-seed "$SPEND_SEED" \
  --api-key "$FILEVERSE_API_KEY"
```

Use `--file path/to/file` instead of `--data` for file content.

### Read a memory

```bash
cargo run --bin rok -- memory read \
  --scope "/finance" \
  --name "report" \
  --key "$READ_KEY" \
  --spend-seed "$SPEND_SEED" \
  --api-key "$FILEVERSE_API_KEY"
```

### List memories at a scope

```bash
cargo run --bin rok -- memory list \
  --key "$READ_KEY" \
  --spend-seed "$SPEND_SEED" \
  --api-key "$FILEVERSE_API_KEY"
```

### Grant scoped access to an agent

```bash
cargo run --bin rok -- memory grant \
  --scope "/finance" \
  --spend-seed "$SPEND_SEED" \
  --api-key "$FILEVERSE_API_KEY"
```

Returns a base58-encoded read key. The agent can decrypt memories at that scope and below.

### Accept an agent's proposed memory

```bash
cargo run --bin rok -- memory propose \
  --scope "/engineering" \
  --key "finding-2024" \
  --data "Found a pattern in auth module" \
  --agent-id "claude-code" \
  --spend-seed "$SPEND_SEED" \
  --api-key "$FILEVERSE_API_KEY"
```

## Workflow

1. Ask what the user wants: **list**, **read**, **write**, **grant**, or **propose**
2. Check `FILEVERSE_API_KEY` — if missing, ask the user
3. Ask for `--spend-seed` if not already known in conversation
4. For read/list: ask for the read key (`--key`) or offer to grant one first
5. Run the command and display results

## Key Concepts

- **Spend seed**: 64 hex chars, the owner's master key. Required for all operations.
- **Read key**: Base58-encoded, scoped. Grants read access at a scope and its descendants.
- **Scope**: Hierarchical path like `/`, `/finance`, `/finance/q1`. A `/finance` key can read `/finance/q1` but not `/engineering`.
- **Scope-based encryption**: Memories are encrypted so any ancestor read key auto-derives access. No per-recipient key management needed.
