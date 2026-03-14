---
name: rok-memory
description: >
  Encrypted decentralized memory layer backed by Fileverse via the rok-mcp server.
  Triggers on: "list/read/write/grant memories", "store this at /scope",
  "grant access", "sync memories", "rok init", or any rok memory CRUD operation.
---

# rok Memory — MCP Plugin Guide

rok-mcp is an MCP server that manages encrypted hierarchical memories on Fileverse.
All operations go through MCP tools — no shell commands needed.

## Available Tools

| Tool | Role | Purpose |
|------|------|---------|
| `rok_login` | any | Start session with spend_seed (owner) or read_key+spend_public (agent) |
| `rok_logout` | any | End session, zeroize credentials |
| `rok_list` | any | List all accessible memories |
| `rok_read` | any | Decrypt a memory by scope + key |
| `rok_write` | owner | Encrypt and store a memory |
| `rok_grant` | owner | Export a scoped read key for delegation |
| `rok_propose` | any | Stage (agent) or accept (owner) a proposed write |
| `rok_status` | any | Show session role, scope, loaded count |

## Roles

- **Owner** (has spend seed): full read/write/grant/propose
- **Agent** (has read key + spend public): read-only + propose via staging

## Workflow

1. If `~/.rok/session.json` exists, the server auto-bootstraps a session on startup
2. Otherwise, call `rok_login` with credentials
3. Use `rok_list` / `rok_read` / `rok_write` to manage memories
4. Use `rok_grant` to delegate scoped access to agents
5. Call `rok_logout` when done (or let the server process end)

## Resources

Each memory is also exposed as an MCP resource at `rok://memory/{scope}/{key}`.
Clients that support MCP resources can browse and read memories directly.

## Notes

- Never echo spend seeds, read keys, or API keys in output
- Agent role cannot write directly — changes are staged as proposals
- Scope hierarchy: a key at `/finance` can read `/finance/q1` but not `/engineering`
- Config: `~/.rok/session.json` with `apiKey`, `fileverseUrl`, `spendSeed`, `readKey`, `spendPublic`
