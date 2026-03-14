---
name: rok-memory
description: >
  Encrypted decentralized memory layer backed by Fileverse via the rok-mcp server.
  Proactively loads memories at conversation start if autoLoad is configured.
  Triggers on: "list/read/write/grant memories", "store this at /scope",
  "grant access", "remember this", "rok setup", or any memory CRUD operation.
---

# rok Memory — Plugin Guide

All operations go through `rok_memory:*` MCP tools.

## Tools

| Tool | Role | Purpose |
|------|------|---------|
| `rok_memory:setup` | any | Configure credentials and write ~/.rok/session.json |
| `rok_memory:login` | any | Start session (if not using setup/auto-config) |
| `rok_memory:logout` | any | End session, zeroize credentials |
| `rok_memory:list` | any | List all accessible memories |
| `rok_memory:read` | any | Decrypt a memory by scope + key |
| `rok_memory:write` | owner | Encrypt and store a memory |
| `rok_memory:grant` | owner | Export a scoped read key for delegation |
| `rok_memory:propose` | any | Stage (agent) or accept (owner) a proposed write |
| `rok_memory:status` | any | Show session role, scope, memory count |

## Roles

- **Owner** (has spend seed): full read/write/grant/propose
- **Agent** (has read key + spend public): read-only + propose via staging

## When to write memories

When the user says "remember this", "store this", "save to memory", or similar:
- **Owner**: call `rok_memory:write` with scope and key
- **Agent**: call `rok_memory:propose` to stage the change

## Notes

- Never echo spend seeds, read keys, or API keys in output
- Scope hierarchy: `/finance` can read `/finance/q1` but not `/engineering`
- Resources available at `rok://memory/{scope}/{key}`
