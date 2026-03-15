# Auto-sync: Persist conversation context to Fileverse

## Problem

As the user works in a project, Claude accumulates context — decisions made, patterns discovered, bugs fixed, architecture changes. This context is valuable but ephemeral — it dies when the conversation ends. Currently the user must explicitly say "remember this" for Claude to call `rok_memory:write`.

## Solution

A Stop hook that prompts Claude to review what it learned and sync meaningful updates to Fileverse automatically at conversation end.

## Flow

```
Session Start                During Work               Conversation End
┌──────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│SessionStart  │     │ Direct writes via    │     │ Stop hook fires  │
│hook: --dump  │────▶│ rok_memory:write work│────▶│ Prompts Claude:  │
│inject context│     │ as before            │     │ "what did you    │
└──────────────┘     └──────────────────────┘     │  learn? sync it" │
                                                  │ Claude calls     │
                                                  │ rok_memory:sync  │
                                                  └──────────────────┘
```

## Implementation steps

### Step 1: New `rok_memory:sync` MCP tool

**File:** `crates/rok-mcp/src/tools.rs`

Batch upsert with dedup:

```rust
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SyncEntry {
    pub scope: String,
    pub key: String,
    pub content: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SyncParams {
    /// List of memories to upsert.
    pub entries: Vec<SyncEntry>,
}
```

For each entry:
1. Read existing value via `MemoryReader::read` (if any)
2. If content unchanged → skip (dedup, avoids re-encrypting)
3. If owner → `MemoryStore::write` directly to Fileverse
4. If agent → stage as proposal (same behavior as `rok_memory:propose`)

Add `"mcp__rok-memory__rok_memory:sync"` to `ROK_PERMISSIONS` in `ensure_permissions()`.

### Step 2: New `--status` CLI flag

**File:** `crates/rok-mcp/src/main.rs`

Lightweight session check for hooks. Loads `session.json`, validates, prints JSON:

```json
{"active": true, "role": "owner", "auto_load": true, "memory_count": 5}
```

No Fileverse call needed — just config validation.

### Step 3: Stop hook script

**File:** `plugin/rok-memory/hooks/auto-sync.sh`

```bash
#!/usr/bin/env bash
# Prompt Claude to sync accumulated context at conversation end.

if ! command -v rok-mcp &>/dev/null; then
    exit 0
fi

STATUS=$(rok-mcp --status 2>/dev/null)
if [ $? -ne 0 ]; then
    exit 0
fi

AUTO=$(echo "$STATUS" | grep -o '"auto_load":true')
if [ -z "$AUTO" ]; then
    exit 0
fi

ROLE=$(echo "$STATUS" | grep -o '"role":"[^"]*"' | cut -d'"' -f4)

CURRENT=$(rok-mcp --dump 2>/dev/null)

cat <<EOF
[rok-memory auto-sync] Review this conversation for new knowledge worth persisting.

Current memories:
${CURRENT:-"(none)"}

Instructions:
- Compare what you learned in this conversation against the memories above.
- If there are meaningful updates (decisions, patterns, bugs fixed, architecture changes), call rok_memory:sync with the updates.
- Merge updates into existing entries rather than creating duplicates.
- Use descriptive scopes (e.g. /project/decisions, /project/architecture).
- If nothing new was learned, do nothing.
- Role: ${ROLE} $([ "$ROLE" = "agent" ] && echo "(changes will be staged as proposals)")
EOF
```

### Step 4: Register Stop hook

**File:** `plugin/rok-memory/hooks/hooks.json`

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/hooks/auto-load.sh",
            "timeout": 30
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/hooks/auto-sync.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

### Step 5: Update SKILL.md

Add `rok_memory:sync` to tools table and document auto-sync behavior.

## Design decisions

### Why Claude decides what to sync (not code)

Building change-tracking in Rust would be complex and fragile. Claude already has full conversation context and is good at summarizing what matters. The hook provides the baseline (current memories) and the prompt — Claude does the thinking.

### Role handling

- **Owner**: `rok_memory:sync` writes directly to Fileverse
- **Agent**: `rok_memory:sync` stages proposals

### Dedup

Before writing, read the existing value. If content is identical, skip. This avoids re-encrypting unchanged memories and wasting Fileverse round-trips.

### Config

Reuses `autoLoad: true` in `~/.rok/session.json` as the gate for both auto-load and auto-sync. Can split into a separate `autoSync` field later if needed.

## Edge cases

| Scenario | Handling |
|----------|----------|
| Nothing new learned | Claude calls nothing — Stop hook output is ignored |
| Stop hook timeout (30s) | Claude has limited time — keep sync prompt concise |
| Concurrent sessions | Last write wins per scope/key. Acceptable for single-user |
| Large memory set in --dump | Text output may be large. Switch to scope/key listing if needed |
| Agent proposals | Printed as text — owner sees them next session |
| Idempotent re-sync | Dedup prevents duplicate writes if conversation restarts |
