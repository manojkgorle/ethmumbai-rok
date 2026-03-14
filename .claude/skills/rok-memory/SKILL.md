---
name: rok-memory
description: >
  Encrypted decentralized memory layer backed by Fileverse. Automatically bootstraps
  a session (keys + connectivity), fetches scoped memories into local context, uses them
  throughout the workflow, and writes back changes on teardown. Triggers on: conversation
  start if .rok-scope exists, "list/read/write/grant memories", "store this at /scope",
  "grant access", "sync memories", "rok init", or any rok memory CRUD operation.
---

# rok Memory — Session Lifecycle Skill

Manage encrypted hierarchical memories on Fileverse with automatic session bootstrap,
context-aware retrieval, and conflict-safe writeback.

Supports two access roles:
- **Owner** (has spend seed) — full read/write/grant/propose
- **Agent** (has scoped read key + spend public only) — read-only + propose via staging

## Architecture

```
 SESSION START              DURING WORK                SESSION END
┌──────────────-┐     ┌─────────────────────┐     ┌─────────────────┐
│ 1. Bootstrap  │────▶│ 2. Context is live  │────▶│ 3. Teardown     │
│    detect role│     │    read/search/edit │     │    diff & sync  │
│    fetch all  │     │    memories in-place│     │    writeback or │
│    materialize│     │    track mutations  │     │    stage proposals│
└──────────────-┘     └─────────────────────┘     └─────────────────┘
```

---

## Phase 1 — Session Bootstrap

Run this at the START of any conversation that needs rok memory, or when the user
says "rok init", "load memories", "fetch context", etc.

### Step 1: Detect role and resolve credentials

Determine the **session role** based on what credentials are available.
Check sources in order (stop at first hit for each):

#### Credential resolution table

| Credential         | Source 1 (env)         | Source 2 (dotfile)                       | Source 3 (ask user) |
|--------------------|------------------------|------------------------------------------|---------------------|
| `FILEVERSE_API_KEY`| `$FILEVERSE_API_KEY`   | `~/.rok/session.json` → `.apiKey`        | Prompt once          |
| `FILEVERSE_URL`    | `$FILEVERSE_URL`       | `~/.rok/session.json` → `.fileverseUrl`  | Default: `http://127.0.0.1:8001` |
| `SPEND_SEED`       | `$ROK_SPEND_SEED`      | `~/.rok/session.json` → `.spendSeed`     | *(optional)*         |
| `READ_KEY`         | `$ROK_READ_KEY`        | `~/.rok/session.json` → `.readKey`       | *(optional)*         |
| `SPEND_PUBLIC`     | `$ROK_SPEND_PUBLIC`    | `~/.rok/session.json` → `.spendPublic`   | *(optional)*         |

#### Role detection logic

```
if SPEND_SEED is available:
    role = OWNER
    → can derive any read key on the fly
    → can write, grant, propose
    → READ_KEY and SPEND_PUBLIC are derived (not needed from user)

else if READ_KEY and SPEND_PUBLIC are available:
    role = AGENT
    → read-only at the key's scope and descendants
    → cannot write directly; changes are staged locally as proposals
    → cannot grant sub-keys

else:
    → ask user: "Do you have a spend seed (owner) or a read key (agent)?"
    → if they provide a read key, also ask for the spend public key
```

**IMPORTANT**: Never echo, log, or display the spend seed, read key, or API key in output.

#### Persist credentials (offer once)

```bash
mkdir -p ~/.rok && cat > ~/.rok/session.json << 'ENDJSON'
{
  "apiKey": "<value>",
  "fileverseUrl": "http://127.0.0.1:8001",
  "spendSeed": "<value-or-null>",
  "readKey": "<value-or-null>",
  "spendPublic": "<value-or-null>"
}
ENDJSON
chmod 600 ~/.rok/session.json
```

### Step 2: Verify connectivity

```bash
curl -sf "$ROK_URL/ping"
```

If this fails: "Fileverse server is not reachable at $ROK_URL. Start it with `fileverse-api` or set FILEVERSE_URL."

### Step 3: Resolve scope and derive session keys

Check for a `.rok-scope` file in the project root or `~/.rok/default-scope`:

```bash
SESSION_SCOPE=$(cat .rok-scope 2>/dev/null || cat ~/.rok/default-scope 2>/dev/null || echo "/")
```

#### If role = OWNER

Derive a read key for the session scope from the spend seed:

```bash
GRANT_OUTPUT=$(cargo run --bin rok -- memory grant \
  --scope "$SESSION_SCOPE" \
  --spend-seed "$ROK_SPEND_SEED" \
  --api-key "$ROK_API_KEY" 2>&1)

ROK_READ_KEY=$(echo "$GRANT_OUTPUT" | grep "Exported Key:" | awk '{print $NF}')
ROK_SPEND_PUBLIC=$(echo "$GRANT_OUTPUT" | grep "Spend Public:" | awk '{print $NF}')
```

#### If role = AGENT

Use the provided read key and spend public directly. The scope is **embedded in the
read key** — the key already constrains what you can access. If the user also provided
a `.rok-scope`, validate it matches or is a descendant of the key's scope (the `list`
command will simply return nothing if the key can't reach that scope).

```bash
# Already have these from credential resolution:
ROK_READ_KEY="$READ_KEY"
ROK_SPEND_PUBLIC="$SPEND_PUBLIC"
```

### Step 4: Fetch and materialize memories

```bash
mkdir -p /tmp/rok-context

# List all accessible memories (works for both roles)
cargo run --bin rok -- memory list \
  --key "$ROK_READ_KEY" \
  --spend-public "$ROK_SPEND_PUBLIC" \
  --api-key "$ROK_API_KEY"
```

For each memory entry returned, fetch full content into a local mirror:

```bash
# For each (scope, name) pair from the list:
cargo run --bin rok -- memory read \
  --scope "$SCOPE" \
  --name "$NAME" \
  --key "$ROK_READ_KEY" \
  --spend-public "$ROK_SPEND_PUBLIC" \
  --api-key "$ROK_API_KEY" \
  --output "/tmp/rok-context${SCOPE}/${NAME}.md"
```

Creates a local tree:

```
/tmp/rok-context/
  engineering/
    decision-log.md
    patterns.md
  finance/
    q1-report.md
```

### Step 5: Build context index and record role

```bash
# Checksums for change detection
find /tmp/rok-context -type f -exec md5 {} \; > /tmp/rok-context/.manifest

# Persist session role for teardown
echo "$ROLE" > /tmp/rok-context/.role
```

Print summary:

```
rok memory session started
  Role: OWNER | AGENT (scope: /engineering)
  Memories loaded: 5
  Local mirror: /tmp/rok-context/
  Capabilities: read, write, grant | read-only, propose
```

Read the materialized files to load them into your working context.

---

## Phase 2 — Working With Memories

During the conversation, memories are live local files. Use them naturally.

### Reading / searching memories (OWNER + AGENT)

When the user asks about past decisions, patterns, or stored knowledge:

1. Search `/tmp/rok-context/` with Grep or Read — don't re-fetch from Fileverse
2. Reference the memory by scope and name: "From `/engineering/decision-log`: ..."

### Writing / updating memories (OWNER only)

When the user says "remember this", "store this", "update the decision log":

1. **Edit the local file** in `/tmp/rok-context/` (or create a new one)
2. The teardown phase will detect changes via manifest diff and write them back

### Staging proposals (AGENT only)

When the user wants to save something but the session role is AGENT:

1. **Edit or create the local file** in `/tmp/rok-context/` as usual
2. Also record the intent in `/tmp/rok-context/.proposals`:

```
NEW /engineering/api-patterns "Discovered consistent auth pattern"
MODIFIED /engineering/decision-log "Added ChaCha20 benchmark results"
```

3. Tell the user: "Staged as a proposal. The owner will need to accept this with
   their spend seed for it to be persisted on Fileverse."

The teardown phase handles these differently based on role.

### Granting access (OWNER only)

When the user says "grant X access to /scope":

```bash
cargo run --bin rok -- memory grant \
  --scope "/target-scope" \
  --spend-seed "$ROK_SPEND_SEED" \
  --api-key "$ROK_API_KEY"
```

Return the exported key and spend public. Explain scope coverage.

If role is AGENT and user asks to grant: explain that granting requires the spend seed.
Only the owner can delegate access.

### Deriving a narrower key (OWNER only)

If the user wants to share access to a sub-scope only:

```bash
cargo run --bin rok -- memory grant \
  --scope "/engineering/frontend" \
  --spend-seed "$ROK_SPEND_SEED" \
  --api-key "$ROK_API_KEY"
```

The resulting key can read `/engineering/frontend` and below, but NOT `/engineering/backend`.

---

## Phase 3 — Teardown (Sync & Writeback)

Run when the user says "sync memories", "save and close", "push changes",
or when the conversation is ending and local memories were modified.

### Step 1: Detect changes

```bash
find /tmp/rok-context -type f -not -name '.*' -exec md5 {} \; > /tmp/rok-context/.manifest-current
diff /tmp/rok-context/.manifest /tmp/rok-context/.manifest-current
```

Categorize: **new**, **modified**, **unchanged**, **deleted**.

### Step 2: Branch by role

Read the session role:

```bash
ROLE=$(cat /tmp/rok-context/.role)
```

---

### Teardown: OWNER path

#### Confirm with user

```
rok memory changes detected:
  MODIFIED  /engineering/decision-log  (added 3 lines)
  NEW       /engineering/api-patterns  (142 bytes)
  DELETED   /finance/old-report

Sync these to Fileverse? [y/n]
```

**Never auto-push without confirmation.**

#### Write back

For each **new** or **modified** memory:

```bash
cargo run --bin rok -- memory write \
  --scope "/engineering" \
  --key "decision-log" \
  --file "/tmp/rok-context/engineering/decision-log.md" \
  --spend-seed "$ROK_SPEND_SEED" \
  --api-key "$ROK_API_KEY"
```

For **deleted** memories: warn that Fileverse doesn't support deletion. Suggest
overwriting with a tombstone if needed.

---

### Teardown: AGENT path

Agents cannot write directly. Two options:

#### Option A: Export proposals as files (default)

Write all staged changes to a handoff directory the owner can review:

```bash
mkdir -p /tmp/rok-proposals
# Copy each changed file with metadata
cp /tmp/rok-context/engineering/api-patterns.md /tmp/rok-proposals/
cp /tmp/rok-context/.proposals /tmp/rok-proposals/MANIFEST.md
```

Tell the user:

```
rok agent session ending — 2 proposals staged
  NEW       /engineering/api-patterns  (142 bytes)
  MODIFIED  /engineering/decision-log  (added 3 lines)

Proposals saved to /tmp/rok-proposals/
The owner can accept these by running:

  rok memory propose \
    --scope "/engineering" --key "api-patterns" \
    --file /tmp/rok-proposals/api-patterns.md \
    --agent-id "claude-code" \
    --spend-seed <OWNER_SEED> \
    --api-key <API_KEY>
```

#### Option B: If owner spend seed becomes available

If during the conversation the user provides the spend seed (elevating to OWNER):

1. Update the session: `echo "OWNER" > /tmp/rok-context/.role`
2. Set `ROK_SPEND_SEED` for the session
3. Proceed with the OWNER teardown path

---

### Cleanup

```bash
rm -rf /tmp/rok-context
```

Print summary:

```
rok memory sync complete
  Role: OWNER → Written: 2, Skipped: 3
  Role: AGENT → Proposals: 2, Saved to: /tmp/rok-proposals/
```

---

## Quick Reference

### Owner commands (spend seed required)

```bash
# Write a memory
rok memory write --scope S --key K --data "..." --spend-seed $SEED --api-key $KEY

# Grant scoped access
rok memory grant --scope S --spend-seed $SEED --api-key $KEY

# Accept agent proposal
rok memory propose --scope S --key K --agent-id A --data "..." --spend-seed $SEED --api-key $KEY
```

### Agent commands (read key + spend public only)

```bash
# List accessible memories
rok memory list --key $READ_KEY --spend-public $SPEND_PUB --api-key $KEY

# Read a specific memory
rok memory read --scope S --name N --key $READ_KEY --spend-public $SPEND_PUB --api-key $KEY
```

### Capability matrix

| Action      | Owner | Agent | Notes |
|-------------|-------|-------|-------|
| **list**    |  yes  |  yes  | Scope determined by read key |
| **read**    |  yes  |  yes  | Can read at key's scope + descendants |
| **write**   |  yes  |  no   | Agent stages locally, owner writes back |
| **grant**   |  yes  |  no   | Only owner can delegate keys |
| **propose** |  yes  |  no*  | *Agent stages; owner runs `propose` to accept |

---

## Error Recovery

| Problem | Solution |
|---------|----------|
| Server unreachable | `fileverse-api` to start, or check `$ROK_URL` |
| "API key required" | Set `FILEVERSE_API_KEY` or update `~/.rok/session.json` |
| "spend seed must be 32 bytes" | Seed is 64 hex chars (32 bytes). Check format. |
| Read key won't decrypt | Key scope doesn't cover target. Need a higher-level key. |
| Agent tries to write | Stage as proposal. Inform user owner action is needed. |
| Agent tries to grant | Not possible. Only spend seed holder can grant. |
| Stale local context | Re-run Phase 1 Steps 4-5 to refresh from Fileverse. |
| Conflict (remote changed) | Re-fetch, show diff, ask user which version to keep. |
| Role escalation | User provides spend seed mid-session → update `.role` to OWNER. |

---

## Config Files

### `~/.rok/session.json` (credentials, chmod 600)

```json
{
  "apiKey": "fv-...",
  "fileverseUrl": "http://127.0.0.1:8001",
  "spendSeed": "a1b2c3...64hex",
  "readKey": null,
  "spendPublic": null
}
```

Owner config: `spendSeed` set, `readKey`/`spendPublic` null (derived on the fly).

Agent config: `spendSeed` null, `readKey` + `spendPublic` set.

### `.rok-scope` (project root, committed or gitignored)

```
/engineering
```

Sets the default session scope. If absent, defaults to `/` (root).
For agents, this is informational — the read key already constrains access.
