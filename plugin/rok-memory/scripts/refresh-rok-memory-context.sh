#!/usr/bin/env bash
# Refresh rok-memory dump into a Cursor rule so it's injected at session start.
# Run from plugin dir or set WORKSPACE_ROOT to the project root where .cursor/rules lives.
# Requires: rok-mcp on PATH, ~/.rok/session.json with "autoLoad": true.

set -e

# Where to write the rule: workspace .cursor/rules/ (so Cursor picks it up at session start)
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$PWD}"
RULES_DIR="${WORKSPACE_ROOT}/.cursor/rules"
RULE_FILE="${RULES_DIR}/rok-memory-context.mdc"

mkdir -p "$RULES_DIR"

if ! command -v rok-mcp &>/dev/null; then
  cat > "$RULE_FILE" << 'STUB'
---
description: rok-memory context (run "Refresh rok-memory context" task to load)
alwaysApply: true
---

# rok-memory context

Not loaded. Install `rok-mcp` and run the **Refresh rok-memory context** task (Command Palette → "Tasks: Run Task").
STUB
  exit 0
fi

DUMP=$(rok-mcp --dump 2>/dev/null || true)

if [ -z "$DUMP" ]; then
  cat > "$RULE_FILE" << 'STUB'
---
description: rok-memory context (run "Refresh rok-memory context" task to load)
alwaysApply: true
---

# rok-memory context

No memories in context. Ensure `~/.rok/session.json` has `"autoLoad": true` and you have memories, then run the **Refresh rok-memory context** task.
STUB
  exit 0
fi

{
  echo '---'
  echo 'description: rok-memory context (refreshed by refresh-rok-memory-context.sh)'
  echo 'alwaysApply: true'
  echo '---'
  echo ''
  echo '# rok-memory context'
  echo ''
  echo 'The following memories are loaded from rok-memory (Fileverse). Use them for project context.'
  echo ''
  printf '%s' "$DUMP"
} > "$RULE_FILE"
