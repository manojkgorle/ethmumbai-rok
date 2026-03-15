#!/usr/bin/env bash
# Prompt Claude to sync accumulated context at conversation end.
# Stop hook — output is injected into Claude's context before shutdown.

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
