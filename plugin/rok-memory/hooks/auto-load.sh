#!/usr/bin/env bash
# Auto-load rok memories into Claude's context.
# Calls rok-mcp --dump which reads session.json, fetches all memories,
# and prints them to stdout. The output gets injected into context.

if ! command -v rok-mcp &>/dev/null; then
    exit 0
fi

rok-mcp --dump 2>/dev/null
