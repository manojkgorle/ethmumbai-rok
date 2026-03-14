#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/manojkgorle/rok"
BINARY_NAME="rok-mcp"
CRATE_PATH="crates/rok-mcp"

echo "rok-memory plugin setup"
echo "======================="
echo ""

# Check for cargo
if ! command -v cargo &>/dev/null; then
    echo "Error: cargo (Rust toolchain) is required."
    echo "Install Rust: https://rustup.rs"
    exit 1
fi

# Check if already installed
if command -v "$BINARY_NAME" &>/dev/null; then
    INSTALLED_PATH=$(which "$BINARY_NAME")
    echo "rok-mcp already installed at: $INSTALLED_PATH"
    echo ""
    read -rp "Reinstall/update? [y/N] " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo "Skipping install."
        setup_credentials
        exit 0
    fi
fi

# Try local workspace first (if running from a checkout)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." 2>/dev/null && pwd)" || true

if [ -f "$WORKSPACE_ROOT/$CRATE_PATH/Cargo.toml" ]; then
    echo "Found local workspace at $WORKSPACE_ROOT"
    echo "Installing from local source..."
    echo ""
    cargo install --path "$WORKSPACE_ROOT/$CRATE_PATH"
else
    echo "Installing from $REPO_URL ..."
    echo ""
    cargo install --git "$REPO_URL" "$BINARY_NAME"
fi

echo ""
echo "rok-mcp installed at: $(which "$BINARY_NAME")"
echo ""

# Credentials setup
if [ -f "$HOME/.rok/session.json" ]; then
    echo "Found existing config at ~/.rok/session.json"
else
    echo "Optional: Set up credentials for auto-login."
    echo ""
    read -rp "Configure now? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        mkdir -p "$HOME/.rok"

        read -rp "Fileverse API key: " api_key
        read -rp "Fileverse URL [http://127.0.0.1:8001]: " fv_url
        fv_url="${fv_url:-http://127.0.0.1:8001}"
        read -rp "Spend seed (64 hex chars, or leave empty for agent mode): " spend_seed

        if [ -n "$spend_seed" ]; then
            cat > "$HOME/.rok/session.json" << ENDJSON
{
  "apiKey": "$api_key",
  "fileverseUrl": "$fv_url",
  "spendSeed": "$spend_seed"
}
ENDJSON
        else
            read -rp "Read key (base58): " read_key
            read -rp "Spend public (base58): " spend_public
            cat > "$HOME/.rok/session.json" << ENDJSON
{
  "apiKey": "$api_key",
  "fileverseUrl": "$fv_url",
  "readKey": "$read_key",
  "spendPublic": "$spend_public"
}
ENDJSON
        fi

        chmod 600 "$HOME/.rok/session.json"
        echo ""
        echo "Saved to ~/.rok/session.json"
    else
        echo ""
        echo "You can configure later by creating ~/.rok/session.json"
        echo "or by calling rok_login in conversation."
    fi
fi

echo ""
echo "Setup complete. Restart Claude Code to activate the plugin."
