#!/usr/bin/env python3
"""
rok Agent POC — A Python agent that:
1. Receives a scoped read key + spend public key from the owner
2. Reads memories at its granted scope via rok CLI (read-only, no spend seed)
3. Optionally seeds and proposes memories (requires --spend-seed for owner ops)
4. Decrypts a specified memory and saves it to a local file

Usage (agent / read-only):
    export FILEVERSE_API_KEY="your-api-key"
    python3 poc/agent.py --read-key <base58> --spend-public <base58> --scope /finance

Usage (owner / full access):
    python3 poc/agent.py --spend-seed <hex> --scope /finance --seed --propose

The agent will:
    - List all accessible memories (read key + spend public only)
    - Decrypt and save a specified memory to disk
    - Optionally write seed memories and propose new ones (spend seed required)
"""

import argparse
import json
import os
import subprocess
import sys

ROK_BIN = os.environ.get("ROK_BIN", "cargo")
ROK_ARGS = ["run", "--bin", "rok", "--"]


def rok(*args: str) -> str:
    """Run a rok CLI command and return stdout."""
    cmd = [ROK_BIN] + ROK_ARGS + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
    if result.returncode != 0:
        print(f"[rok error] {result.stderr}", file=sys.stderr)
        raise RuntimeError(f"rok command failed: {' '.join(args)}")
    return result.stdout.strip()


def grant_key(spend_seed: str, scope: str, api_key: str) -> tuple[str, str]:
    """Grant a scoped read key and return (exported_key, spend_public)."""
    output = rok(
        "memory", "grant",
        "--scope", scope,
        "--spend-seed", spend_seed,
        "--api-key", api_key,
    )
    exported_key = None
    spend_public = None
    for line in output.splitlines():
        if "Exported Key:" in line:
            exported_key = line.split("Exported Key:")[1].strip()
        if "Spend Public:" in line:
            spend_public = line.split("Spend Public:")[1].strip()
    if not exported_key:
        raise RuntimeError(f"Could not parse exported key from: {output}")
    if not spend_public:
        raise RuntimeError(f"Could not parse spend public from: {output}")
    return exported_key, spend_public


def list_memories(spend_public: str, read_key: str, api_key: str) -> str:
    """List memories visible to the read key (read-only, no spend seed needed)."""
    return rok(
        "memory", "list",
        "--key", read_key,
        "--spend-public", spend_public,
        "--api-key", api_key,
    )


def read_memory(spend_public: str, read_key: str, scope: str, name: str, api_key: str) -> str:
    """Read a specific memory (read-only, no spend seed needed)."""
    return rok(
        "memory", "read",
        "--scope", scope,
        "--name", name,
        "--key", read_key,
        "--spend-public", spend_public,
        "--api-key", api_key,
    )


def decrypt_and_save(spend_public: str, read_key: str, scope: str, name: str, output: str, api_key: str) -> str:
    """Decrypt a memory from Fileverse and save it to a local file."""
    return rok(
        "memory", "read",
        "--scope", scope,
        "--name", name,
        "--key", read_key,
        "--spend-public", spend_public,
        "--api-key", api_key,
        "--output", output,
    )


def propose_memory(spend_seed: str, scope: str, key: str, data: str, agent_id: str, api_key: str) -> str:
    """Propose a new memory (user must provide spend_seed to approve)."""
    return rok(
        "memory", "propose",
        "--scope", scope,
        "--key", key,
        "--data", data,
        "--agent-id", agent_id,
        "--spend-seed", spend_seed,
        "--api-key", api_key,
    )


def write_memory(spend_seed: str, scope: str, key: str, data: str, api_key: str) -> str:
    """Write a memory directly (owner operation)."""
    return rok(
        "memory", "write",
        "--scope", scope,
        "--key", key,
        "--data", data,
        "--spend-seed", spend_seed,
        "--api-key", api_key,
    )


def main():
    parser = argparse.ArgumentParser(description="rok Agent POC")
    parser.add_argument("--read-key", help="Exported scoped read key (base58). Required for agent mode.")
    parser.add_argument("--spend-public", help="Spend public key (base58) for signature verification")
    parser.add_argument("--spend-seed", help="Hex-encoded spend key seed (owner operations only)")
    parser.add_argument("--scope", default="/agent", help="Scope to operate at")
    parser.add_argument("--agent-id", default="python-poc-agent", help="Agent identifier")
    parser.add_argument("--seed", action="store_true", help="Write seed memories (requires --spend-seed)")
    parser.add_argument("--propose", action="store_true", help="Propose a new memory (requires --spend-seed)")
    args = parser.parse_args()

    api_key = os.environ.get("FILEVERSE_API_KEY")
    if not api_key:
        print("Error: FILEVERSE_API_KEY environment variable not set")
        sys.exit(1)

    # Validate: either provide read-key + spend-public, or spend-seed (which derives both)
    if not args.read_key and not args.spend_seed:
        print("Error: provide --read-key + --spend-public (agent mode) or --spend-seed (owner mode)")
        sys.exit(1)

    if (args.seed or args.propose) and not args.spend_seed:
        print("Error: --seed and --propose require --spend-seed (owner operations)")
        sys.exit(1)

    if args.read_key and not args.spend_public:
        print("Error: --spend-public is required with --read-key (agent mode)")
        sys.exit(1)

    spend_public = args.spend_public
    read_key = args.read_key

    print(f"=== rok Agent POC ===")
    print(f"Agent ID: {args.agent_id}")
    print(f"Scope: {args.scope}")
    print()

    # Step 1: Write some seed memories (optional, owner only)
    if args.seed:
        print("[1] Writing seed memories...")
        write_memory(args.spend_seed, args.scope, "greeting",
                     "Hello from the memory store!", api_key)
        write_memory(args.spend_seed, f"{args.scope}/notes", "first-note",
                     "This is a test note stored at a child scope.", api_key)
        print("    Written 2 seed memories.")
        print()
    else:
        print("[1] Skipping seed memories (use --seed to write them)")
        print()

    # Step 2: Grant a scoped read key + get spend public (owner mode)
    #         or use provided keys (agent mode)
    if not read_key:
        print("[2] Granting read key (owner mode)...")
        read_key, spend_public = grant_key(args.spend_seed, args.scope, api_key)
        print(f"    Read key: {read_key[:20]}...")
        print(f"    Spend public: {spend_public[:20]}...")
        print()
    else:
        print(f"[2] Using provided read key: {read_key[:20]}...")
        print(f"    Spend public: {spend_public[:20]}...")
        print()

    # Step 3: List memories with the read key (read-only, no spend seed)
    print("[3] Listing memories visible to agent...")
    listing = list_memories(spend_public, read_key, api_key)
    print(listing)
    print()

    # Step 4: Agent proposes a new memory (optional, owner only)
    if args.propose:
        print("[4] Agent proposing a new memory...")
        summary = f"Agent {args.agent_id} observed memories at scope {args.scope}. All accessible."
        result = propose_memory(
            args.spend_seed, args.scope, "agent-observation",
            summary, args.agent_id, api_key
        )
        print(f"    {result}")
        print()

        # Step 5: Verify the proposed memory is now readable
        print("[5] Verifying proposed memory is stored...")
        listing2 = list_memories(spend_public, read_key, api_key)
        print(listing2)
        print()
    else:
        print("[4] Skipping propose (use --propose to enable)")
        print()

    # Step 6: Decrypt a memory and save to local file (read-only, no spend seed)
    memory_name = input("[6] Enter memory name to decrypt (or press Enter to skip): ").strip()
    if memory_name:
        output_file = os.path.join(os.path.dirname(__file__), f"decrypted_{memory_name}.md")
        print(f"    Decrypting '{memory_name}' -> {output_file}")
        result = decrypt_and_save(
            spend_public, read_key, args.scope, memory_name,
            output_file, api_key
        )
        print(f"    {result}")
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                print(f"    File contents: {f.read()}")
    else:
        print("    Skipping decrypt.")
    print()

    print("=== POC Complete ===")


if __name__ == "__main__":
    main()
