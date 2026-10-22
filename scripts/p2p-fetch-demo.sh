#!/usr/bin/env bash
# Full P2P demo: Margo registry → IPFS → Kubo Desktop fetch.
#
# Usage: ./scripts/p2p-fetch-demo.sh [registry-dir] [port]
#
# This script:
#   1. Builds margo (if needed)
#   2. Initializes a registry (if needed)
#   3. Adds a crate with --ipfs
#   4. Starts margo serve (IPFS gateway + P2P)
#   5. Publishes the registry to IPFS (--publish)
#   6. Prints the root CID and peer ID for Kubo Desktop
#   7. Shows how to fetch crates via Kubo CLI
#
# Defaults: registry-dir="my-registry", port=8080

set -euo pipefail

REGISTRY_DIR="${1:-my-registry}"
PORT="${2:-8080}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MARGO="${MARGO:-$REPO_ROOT/target/debug/margo}"

# Resolve margo binary
if [ ! -f "$MARGO" ]; then
    MARGO="$HOME/.cache/cargo/debug/margo"
fi
if [ ! -f "$MARGO" ]; then
    echo "Building margo..."
    cd "$REPO_ROOT"
    cargo build --features ipfs
    MARGO="$REPO_ROOT/target/debug/margo"
    [ -f "$MARGO" ] || MARGO="$HOME/.cache/cargo/debug/margo"
fi

echo "==> Using margo: $MARGO"

# Resolve registry path (absolute or relative)
if [[ "$REGISTRY_DIR" = /* ]]; then
    REGISTRY_ABS="$REGISTRY_DIR"
elif [[ -d "$REGISTRY_DIR" ]]; then
    REGISTRY_ABS="$(cd "$REGISTRY_DIR" && pwd)"
else
    REGISTRY_ABS="$REPO_ROOT/$REGISTRY_DIR"
fi

# Initialize registry if needed
if [ ! -f "$REGISTRY_ABS/margo-config.toml" ]; then
    echo "==> Initializing registry at $REGISTRY_ABS..."
    "$MARGO" init --defaults --base-url "http://127.0.0.1:$PORT/" --html true "$REGISTRY_ABS"
fi

echo "==> Registry: $REGISTRY_ABS"
echo "==> Port: $PORT"

# Check if kubo is available
KUBO_AVAILABLE=false
if command -v ipfs &>/dev/null; then
    KUBO_AVAILABLE=true
    echo "==> Kubo (ipfs) found: $(ipfs --version)"
else
    echo "==> Kubo (ipfs) not found — install with: brew install kubo"
fi

# Check if registry has crates
CRATE_COUNT=0
if [ -d "$REGISTRY_ABS/de" ]; then
    CRATE_COUNT=$(ls "$REGISTRY_ABS/de/" 2>/dev/null | wc -l)
fi
if [ "$CRATE_COUNT" -eq 0 ]; then
    echo "==> No crates found. Add one with:"
    echo "    margo add --registry $REGISTRY_ABS --ipfs <crate.crate>"
    echo ""
fi

# Start margo serve with publish
echo "==> Starting margo serve (port $PORT)..."
"$MARGO" serve --registry "$REGISTRY_ABS" --publish --networked > /tmp/margo-serve.log 2>&1 &
SERVE_PID=$!
sleep 4

PORT_ACTUAL=$(grep -oE '0.0.0.0:[0-9]+' /tmp/margo-serve.log | head -1 | cut -d: -f2)
PEER_ID=$(grep "peer id:" /tmp/margo-serve.log | awk '{print $NF}')
ROOT_CID=$(grep "root CID:" /tmp/margo-serve.log | awk '{print $NF}')

echo ""
echo "============================================"
echo "  Margo P2P Registry is running!"
echo "============================================"
echo ""
echo "  HTTP endpoint:  http://127.0.0.1:$PORT_ACTUAL/"
echo "  Peer ID:        $PEER_ID"
echo "  Root CID:       $ROOT_CID"
echo "  Multiaddr:      /ip4/127.0.0.1/tcp/$PORT_ACTUAL/p2p/$PEER_ID"
echo ""
echo "  Registry files:"
echo "    config.json:  http://127.0.0.1:$PORT_ACTUAL/config.json"
echo "    index:        http://127.0.0.1:$PORT_ACTUAL/de/mo/<crate>"
echo "    crate bytes:  http://127.0.0.1:$PORT_ACTUAL/crates/... (302 → /ipfs/<cid>)"
echo "    IPFS gateway: http://127.0.0.1:$PORT_ACTUAL/ipfs/<cid>"
echo ""

if [ "$KUBO_AVAILABLE" = true ]; then
    echo "  To fetch in Kubo Desktop / CLI:"
    echo "    ipfs get $ROOT_CID -o ./margo-registry"
    echo "    ipfs cat $ROOT_CID/config.json"
    echo "    ipfs cat $ROOT_CID/de/mo/<crate>"
    echo ""
    echo "  To connect Kubo to this node:"
    echo "    ipfs swarm connect /ip4/127.0.0.1/tcp/$PORT_ACTUAL/p2p/$PEER_ID"
    echo ""
    echo "  To use as Cargo registry:"
    echo "    # .cargo/config.toml"
    echo "    [registries]"
    echo "    my-registry = { index = \"sparse+http://127.0.0.1:$PORT_ACTUAL/\" }"
    echo ""
fi

echo "  Web UI (browser IPFS):"
echo "    ./scripts/serve-web.sh $REGISTRY_DIR"
echo ""
echo "  Press Ctrl+C to stop."
echo "============================================"
echo ""

# Wait for serve process
wait $SERVE_PID