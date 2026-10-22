#!/usr/bin/env bash
# Build and serve the Margo browser-based IPFS node (web/).
#
# Usage: ./scripts/serve-web.sh [registry-dir] [port]
#
# Defaults: registry-dir="my-registry", port=5173
#
# This script builds the web app with the registry embedded and serves it
# with Vite's dev server (hot reload) or preview server (production).

set -euo pipefail

TARGET="${1:-repo}"
PORT="${2:-5173}"
MODE="${MODE:-dev}"  # dev or preview

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$REPO_ROOT/web"

# Resolve target path
if [ "$TARGET" = "repo" ]; then
    REGISTRY_ABS="$REPO_ROOT"
elif [[ ! -d "$TARGET" ]]; then
    REGISTRY_ABS="$REPO_ROOT/$TARGET"
else
    REGISTRY_ABS="$(cd "$TARGET" && pwd)"
fi

# If it's a Margo registry, verify it
if [ -f "$REGISTRY_ABS/margo-config.toml" ]; then
    echo "==> Serving Margo registry: $REGISTRY_ABS"
else
    echo "==> Serving repository: $REGISTRY_ABS"
fi

echo "==> Target: $REGISTRY_ABS"
echo "==> Port: $PORT"
echo "==> Mode: $MODE"

cd "$WEB_DIR"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "==> Installing dependencies..."
    npm install
fi

export REPO_ROOT="$REGISTRY_ABS"

if [ "$MODE" = "preview" ]; then
    echo "==> Building production bundle..."
    npm run build
    echo "==> Serving at http://127.0.0.1:$PORT"
    echo "    Press Ctrl+C to stop."
    npm run preview -- --host 127.0.0.1 --port "$PORT"
else
    echo "==> Starting dev server at http://127.0.0.1:$PORT"
    echo "    Press Ctrl+C to stop."
    npm run dev -- --host 127.0.0.1 --port "$PORT"
fi