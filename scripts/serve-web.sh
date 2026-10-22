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

REGISTRY_DIR="${1:-my-registry}"
PORT="${2:-5173}"
MODE="${MODE:-dev}"  # dev or preview

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEB_DIR="$REPO_ROOT/web"

# Resolve registry path
if [[ ! -d "$REGISTRY_DIR" ]]; then
    REGISTRY_ABS="$REPO_ROOT/$REGISTRY_DIR"
else
    REGISTRY_ABS="$(cd "$REGISTRY_DIR" && pwd)"
fi

if [ ! -f "$REGISTRY_ABS/margo-config.toml" ]; then
    echo "==> Registry not found at $REGISTRY_ABS"
    echo "    Run: margo init $REGISTRY_DIR --base-url http://localhost:$PORT --html true"
    echo "    Then: margo add --registry $REGISTRY_DIR <crate.crate>"
    echo "    Then: margo generate-html --registry $REGISTRY_DIR"
    exit 1
fi

echo "==> Registry: $REGISTRY_ABS"
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