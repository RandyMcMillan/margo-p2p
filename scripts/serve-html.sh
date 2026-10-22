#!/usr/bin/env bash
# Serve a Margo registry with its HTML index page.
#
# Usage: ./scripts/serve-html.sh [registry-dir] [port]
#
# Defaults: registry-dir="my-registry", port=8080
#
# This script initializes a registry (if needed), generates the HTML index,
# and serves it with Python's http.server.

set -euo pipefail

REGISTRY_DIR="${1:-my-registry}"
PORT="${2:-8080}"
MARGO="${MARGO:-margo}"

# Resolve margo binary
if ! command -v "$MARGO" &>/dev/null; then
    MARGO="$(cd "$(dirname "$0")/.." && pwd)/target/debug/margo"
    if [ ! -f "$MARGO" ]; then
        MARGO="$HOME/.cache/cargo/debug/margo"
    fi
fi

echo "==> Using margo: $MARGO"
echo "==> Registry: $REGISTRY_DIR"
echo "==> Port: $PORT"

# Initialize registry if it doesn't exist
if [ ! -f "$REGISTRY_DIR/margo-config.toml" ]; then
    echo "==> Initializing registry..."
    "$MARGO" init --defaults --base-url "http://127.0.0.1:$PORT/" --html true "$REGISTRY_DIR"
fi

# Generate HTML index
echo "==> Generating HTML index..."
"$MARGO" generate-html --registry "$REGISTRY_DIR"

echo ""
echo "==> Serving at http://127.0.0.1:$PORT/index.html"
echo "    Press Ctrl+C to stop."
echo ""

cd "$REGISTRY_DIR"
python3 -m http.server "$PORT" --bind 127.0.0.1