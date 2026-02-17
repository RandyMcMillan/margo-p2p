#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$(mktemp -d)"
REGISTRY_DIR="$WORK_DIR/registry"
GNOSTR_DIR="$WORK_DIR/gnostr"
HTTP_PID=""

cleanup() {
    if [[ -n "$HTTP_PID" ]]; then
        kill "$HTTP_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "==> Working directory: $WORK_DIR"

# ── Step 1: Build margo ───────────────────────────────────────────
echo "==> Building margo..."
MARGO="${MARGO:-}"
if [[ -z "$MARGO" ]]; then
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml"
    MARGO="$REPO_ROOT/target/debug/margo"
fi
echo "    margo binary: $MARGO"
"$MARGO" --help >/dev/null

# ── Step 2: Clone and package gnostr ──────────────────────────────
echo "==> Cloning gnostr..."
git clone --depth 1 https://github.com/gnostr-org/gnostr "$GNOSTR_DIR"

echo "==> Packaging gnostr..."
cd "$GNOSTR_DIR"
# Remove dev-only path dep that lacks a version field
sed -i '/test_utils.*path/d' Cargo.toml
cargo package --no-verify --allow-dirty
CRATE_FILE=$(find "$GNOSTR_DIR/target/package" -name '*.crate' -print -quit)
echo "    Crate file: $CRATE_FILE"

# ── Step 3: Initialize test registry ──────────────────────────────
echo "==> Initializing margo registry..."
"$MARGO" init \
    --defaults \
    --base-url "http://127.0.0.1:8000/" \
    "$REGISTRY_DIR"

# ── Step 4: Add gnostr to registry ───────────────────────────────
echo "==> Adding gnostr to registry..."
"$MARGO" add --registry "$REGISTRY_DIR" "$CRATE_FILE"
"$MARGO" list --registry "$REGISTRY_DIR"

# ── Step 5: Start HTTP server ─────────────────────────────────────
echo "==> Starting HTTP server on :8000..."
python3 -m http.server 8000 --directory "$REGISTRY_DIR" &
HTTP_PID=$!
sleep 1
curl -sf http://127.0.0.1:8000/config.json >/dev/null
echo "    Registry is live."

# ── Step 6: Build test-consumer ───────────────────────────────────
echo "==> Building test-consumer..."
cd "$SCRIPT_DIR"
cargo build

echo "==> Running test-consumer..."
cargo run

echo ""
echo "=== All tests passed ==="
