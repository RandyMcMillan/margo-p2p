#!/usr/bin/env bash
# Entrypoint for margo Docker container

set -e

MARGO="${MARGO:-/usr/local/bin/margo}"
REGISTRY="${MARGO_REGISTRY:-/data/registry}"
BASE_URL="${MARGO_BASE_URL:-http://localhost:8080/}"
PORT="${MARGO_PORT:-8080}"
FEATURES="${MARGO_FEATURES:-ipfs}"

# Initialize registry if needed
if [ ! -f "$REGISTRY/margo-config.toml" ]; then
    echo "Initializing registry at $REGISTRY..."
    $MARGO init --defaults --base-url "$BASE_URL" "$REGISTRY"
fi

# Determine command
CMD="${1:-serve}"
shift 2>/dev/null || true

case "$CMD" in
    serve)
        exec $MARGO serve --registry "$REGISTRY" --listen "/ip4/0.0.0.0/tcp/$PORT" "$@"
        ;;
    init)
        exec $MARGO init "$@"
        ;;
    add)
        exec $MARGO add --registry "$REGISTRY" "$@"
        ;;
    verify)
        exec $MARGO verify --registry "$REGISTRY" "$@"
        ;;
    sync)
        exec $MARGO sync --registry "$REGISTRY" "$@"
        ;;
    generate-html)
        exec $MARGO generate-html --registry "$REGISTRY" "$@"
        ;;
    *)
        exec $MARGO "$CMD" "$@"
        ;;
esac