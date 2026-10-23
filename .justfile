# Margo development commands
# Run `just` to see available recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Default recipe: list available commands.
default:
    @just --list

# ── Build ──────────────────────────────────────────────────────────────
build:
    cargo build

build-release:
    cargo build --release

build-ipfs:
    cargo build --features ipfs

build-all-features:
    cargo build --all-features

# ── Test ──────────────────────────────────────────────────────────────
test:
    cargo test

test-all:
    cargo test --all-features

test-conformance:
    cd conformance && cargo run

test-ipfs:
    cargo test --features ipfs -- --nocapture

# ── Lint / Format ─────────────────────────────────────────────────────
fmt:
    cargo fmt --all
    pnpm fmt

fmt-check:
    cargo fmt --all -- --check
    pnpm fmt:check

clippy:
    cargo clippy --workspace --all-targets

clippy-all:
    cargo clippy --all-targets --all-features

clippy-ipfs:
    cargo clippy --features ipfs --all-targets

typecheck:
    pnpm check

# ── Assets ────────────────────────────────────────────────────────────
assets:
    cargo xtask assets

assets-watch:
    cargo xtask assets --watch

# ── UI ────────────────────────────────────────────────────────────────
ui-build:
    pnpm build

ui-fmt:
    pnpm fmt

ui-fmt-check:
    pnpm fmt:check

# ── Integration tests (Ruby) ──────────────────────────────────────────
ruby-lint:
    cd integration-tests && bundle exec rubocop

ruby-test:
    cd integration-tests && bundle exec rspec

# ── Registry helpers ──────────────────────────────────────────────────
init-registry dir="my-registry" port="8080":
    cargo run -- init --defaults --base-url "http://127.0.0.1:{{port}}/" --html true "{{dir}}"

serve registry="my-registry" port="8080":
    cargo run -- serve --registry "{{registry}}" --port "{{port}}"

generate-html registry="my-registry":
    cargo run -- generate-html --registry "{{registry}}"

# ── Scripts ───────────────────────────────────────────────────────────
serve-html dir="my-registry" port="8080":
    ./scripts/serve-html.sh "{{dir}}" "{{port}}"

serve-web target="repo" port="5173":
    ./scripts/serve-web.sh "{{target}}" "{{port}}"

p2p-demo registry="my-registry" port="8080":
    ./scripts/p2p-fetch-demo.sh "{{registry}}" "{{port}}"

# ── Docker ────────────────────────────────────────────────────────────
docker-build-margo:
    docker build -f docker/Dockerfile.margo -t margo:local .

docker-build-web:
    docker build -f docker/Dockerfile.web -t margo-web:local .

docker-up:
    docker compose -f docker/docker-compose.yml up

docker-down:
    docker compose -f docker/docker-compose.yml down

# ── Release ───────────────────────────────────────────────────────────
prepare-release tag:
    cargo xtask prepare-release "{{tag}}"

# ── Aggregate checks ──────────────────────────────────────────────────
check: fmt-check clippy test

check-all: fmt-check clippy-all test-all test-conformance

clean:
    cargo clean
    rm -rf ui/dist target/debug/margo