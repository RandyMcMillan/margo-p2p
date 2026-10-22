# Margo Registry + IPFS P2P Docker Setup

This directory contains Docker configurations for running a Margo registry
with IPFS peer-to-peer distribution, Blossom blob storage, and a browser-based
IPFS node.

## Quick Start

```bash
# Build and start all services
cd docker
docker compose up -d

# Initialize a registry (first time only)
docker compose exec margo margo init /data/registry --base-url http://localhost:8080 --html true

# Add a crate
docker compose exec margo margo add --registry /data/registry --ipfs /data/crates/my-crate-1.0.0.crate

# Serve with P2P
docker compose exec margo margo serve --registry /data/registry --networked --publish

# View the registry
open http://localhost:8080/index.html
```

## Services

| Service | Port | Description |
|---|---|---|
| `margo` | 8080 | Margo registry HTTP + IPFS gateway |
| `kubo` | 4001 (swarm), 5001 (API), 8081 (gateway) | IPFS Kubo node (optional, for P2P) |
| `blossom` | 3000 | Blossom blob storage server (optional) |
| `web` | 5173 | Browser-based IPFS node (Helia) |

## Files

- `Dockerfile.margo` — builds margo from source (multi-stage, Rust + Go)
- `Dockerfile.web` — builds the browser IPFS node (Node.js + Vite)
- `docker-compose.yml` — orchestrates all services
- `docker-compose.ipfs.yml` — IPFS-only overlay (adds Kubo node)
- `docker-compose.blossom.yml` — Blossom overlay (adds Blossom server)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Compose Network                              │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │  margo   │  │  kubo    │  │ blossom  │          │
│  │  :8080   │  │  :4001   │  │  :3000   │          │
│  │          │  │  :5001   │  │          │          │
│  │  HTTP +  │  │  :8081   │  │  blobs   │          │
│  │  IPFS GW │  │          │  │          │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │              │              │              │
│       └──────────────┼──────────────┘              │
│                      │                              │
│  ┌───────────────────▼──────────────────────────┐   │
│  │  web (browser IPFS node)                     │   │
│  │  :5173 — Helia, embeds registry files        │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Building

### Margo only (no IPFS)

```bash
docker build -f docker/Dockerfile.margo -t margo .
docker run -v $(pwd)/registry:/data/registry -p 8080:8080 margo serve --registry /data/registry
```

### Full stack (Margo + IPFS + Blossom)

```bash
cd docker
docker compose up -d
```

### With IPFS overlay

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.ipfs.yml up -d
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MARGO_REGISTRY` | `/data/registry` | Registry directory |
| `MARGO_BASE_URL` | `http://localhost:8080/` | Base URL for the registry |
| `MARGO_PORT` | `8080` | Port for margo serve |
| `MARGO_FEATURES` | `ipfs` | Cargo features to enable |
| `SWARM_KEY` | (none) | Path to swarm.key for private swarm |
| `BLOSSOM_URL` | (none) | Blossom server URL for uploads |

## Volumes

| Volume | Mount point | Description |
|---|---|---|
| `registry-data` | `/data/registry` | Registry files (persistent) |
| `ipfs-data` | `/data/ipfs` | IPFS repo (persistent) |
| `blossom-data` | `/data/blossom` | Blossom blob storage (persistent) |

## Notes

- The `ipfs` feature requires a Go toolchain at build time. The Dockerfile handles this.
- The `blossom` feature requires additional dependencies (axum, reqwest, tokio). Use `MARGO_FEATURES="ipfs blossom"` to enable.
- For production, use a reverse proxy (nginx/Caddy) for TLS and auth.
- The web app (browser IPFS node) is built separately and deployed to GitHub Pages.