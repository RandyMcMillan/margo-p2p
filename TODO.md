# P2P Implementation TODO

Roadmap for the `p2p` feature (`src/p2p.rs`, `margo serve`).

## Strategic update: kubo FFI as the implementation substrate

The original plan (Phases 0–4 below) was built on the hand-rolled libp2p stack in
`src/p2p.rs`. Empirical testing showed that stack re-implements content
distribution, sync, and peer management from scratch and is broken in
fundamental ways (see _Evidence_).

A viable alternative now exists: the `RandyMcMillan/kubo` fork ships a C FFI
layer (`kubo/ffi/`) with a Rust binding (`kubo/ffi/rust/`) that exposes a full
IPFS node in-process. A completed, tested version of that FFI is on branch
`1843/972514/263127/a1a6dbad6/867d72303-begin-margo-p2p` (commit `d6241bbe5`).

The FFI provides exactly the shape margo-p2p needs:

- `kubo_init_repo` / `kubo_init_repo_networked` / `kubo_init_repo_with_config`
- `kubo_node_start` / `kubo_node_stop`
- `kubo_unixfs_add_bytes` (pinned) / `kubo_unixfs_cat` (binary-safe)
- `kubo_node_add_static` (serve a registry dir) + `kubo_node_start_gateway`
  (public-safe: gateway + static only, no writable CoreAPI)
- `kubo_node_connect`, `kubo_node_peer_id`, `kubo_node_listening_addrs`
- `kubo_node_start_api` (full, for local/dev use)

Verified end-to-end: two nodes exchange a real `.crate` file (788 bytes, 12
NUL bytes) byte-for-byte; `GET /ipfs/<cid>` returns the exact bytes with a
matching sha256; `/config.json` and `/de/mo/<crate>` are served; the writable
CoreAPI is NOT exposed on the gateway listener. All 13 Rust FFI tests pass.

**Recommendation: pivot the `p2p` feature to the kubo FFI.** Delete the
hand-rolled libp2p machinery (`Behaviour`, `CommitCodec`, gossipsub, mDNS,
request-response, `GetCommitData`) and rebuild on the FFI. This eliminates
~8 of the ~30 items below (integrity verification, git-repo precondition,
peer dial/bootstrap, NAT traversal, dedup, chunking, blocking event loop,
stale commit hash) for roughly 400 lines of code.

---

## Context (original)

The `p2p` feature adds a libp2p node to a Margo registry. The intent is to
distribute crate metadata and packages peer-to-peer instead of relying solely on
HTTP.

The transport and codec layers work: once two peers are actually connected,
`GetHead` and `GetCommitData` both round-trip correctly. What is missing is
everything between "bytes arrived" and "registry updated", plus the plumbing
needed for peers to connect at all.

### Status

| Area                                             | Status    |
| ------------------------------------------------ | --------- |
| Swarm construction (TCP + Noise + Yamux)         | done      |
| Length-prefixed JSON codec over request-response | done      |
| mDNS discovery, identify, ping                   | done      |
| Git commit hash announcement (gossipsub)         | broken    |
| Commit data fetch (`GetCommitData`)              | not wired |
| Applying fetched data to the local registry      | not done  |
| Peer dial / bootstrap                            | missing   |
| Authentication / authorization                   | missing   |
| Tests                                            | none      |
| CI coverage of the feature                       | none      |
| Documentation                                    | none      |
| **kubo FFI (alternative substrate)**             | **done**  |

### Evidence

All findings below were reproduced by running two live nodes against each
other. Temporary source patches used for the experiment have been reverted.

- `publish()` returned `InsufficientPeers` on 100% of attempts, on every run.
- Forcing `mesh_n(2)` still failed on publish-on-connect; publish-on-subscribe
  succeeded.
- Two nodes on the same host frequently never discovered each other over mDNS.
- `collect_commit_files` on a 302-file registry: **2.429s** blocking, versus
  **0.044s** for a single `git archive --format=tar`.
- Ping latency on the serving node inflated from ~20ms to ~125ms while a
  commit was being collected.
- The same 302-file commit was served 8 times in 12 seconds.
- A local kubo IPFS daemon and several gnostr nodes on the LAN all received
  our registry's commit hash.

---

## Phase 0 — Make it possible to test

Do this first. None of the later phases can be verified without it.

- [ ] Add a `--peer` / `--bootstrap` option to `margo serve` so a node can dial
      a known multiaddr (`src/main.rs:111-124`).
- [ ] Add an `--identity` keyfile option and load/save the keypair, so the
      `PeerId` is stable across restarts and can be allowlisted
      (`src/p2p.rs:241` currently uses `SwarmBuilder::with_new_identity()`).
- [ ] Extract swarm construction from `start_node` into a reusable function so
      tests can drive it directly.
- [ ] Write a two-node integration test that runs both nodes in-process and
      asserts on the protocol exchange.
- [ ] Add unit tests for the `CommitCodec` (framing, size limits, malformed
      input).
- [ ] Restore the CI lint gates: `cargo fmt --all -- --check`,
      `cargo clippy -- -D warnings`, `pnpm fmt:check`.
- [ ] Add a `p2p-integration` CI job that runs the new tests.

## Phase 1 — Make the protocol actually work

- [ ] Retune gossipsub for small meshes: `mesh_n` 2-3, `mesh_n_low` 1-2,
      `mesh_outbound_min` 1 (`src/p2p.rs:264-267`).
- [ ] Publish from the `Subscribed` handler instead of on connect
      (`src/p2p.rs:375-379`), and keep the `Subscribed` handler's topic check
      so we only react to our own topic.
- [ ] Retry the publish when it fails with `InsufficientPeers`.
- [ ] Stop publishing to every peer on connect (`src/p2p.rs:426-450`). Only
      publish to peers that are subscribed to our topic.
- [ ] Issue `CommitRequest::GetCommitData` when an announcement is received
      (`src/p2p.rs:363-373`). It is currently never constructed anywhere.
- [ ] Deduplicate in-flight and already-fetched commits so a repeated
      announcement does not trigger a repeated fetch.
- [ ] **Apply** the fetched data: write the files, verify them, and update the
      local registry (`src/p2p.rs:413-418` currently only prints).
- [ ] Re-detect the registry HEAD periodically so commits made after startup
      are announced (`src/p2p.rs:233` captures it once).

## Phase 2 — Correctness and safety

- [ ] Move git work off the event loop with `tokio::task::spawn_blocking`, or
      replace the per-file `git show` loop with a single `git archive` /
      `git cat-file --batch` stream (`src/p2p.rs:50-83`, `src/p2p.rs:391`).
- [ ] Stream responses instead of buffering the whole commit in memory.
- [ ] Enforce a server-side response size limit, and reconcile it with the
      client's 64 MiB read cap (`src/p2p.rs:153`) so large registries do not
      break the transfer.
- [ ] Verify received data against the announced commit hash. The gossipsub
      message is signed, but the request/response payload is currently
      unbound.
- [ ] Honor the registry's `auth_required` setting, and add a peer allowlist.
      The P2P path currently exposes the whole registry to any peer that can
      reach the node.
- [ ] Add request timeouts, rate limiting, and bounded concurrency for
      `GetCommitData`.
- [ ] Replace the `_ => {}` catch-all (`src/p2p.rs:457`) with real handling
      for `DialError`, `ListenError`, `OutgoingConnectionError`, and
      `ConnectionClosed` causes. Also stop discarding the result of
      `swarm.dial(...)` (`src/p2p.rs:327`).
- [ ] Add graceful shutdown: handle `SwarmEvent::Terminated` and Ctrl-C.
- [ ] Surface errors instead of `println!`; consider structured logging.

## Phase 3 — Reachability

- [ ] Add QUIC and WebSocket transports.
- [ ] Add circuit relay so peers behind NAT can be reached.
- [ ] Add either a DHT (kademlia) or a static bootstrap peer list.
- [ ] Persist a peer store so nodes can rediscover each other after restart.

## Phase 4 — Settle the sync model

Resolve this before building further on Phase 1 item "apply fetched data".

- [ ] Decide what the unit of sync is:
  - git commit, as implemented today,
  - the registry file set (index files plus `.crate` files),
  - or content-addressed chunks.
- [ ] `margo init` does not create a git repository. On a normal registry,
      `margo serve` prints "Registry is not a git repository (commit
      broadcasting disabled)" and then does nothing useful while still
      connecting to unrelated LAN peers. Either own that decision in the
      registry layout, or document it as a hard precondition.

## Phase 5 — Pivot to kubo FFI (recommended)

Replace the hand-rolled libp2p stack with the kubo FFI. This eliminates
Phases 1–4 for the content-distribution and reachability concerns.

- [ ] Add `kubo-ffi` as a dependency of `margo-p2p` (git dep on
      `RandyMcMillan/kubo`, branch
      `1843/972514/263127/a1a6dbad6/867d72303-begin-margo-p2p`, or a
      vendored copy under `vendor/kubo/ffi`).
- [ ] Implement `margo serve` on top of the FFI:
  - `kubo_init_repo_networked` (or `init_repo_with_config`) for the repo.
  - `kubo_node_start` + `kubo_node_add_static("/", registry_dir)` before
    `kubo_node_start_gateway("/ip4/0.0.0.0/tcp/0")`.
  - Publish each crate via `kubo_unixfs_add_bytes` and store the returned CID
    in the index entry's `ipfs_cid` field (Cargo ignores unknown fields —
    verified).
  - Set `dl` to the gateway URL (or keep it as-is and let the server 302 to
    `/ipfs/<cid>`).
- [ ] Add `--peer` / `--bootstrap` to dial known peers via
      `kubo_node_connect` (the FFI already supports dnsaddr multiaddrs).
- [ ] Add `--identity` keyfile support (the FFI generates Ed25519 keys; persist
      the repo so the PeerId is stable).
- [ ] Re-implement registry sync on top of IPFS: publish the whole registry
      dir to IPFS and an IPNS name; or simply let each node fetch missing
      crates by CID from peers.
- [ ] Verify received crate bytes against `cksum` (Cargo does this on
      download; add an explicit check for the IPFS path).
- [ ] Honor `auth_required`: put the gateway behind an access-controlled proxy
      or run a private swarm.
- [ ] Add a `p2p-integration` CI job that builds the FFI and runs a
      two-node smoke test.
- [ ] Document the feature: `margo serve`, the protocol, the kubo dependency,
      the threat model.

## Housekeeping

- [ ] Replace `announced_peers: HashMap<PeerId, bool>` with a `HashSet`
      (`src/p2p.rs:305`); clippy already flags this.
- [ ] Use `io::Error::other(_)` instead of `io::Error::new(io::ErrorKind::Other, _)`
      (`src/p2p.rs:58`); clippy already flags this.
- [ ] Revisit the `identify` protocol version string
      (`format!("/margo/{}", version)` at `src/p2p.rs:253`); it should be a
      protocol identifier, not a path-like string.
- [ ] Rename `margo serve`. It starts only the P2P node and does not serve the
      registry over HTTP.
- [ ] Document the P2P feature in the README: the `serve` command, the
      protocol, the git requirement, and the threat model.
- [ ] Verify the MSRV (`rust-version = "1.81.0"`) against the `p2p` feature.
      Every CI matrix entry except `nightly` is currently commented out.
- [ ] Fix `margo --help`, which prints nothing. This is pre-existing on
      `upstream/main`, not introduced by the P2P work, but it makes the CI
      `--help` smoke test vacuous.

---

## Out of scope for this plan

- The HTML index and the Rust/Ruby/TypeScript test suites are unaffected by
  the `p2p` feature.
- The `integration-gnostr` CI job does not exercise P2P and needs no changes.
- The kubo FFI's git/nostr/libp2p helpers are not needed for margo-p2p and
  can be ignored.
