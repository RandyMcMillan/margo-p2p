# Margo

Margo is an alternate [Cargo registry][registry] that is built using
completely static files, allowing it to be easily served.

[registry]: https://doc.rust-lang.org/cargo/reference/registries.html

## Quickstart

To use Margo in GitHub Actions, such as hosting your registry on
GitHub Pages, check out our [action][].

[action]: https://github.com/integer32llc/margo-actions

### Install Margo

```bash
cargo install margo --index sparse+https://integer32llc.github.io/margo/
```

### Initialize the registry

This will create a new registry in the directory
`my-registry-directory` that you plan to serve from
`https://my-registry.example.com`.

```bash
margo init my-registry-directory --base-url https://my-registry.example.com
```

### Add a crate to the registry

To add a new crate or version to the registry, run `margo add` and specify
the path to the directory you gave to `margo init` and the `.crate` file
to publish.

```bash
# Acquire a crate package, such as by running `cargo package`
margo add --registry my-registry-directory some-crate/target/package/some-crate-1.2.3.crate
```

### Serve the registry files with your choice of webserver

For example, using Python and serving the registry in the directory
at `127.0.0.1`:

```bash
python3 -m http.server --bind '127.0.0.1' --dir 'my-registry-directory'
```

You should be able to visit `127.0.0.1/config.json` in your browser.
Your next step is to serve those files from
`https://my-registry.example.com` instead, in whatever way you
serve static files from whatever URL you've specified.

### Browser-based IPFS node (optional)

Margo includes a browser-based IPFS node (`web/`) built with [Helia](https://github.com/ipfs/helia).
It embeds all repository files at build time and adds them to IPFS on load,
so anyone can browse and fetch files via IPFS directly in their browser.

```bash
# Build the web app with the repo embedded
cd web
npm install
REPO_ROOT=.. npm run build

# Serve locally
npm run preview
# Open http://localhost:4173
```

Or use the convenience script:

```bash
./scripts/serve-web.sh              # dev mode with hot reload
./scripts/serve-web.sh . 5174 preview  # production build + preview
```

The web app can also be deployed to GitHub Pages using the
[RandyMcMillan/ipfs-gh-pages](https://github.com/RandyMcMillan/ipfs-gh-pages)
action, which embeds all repository files automatically.

### Peer-to-peer distribution (optional)

Margo can optionally publish crates to [IPFS][ipfs] and/or [Blossom][blossom]
and serve the registry over an embedded node, so crates can be fetched
peer-to-peer in addition to (or instead of) the static HTTP files. The `ipfs`
feature is on by default; the `blossom` feature is optional.

[ipfs]: https://ipfs.tech
[blossom]: https://github.com/hzrd149/blossom

```bash
# Publish a crate to IPFS while adding it to the registry
margo add --registry my-registry-directory --ipfs some-crate/target/package/some-crate-1.2.3.crate

# Serve the registry over HTTP + IPFS gateway
margo serve --registry my-registry-directory

# Publish a crate to a Blossom server (Nostr-authenticated blob storage)
margo add --registry my-registry-directory --blossom http://localhost:3000 some-crate/target/package/some-crate-1.2.3.crate

# Store a crate as a local Blossom blob and serve it
margo add --registry my-registry-directory --blossom some-crate/target/package/some-crate-1.2.3.crate
margo serve --registry my-registry-directory --blossom
```

`margo serve` (ipfs) does three things:

- serves the static registry files (`config.json`, index entries) over HTTP,
- serves an IPFS gateway at `/ipfs/<cid>` for crate bytes, and
- dials peers given via repeated `--peer <multiaddr>`.

Crates published with `--ipfs` get an `ipfs_cid` field in their index entry
(Cargo ignores unknown fields). The crate's `cksum` is still verified by Cargo
on download, so integrity is enforced end-to-end.

```bash
# Verify every crate file against its recorded cksum (and IPFS, if present)
margo verify --registry my-registry-directory

# Sync a local registry with a remote one via IPFS
margo sync --registry my-registry-directory --cid Qm...rootCID...
margo sync --registry my-registry-directory --ipns k51qzi5uqu5d...

# Sync via git (clone + merge)
margo sync --registry my-registry-directory --git https://github.com/org/registry.git

# Sync via GRASP (Nostr-authorized git relay)
margo sync --registry my-registry-directory --grasp http://relay:8080 --grasp-npub npub1... --grasp-repo registry

# Discover Nostr relays and their capabilities
margo discover wss://relay.damus.io wss://nos.lol
margo discover --nip 34 wss://relay.damus.io wss://nos.lol
```

For public-network participation, use `--networked` (enables mDNS, QUIC,
relay, AutoTLS and Kubo's default bootstrap peers):

```bash
margo serve --registry my-registry-directory --networked
```

### Private swarm (authenticated registries)

For registries with `auth_required: true`, use a private IPFS swarm to
ensure only authorized peers can access crate content:

````bash
# Generate a swarm key
ipfs swarm key gen > swarm.key

# Initialize with the swarm key
margo init my-registry-directory --base-url https://my-registry.example.com --swarm-key swarm.key

# Serve with the swarm key
margo serve --registry my-registry-directory --swarm-key swarm.key --networked

# Serve with a private swarm derived from a Nostr key
margo serve --registry my-registry-directory --swarm-key-nsec nsec1...

# Serve with a GRASP (NIP-34) git relay
margo serve --registry my-registry-directory --grasp

Only peers possessing the same `swarm.key` can connect and fetch crates.
Combine with a reverse proxy (nginx/Caddy) for HTTP-level authentication.

The `ipfs` feature depends on a vendored copy of the [Kubo][kubo] FFI
(`kubo/ffi`), which requires a Go toolchain to build. To build without it:

```bash
cargo build --no-default-features --features "html"
````

[kubo]: https://github.com/ipfs/kubo

### Configure Cargo

```bash
# In your Rust project that wants to use `some-crate`
mkdir .cargo
cat >>.cargo/config.toml <<EOF
[registries]
my-registry = { index = "sparse+https://my-registry.example.com" }
EOF
```

### Add your crate

```bash
cargo add --registry my-registry some-crate
```

## Other Margo commands

You can omit the `--registry` argument by running the command in the
registry directory directly.

### List the crates in the registry

```bash
margo list --registry my-registry
```

### Remove a crate

```bash
margo rm --registry my-registry some-crate --version x.y.z
```

## Key differences from Crates.io

- 💅 Does not impose file size limits
- 💅 Can depend on crates from registries other than crates.io
- 💅 Dependencies are not required to exist
- 💅 Development dependency info is not stored in the index
- 💅 Does not require JavaScript
- 💅 Simpler so it's easier to customize for your use case
- 💅 Access managed via however you currently manage read or write access to static files

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md).
