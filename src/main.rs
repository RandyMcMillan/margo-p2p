use common::CrateName;
use semver::Version;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    str,
};
use url::Url;

#[cfg(feature = "html")]
mod html;

#[cfg(feature = "ipfs")]
use kubo_ffi as _;

#[cfg(feature = "blossom-client")]
use blossom_rs as _;

#[cfg(feature = "blossom-client")]
use tokio as _;

#[cfg(feature = "grasp")]
use blossom_nip34 as _;

#[derive(Debug, argh::FromArgs)]
/// Manage a static crate registry
struct Args {
    #[argh(subcommand)]
    subcommand: Subcommand,
}

#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    Init(InitArgs),
    Add(AddArgs),
    Remove(RemoveArgs),
    Yank(YankArgs),
    List(ListArgs),
    Verify(VerifyArgs),
    GenerateHtml(GenerateHtmlArgs),
    #[cfg(any(feature = "ipfs", feature = "blossom-server"))]
    Serve(ServeArgs),
    #[cfg(feature = "ipfs")]
    Sync(SyncArgs),
}

/// Initialize a new registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "init")]
struct InitArgs {
    /// the URL that the registry is hosted at
    #[argh(option)]
    base_url: Option<Url>,

    /// use default values where possible, instead of prompting for them
    #[argh(switch)]
    defaults: bool,

    /// require HTTP authentication to access crates
    #[argh(option)]
    auth_required: Option<bool>,

    /// generate an HTML file showing crates in the index
    #[argh(option)]
    html: Option<bool>,

    /// name you'd like to suggest other people call your registry
    #[argh(option)]
    html_suggested_registry_name: Option<String>,

    /// path to a swarm.key file for private IPFS swarm (optional)
    #[argh(option)]
    swarm_key: Option<PathBuf>,

    /// nostr private key (nsec or hex) to derive a swarm key from
    #[cfg(feature = "ipfs")]
    #[argh(option)]
    swarm_key_nsec: Option<String>,

    #[argh(positional)]
    path: PathBuf,

    /// initialize the registry as a git repository
    #[argh(switch)]
    git: bool,

    /// generate and store a Nostr keypair for GRASP publishing
    #[cfg(feature = "ipfs")]
    #[argh(switch)]
    nostr_key: bool,
}

/// Add a crate to the registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "add")]
struct AddArgs {
    /// path to the registry to modify
    #[argh(option)]
    registry: Option<PathBuf>,

    /// publish the crate to IPFS and record its CID in the index entry
    #[cfg(feature = "ipfs")]
    #[argh(switch)]
    ipfs: bool,

    /// store the crate as a local Blossom blob (in .blossom-blobs/)
    #[cfg(feature = "blossom-client")]
    #[argh(switch)]
    blossom: bool,

    /// upload the crate to a remote Blossom server URL
    #[cfg(feature = "blossom-client")]
    #[argh(option)]
    blossom_server: Option<String>,

    /// nostr secret key (hex or nsec) for Blossom auth upload
    #[cfg(feature = "blossom-client")]
    #[argh(option)]
    blossom_key: Option<String>,

    #[argh(positional)]
    path: Vec<PathBuf>,
}

/// Remove a crate from the registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "rm")]
struct RemoveArgs {
    /// path to the registry to modify
    #[argh(option)]
    registry: Option<PathBuf>,

    // FUTURE: Allow removing all versions at once?
    /// the version of the crate
    #[argh(option)]
    version: Version,

    #[argh(positional)]
    name: CrateName,
}

/// Generate an HTML index for the registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "generate-html")]
struct GenerateHtmlArgs {
    /// path to the registry to modify
    #[argh(option)]
    registry: Option<PathBuf>,
}

/// Serve the registry over HTTP and IPFS
#[cfg(any(feature = "ipfs", feature = "blossom-server"))]
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "serve")]
struct ServeArgs {
    /// path to the registry to serve
    #[argh(option)]
    registry: Option<PathBuf>,

    /// multiaddr to listen on (default: /ip4/0.0.0.0/tcp/0)
    #[argh(option)]
    listen: Option<String>,

    /// peer multiaddr to dial on startup (repeatable)
    #[argh(option)]
    peer: Vec<String>,

    /// use a networked (public) repo config instead of isolated
    #[argh(switch)]
    networked: bool,

    /// publish the registry directory to IPFS on startup and print the root CID
    #[argh(switch)]
    publish: bool,

    /// also serve blobs via an embedded Blossom server
    #[cfg(feature = "blossom-server")]
    #[argh(switch)]
    blossom: bool,

    /// also serve a GRASP (NIP-34) git relay for the registry
    #[cfg(feature = "grasp")]
    #[argh(switch)]
    grasp: bool,

    /// path to a swarm.key file for private IPFS swarm (optional)
    #[argh(option)]
    swarm_key: Option<PathBuf>,

    /// nostr private key (nsec or hex) to derive a swarm key from
    #[cfg(feature = "ipfs")]
    #[argh(option)]
    swarm_key_nsec: Option<String>,

    /// bearer token for HTTP authentication (enables auth on the gateway)
    #[argh(option)]
    auth_token: Option<String>,
}

/// Yank a version of a crate from the registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "yank")]
struct YankArgs {
    /// path to the registry to modify
    #[argh(option)]
    registry: Option<PathBuf>,

    /// undo a previous yank
    #[argh(switch)]
    undo: bool,

    /// the version of the crate
    #[argh(option)]
    version: Version,

    /// the name of the crate
    #[argh(positional)]
    name: CrateName,
}

/// List all crates and their versions in the registry
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "list")]
struct ListArgs {
    /// path to the registry to list
    #[argh(option)]
    registry: Option<PathBuf>,
}

/// Verify that every crate file in the registry matches its index entry's cksum
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "verify")]
struct VerifyArgs {
    /// path to the registry to verify
    #[argh(option)]
    registry: Option<PathBuf>,
}

/// Sync a local registry with a remote registry via IPFS
#[cfg(feature = "ipfs")]
#[derive(Debug, argh::FromArgs)]
#[argh(subcommand)]
#[argh(name = "sync")]
struct SyncArgs {
    /// path to the local registry to sync into
    #[argh(option)]
    registry: Option<PathBuf>,

    /// root CID of the remote registry snapshot
    #[argh(option)]
    cid: Option<String>,

    /// IPNS name to resolve to a root CID
    #[argh(option)]
    ipns: Option<String>,

    /// peer multiaddr to dial (optional, for direct fetch)
    #[argh(option)]
    peer: Option<String>,

    /// git remote URL to sync from (alternative to IPFS)
    #[cfg(feature = "ipfs")]
    #[argh(option)]
    git: Option<String>,

    /// GRASP relay URL to sync from (Nostr-authorized git)
    #[cfg(feature = "grasp")]
    #[argh(option)]
    grasp: Option<String>,

    /// npub of the repository owner on the GRASP relay
    #[cfg(feature = "grasp")]
    #[argh(option)]
    grasp_npub: Option<String>,

    /// repository name on the GRASP relay
    #[cfg(feature = "grasp")]
    #[argh(option)]
    grasp_repo: Option<String>,
}

#[snafu::report]
fn main() -> Result<(), Error> {
    let args: Args = argh::from_env();

    let global = Global::new()?;
    let global = Box::leak(Box::new(global));

    match args.subcommand {
        Subcommand::Init(init) => do_init(global, init)?,
        Subcommand::Add(add) => do_add(global, add)?,
        Subcommand::Remove(rm) => do_remove(global, rm)?,
        Subcommand::Yank(yank) => do_yank(global, yank)?,
        Subcommand::List(list) => do_list(global, list)?,
        Subcommand::Verify(verify) => do_verify(global, verify)?,
        Subcommand::GenerateHtml(html) => do_generate_html(global, html)?,
        #[cfg(any(feature = "ipfs", feature = "blossom-server"))]
        Subcommand::Serve(serve) => do_serve_ipfs(global, serve)?,
        #[cfg(feature = "ipfs")]
        Subcommand::Sync(sync) => do_sync_ipfs(global, sync)?,
    }

    Ok(())
}

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Could not initialize global variables"))]
    #[snafu(context(false))]
    Global {
        #[snafu(source(from(GlobalError, Box::new)))]
        source: Box<GlobalError>,
    },

    #[snafu(transparent)]
    Initialize {
        #[snafu(source(from(DoInitializeError, Box::new)))]
        source: Box<DoInitializeError>,
    },

    #[snafu(transparent)]
    Open {
        #[snafu(source(from(DiscoverRegistryError, Box::new)))]
        source: Box<DiscoverRegistryError>,
    },

    #[snafu(transparent)]
    Add {
        #[snafu(source(from(AddError, Box::new)))]
        source: Box<AddError>,
    },

    #[snafu(transparent)]
    Remove {
        #[snafu(source(from(RemoveError, Box::new)))]
        source: Box<RemoveError>,
    },

    #[snafu(transparent)]
    Html {
        #[snafu(source(from(HtmlError, Box::new)))]
        source: Box<HtmlError>,
    },

    #[snafu(transparent)]
    Yank {
        #[snafu(source(from(YankError, Box::new)))]
        source: Box<YankError>,
    },

    #[cfg(feature = "ipfs")]
    #[snafu(transparent)]
    IpfsServe {
        #[snafu(source(from(IpfsServeError, Box::new)))]
        source: Box<IpfsServeError>,
    },

    #[cfg(feature = "ipfs")]
    #[snafu(transparent)]
    Sync {
        #[snafu(source(from(SyncError, Box::new)))]
        source: Box<SyncError>,
    },

    #[snafu(transparent)]
    Verify {
        #[snafu(source(from(VerifyError, Box::new)))]
        source: Box<VerifyError>,
    },
}

trait UnwrapOrDialog<T> {
    fn apply_default(self, use_default: bool, value: impl Into<T>) -> Self;

    fn unwrap_or_dialog(self, f: impl FnOnce() -> dialoguer::Result<T>) -> dialoguer::Result<T>;
}

impl<T> UnwrapOrDialog<T> for Option<T> {
    fn apply_default(self, use_default: bool, value: impl Into<T>) -> Self {
        if self.is_none() && use_default {
            Some(value.into())
        } else {
            self
        }
    }

    fn unwrap_or_dialog(self, f: impl FnOnce() -> dialoguer::Result<T>) -> dialoguer::Result<T> {
        match self {
            Some(v) => Ok(v),
            None => f(),
        }
    }
}

fn store_swarm_key_if_provided(swarm_key: Option<&PathBuf>, registry_path: &std::path::Path) {
    if let Some(sk) = swarm_key {
        let dest = registry_path.join(".swarm-key");
        if let Err(e) = std::fs::copy(sk, &dest) {
            eprintln!("Warning: could not store swarm key: {}", e);
        } else {
            println!("Stored swarm key at {}", dest.display());
        }
    }
}

fn do_init(_global: &Global, init: InitArgs) -> Result<(), DoInitializeError> {
    use do_initialize_error::*;

    let base_url = init
        .base_url
        .unwrap_or_dialog(|| {
            dialoguer::Input::new()
                .with_prompt("What URL will the registry be served from")
                .interact()
        })
        .context(BaseUrlSnafu)?;

    let auth_required = init
        .auth_required
        .apply_default(init.defaults, ConfigV1::USER_DEFAULT_AUTH_REQUIRED)
        .unwrap_or_dialog(|| {
            dialoguer::Confirm::new()
                .default(ConfigV1::USER_DEFAULT_AUTH_REQUIRED)
                .show_default(true)
                .with_prompt("Require HTTP authentication to access crates?")
                .interact()
        })
        .context(AuthRequiredSnafu)?;

    let enabled = init
        .html
        .apply_default(init.defaults, ConfigV1Html::USER_DEFAULT_ENABLED)
        .unwrap_or_dialog(|| {
            dialoguer::Confirm::new()
                .default(ConfigV1Html::USER_DEFAULT_ENABLED)
                .show_default(true)
                .with_prompt("Enable HTML index generation?")
                .interact()
        })
        .context(HtmlEnabledSnafu)?;

    let suggested_registry_name = if enabled {
        let name = init
            .html_suggested_registry_name
            .apply_default(
                init.defaults,
                ConfigV1Html::USER_DEFAULT_SUGGESTED_REGISTRY_NAME,
            )
            .unwrap_or_dialog(|| {
                dialoguer::Input::new()
                    .default(ConfigV1Html::USER_DEFAULT_SUGGESTED_REGISTRY_NAME.to_owned())
                    .show_default(true)
                    .with_prompt("Name you'd like to suggest other people call your registry")
                    .interact()
            })
            .context(HtmlSuggestedRegistryNameSnafu)?;

        Some(name)
    } else {
        None
    };

    let config = ConfigV1 {
        base_url,
        auth_required,
        html: ConfigV1Html {
            enabled,
            suggested_registry_name,
        },
    };

    let r = Registry::initialize(config, &init.path)?;

    // Store swarm key if provided (for private IPFS swarm)
    store_swarm_key_if_provided(init.swarm_key.as_ref(), &r.path);

    // Derive swarm key from nostr nsec if provided
    #[cfg(feature = "ipfs")]
    if let Some(nsec) = &init.swarm_key_nsec {
        match kubo_ffi::nostr_nsec_to_swarm_key(nsec) {
            Ok(key) => {
                let dest = r.path.join(".swarm-key");
                std::fs::write(&dest, &key).ok();
                println!(
                    "Derived swarm key from nostr nsec, stored at {}",
                    dest.display()
                );
            }
            Err(e) => eprintln!("Warning: could not derive swarm key: {}", e),
        }
    }

    // Initialize as git repo if requested
    if init.git {
        let status = std::process::Command::new("git")
            .args(["init"])
            .current_dir(&r.path)
            .status();
        match status {
            Ok(s) if s.success() => {
                let _ = std::process::Command::new("git")
                    .args(["config", "user.email", "margo@localhost"])
                    .current_dir(&r.path)
                    .status();
                let _ = std::process::Command::new("git")
                    .args(["config", "user.name", "margo"])
                    .current_dir(&r.path)
                    .status();
                let _ = std::process::Command::new("git")
                    .args(["add", "-A"])
                    .current_dir(&r.path)
                    .status();
                let _ = std::process::Command::new("git")
                    .args(["commit", "-m", "initial registry"])
                    .current_dir(&r.path)
                    .status();
                println!("Initialized git repository in {}", r.path.display());
            }
            _ => eprintln!("Warning: git init failed"),
        }
    }

    // Generate and store Nostr keypair for GRASP if requested
    #[cfg(feature = "ipfs")]
    if init.nostr_key {
        match kubo_ffi::swarm_key_generate() {
            Ok(key) => {
                let dest = r.path.join(".nostr-key");
                std::fs::write(&dest, &key).ok();
                println!("Generated Nostr key, stored at {}", dest.display());
            }
            Err(e) => eprintln!("Warning: could not generate Nostr key: {}", e),
        }
    }

    if r.config.html.enabled {
        let res = r.generate_html();

        if cfg!(feature = "html") {
            res?;
        } else if let Err(e) = res {
            eprintln!("Warning: {e}");
        }
    }

    Ok(())
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum DoInitializeError {
    #[snafu(display("Could not determine the base URL"))]
    BaseUrl { source: dialoguer::Error },

    #[snafu(display("Could not determine if HTTP authorization is required"))]
    AuthRequired { source: dialoguer::Error },

    #[snafu(display("Could not determine if HTML generation is enabled"))]
    HtmlEnabled { source: dialoguer::Error },

    #[snafu(display("Could not determine the suggested registry name"))]
    HtmlSuggestedRegistryName { source: dialoguer::Error },

    #[snafu(transparent)]
    Initialize { source: InitializeError },

    #[snafu(transparent)]
    Html { source: HtmlError },
}

#[allow(unused_variables)]
fn do_add(global: &Global, add: AddArgs) -> Result<(), Error> {
    let r = discover_registry(add.registry)?;

    #[cfg(feature = "ipfs")]
    let publish_ipfs = add.ipfs;
    #[cfg(not(feature = "ipfs"))]
    let publish_ipfs = false;

    for i in add.path {
        #[cfg(feature = "blossom-client")]
        r.add(
            global,
            i,
            publish_ipfs,
            add.blossom,
            add.blossom_server.clone(),
            add.blossom_key.clone(),
        )?;
        #[cfg(not(feature = "blossom-client"))]
        r.add(global, i, publish_ipfs, false, None, None)?;
    }
    r.maybe_generate_html()?;

    Ok(())
}

fn do_remove(_global: &Global, rm: RemoveArgs) -> Result<(), Error> {
    let r = discover_registry(rm.registry)?;

    r.remove(rm.name, rm.version)?;
    r.maybe_generate_html()?;

    Ok(())
}

fn do_generate_html(_global: &Global, html: GenerateHtmlArgs) -> Result<(), Error> {
    let r = discover_registry(html.registry)?;
    r.generate_html()?;
    Ok(())
}

fn do_yank(_global: &Global, yank: YankArgs) -> Result<(), Error> {
    let r = discover_registry(yank.registry)?;

    r.yank(yank.name, yank.version, !yank.undo)?;
    r.maybe_generate_html()?;

    Ok(())
}

fn do_verify(_global: &Global, verify: VerifyArgs) -> Result<(), Error> {
    let r = discover_registry(verify.registry)?;
    let crates = r.list_all().unwrap();

    let mut ok_count = 0usize;
    let mut fail_count = 0usize;
    for (name, versions) in &crates {
        for (version, entry) in versions {
            let path = r.crate_file_path_for(name, version);
            if !path.exists() {
                println!("MISSING  {} {}", name, version);
                fail_count += 1;
                continue;
            }
            let bytes = std::fs::read(&path).unwrap_or_default();
            use sha2::Digest;
            let actual = hex::encode(sha2::Sha256::digest(&bytes));
            match entry.cksum.as_str() {
                expected if expected == actual => {
                    println!("OK       {} {} {}", name, version, &actual[..12]);
                    ok_count += 1;
                }
                expected => {
                    println!(
                        "MISMATCH {} {} expected={} actual={}",
                        name, version, expected, actual
                    );
                    fail_count += 1;
                }
            }

            #[cfg(feature = "ipfs")]
            if let Some(cid) = &entry.ipfs_cid {
                // Best-effort: try to fetch from IPFS via the local repo if present.
                let repo_path = r.path.join(".ipfs-repo");
                if repo_path.exists() {
                    if let Ok(node) = kubo_ffi::Node::start(&repo_path.to_string_lossy(), true) {
                        if let Ok(fetched) = node.unixfs_cat(cid) {
                            let fetched_hash = hex::encode(sha2::Sha256::digest(&fetched));
                            if fetched_hash == actual {
                                println!("         IPFS ok  {} (cid={})", name, cid);
                            } else {
                                println!(
                                    "         IPFS MISMATCH {} cid={} (expected cksum {}, got {})",
                                    name, cid, actual, fetched_hash
                                );
                                fail_count += 1;
                            }
                        }
                        // node dropped
                    }
                }
            }
        }
    }

    println!();
    println!("{} ok, {} failed", ok_count, fail_count);
    if fail_count > 0 {
        return Err(VerifyError::Failed { count: fail_count }.into());
    }
    Ok(())
}

#[derive(Debug, Snafu)]
enum VerifyError {
    #[snafu(display("{} crate(s) failed verification", count))]
    Failed { count: usize },
}

fn do_list(_global: &Global, list: ListArgs) -> Result<(), Error> {
    let r = discover_registry(list.registry)?;

    let crates = r.list_all().unwrap();

    #[derive(Default)]
    struct Max(usize, String);

    impl Max {
        fn push(&mut self, v: impl fmt::Display) {
            use std::fmt::Write;

            let Self(m, s) = self;

            s.clear();
            _ = write!(s, "{v}");
            *m = usize::max(*m, s.len());
        }

        fn max(&self) -> usize {
            self.0
        }
    }

    let mut max_c = Max::default();
    let mut max_v = Max::default();

    for (crate_, versions) in &crates {
        max_c.push(crate_);
        for version in versions.keys() {
            max_v.push(version);
        }
    }

    let max_c = max_c.max();
    let max_v = max_v.max();

    for (crate_, versions) in crates {
        for version in versions.keys() {
            println!("{crate_:<max_c$} {version:<max_v$}");
        }
    }

    Ok(())
}

#[cfg(feature = "ipfs")]
fn extract_last_cid(s: &str) -> Option<String> {
    // The FFI command runner returns a Go struct dump like:
    //   &{path CID %!s(int64=0) ...}&{path2 CID2 ...}
    // The root CID is the last CID in the output. Find all CID-like tokens.
    let mut last: Option<String> = None;
    for token in s.split_whitespace() {
        let t = token.trim_matches(|c: char| !c.is_alphanumeric());
        if (t.starts_with("Qm") && t.len() >= 40) || (t.starts_with("baf") && t.len() >= 50) {
            last = Some(t.to_string());
        }
    }
    last
}

#[cfg(feature = "ipfs")]
fn do_serve_ipfs(_global: &Global, serve: ServeArgs) -> Result<(), Error> {
    use kubo_ffi::Node;

    let r = discover_registry(serve.registry)?;

    #[cfg(feature = "ipfs")]
    {
        // Read auth_required from config.json if present.
        let config_path = r.path.join("config.json");
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                if v.get("auth-required")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false)
                {
                    let listen = serve.listen.as_deref().unwrap_or("/ip4/0.0.0.0/tcp/0");
                    if !listen.contains("127.0.0.1") && !listen.contains("localhost") {
                        eprintln!(
                            "WARNING: auth_required is true but margo serve is binding to {}. \
                             IPFS content is public by default. Consider binding to localhost \
                             and putting a reverse proxy (nginx/Caddy) in front for auth.",
                            listen
                        );
                    }
                }
            }
        }
    }

    // 1. init repo (reuse .ipfs-repo if it exists from `margo add --ipfs`)
    let repo_path = r.path.join(".ipfs-repo");
    if !repo_path.exists() {
        // Check for swarm key: from --swarm-key flag, --swarm-key-nsec, or .swarm-key file
        #[cfg(feature = "ipfs")]
        if let Some(nsec) = &serve.swarm_key_nsec {
            match kubo_ffi::nostr_nsec_to_swarm_key(nsec) {
                Ok(key) => {
                    let dest = r.path.join(".swarm-key");
                    std::fs::write(&dest, &key).ok();
                    println!("Derived swarm key from nostr nsec");
                }
                Err(e) => eprintln!("Warning: could not derive swarm key: {}", e),
            }
        }

        let swarm_key_path = serve.swarm_key.clone().or_else(|| {
            let p = r.path.join(".swarm-key");
            if p.exists() {
                Some(p)
            } else {
                None
            }
        });

        if let Some(sk_path) = &swarm_key_path {
            let key_content =
                std::fs::read_to_string(sk_path).map_err(|e| IpfsServeError::Init {
                    reason: e.to_string(),
                })?;
            let config = serde_json::json!({
                "Swarm": {
                    "Key": key_content.trim()
                }
            });
            let config_str = serde_json::to_string(&config).map_err(|e| IpfsServeError::Init {
                reason: e.to_string(),
            })?;
            kubo_ffi::init_repo_with_config(&repo_path.to_string_lossy(), &config_str)
                .map_err(|e| IpfsServeError::Init { reason: e })?;
            println!(
                "Private swarm mode: using swarm key from {}",
                sk_path.display()
            );
        } else if serve.networked {
            kubo_ffi::init_repo_networked(&repo_path.to_string_lossy())
                .map_err(|e| IpfsServeError::Init { reason: e })?;
        } else {
            kubo_ffi::init_repo(&repo_path.to_string_lossy())
                .map_err(|e| IpfsServeError::Init { reason: e })?;
        }
    }

    // 2. start node
    let node = Node::start(&repo_path.to_string_lossy(), true)
        .map_err(|e| IpfsServeError::NodeStart { reason: e })?;

    // 2b. set auth token if provided
    if let Some(token) = &serve.auth_token {
        if !node.set_auth_token(token) {
            eprintln!("Warning: failed to set auth token");
        } else {
            println!("Auth enabled: Bearer token required");
        }
    }

    // 3. register static registry dir BEFORE starting the gateway
    if !node.add_static("/", &r.path.to_string_lossy()) {
        return Err(IpfsServeError::Static {
            reason: kubo_ffi::last_error().unwrap_or_else(|| "add_static failed".into()),
        }
        .into());
    }
    // register crate redirect: /crates/... -> /ipfs/<cid> when available
    node.add_crate_redirect(&r.path.to_string_lossy());

    // 4. dial peers
    for peer in &serve.peer {
        if !node.connect(peer) {
            eprintln!(
                "warning: failed to connect to {}: {}",
                peer,
                kubo_ffi::last_error().unwrap_or_default()
            );
        } else {
            println!("connected to {}", peer);
        }
    }

    // 4b. optionally publish the registry directory to IPFS
    if serve.publish {
        let reg_path = r.path.to_string_lossy().to_string();
        match node.run_on_node(
            &repo_path.to_string_lossy(),
            &["add", "-r", "-Q", &reg_path],
        ) {
            Ok(out) => {
                // Extract the last CID from the struct-dump output.
                let cid = extract_last_cid(&out);
                match cid {
                    Some(c) => {
                        println!("Published registry to IPFS: {}", c);
                        println!("  root CID: {}", c);
                        // Try IPNS publish
                        match node.run_on_node(
                            &repo_path.to_string_lossy(),
                            &["name", "publish", &format!("/ipfs/{}", c)],
                        ) {
                            Ok(out2) => {
                                println!(
                                    "IPNS publish result: {}",
                                    out2.chars().take(120).collect::<String>()
                                );
                            }
                            Err(e) => eprintln!("IPNS publish failed: {}", e),
                        }
                    }
                    None => eprintln!(
                        "Could not parse root CID from: {}",
                        out.chars().take(200).collect::<String>()
                    ),
                }
            }
            Err(e) => eprintln!("IPFS publish failed: {}", e),
        }
    }

    // 5. start gateway (public-safe)
    let default_addr = "/ip4/0.0.0.0/tcp/0";
    let addr_str = serve.listen.as_deref().unwrap_or(default_addr);
    let gw = node
        .start_gateway(addr_str)
        .ok_or_else(|| IpfsServeError::Gateway {
            reason: kubo_ffi::last_error().unwrap_or_else(|| "start_gateway failed".into()),
        })?;

    // convert multiaddr to a printable http url
    let port = gw.split("/tcp/").nth(1).unwrap_or("0");
    println!("margo ipfs registry serving on http://0.0.0.0:{}", port);
    println!("  gateway:  http://0.0.0.0:{}/ipfs/<cid>", port);
    println!("  registry: http://0.0.0.0:{}/config.json", port);
    println!("  peer id:  {}", node.peer_id().unwrap_or_default());

    // 6. optionally start an embedded Blossom server
    #[cfg(feature = "blossom-server")]
    if serve.blossom {
        let blossom_port = 3000u16;
        let blobs_dir = r.path.join(".blossom-blobs");
        std::fs::create_dir_all(&blobs_dir).ok();
        let base_url = format!("http://0.0.0.0:{}", blossom_port);
        let backend = blossom_rs::FilesystemBackend::new(&blobs_dir.to_string_lossy())
            .expect("failed to create blossom backend");
        let server = blossom_rs::BlobServer::new(backend, &base_url);
        let router = server.router();
        // Add static file serving for registry files
        let static_dir = r.path.clone();
        let app = router.fallback_service(tower_http::services::ServeDir::new(&static_dir));

        let addr = format!("0.0.0.0:{}", blossom_port);
        println!(
            "Blossom server listening on http://0.0.0.0:{}",
            blossom_port
        );
        println!("  blobs: {}/.blossom-blobs/", r.path.display());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
    }

    // 6b. optionally start a GRASP (NIP-34) git relay
    #[cfg(feature = "grasp")]
    if serve.grasp {
        let grasp_port = 8080u16;
        let repos_dir = r.path.join(".grasp-repos");
        let db_dir = r.path.join(".grasp-db");
        std::fs::create_dir_all(&repos_dir).ok();
        std::fs::create_dir_all(&db_dir).ok();

        // Load or generate Nostr keypair
        let key_path = r.path.join(".nostr-key");
        let nsec = if key_path.exists() {
            std::fs::read_to_string(&key_path)
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            let key = kubo_ffi::nostr_generate_key().unwrap_or_default();
            std::fs::write(&key_path, &key).ok();
            key
        };
        let npub = kubo_ffi::nostr_get_public_key(&nsec).unwrap_or_else(|_| "unknown".to_string());
        println!("Nostr pubkey: {}", npub);

        // Create a bare clone of the registry git repo if it's a git repo
        let git_dir = r.path.join(".git");
        if git_dir.exists() {
            let bare_repo = repos_dir.join(&npub).join("registry.git");
            if !bare_repo.exists() {
                std::fs::create_dir_all(bare_repo.parent().unwrap()).ok();
                let _ = std::process::Command::new("git")
                    .args([
                        "clone",
                        "--bare",
                        &r.path.to_string_lossy(),
                        &bare_repo.to_string_lossy(),
                    ])
                    .status();
            }
        }

        let config = blossom_nip34::Nip34Config {
            domain: "localhost".into(),
            server_url: format!("http://localhost:{}", grasp_port),
            lmdb_path: db_dir,
            repos_path: repos_dir,
            git_path: "git".into(),
            ..Default::default()
        };

        let router = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(blossom_nip34::build_nip34_router(config))
            .expect("failed to build GRASP router");

        let addr = format!("0.0.0.0:{}", grasp_port);
        println!("GRASP relay listening on http://0.0.0.0:{}", grasp_port);
        println!("  npub: {}", npub);
        println!(
            "  clone URL: http://localhost:{}/{}/registry.git",
            grasp_port, npub
        );

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
                axum::serve(listener, router).await.unwrap();
            });
        });
    }

    // 7. block forever (Ctrl-C to exit)
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

#[cfg(feature = "ipfs")]
#[derive(Debug, Snafu)]
enum IpfsServeError {
    #[snafu(display("Could not initialize kubo repo: {reason}"))]
    Init { reason: String },

    #[snafu(display("Could not start kubo node: {reason}"))]
    NodeStart { reason: String },

    #[snafu(display("Could not register static dir: {reason}"))]
    Static { reason: String },

    #[snafu(display("Could not start gateway: {reason}"))]
    Gateway { reason: String },
}

#[cfg(feature = "ipfs")]
fn do_sync_ipfs(_global: &Global, sync: SyncArgs) -> Result<(), Error> {
    use kubo_ffi::Node;

    let r = discover_registry(sync.registry)?;

    // 0a. GRASP sync path (Nostr-authorized git relay)
    #[cfg(feature = "grasp")]
    if let Some(relay_url) = &sync.grasp {
        let npub = sync.grasp_npub.as_deref().unwrap_or("");
        let repo = sync.grasp_repo.as_deref().unwrap_or("registry");
        let clone_url = format!("{}/{}/{}.git", relay_url.trim_end_matches('/'), npub, repo);
        println!("Syncing from GRASP relay: {}", clone_url);

        let tmp_dir = std::env::temp_dir().join(format!("margo-grasp-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        let status = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                &clone_url,
                &tmp_dir.to_string_lossy(),
            ])
            .status()
            .map_err(|e| SyncError::GitClone {
                reason: e.to_string(),
            })?;
        if !status.success() {
            return Err(SyncError::GitClone {
                reason: "git clone from GRASP relay failed".to_string(),
            }
            .into());
        }

        // Find the registry dir in the clone
        let src_dir = if tmp_dir.join("config.json").exists() {
            tmp_dir.clone()
        } else {
            std::fs::read_dir(&tmp_dir)
                .ok()
                .and_then(|mut entries| {
                    entries.find_map(|e| {
                        let p = e.ok()?.path();
                        if p.join("config.json").exists() {
                            Some(p)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(tmp_dir.clone())
        };

        println!("Syncing from: {}", src_dir.display());

        // Merge (same logic as git sync)
        let mut merged = 0usize;
        let mut added = 0usize;
        for entry in walkdir::WalkDir::new(&src_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let rel = path.strip_prefix(&src_dir).unwrap_or(path);
            let rel_str = rel.to_string_lossy();
            if rel_str == "config.json"
                || rel_str.starts_with("crates/")
                || rel_str.ends_with(".crate")
            {
                if rel_str.ends_with(".crate") {
                    let dest = r.path.join(&*rel_str);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }
                    if !dest.exists() {
                        std::fs::copy(path, &dest).ok();
                    }
                }
                continue;
            }
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let remote_entry: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let name_str = match remote_entry.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => continue,
                };
                let name = match CrateName::try_from(name_str) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let version_str = match remote_entry.get("vers").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => continue,
                };
                let version: semver::Version = match version_str.parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let index_path = r.index_file_path_for(&name);
                let mut local_index: Index = if index_path.exists() {
                    Registry::parse_index_file(&index_path).unwrap_or_default()
                } else {
                    Default::default()
                };

                let has_entry = local_index.contains_key(&version);
                if has_entry {
                    let ipfs_cid_missing = local_index.get(&version).unwrap().ipfs_cid.is_none();
                    let blossom_url_missing =
                        local_index.get(&version).unwrap().blossom_url.is_none();
                    if ipfs_cid_missing {
                        if let Some(cid) = remote_entry.get("ipfs_cid").and_then(|v| v.as_str()) {
                            let mut updated = local_index.get(&version).unwrap().clone();
                            updated.ipfs_cid = Some(cid.to_string());
                            local_index.insert(version.clone(), updated);
                            merged += 1;
                        }
                    }
                    if blossom_url_missing {
                        if let Some(url) = remote_entry.get("blossom_url").and_then(|v| v.as_str())
                        {
                            let mut updated = local_index.get(&version).unwrap().clone();
                            updated.blossom_url = Some(url.to_string());
                            local_index.insert(version.clone(), updated);
                            merged += 1;
                        }
                    }
                } else {
                    if let Ok(entry) = serde_json::from_str::<index_entry::Root>(line) {
                        local_index.insert(version.clone(), entry);
                        added += 1;
                    }
                }

                if let Some(parent) = index_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let lines_out: Vec<String> = local_index
                    .values()
                    .map(|e| serde_json::to_string(e).unwrap())
                    .collect();
                std::fs::write(
                    &index_path,
                    lines_out.join("\n") + if !lines_out.is_empty() { "\n" } else { "" },
                )
                .ok();
            }
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
        println!("GRASP sync complete: {} added, {} merged", added, merged);
        return Ok(());
    }

    // 0. Git sync path (alternative to IPFS)
    #[cfg(feature = "ipfs")]
    if let Some(git_url) = &sync.git {
        println!("Syncing from git remote: {}", git_url);
        let tmp_dir = std::env::temp_dir().join(format!("margo-git-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // Clone the remote repo
        let status = std::process::Command::new("git")
            .args(["clone", "--depth", "1", git_url, &tmp_dir.to_string_lossy()])
            .status()
            .map_err(|e| SyncError::GitClone {
                reason: e.to_string(),
            })?;
        if !status.success() {
            return Err(SyncError::GitClone {
                reason: "git clone failed".to_string(),
            }
            .into());
        }

        // The cloned repo might have the registry at root or in a subdirectory.
        // Try root first, then look for config.json.
        let src_dir = if tmp_dir.join("config.json").exists() {
            tmp_dir.clone()
        } else {
            // Look one level deep
            std::fs::read_dir(&tmp_dir)
                .ok()
                .and_then(|mut entries| {
                    entries.find_map(|e| {
                        let p = e.ok()?.path();
                        if p.join("config.json").exists() {
                            Some(p)
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(tmp_dir.clone())
        };

        println!("Syncing from: {}", src_dir.display());

        // Walk the cloned registry and merge
        let mut merged = 0usize;
        let mut added = 0usize;
        for entry in walkdir::WalkDir::new(&src_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let rel = path.strip_prefix(&src_dir).unwrap_or(path);
            let rel_str = rel.to_string_lossy();
            if rel_str == "config.json"
                || rel_str.starts_with("crates/")
                || rel_str.ends_with(".crate")
            {
                // Copy crate files
                if rel_str.ends_with(".crate") {
                    let dest = r.path.join(&*rel_str);
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }
                    if !dest.exists() {
                        std::fs::copy(path, &dest).ok();
                    }
                }
                continue;
            }
            // Index file: parse and merge
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let remote_entry: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let name_str = match remote_entry.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => continue,
                };
                let name = match CrateName::try_from(name_str) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let version_str = match remote_entry.get("vers").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => continue,
                };
                let version: semver::Version = match version_str.parse() {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let index_path = r.index_file_path_for(&name);
                let mut local_index: Index = if index_path.exists() {
                    Registry::parse_index_file(&index_path).unwrap_or_default()
                } else {
                    Default::default()
                };

                let has_entry = local_index.contains_key(&version);
                if has_entry {
                    let ipfs_cid_missing = local_index.get(&version).unwrap().ipfs_cid.is_none();
                    let blossom_url_missing =
                        local_index.get(&version).unwrap().blossom_url.is_none();
                    if ipfs_cid_missing {
                        if let Some(cid) = remote_entry.get("ipfs_cid").and_then(|v| v.as_str()) {
                            let mut updated = local_index.get(&version).unwrap().clone();
                            updated.ipfs_cid = Some(cid.to_string());
                            local_index.insert(version.clone(), updated);
                            merged += 1;
                        }
                    }
                    if blossom_url_missing {
                        if let Some(url) = remote_entry.get("blossom_url").and_then(|v| v.as_str())
                        {
                            let mut updated = local_index.get(&version).unwrap().clone();
                            updated.blossom_url = Some(url.to_string());
                            local_index.insert(version.clone(), updated);
                            merged += 1;
                        }
                    }
                } else {
                    if let Ok(entry) = serde_json::from_str::<index_entry::Root>(line) {
                        local_index.insert(version.clone(), entry);
                        added += 1;
                    }
                }

                if let Some(parent) = index_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let lines_out: Vec<String> = local_index
                    .values()
                    .map(|e| serde_json::to_string(e).unwrap())
                    .collect();
                std::fs::write(
                    &index_path,
                    lines_out.join("\n") + if !lines_out.is_empty() { "\n" } else { "" },
                )
                .ok();
            }
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
        println!("Git sync complete: {} added, {} merged", added, merged);
        return Ok(());
    }

    // 1. Init/reuse IPFS repo
    let repo_path = r.path.join(".ipfs-repo");
    if !repo_path.exists() {
        kubo_ffi::init_repo(&repo_path.to_string_lossy())
            .map_err(|e| SyncError::RepoInit { reason: e })?;
    }
    let node = Node::start(&repo_path.to_string_lossy(), true)
        .map_err(|e| SyncError::NodeStartup { reason: e })?;

    // 2. Dial peer if given
    if let Some(peer) = &sync.peer {
        if !node.connect(peer) {
            eprintln!(
                "warning: failed to connect to {}: {}",
                peer,
                kubo_ffi::last_error().unwrap_or_default()
            );
        } else {
            println!("connected to {}", peer);
        }
    }

    // 3. Resolve root CID
    let root_cid = if let Some(cid) = &sync.cid {
        cid.clone()
    } else if let Some(ipns) = &sync.ipns {
        let out = node
            .run_on_node(&repo_path.to_string_lossy(), &["name", "resolve", ipns])
            .map_err(|e| SyncError::Resolve { reason: e })?;
        // Output is like "/ipfs/Qm..." or a struct dump; extract CID
        let cid = extract_last_cid(&out).ok_or_else(|| SyncError::Resolve {
            reason: format!("could not parse CID from: {}", out),
        })?;
        cid
    } else {
        return Err(SyncError::MissingCid.into());
    };

    println!("Syncing from root CID: {}", root_cid);

    // 4. Fetch remote registry into a temp dir
    let tmp_dir = std::env::temp_dir().join(format!("margo-sync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).map_err(|e| SyncError::Io {
        reason: e.to_string(),
    })?;

    // Recursive fetcher: walks the IPFS DAG and writes files to tmp_dir
    fn fetch_tree(
        node: &Node,
        repo_path: &str,
        cid: &str,
        prefix: &str,
        base_dir: &std::path::Path,
    ) -> Result<(), String> {
        let ls_path = if prefix.is_empty() {
            cid.to_string()
        } else {
            format!("{}/{}", cid, prefix)
        };
        let ls_arg = ls_path.clone();
        let out = node.run_on_node(repo_path, &["ls", &ls_arg])?;
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let _entry_cid = parts[0];
            let size = parts[1];
            let name = parts[2];
            let remote_path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{}/{}", prefix, name)
            };
            let local_path = base_dir.join(&remote_path);
            if size == "-" {
                // directory
                std::fs::create_dir_all(&local_path).ok();
                fetch_tree(node, repo_path, cid, &remote_path, base_dir)?;
            } else {
                // file
                if let Some(parent) = local_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                let ipfs_path = format!("/ipfs/{}/{}", cid, remote_path);
                let bytes = node.unixfs_cat(&ipfs_path)?;
                std::fs::write(&local_path, &bytes).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    fetch_tree(&node, &repo_path.to_string_lossy(), &root_cid, "", &tmp_dir)
        .map_err(|e| SyncError::Fetch { reason: e })?;

    println!("Fetched remote registry to {}", tmp_dir.display());

    // 5. Parse remote index files and merge into local registry
    // Walk the temp dir for index files (files without extension in prefix dirs)
    let mut merged = 0usize;
    let mut added = 0usize;
    for entry in walkdir::WalkDir::new(&tmp_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip config.json, .crate files, and files in crates/
        let rel = path.strip_prefix(&tmp_dir).unwrap_or(path);
        let rel_str = rel.to_string_lossy();
        if rel_str == "config.json" || rel_str.starts_with("crates/") || rel_str.ends_with(".crate")
        {
            continue;
        }
        // This is an index file. Parse it.
        let contents = std::fs::read_to_string(path).unwrap_or_default();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let remote_entry: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let name_str = match remote_entry.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let name = match CrateName::try_from(name_str) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let version_str = match remote_entry.get("vers").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => continue,
            };
            let version: semver::Version = match version_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Read local index
            let index_path = r.index_file_path_for(&name);
            let mut local_index: Index = if index_path.exists() {
                Registry::parse_index_file(&index_path).unwrap_or_default()
            } else {
                Default::default()
            };

            // Check if this version already exists locally
            if let Some(local_entry) = local_index.get(&version) {
                // Merge ipfs_cid if missing
                if local_entry.ipfs_cid.is_none() {
                    if let Some(cid) = remote_entry.get("ipfs_cid").and_then(|v| v.as_str()) {
                        // Update the local entry
                        let mut updated = local_entry.clone();
                        updated.ipfs_cid = Some(cid.to_string());
                        local_index.insert(version.clone(), updated);
                        merged += 1;
                    }
                }
            } else {
                // New crate/version: fetch the .crate file if ipfs_cid is available
                if let Some(_cid) = remote_entry.get("ipfs_cid").and_then(|v| v.as_str()) {
                    let crate_path = r.crate_file_path_for(&name, &version);
                    if !crate_path.exists() {
                        if let Some(parent) = crate_path.parent() {
                            std::fs::create_dir_all(parent).ok();
                        }
                        // Fetch from the remote registry's crate path
                        let remote_crate_path = format!(
                            "/ipfs/{}/crates/{}/{}.crate",
                            root_cid,
                            // Need prefix - compute from name
                            {
                                let n = name.len();
                                if n <= 1 {
                                    "1".to_string()
                                } else if n == 2 {
                                    "2".to_string()
                                } else if n == 3 {
                                    format!("3/{}", &name.as_str()[0..1])
                                } else {
                                    format!("{}/{}", &name.as_str()[0..2], &name.as_str()[2..4])
                                }
                            },
                            version
                        );
                        if let Ok(bytes) = node.unixfs_cat(&remote_crate_path) {
                            std::fs::write(&crate_path, &bytes).ok();
                        }
                    }
                }
                // Insert the remote entry into local index
                // We need to deserialize into index_entry::Root
                if let Ok(entry) = serde_json::from_str::<index_entry::Root>(line) {
                    local_index.insert(version.clone(), entry);
                    added += 1;
                }
            }

            // Write the updated index file
            if let Some(parent) = index_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            // Write all entries
            let lines_out: Vec<String> = local_index
                .values()
                .map(|e| serde_json::to_string(e).unwrap())
                .collect();
            std::fs::write(
                &index_path,
                lines_out.join("\n") + if !lines_out.is_empty() { "\n" } else { "" },
            )
            .ok();
        }
    }

    println!(
        "Sync complete: {} added, {} merged (ipfs_cid)",
        added, merged
    );

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Drop node
    drop(node);

    Ok(())
}

#[cfg(feature = "ipfs")]
#[derive(Debug, Snafu)]
enum SyncError {
    #[snafu(display("Could not clone git remote: {reason}"))]
    GitClone { reason: String },

    #[snafu(display("Could not initialize kubo repo: {reason}"))]
    RepoInit { reason: String },

    #[snafu(display("Could not start kubo node: {reason}"))]
    NodeStartup { reason: String },

    #[snafu(display("Could not resolve IPNS name: {reason}"))]
    Resolve { reason: String },

    #[snafu(display("Root CID is required (--cid or --ipns)"))]
    MissingCid,

    #[snafu(display("Could not fetch remote registry: {reason}"))]
    Fetch { reason: String },

    #[snafu(display("IO error: {reason}"))]
    Io { reason: String },
}

fn discover_registry(path: Option<PathBuf>) -> Result<Registry, DiscoverRegistryError> {
    use discover_registry_error::*;

    match path {
        Some(p) => Registry::open(p).context(OpenSnafu),
        None => {
            let cwd = env::current_dir().context(CurrentDirSnafu)?;

            match Registry::open(cwd) {
                Ok(r) => Ok(r),
                Err(e) if e.is_not_found() => FallbackNotFoundSnafu.fail(),
                Err(e) => Err(e).context(FallbackOpenSnafu)?,
            }
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum DiscoverRegistryError {
    #[snafu(display("Could not open the specified registry"))]
    Open { source: OpenError },

    #[snafu(display("Could not determine the current directory, {}", Self::TRY_THIS))]
    CurrentDir { source: io::Error },

    #[snafu(display(
        "The current directory does not contain a registry, {}",
        Self::TRY_THIS,
    ))]
    FallbackNotFound,

    #[snafu(display("Could not open the registry in the current directory"))]
    FallbackOpen { source: OpenError },
}

impl DiscoverRegistryError {
    const TRY_THIS: &'static str = "please use the `--registry` command line option";
}

#[derive(Debug)]
struct Registry {
    path: PathBuf,
    config: ConfigV1,
}

type Index = BTreeMap<Version, index_entry::Root>;
type ListAll = BTreeMap<CrateName, Index>;

impl Registry {
    fn initialize(config: ConfigV1, path: impl Into<PathBuf>) -> Result<Self, InitializeError> {
        use initialize_error::*;

        let config = config.normalize();
        let path = path.into();

        println!("Initializing registry in `{}`", path.display());

        fs::create_dir_all(&path).context(RegistryCreateSnafu)?;

        let config_toml_path = path.join(CONFIG_FILE_NAME);
        let config = Config::V1(config);
        let config_toml = toml::to_string(&config).context(ConfigTomlSerializeSnafu)?;
        fs::write(&config_toml_path, config_toml).context(ConfigTomlWriteSnafu {
            path: &config_toml_path,
        })?;

        let Config::V1(config) = config;

        let dl = format!(
            "{base_url}crates/{{lowerprefix}}/{{crate}}/{{version}}.crate",
            base_url = config.base_url,
        );
        let auth_required = config.auth_required;

        let this = Self { path, config };

        let config_json_path = this.config_json_path();
        let config_json = config_json::Root {
            dl,
            api: None,
            auth_required,
        };
        let config_json = serde_json::to_string(&config_json).context(ConfigJsonSerializeSnafu)?;
        fs::write(&config_json_path, config_json).context(ConfigJsonWriteSnafu {
            path: &config_json_path,
        })?;

        Ok(this)
    }

    fn open(path: impl Into<PathBuf>) -> Result<Self, OpenError> {
        use open_error::*;

        let path = path.into();

        let config_path = path.join(CONFIG_FILE_NAME);
        let config = fs::read_to_string(&config_path).context(ReadSnafu { path: &config_path })?;
        let Config::V1(config) =
            toml::from_str(&config).context(DeserializeSnafu { path: &config_path })?;

        Ok(Self { path, config })
    }

    #[cfg_attr(not(feature = "ipfs"), allow(unused_variables))]
    #[cfg_attr(not(feature = "blossom-client"), allow(unused_variables))]
    fn add(
        &self,
        global: &Global,
        crate_path: impl AsRef<Path>,
        publish_ipfs: bool,
        blossom_local: bool,
        blossom_server: Option<String>,
        _blossom_key: Option<String>,
    ) -> Result<(), AddError> {
        use add_error::*;

        let crate_path = crate_path.as_ref();

        println!("Adding crate `{}` to registry", crate_path.display());

        let crate_file = fs::read(crate_path).context(ReadCrateSnafu)?;

        use sha2::Digest;
        let checksum = sha2::Sha256::digest(&crate_file);
        let checksum_hex = hex::encode(checksum);

        let cargo_toml = extract_root_cargo_toml(&crate_file)?.context(CargoTomlMissingSnafu)?;

        let cargo_toml = String::from_utf8(cargo_toml).context(CargoTomlUtf8Snafu)?;
        let cargo_toml = toml::from_str(&cargo_toml).context(CargoTomlMalformedSnafu)?;

        #[cfg_attr(not(feature = "ipfs"), allow(unused_mut))]
        let mut index_entry =
            adapt_cargo_toml_to_index_entry(global, &self.config, cargo_toml, checksum_hex);

        #[cfg(feature = "ipfs")]
        if publish_ipfs {
            let config_path = self.path.join("config.json");
            let auth_required = std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
                .and_then(|v| v.get("auth-required").and_then(|x| x.as_bool()))
                .unwrap_or(self.config.auth_required);
            if auth_required {
                eprintln!(
                    "WARNING: auth_required is true but --ipfs publishes the crate to the PUBLIC \
                     IPFS network. Anyone with the CID can fetch it, bypassing auth. \
                     Proceeding anyway; use a private swarm (--networked + swarm key) for privacy."
                );
            }
            let repo_path = self.path.join(".ipfs-repo");
            if !repo_path.exists() {
                kubo_ffi::init_repo_networked(&repo_path.to_string_lossy())
                    .map_err(|e| AddError::Ipfs { reason: e })?;
            }
            let node = kubo_ffi::Node::start(&repo_path.to_string_lossy(), true)
                .map_err(|e| AddError::Ipfs { reason: e })?;
            let cid = node
                .unixfs_add_bytes(&crate_file)
                .map_err(|e| AddError::Ipfs { reason: e })?;
            println!("Published to IPFS: {}", cid);
            index_entry.ipfs_cid = Some(cid);
            // node dropped here; repo + pin persist on disk
        }

        #[cfg(feature = "blossom-client")]
        if blossom_local {
            // Store blob locally in .blossom-blobs/<sha256>
            use sha2::Digest;
            let sha256 = hex::encode(sha2::Sha256::digest(&crate_file));
            let blobs_dir = self.path.join(".blossom-blobs");
            std::fs::create_dir_all(&blobs_dir).ok();
            std::fs::write(blobs_dir.join(format!("{}.blob", sha256)), &crate_file).ok();
            println!(
                "Stored Blossom blob locally: {} (sha256={})",
                sha256, sha256
            );
            index_entry.blossom_url = Some(format!("http://localhost:3000/{}", sha256));
        }

        #[cfg(feature = "blossom-client")]
        if let Some(server_url) = &blossom_server {
            if let Some(key) = &_blossom_key {
                // Authenticated upload via blossom-rs client (Nostr BIP-340 auth)
                let signer = blossom_rs::Signer::from_secret_hex(key)
                    .map_err(|e| AddError::Blossom { reason: e })?;
                let client = blossom_rs::BlossomClient::new(vec![server_url.clone()], signer);
                let rt = tokio::runtime::Runtime::new().map_err(|e| AddError::Blossom {
                    reason: e.to_string(),
                })?;
                let desc = rt
                    .block_on(client.upload(&crate_file, "application/gzip"))
                    .map_err(|e| AddError::Blossom { reason: e })?;
                let blob_url = desc.url.clone().unwrap_or_else(|| {
                    format!("{}/{}", server_url.trim_end_matches('/'), desc.sha256)
                });
                println!(
                    "Published to Blossom (auth): {} (sha256={})",
                    blob_url, desc.sha256
                );
                index_entry.blossom_url = Some(blob_url);
            } else {
                // Anonymous upload via HTTP
                let url = format!("{}/upload", server_url.trim_end_matches('/'));
                let rt = tokio::runtime::Runtime::new().map_err(|e| AddError::Blossom {
                    reason: e.to_string(),
                })?;
                let resp = rt
                    .block_on(async {
                        reqwest::Client::new()
                            .put(&url)
                            .header("Content-Type", "application/gzip")
                            .body(crate_file.clone())
                            .send()
                            .await
                    })
                    .map_err(|e| AddError::Blossom {
                        reason: e.to_string(),
                    })?;
                if !resp.status().is_success() {
                    return Err(AddError::Blossom {
                        reason: format!("HTTP {}", resp.status()),
                    });
                }
                let text = rt.block_on(resp.text()).map_err(|e| AddError::Blossom {
                    reason: e.to_string(),
                })?;
                let body: serde_json::Value =
                    serde_json::from_str(&text).map_err(|e| AddError::Blossom {
                        reason: e.to_string(),
                    })?;
                let sha256 = body
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let blob_url = body
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}/{}", server_url.trim_end_matches('/'), sha256));
                println!("Published to Blossom: {} (sha256={})", blob_url, sha256);
                index_entry.blossom_url = Some(blob_url);
            }
        }

        let index_path = self.index_file_path_for(&index_entry.name);
        if let Some(path) = index_path.parent() {
            fs::create_dir_all(path).context(IndexDirSnafu { path })?;
        }

        let crate_file_path = self.crate_file_path_for(&index_entry.name, &index_entry.vers);
        if let Some(path) = crate_file_path.parent() {
            fs::create_dir_all(path).context(CrateDirSnafu { path })?;
        }

        // FUTURE: Stronger file system consistency (atomic file overwrites, rollbacks on error)
        // FUTURE: "transactional" adding of multiple crates

        self.read_modify_write(&index_entry.name.clone(), |index_file| {
            index_file.insert(index_entry.vers.clone(), index_entry);
            Ok::<_, AddError>(())
        })?;

        println!("Wrote crate index to `{}`", index_path.display());

        fs::write(&crate_file_path, &crate_file).context(CrateWriteSnafu {
            path: &crate_file_path,
        })?;
        println!("Wrote crate to `{}`", crate_file_path.display());

        Ok(())
    }

    fn remove(&self, name: CrateName, version: Version) -> Result<(), RemoveError> {
        use remove_error::*;

        self.read_modify_write(&name, |index| {
            index.remove(&version);
            Ok::<_, RemoveError>(())
        })?;

        let crate_file = self.crate_file_path_for(&name, &version);
        match fs::remove_file(&crate_file) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context(DeleteSnafu { path: crate_file }),
        }
    }

    #[cfg(feature = "html")]
    fn generate_html(&self) -> Result<(), HtmlError> {
        html::write(self)
    }

    #[cfg(not(feature = "html"))]
    fn generate_html(&self) -> Result<(), HtmlError> {
        Err(HtmlError)
    }

    fn maybe_generate_html(&self) -> Result<(), HtmlError> {
        if self.config.html.enabled {
            self.generate_html()
        } else {
            Ok(())
        }
    }

    fn yank(&self, name: CrateName, version: Version, yanked: bool) -> Result<(), YankError> {
        use yank_error::*;

        self.read_modify_write(&name, |index| {
            let entry = index.get_mut(&version).context(VersionSnafu)?;
            entry.yanked = yanked;
            Ok(())
        })
    }

    fn read_modify_write<T, E>(
        &self,
        name: &CrateName,
        modify: impl FnOnce(&mut Index) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ReadModifyWriteError>,
    {
        use read_modify_write_error::*;

        let path = self.index_file_path_for(name);
        let mut index = Self::parse_index_file(&path).context(IndexParseSnafu { path: &path })?;

        let val = modify(&mut index)?;

        Self::write_index_file(index, &path).context(IndexWriteSnafu { path })?;

        Ok(val)
    }

    fn list_crate_files(
        crate_dir: &Path,
    ) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> {
        walkdir::WalkDir::new(crate_dir)
            .into_iter()
            .flat_map(|entry| {
                let Ok(entry) = entry else { return Some(entry) };

                let fname = entry.path().file_name()?;
                let fname = Path::new(fname);

                let extension = fname.extension()?;
                if extension == "crate" {
                    Some(Ok(entry))
                } else {
                    None
                }
            })
    }

    fn list_index_files(&self) -> Result<BTreeSet<PathBuf>, ListIndexFilesError> {
        use list_index_files_error::*;

        let crate_dir = self.crate_dir();

        let index_files = Self::list_crate_files(&crate_dir)
            .map(|entry| {
                let entry = entry.context(WalkdirSnafu { path: &crate_dir })?;

                let mut path = entry.into_path();
                path.pop();

                let subdir = path.strip_prefix(&crate_dir).context(PrefixSnafu {
                    path: &path,
                    prefix: &crate_dir,
                })?;
                let index_path = self.path.join(subdir);
                Ok(index_path)
            })
            .collect::<Result<BTreeSet<_>, ListIndexFilesError>>();

        match index_files {
            Err(e) if e.is_not_found() => Ok(Default::default()),
            r => r,
        }
    }

    fn list_all(&self) -> Result<ListAll, ListAllError> {
        use list_all_error::*;

        let mut crates = BTreeMap::new();

        for path in self.list_index_files()? {
            let index = Self::parse_index_file(&path).context(ParseSnafu { path })?;

            if let Some(entry) = index.values().next() {
                crates.insert(entry.name.clone(), index);
            }
        }

        Ok(crates)
    }

    fn parse_index_file(path: &Path) -> Result<Index, ParseIndexError> {
        use parse_index_error::*;

        let index_file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Default::default()),
            Err(e) => Err(e).context(OpenSnafu)?,
        };
        let index_file = BufReader::new(index_file);

        let mut index = BTreeMap::new();

        for (i, line) in index_file.lines().enumerate() {
            let line = line.context(ReadSnafu { line: i })?;
            let entry =
                serde_json::from_str::<index_entry::Root>(&line).context(ParseSnafu { line: i })?;

            index.insert(entry.vers.clone(), entry);
        }

        Ok(index)
    }

    fn write_index_file(index_file: Index, path: &Path) -> Result<(), WriteIndexError> {
        use write_index_error::*;

        let file = File::create(path).context(OpenSnafu)?;
        let mut file = BufWriter::new(file);

        for entry in index_file.values() {
            serde_json::to_writer(&mut file, entry).context(EntrySerializeSnafu)?;
            file.write_all(b"\n").context(EntryNewlineSnafu)?;
        }

        Ok(())
    }

    fn crate_dir(&self) -> PathBuf {
        self.path.join(CRATE_DIR_NAME)
    }

    #[cfg(test)]
    fn margo_config_toml_path(&self) -> PathBuf {
        self.path.join(CONFIG_FILE_NAME)
    }

    fn config_json_path(&self) -> PathBuf {
        self.path.join("config.json")
    }

    fn index_file_path_for(&self, name: &CrateName) -> PathBuf {
        let mut index_path = self.path.clone();
        name.append_prefix_directories(&mut index_path);
        index_path.push(name);
        index_path
    }

    fn crate_dir_for(&self, name: &CrateName) -> PathBuf {
        let mut crate_dir = self.crate_dir();
        name.append_prefix_directories(&mut crate_dir);
        crate_dir.push(name);
        crate_dir
    }

    fn crate_file_path_for(&self, name: &CrateName, version: &Version) -> PathBuf {
        let mut crate_file_path = self.crate_dir_for(name);
        crate_file_path.push(format!("{}.crate", version));
        crate_file_path
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum InitializeError {
    #[snafu(display("Could not create the registry directory"))]
    RegistryCreate { source: io::Error },

    #[snafu(display("Could not serialize the registry's internal configuration"))]
    ConfigTomlSerialize { source: toml::ser::Error },

    #[snafu(display("Could not write the registry's internal configuration to {}", path.display()))]
    ConfigTomlWrite { source: io::Error, path: PathBuf },

    #[snafu(display("Could not serialize the registry's public configuration"))]
    ConfigJsonSerialize { source: serde_json::Error },

    #[snafu(display("Could not write the registry's public configuration to {}", path.display()))]
    ConfigJsonWrite { source: io::Error, path: PathBuf },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum OpenError {
    #[snafu(display("Could not open the registry's internal configuration at {}", path.display()))]
    Read { source: io::Error, path: PathBuf },

    #[snafu(display("Could not deserialize the registry's internal configuration at {}", path.display()))]
    Deserialize {
        source: toml::de::Error,
        path: PathBuf,
    },
}

impl OpenError {
    fn is_not_found(&self) -> bool {
        match self {
            Self::Read { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Self::Deserialize { .. } => false,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum AddError {
    #[snafu(display("Could not read the crate package"))]
    ReadCrate { source: io::Error },

    #[snafu(transparent)]
    CargoTomlExtract { source: ExtractRootCargoTomlError },

    #[snafu(display("The crate package does not contain a Cargo.toml file"))]
    CargoTomlMissing,

    #[snafu(display("The crate's Cargo.toml is not valid UTF-8"))]
    CargoTomlUtf8 { source: std::string::FromUtf8Error },

    #[snafu(display("The crate's Cargo.toml is malformed"))]
    CargoTomlMalformed { source: toml::de::Error },

    #[snafu(display("Could not create the crate's index directory {}", path.display()))]
    IndexDir { source: io::Error, path: PathBuf },

    #[snafu(transparent)]
    IndexModify { source: ReadModifyWriteError },

    #[snafu(display("Could not create the crate directory {}", path.display()))]
    CrateDir { source: io::Error, path: PathBuf },

    #[snafu(display("Could not write the crate {}", path.display()))]
    CrateWrite { source: io::Error, path: PathBuf },

    #[cfg(feature = "ipfs")]
    #[snafu(display("IPFS publish failed: {reason}"))]
    Ipfs { reason: String },

    #[cfg(feature = "blossom-client")]
    #[snafu(display("Blossom publish failed: {reason}"))]
    Blossom { reason: String },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum RemoveError {
    #[snafu(transparent)]
    IndexModify { source: ReadModifyWriteError },

    #[snafu(display("Could not delete the crate file {}", path.display()))]
    Delete { source: io::Error, path: PathBuf },
}

#[cfg(feature = "html")]
use html::Error as HtmlError;

#[cfg(not(feature = "html"))]
#[derive(Debug, Snafu)]
#[snafu(display("Margo was not compiled with the HTML feature enabled. This binary will not be able to generate HTML files"))]
struct HtmlError;

#[derive(Debug, Snafu)]
#[snafu(module)]
enum YankError {
    #[snafu(display("The version does not exist in the index"))]
    Version,

    #[snafu(transparent)]
    Modify { source: ReadModifyWriteError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum ReadModifyWriteError {
    #[snafu(display("Could not parse the crate's index file {}", path.display()))]
    IndexParse {
        source: ParseIndexError,
        path: PathBuf,
    },

    #[snafu(display("Could not write the crate's index file {}", path.display()))]
    IndexWrite {
        source: WriteIndexError,
        path: PathBuf,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum ListIndexFilesError {
    #[snafu(display("Could not enumerate the crate directory `{}`", path.display()))]
    Walkdir {
        source: walkdir::Error,
        path: PathBuf,
    },

    #[snafu(display(
        "Could not remove the path prefix `{prefix}` from the crate package entry `{path}`",
        prefix = prefix.display(),
        path = path.display(),
    ))]
    Prefix {
        source: std::path::StripPrefixError,
        path: PathBuf,
        prefix: PathBuf,
    },
}

impl ListIndexFilesError {
    fn is_not_found(&self) -> bool {
        if let Self::Walkdir { source, .. } = self {
            if let Some(e) = source.io_error() {
                if e.kind() == io::ErrorKind::NotFound {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum ListAllError {
    #[snafu(display("Unable to list the crate index files"))]
    #[snafu(context(false))]
    ListIndex { source: ListIndexFilesError },

    #[snafu(display("Unable to parse the crate index file at `{}`", path.display()))]
    Parse {
        source: ParseIndexError,
        path: PathBuf,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum ParseIndexError {
    #[snafu(display("Could not open the file"))]
    Open { source: io::Error },

    #[snafu(display("Could not read line {line}"))]
    Read { source: io::Error, line: usize },

    #[snafu(display("Could not parse line {line}"))]
    Parse {
        source: serde_json::Error,
        line: usize,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum WriteIndexError {
    #[snafu(display("Could not open the file"))]
    Open { source: io::Error },

    #[snafu(display("Could not serialize the entry"))]
    EntrySerialize { source: serde_json::Error },

    #[snafu(display("Could not write the entry's newline"))]
    EntryNewline { source: io::Error },
}

fn extract_root_cargo_toml(
    crate_data: &[u8],
) -> Result<Option<Vec<u8>>, ExtractRootCargoTomlError> {
    use extract_root_cargo_toml_error::*;

    let crate_data = flate2::read::GzDecoder::new(crate_data);
    let mut crate_data = tar::Archive::new(crate_data);

    let entries = crate_data.entries().context(EntriesSnafu)?;

    let mut dirname = None;

    for entry in entries {
        let mut entry = entry.context(EntrySnafu)?;
        let path = entry.path().context(PathSnafu)?;

        let dirname = match &mut dirname {
            Some(v) => v,
            None => {
                let Some(Component::Normal(first)) = path.components().next() else {
                    return MalformedSnafu.fail();
                };

                dirname.insert(first.to_owned())
            }
        };

        let fname = path.strip_prefix(dirname).context(PrefixSnafu)?;

        if fname == Path::new("Cargo.toml") {
            let mut data = vec![];
            entry.read_to_end(&mut data).context(ReadSnafu)?;
            return Ok(Some(data));
        }
    }

    Ok(None)
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum ExtractRootCargoTomlError {
    #[snafu(display("Could not get the entries of the crate package"))]
    Entries { source: io::Error },

    #[snafu(display("Could not get the next crate package entry"))]
    Entry { source: io::Error },

    #[snafu(display("Could not get the path of the crate package entry"))]
    Path { source: io::Error },

    #[snafu(display("The crate package was malformed"))]
    Malformed,

    #[snafu(display("Could not remove the path prefix from the crate package entry"))]
    Prefix { source: std::path::StripPrefixError },

    #[snafu(display("Could not read the crate package entry for Cargo.toml"))]
    Read { source: io::Error },
}

fn adapt_cargo_toml_to_index_entry(
    global: &Global,
    config: &ConfigV1,
    mut cargo_toml: cargo_toml::Root,
    checksum_hex: String,
) -> index_entry::Root {
    // Remove features that refer to dev-dependencies as we don't
    // track those anyway.
    {
        // Ignore dependencies that also occur as a regular or build
        // dependency, as we *do* track those.
        let reg_dep_names = cargo_toml.dependencies.keys();
        let build_dep_names = cargo_toml.build_dependencies.keys();
        let mut only_dev_dep_names = cargo_toml.dev_dependencies.keys().collect::<BTreeSet<_>>();
        for name in reg_dep_names.chain(build_dep_names) {
            only_dev_dep_names.remove(name);
        }

        for name in only_dev_dep_names {
            // We don't care about the official package name here as the
            // feature syntax has to match the user-specified dependency
            // name.
            let prefix = format!("{name}/");

            for enabled in cargo_toml.features.values_mut() {
                enabled.retain(|enable| !enable.starts_with(&prefix));
            }
        }
    }

    let mut deps: Vec<_> = cargo_toml
        .dependencies
        .into_iter()
        .map(|(name, dep)| adapt_dependency(global, config, dep, name))
        .collect();

    let build_deps = cargo_toml
        .build_dependencies
        .into_iter()
        .map(|(name, dep)| {
            let mut dep = adapt_dependency(global, config, dep, name);
            dep.kind = index_entry::DependencyKind::Build;
            dep
        });
    deps.extend(build_deps);

    for (target, defn) in cargo_toml.target {
        let target_deps = defn.dependencies.into_iter().map(|(name, dep)| {
            let mut dep = adapt_dependency(global, config, dep, name);
            dep.target = Some(target.clone());
            dep
        });
        deps.extend(target_deps);
    }

    // FUTURE: Opt-in to checking that all dependencies already exist

    index_entry::Root {
        name: cargo_toml.package.name,
        vers: cargo_toml.package.version,
        deps,
        cksum: checksum_hex,
        features: cargo_toml.features,
        yanked: false,
        links: cargo_toml.package.links,
        v: 2,
        features2: Default::default(),
        rust_version: cargo_toml.package.rust_version,
        ipfs_cid: None,
        blossom_url: None,
    }
}

fn adapt_dependency(
    global: &Global,
    config: &ConfigV1,
    dep: cargo_toml::Dependency,
    name: String,
) -> index_entry::Dependency {
    let cargo_toml::Dependency {
        version,
        features,
        optional,
        default_features,
        registry_index,
        package,
    } = dep;

    index_entry::Dependency {
        name,
        req: version,
        features,
        optional,
        default_features,
        target: None,
        kind: index_entry::DependencyKind::Normal,
        registry: adapt_index(global, config, registry_index),
        package,
    }
}

fn adapt_index(global: &Global, config: &ConfigV1, registry_index: Option<Url>) -> Option<Url> {
    // The dependency is in...
    match registry_index {
        // ...crates.io
        None => Some(global.crates_io_index_url.clone()),

        // ...this registry
        Some(url) if url == config.base_url => None,

        // ...another registry
        r => r,
    }
}

/// Only intended for the normalized Cargo.toml created for the
/// packaged crate.
mod cargo_toml {
    use semver::{Version, VersionReq};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use url::Url;

    use crate::common::{CrateName, RustVersion};

    pub type Dependencies = BTreeMap<String, Dependency>;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Root {
        pub package: Package,

        #[serde(default)]
        pub features: BTreeMap<String, Vec<String>>,

        #[serde(default)]
        pub dependencies: Dependencies,

        #[serde(default)]
        pub build_dependencies: Dependencies,

        #[serde(default)]
        pub dev_dependencies: Dependencies,

        #[serde(default)]
        pub target: BTreeMap<String, Target>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Package {
        pub name: CrateName,

        pub version: Version,

        #[serde(default)]
        pub links: Option<String>,

        #[serde(default)]
        pub rust_version: Option<RustVersion>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Dependency {
        pub version: VersionReq,

        #[serde(default)]
        pub features: Vec<String>,

        #[serde(default)]
        pub optional: bool,

        #[serde(default = "true_def")]
        pub default_features: bool,

        #[serde(default)]
        pub registry_index: Option<Url>,

        #[serde(default)]
        pub package: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Target {
        #[serde(default)]
        pub dependencies: Dependencies,
    }

    fn true_def() -> bool {
        true
    }
}

const CONFIG_FILE_NAME: &str = "margo-config.toml";
const CRATE_DIR_NAME: &str = "crates";

const CRATES_IO_INDEX_URL: &str = "https://github.com/rust-lang/crates.io-index";

#[derive(Debug)]
struct Global {
    crates_io_index_url: Url,
}

impl Global {
    fn new() -> Result<Self, GlobalError> {
        use global_error::*;

        Ok(Self {
            crates_io_index_url: CRATES_IO_INDEX_URL.parse().context(CratesIoIndexUrlSnafu)?,
        })
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum GlobalError {
    #[snafu(display("Could not parse the crates.io index URL"))]
    CratesIoIndexUrl { source: url::ParseError },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "version")]
enum Config {
    #[serde(rename = "1")]
    V1(ConfigV1),
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigV1 {
    base_url: Url,

    #[serde(default)]
    auth_required: bool,

    #[serde(default)]
    html: ConfigV1Html,
}

impl ConfigV1 {
    const USER_DEFAULT_AUTH_REQUIRED: bool = false;

    fn normalize(mut self) -> ConfigV1 {
        ensure_last_segment_empty(&mut self.base_url);

        self
    }
}

fn ensure_last_segment_empty(url: &mut Url) {
    if let Ok(mut s) = url.path_segments_mut() {
        s.pop_if_empty().push("");
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ConfigV1Html {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    suggested_registry_name: Option<String>,
}

impl ConfigV1Html {
    const USER_DEFAULT_ENABLED: bool = true;
    const USER_DEFAULT_SUGGESTED_REGISTRY_NAME: &'static str = "my-awesome-registry";

    fn suggested_registry_name(&self) -> &str {
        self.suggested_registry_name
            .as_deref()
            .unwrap_or(Self::USER_DEFAULT_SUGGESTED_REGISTRY_NAME)
    }
}

mod config_json {
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct Root {
        // This field cannot be a `url::Url` because that type
        // percent-escapes the `{` and `}` characters. Cargo performs
        // string-replacement on this value based on those literal `{`
        // and `}` characters.
        pub dl: String,

        pub api: Option<String>, // Modified

        /// A private registry requires all operations to be authenticated.
        ///
        /// This includes API requests, crate downloads and sparse
        /// index updates.
        pub auth_required: bool,
    }
}

mod index_entry {
    use semver::{Version, VersionReq};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use url::Url;

    use crate::common::{CrateName, RustVersion};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Root {
        /// The name of the package.
        pub name: CrateName,

        /// The version of the package this row is describing.
        ///
        /// This must be a valid version number according to the
        /// Semantic Versioning 2.0.0 spec at https://semver.org/.
        pub vers: Version,

        /// Direct dependencies of the package.
        pub deps: Vec<Dependency>,

        /// A SHA256 checksum of the `.crate` file.
        pub cksum: String,

        /// Set of features defined for the package.
        ///
        /// Each feature maps to features or dependencies it enables.
        pub features: BTreeMap<String, Vec<String>>,

        /// Boolean of whether or not this version has been yanked.
        pub yanked: bool,

        /// The `links` value from the package's manifest.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub links: Option<String>,

        /// The schema version of this entry.
        //
        /// If this not specified, it should be interpreted as the default of 1.
        //
        /// Cargo (starting with version 1.51) will ignore versions it does not
        /// recognize. This provides a method to safely introduce changes to index
        /// entries and allow older versions of cargo to ignore newer entries it
        /// doesn't understand. Versions older than 1.51 ignore this field, and
        /// thus may misinterpret the meaning of the index entry.
        //
        /// The current values are:
        //
        /// * 1: The schema as documented here, not including newer additions.
        ///   This is honored in Rust version 1.51 and newer.
        /// * 2: The addition of the `features2` field.
        ///   This is honored in Rust version 1.60 and newer.
        pub v: u32,

        /// Features with new, extended syntax, such as namespaced
        /// features (`dep:`) and weak dependencies (`pkg?/feat`).
        //
        /// This is separated from `features` because versions older than 1.19
        /// will fail to load due to not being able to parse the new syntax, even
        /// with a `Cargo.lock` file.
        //
        /// Cargo will merge any values listed here with the "features" field.
        //
        /// If this field is included, the "v" field should be set to at least 2.
        //
        /// Registries are not required to use this field for extended feature
        /// syntax, they are allowed to include those in the "features" field.
        /// Using this is only necessary if the registry wants to support cargo
        /// versions older than 1.19, which in practice is only crates.io since
        /// those older versions do not support other registries.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        pub features2: BTreeMap<String, Vec<String>>,

        /// The minimal supported Rust version
        ///
        /// This must be a valid version requirement without an operator (e.g. no `=`)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rust_version: Option<RustVersion>,

        /// Optional IPFS CID of the `.crate` file, for peer-to-peer distribution.
        ///
        /// Cargo ignores unknown index-entry fields, so this is safe to add.
        /// When present, `margo serve` (ipfs feature) can resolve the crate
        /// through the IPFS gateway instead of (or in addition to) the static
        /// `dl` URL.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ipfs_cid: Option<String>,

        /// Optional Blossom blob URL for the `.crate` file.
        ///
        /// Blossom provides content-addressed blob storage with Nostr auth.
        /// When present, consumers can fetch the crate from this URL (with
        /// Nostr BIP-340 authentication if required).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blossom_url: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Dependency {
        /// Name of the dependency.
        ///
        /// If the dependency is renamed from the original package
        /// name, this is the new name. The original package name is
        /// stored in the `package` field.
        pub name: String,

        /// The SemVer requirement for this dependency.
        ///
        /// This must be a valid version requirement defined at
        /// https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html.
        pub req: VersionReq,

        /// Features enabled for this dependency.
        pub features: Vec<String>,

        /// Whether or not this is an optional dependency.
        pub optional: bool,

        /// Whether or not default features are enabled.
        pub default_features: bool,

        /// The target platform for the dependency.
        ///
        /// A string such as `cfg(windows)`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub target: Option<String>,

        /// The dependency kind.
        ///
        /// Note: this is a required field, but a small number of entries
        /// exist in the crates.io index with either a missing or null
        /// `kind` field due to implementation bugs.
        pub kind: DependencyKind,

        /// The URL of the index of the registry where this dependency
        /// is from.
        ///
        /// If not specified or null, it is assumed the dependency is
        /// in the current registry.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub registry: Option<Url>,

        /// If the dependency is renamed, this is the actual package
        /// name.
        ///
        /// If not specified or null, this dependency is not renamed.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub package: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum DependencyKind {
        #[allow(unused)]
        // Stored in the index, but not actually used by Cargo
        Dev,
        Build,
        Normal,
    }
}

mod common {
    use ascii::{AsciiChar, AsciiStr, AsciiString};
    use semver::Version;
    use serde::{de::Error, Deserialize, Serialize};
    use snafu::prelude::*;
    use std::{
        borrow::Cow,
        fmt, ops,
        path::{Path, PathBuf},
        str::FromStr,
    };

    /// Contains only alphanumeric, `-`, or `_` characters.
    #[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    pub struct CrateName(AsciiString);

    impl CrateName {
        pub fn as_str(&self) -> &str {
            self.0.as_str()
        }

        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn append_prefix_directories(&self, index_path: &mut PathBuf) {
            match self.len() {
                0 => unreachable!(),
                1 => index_path.push("1"),
                2 => index_path.push("2"),
                3 => {
                    let a = &self[0..1];

                    index_path.push("3");
                    index_path.push(a.as_str());
                }
                _ => {
                    let ab = &self[0..2];
                    let cd = &self[2..4];

                    index_path.push(ab.as_str());
                    index_path.push(cd.as_str());
                }
            };
        }
    }

    impl fmt::Display for CrateName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.fmt(f)
        }
    }

    impl FromStr for CrateName {
        type Err = CrateNameError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.try_into()
        }
    }

    impl TryFrom<&str> for CrateName {
        type Error = CrateNameError;

        fn try_from(value: &str) -> Result<Self, Self::Error> {
            value.to_owned().try_into()
        }
    }

    impl TryFrom<String> for CrateName {
        type Error = CrateNameError;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            AsciiString::from_ascii(value)
                .map_err(|e| e.ascii_error())?
                .try_into()
        }
    }

    impl TryFrom<AsciiString> for CrateName {
        type Error = CrateNameError;

        fn try_from(value: AsciiString) -> Result<Self, Self::Error> {
            use crate_name_error::*;

            let first = value.first().context(EmptySnafu)?;
            ensure!(first.is_alphabetic(), InitialAlphaSnafu);

            if let Some(chr) = value.chars().find(|&chr| !valid_crate_name_char(chr)) {
                return ContainsInvalidCharSnafu { chr }.fail();
            }

            Ok(Self(value))
        }
    }

    #[derive(Debug, Snafu)]
    #[snafu(module)]
    pub enum CrateNameError {
        #[snafu(display("The crate name cannot be empty"))]
        Empty,

        #[snafu(display("The crate name must start with an alphabetic character"))]
        InitialAlpha,

        #[snafu(display("The crate name must only contain alphanumeric characters, hyphen (-) or underscore (_), not {chr}"))]
        ContainsInvalidChar { chr: char },

        #[snafu(transparent)]
        NotAscii { source: ascii::AsAsciiStrError },
    }

    impl<'de> Deserialize<'de> for CrateName {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let ascii: AsciiString = Deserialize::deserialize(deserializer)?;
            Self::try_from(ascii).map_err(D::Error::custom)
        }
    }

    impl ops::Index<ops::Range<usize>> for CrateName {
        type Output = AsciiStr;

        fn index(&self, index: ops::Range<usize>) -> &Self::Output {
            self.0.index(index)
        }
    }

    impl AsRef<Path> for CrateName {
        fn as_ref(&self) -> &Path {
            self.0.as_str().as_ref()
        }
    }

    fn valid_crate_name_char(chr: AsciiChar) -> bool {
        chr.is_alphanumeric() || chr == AsciiChar::UnderScore || chr == AsciiChar::Minus
    }

    #[derive(Debug, Clone)]
    pub struct RustVersion(Version);

    impl FromStr for RustVersion {
        type Err = RustVersionError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            use rust_version_error::*;

            let v: Version = match s.parse() {
                Ok(v) => v,
                Err(e) => {
                    let version = [s, ".0"].concat();
                    match version.parse() {
                        Ok(v) => v,
                        Err(_) => return Err(e)?,
                    }
                }
            };

            ensure!(v.pre.is_empty(), PrereleaseSnafu);
            ensure!(v.build.is_empty(), BuildSnafu);

            Ok(Self(v))
        }
    }

    #[derive(Debug, Snafu)]
    #[snafu(module)]
    pub enum RustVersionError {
        #[snafu(transparent)]
        Semver { source: semver::Error },

        #[snafu(display("May not specify a prerelease version"))]
        Prerelease,

        #[snafu(display("May not specify a version with build metadata"))]
        Build,
    }

    impl From<RustVersion> for Version {
        fn from(value: RustVersion) -> Self {
            value.0
        }
    }

    impl<'de> serde::Deserialize<'de> for RustVersion {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let version = Cow::<str>::deserialize(deserializer)?;
            version.parse().map_err(D::Error::custom)
        }
    }

    impl serde::Serialize for RustVersion {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.0.serialize(serializer)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use registry_conformance::{Crate, ScratchSpace};

    fn default_config() -> ConfigV1 {
        ConfigV1 {
            base_url: "http://example.com".parse().unwrap(),
            auth_required: false,
            html: ConfigV1Html {
                enabled: false,
                suggested_registry_name: None,
            },
        }
    }

    #[tokio::test]
    async fn adding_duplicate_crate() {
        let global = Global::new().unwrap();
        let scratch = ScratchSpace::new().await.unwrap();

        let config = default_config();

        let r = Registry::initialize(config, scratch.registry()).unwrap();

        let c = Crate::new("duplicated", "1.0.0")
            .lib_rs(r#"pub const ID: u8 = 1;"#)
            .create_in(&scratch)
            .await
            .unwrap();
        let p = c.package().await.unwrap();

        r.add(&global, &p, false, false, None, None).unwrap();
        r.add(&global, &p, false, false, None, None).unwrap();

        let name = CrateName::try_from(c.name()).unwrap();
        let index_file_path = r.index_file_path_for(&name);
        let index_contents = fs::read_to_string(index_file_path).unwrap();

        assert_eq!(1, index_contents.lines().count());
    }

    #[tokio::test]
    async fn base_url_requires_trailing_slash() {
        let scratch = ScratchSpace::new().await.unwrap();

        let config = ConfigV1 {
            base_url: "http://example.com/path/to/index".parse().unwrap(),
            ..default_config()
        };

        let r = Registry::initialize(config, scratch.registry()).unwrap();

        let paths = [r.config_json_path(), r.margo_config_toml_path()];

        for path in paths {
            let contents = fs::read_to_string(&path).unwrap();

            assert!(
                contents.contains("/path/to/index/"),
                "{path} does not have the trailing slash:\n{contents}",
                path = path.display(),
            );
        }
    }

    #[tokio::test]
    async fn removing_a_crate_deletes_from_disk() {
        let global = Global::new().unwrap();
        let scratch = ScratchSpace::new().await.unwrap();

        let config = default_config();

        let r = Registry::initialize(config, scratch.registry()).unwrap();

        let name = "to-go-away";
        let version = "1.0.0";

        let c = Crate::new(name, version)
            .lib_rs(r#"pub const ID: u8 = 1;"#)
            .create_in(&scratch)
            .await
            .unwrap();
        let p = c.package().await.unwrap();

        let name = name.parse().unwrap();
        let version = version.parse().unwrap();
        let crate_path = r.crate_file_path_for(&name, &version);

        r.add(&global, p, false, false, None, None).unwrap();

        assert!(
            crate_path.exists(),
            "The crate file should be in the registry at {}",
            crate_path.display(),
        );

        r.remove(name, version).unwrap();

        assert!(
            !crate_path.exists(),
            "The crate file should not be in the registry at {}",
            crate_path.display(),
        );
    }

    #[cfg(feature = "ipfs")]
    #[tokio::test]
    async fn ipfs_private_swarm() {
        println!("=== IPFS private swarm test ===");
        use kubo_ffi::Node;
        use sha2::Digest;

        let tmp = std::env::temp_dir().join("margo-swarm-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Generate a swarm key via FFI
        let swarm_key = kubo_ffi::swarm_key_generate().unwrap();
        println!("swarm key: {}", swarm_key.lines().last().unwrap());

        // Node A: init with swarm key
        let reg_a = tmp.join("regA");
        std::fs::create_dir_all(&reg_a).unwrap();
        let config = format!(
            r#"{{"Swarm":{{"Key":"{}"}}}}"#,
            swarm_key.trim().replace('\n', "\\n")
        );
        // Use proper JSON
        let config_json = serde_json::json!({"Swarm": {"Key": swarm_key.trim()}});
        let config_str = serde_json::to_string(&config_json).unwrap();
        kubo_ffi::init_repo_with_config(&reg_a.join(".ipfs-repo").to_string_lossy(), &config_str)
            .unwrap();
        let node_a = Node::start(&reg_a.join(".ipfs-repo").to_string_lossy(), true).unwrap();
        let peer_id_a = node_a.peer_id().unwrap();
        let addr_a = node_a
            .listening_addrs()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        println!("Node A: peer_id={}, addr={}", peer_id_a, addr_a);

        // Node B: same swarm key → should connect
        let reg_b = tmp.join("regB");
        std::fs::create_dir_all(&reg_b).unwrap();
        kubo_ffi::init_repo_with_config(&reg_b.join(".ipfs-repo").to_string_lossy(), &config_str)
            .unwrap();
        let node_b = Node::start(&reg_b.join(".ipfs-repo").to_string_lossy(), true).unwrap();

        let dial_addr = format!("{}/p2p/{}", addr_a, peer_id_a);
        let connected = node_b.connect(&dial_addr);
        println!("Node B (same key) connect: {}", connected);
        assert!(connected, "Nodes with same swarm key must connect");

        // Publish and fetch
        let data = b"private swarm content";
        let cid = node_a.unixfs_add_bytes(data).unwrap();
        let fetched = node_b.unixfs_cat(&cid).unwrap();
        assert_eq!(fetched, data);
        println!(
            "Node B fetched {} bytes from private swarm: OK",
            fetched.len()
        );

        drop(node_a);
        drop(node_b);
        let _ = std::fs::remove_dir_all(&tmp);
        println!("=== IPFS private swarm test PASSED ===");
    }

    #[cfg(feature = "blossom")]
    #[tokio::test]
    async fn blossom_roundtrip() {
        println!("=== Blossom round-trip test ===");
        use blossom_rs::{BlobServer, FilesystemBackend};
        use std::net::SocketAddr;

        let tmp = std::env::temp_dir().join("margo-blossom-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let blobs_dir = tmp.join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        // Start a Blossom server
        let backend = FilesystemBackend::new(&blobs_dir.to_string_lossy()).unwrap();
        let server = BlobServer::new(backend, "http://127.0.0.1:3099");
        let router = server.router();
        let addr: SocketAddr = "127.0.0.1:3099".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Upload a blob
        let data = b"blossom round-trip test data 12345";
        let client = blossom_rs::BlossomClient::new(
            vec!["http://127.0.0.1:3099".into()],
            blossom_rs::Signer::generate(),
        );
        let desc = client
            .upload(data, "application/octet-stream")
            .await
            .unwrap();
        println!("uploaded: sha256={}", desc.sha256);
        assert!(!desc.sha256.is_empty());

        // Download it back
        let fetched = client.download(&desc.sha256).await.unwrap();
        assert_eq!(fetched, data, "downloaded bytes must match");
        println!("downloaded: {} bytes, match OK", fetched.len());

        handle.abort();
        let _ = std::fs::remove_dir_all(&tmp);
        println!("=== Blossom round-trip test PASSED ===");
    }

    #[cfg(feature = "ipfs")]
    #[tokio::test]
    async fn ipfs_two_node_fetch() {
        println!("=== IPFS two-node fetch test ===");
        use kubo_ffi::Node;
        use sha2::Digest;

        let tmp = std::env::temp_dir().join("margo-two-node-test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Node A: publish a crate
        let reg_a = tmp.join("regA");
        std::fs::create_dir_all(&reg_a).unwrap();
        kubo_ffi::init_repo(&reg_a.join(".ipfs-repo").to_string_lossy()).unwrap();
        let node_a = Node::start(&reg_a.join(".ipfs-repo").to_string_lossy(), true).unwrap();

        let crate_bytes = b"fake crate content for two-node test 1234567890";
        let cid = node_a.unixfs_add_bytes(crate_bytes).unwrap();
        println!("Node A published CID: {}", cid);

        let peer_id_a = node_a.peer_id().unwrap();
        let addr_a = node_a
            .listening_addrs()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        println!("Node A: peer_id={}, addr={}", peer_id_a, addr_a);

        // Node B: fetch by CID
        let reg_b = tmp.join("regB");
        std::fs::create_dir_all(&reg_b).unwrap();
        kubo_ffi::init_repo(&reg_b.join(".ipfs-repo").to_string_lossy()).unwrap();
        let node_b = Node::start(&reg_b.join(".ipfs-repo").to_string_lossy(), true).unwrap();

        let dial_addr = format!("{}/p2p/{}", addr_a, peer_id_a);
        assert!(node_b.connect(&dial_addr), "Node B must connect to Node A");
        println!("Node B connected to Node A");

        let fetched = node_b
            .unixfs_cat(&cid)
            .expect("Node B must fetch crate by CID");
        assert_eq!(fetched, crate_bytes, "fetched bytes must match");
        let hash = hex::encode(sha2::Sha256::digest(&fetched));
        println!(
            "Node B fetched {} bytes, sha256={}",
            fetched.len(),
            &hash[..12]
        );

        // Verify cksum would match (simulate)
        let expected_cksum = hex::encode(sha2::Sha256::digest(crate_bytes));
        assert_eq!(hash, expected_cksum);
        println!("cksum verification: OK");

        drop(node_a);
        drop(node_b);
        let _ = std::fs::remove_dir_all(&tmp);
        println!("=== IPFS two-node fetch test PASSED ===");
    }

    #[cfg(feature = "ipfs")]
    #[tokio::test]
    async fn ipfs_publish_and_verify() {
        println!("=== IPFS publish + verify test ===");
        let global = Global::new().unwrap();
        let scratch = ScratchSpace::new().await.unwrap();

        let config = default_config();
        let r = Registry::initialize(config, scratch.registry()).unwrap();

        let c = Crate::new("ipfs-crate", "1.0.0")
            .lib_rs(r#"pub const ID: u8 = 42;"#)
            .create_in(&scratch)
            .await
            .unwrap();
        let p = c.package().await.unwrap();

        println!("adding crate with --ipfs (publish to IPFS)...");
        r.add(&global, &p, true, false, None, None).unwrap();
        println!("add done");

        let name = CrateName::try_from(c.name()).unwrap();
        let index_file_path = r.index_file_path_for(&name);
        let index_contents = std::fs::read_to_string(&index_file_path).unwrap();
        println!("index entry: {}", index_contents.trim());

        let parsed: serde_json::Value = serde_json::from_str(index_contents.trim()).unwrap();
        let cid = parsed
            .get("ipfs_cid")
            .and_then(|v| v.as_str())
            .expect("ipfs_cid must be present");
        println!("ipfs_cid = {}", cid);
        assert!(!cid.is_empty());
        assert!(cid.starts_with("Qm") || cid.starts_with("baf"));

        // verify cksum matches
        let version: semver::Version = "1.0.0".parse().unwrap();
        let crate_path = r.crate_file_path_for(&name, &version);
        let bytes = std::fs::read(&crate_path).unwrap();
        use sha2::Digest;
        let actual = hex::encode(sha2::Sha256::digest(&bytes));
        assert_eq!(parsed["cksum"].as_str().unwrap(), actual);
        println!("cksum verified: {}", &actual[..12]);

        // round-trip through IPFS
        let repo_path = r.path.join(".ipfs-repo");
        assert!(repo_path.exists(), "ipfs repo must exist");
        let node = kubo_ffi::Node::start(&repo_path.to_string_lossy(), true).unwrap();
        let fetched = node.unixfs_cat(cid).expect("unixfs_cat must succeed");
        assert_eq!(fetched, bytes, "IPFS round-trip bytes must match");
        let fetched_hash = hex::encode(sha2::Sha256::digest(&fetched));
        assert_eq!(fetched_hash, actual);
        println!(
            "IPFS round-trip OK: {} bytes, sha256={}",
            fetched.len(),
            &fetched_hash[..12]
        );
        println!("=== IPFS publish + verify test PASSED ===");
    }
}
