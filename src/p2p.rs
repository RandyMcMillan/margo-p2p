use libp2p::{
    futures::StreamExt,
    gossipsub, identify, mdns,
    multiaddr::Protocol,
    noise, ping,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use snafu::prelude::*;
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const COMMIT_TOPIC: &str = "margo/commit/v1";
const COMMIT_PROTOCOL: StreamProtocol = StreamProtocol::new("/margo/commit/1.0.0");

// ---------------------------------------------------------------------------
// Git helpers
// ---------------------------------------------------------------------------

/// Run `git rev-parse HEAD` inside the given directory and return the full
/// 40-character hex hash, or `None` when the directory is not a git repo (or
/// git is unavailable).
fn detect_git_commit(dir: &Path) -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8(o.stdout).ok()?;
            let trimmed = s.trim().to_owned();
            if trimmed.len() >= 40 {
                Some(trimmed)
            } else {
                None
            }
        })
}

/// Collect the list of files that git tracks at the given commit.
/// Returns pairs of (relative-path, file-contents).
fn collect_commit_files(dir: &Path, commit: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
    let output = Command::new("git")
        .args(["ls-tree", "-r", "--name-only", commit])
        .current_dir(dir)
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "git ls-tree failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    let listing = String::from_utf8(output.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut files = Vec::new();
    for relpath in listing.lines() {
        if relpath.is_empty() {
            continue;
        }
        let show = Command::new("git")
            .args(["show", &format!("{commit}:{relpath}")])
            .current_dir(dir)
            .output()?;
        if show.status.success() {
            files.push((relpath.to_owned(), show.stdout));
        }
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Request/response codec – simple length-prefixed JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CommitCodec;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CommitRequest {
    /// Ask the peer for its current commit hash.
    GetHead,
    /// Ask the peer for the file listing at a specific commit.
    GetCommitData { commit: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CommitResponse {
    /// Current HEAD commit hash (if the registry is a git repo).
    Head { commit: Option<String> },
    /// Files tracked by git at the requested commit.
    /// Each entry is (relative_path, base64-encoded contents).
    CommitData {
        commit: String,
        files: Vec<(String, String)>,
    },
    /// The requested commit was not found or could not be read.
    Error { message: String },
}

#[async_trait::async_trait]
impl Codec for CommitCodec {
    type Protocol = StreamProtocol;
    type Request = CommitRequest;
    type Response = CommitResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            serde_json::to_vec(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&(data.len() as u32).to_be_bytes()).await?;
        io.write_all(&data).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&(data.len() as u32).to_be_bytes()).await?;
        io.write_all(&data).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Combined network behaviour
// ---------------------------------------------------------------------------

/// Combined network behaviour for a margo P2P node.
///
/// - **Identify**: Exchange peer identity information on connect.
/// - **mDNS**: Discover peers on the local network automatically.
/// - **Ping**: Monitor connection liveness.
/// - **Gossipsub**: Broadcast git commit hashes to all peers.
/// - **CommitRpc**: Request/response protocol for fetching commit data.
#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    gossipsub: gossipsub::Behaviour,
    commit_rpc: request_response::Behaviour<CommitCodec>,
}

// ---------------------------------------------------------------------------
// Node entry point
// ---------------------------------------------------------------------------

/// Start a libp2p node for the margo registry.
///
/// The node will:
/// 1. Detect the current git commit hash of the registry.
/// 2. Broadcast it via gossipsub whenever a new peer subscribes.
/// 3. Answer `GetHead` / `GetCommitData` requests from peers.
pub async fn start_node(
    listen_addr: Multiaddr,
    registry_path: PathBuf,
) -> Result<(), P2pError> {
    use p2p_error::*;

    let head_commit = detect_git_commit(&registry_path);
    match &head_commit {
        Some(c) => println!("Registry git HEAD: {c}"),
        None => println!("Registry is not a git repository (commit broadcasting disabled)"),
    }

    // -- build swarm --------------------------------------------------------

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .context(TransportSnafu)?
        .with_behaviour(|key| {
            let local_peer_id = key.public().to_peer_id();

            let identify = identify::Behaviour::new(identify::Config::new(
                format!("/margo/{}", env!("CARGO_PKG_VERSION")),
                key.public(),
            ));

            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                .expect("mDNS behaviour creation should not fail");

            let ping =
                ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(15)));

            // gossipsub for commit hash broadcasting
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .build()
                .expect("valid gossipsub config");
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("valid gossipsub behaviour");

            // request-response for commit data fetching
            let commit_rpc = request_response::Behaviour::new(
                [(COMMIT_PROTOCOL, ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            Behaviour {
                identify,
                mdns,
                ping,
                gossipsub,
                commit_rpc,
            }
        })
        .expect("infallible behaviour construction")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // subscribe to the commit topic
    let topic = gossipsub::IdentTopic::new(COMMIT_TOPIC);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .context(GossipsubSubscribeSnafu)?;

    swarm.listen_on(listen_addr).context(ListenSnafu)?;

    println!("Local peer ID: {}", swarm.local_peer_id());

    // Track peers we've already announced to so we publish once per new peer.
    let mut announced_peers: HashMap<PeerId, bool> = HashMap::new();

    // -- event loop ----------------------------------------------------------

    loop {
        match swarm.select_next_some().await {
            // -- listen addresses -------------------------------------------
            SwarmEvent::NewListenAddr { address, .. } => {
                let full_addr = address
                    .clone()
                    .with(Protocol::P2p(*swarm.local_peer_id()));
                println!("Listening on {full_addr}");
            }

            // -- mDNS -------------------------------------------------------
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                for (peer_id, addr) in peers {
                    println!("mDNS discovered peer: {peer_id} at {addr}");
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    swarm.dial(addr).ok();
                }
            }

            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                for (peer_id, addr) in peers {
                    println!("mDNS peer expired: {peer_id} at {addr}");
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }

            // -- identify ---------------------------------------------------
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                println!(
                    "Identified peer {peer_id}: {} ({})",
                    info.protocol_version, info.agent_version,
                );
            }

            // -- ping -------------------------------------------------------
            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                peer,
                result: Ok(rtt),
                ..
            })) => {
                println!("Ping from {peer}: {rtt:?}");
            }

            // -- gossipsub --------------------------------------------------
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                if let Ok(commit) = String::from_utf8(message.data.clone()) {
                    println!(
                        "Received commit announcement from {propagation_source}: {commit}"
                    );
                }
            }

            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                gossipsub::Event::Subscribed { peer_id, topic: t },
            )) => {
                println!("Peer {peer_id} subscribed to {t}");
            }

            // -- request-response: incoming requests ------------------------
            SwarmEvent::Behaviour(BehaviourEvent::CommitRpc(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                },
            )) => {
                let response = handle_commit_request(&registry_path, &request);
                println!("Serving {request:?} to {peer}");
                let _ = swarm
                    .behaviour_mut()
                    .commit_rpc
                    .send_response(channel, response);
            }

            // -- request-response: incoming responses -----------------------
            SwarmEvent::Behaviour(BehaviourEvent::CommitRpc(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            response, ..
                        },
                },
            )) => {
                match &response {
                    CommitResponse::Head { commit } => {
                        println!("Peer {peer} HEAD: {commit:?}");
                    }
                    CommitResponse::CommitData { commit, files } => {
                        println!(
                            "Received commit data for {commit} from {peer} ({} files)",
                            files.len()
                        );
                    }
                    CommitResponse::Error { message } => {
                        println!("Peer {peer} error: {message}");
                    }
                }
            }

            // -- connections ------------------------------------------------
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Connected to {peer_id}");

                // Publish our commit hash once per new peer.
                if !announced_peers.contains_key(&peer_id) {
                    announced_peers.insert(peer_id, true);
                    if let Some(ref commit) = head_commit {
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), commit.as_bytes())
                        {
                            println!("Failed to publish commit hash: {e}");
                        } else {
                            println!("Broadcast commit {commit} to network");
                        }
                    }
                }

                // Also send a GetHead request to learn the peer's commit.
                swarm
                    .behaviour_mut()
                    .commit_rpc
                    .send_request(&peer_id, CommitRequest::GetHead);
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                println!("Disconnected from {peer_id}: {cause:?}");
                announced_peers.remove(&peer_id);
            }

            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

fn handle_commit_request(registry_path: &Path, request: &CommitRequest) -> CommitResponse {
    match request {
        CommitRequest::GetHead => CommitResponse::Head {
            commit: detect_git_commit(registry_path),
        },
        CommitRequest::GetCommitData { commit } => {
            // Validate: only allow hex commit hashes (prevent command injection).
            if !commit.chars().all(|c| c.is_ascii_hexdigit()) || commit.is_empty() {
                return CommitResponse::Error {
                    message: "invalid commit hash".into(),
                };
            }
            match collect_commit_files(registry_path, commit) {
                Ok(files) => {
                    use base64::Engine;
                    let engine = base64::engine::general_purpose::STANDARD;
                    let encoded: Vec<(String, String)> = files
                        .into_iter()
                        .map(|(path, data)| (path, engine.encode(data)))
                        .collect();
                    CommitResponse::CommitData {
                        commit: commit.clone(),
                        files: encoded,
                    }
                }
                Err(e) => CommitResponse::Error {
                    message: e.to_string(),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum P2pError {
    #[snafu(display("Could not initialize the TCP transport"))]
    Transport { source: noise::Error },

    #[snafu(display("Could not start listening on the given address"))]
    Listen {
        source: libp2p::TransportError<std::io::Error>,
    },

    #[snafu(display("Could not subscribe to gossipsub topic"))]
    GossipsubSubscribe { source: gossipsub::SubscriptionError },
}
