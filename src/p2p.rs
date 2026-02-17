use libp2p::{
    futures::StreamExt,
    identify, mdns,
    multiaddr::Protocol,
    noise, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use snafu::prelude::*;
use std::{path::PathBuf, time::Duration};

/// Combined network behaviour for a margo P2P node.
///
/// Includes:
/// - **Identify**: Exchange peer identity information on connect.
/// - **mDNS**: Discover peers on the local network automatically.
/// - **Ping**: Monitor connection liveness.
#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
}

/// Start a libp2p node for the margo registry.
///
/// This sets up a Swarm with TCP+Noise+Yamux transport, mDNS discovery,
/// identify and ping protocols, then listens on the given address and
/// runs the event loop.
pub async fn start_node(
    listen_addr: Multiaddr,
    registry_path: PathBuf,
) -> Result<(), P2pError> {
    use p2p_error::*;

    println!("Starting margo P2P node for registry at `{}`", registry_path.display());

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

            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                local_peer_id,
            )
            .expect("mDNS behaviour creation should not fail");

            let ping = ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(15)),
            );

            Behaviour {
                identify,
                mdns,
                ping,
            }
        })
        .expect("infallible behaviour construction")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm.listen_on(listen_addr).context(ListenSnafu)?;

    println!("Local peer ID: {}", swarm.local_peer_id());

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let full_addr = address
                    .clone()
                    .with(Protocol::P2p(*swarm.local_peer_id()));
                println!("Listening on {full_addr}");
            }

            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                for (peer_id, addr) in peers {
                    println!("mDNS discovered peer: {peer_id} at {addr}");
                    swarm.dial(addr).ok();
                }
            }

            SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                for (peer_id, addr) in peers {
                    println!("mDNS peer expired: {peer_id} at {addr}");
                }
            }

            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                println!(
                    "Identified peer {peer_id}: {} ({})",
                    info.protocol_version,
                    info.agent_version,
                );
            }

            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
                peer,
                result: Ok(rtt),
                ..
            })) => {
                println!("Ping from {peer}: {rtt:?}");
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Connected to {peer_id}");
            }

            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                println!("Disconnected from {peer_id}: {cause:?}");
            }

            _ => {}
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum P2pError {
    #[snafu(display("Could not initialize the TCP transport"))]
    Transport { source: noise::Error },

    #[snafu(display("Could not start listening on the given address"))]
    Listen {
        source: libp2p::TransportError<std::io::Error>,
    },
}
