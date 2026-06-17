//! CLI entry point: clap parser + command dispatch.

use crate::client::CoordClient;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::identity;
use crate::state::{PeerInfo, State};
use crate::{platform, NABOSCALE_VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use naboscale_crypto::{Identity, Keypair, Tai64N};
use naboscale_tunnel::{Device, ManagerConfig, TunDevice, TunnelManager, UdpTransport};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "naboscale", version = NABOSCALE_VERSION, about = "Mesh VPN client")]
pub struct Cli {
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
        #[arg(long)]
        force: bool,
    },
    Register,
    Peers,
    Status,
    Heartbeat {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        via_relay: Option<String>,
    },
    Up {
        #[arg(long, default_value = "utun99")]
        tun: String,
        #[arg(long, default_value_t = 51820)]
        bind_port: u16,
        #[arg(long)]
        relay: Option<String>,
        /// Public endpoint (ip:port) to advertise to coord. Required when behind NAT
        /// or when binding to 0.0.0.0 (otherwise coord stores 0.0.0.0:port and peers
        /// cannot reach you). Falls back to env NABOSCALE_ADVERTISE_ENDPOINT, then
        /// to the bound local socket address.
        #[arg(long)]
        advertise_endpoint: Option<String>,
    },
    Down,
}

pub async fn run(cli: Cli) -> Result<()> {
    let dir = resolve_config_dir(cli.config_dir.as_deref())?;
    match cli.command {
        Commands::Init { server, force } => cmd_init(&dir, &server, force),
        Commands::Register => cmd_register(&dir).await,
        Commands::Peers => cmd_peers(&dir).await,
        Commands::Status => cmd_status(&dir),
        Commands::Heartbeat { endpoint, via_relay } => {
            cmd_heartbeat(&dir, &endpoint, via_relay.as_deref()).await
        }
        Commands::Up { tun, bind_port, relay, advertise_endpoint } => {
            cmd_up(&dir, &tun, bind_port, relay, advertise_endpoint).await
        }
        Commands::Down => cmd_down(&dir),
    }
}

fn resolve_config_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d.to_path_buf());
    }
    let base = dirs::config_dir().ok_or(crate::Error::NoConfigDir)?;
    Ok(base.join("naboscale"))
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn cmd_init(dir: &Path, server: &str, force: bool) -> Result<()> {
    ensure_dir(dir)?;
    if identity::identity_exists(dir) && !force {
        return Err(Error::BadConfig(
            "identity already exists; use --force to overwrite".into(),
        ));
    }
    let identity = Identity::generate();
    let wg = Keypair::generate();
    identity::save_identity(dir, &identity)?;
    identity::save_wg_key(dir, &wg)?;
    let cfg = Config::default_with_server(server);
    cfg.save(dir)?;
    println!("Initialized in {}", dir.display());
    println!("  identity pub: {}", identity.public_base64());
    println!("  wg pub:      {}", B64.encode(wg.public()));
    println!("Next: naboscale register");
    Ok(())
}

async fn cmd_register(dir: &Path) -> Result<()> {
    ensure_dir(dir)?;
    let identity = identity::load_identity(dir)?;
    let wg = identity::load_wg_key(dir)?;
    let cfg = Config::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    let resp = client.register(&identity, wg.public()).await?;
    let state = State {
        node_id: resp.node_id,
        ip: resp.ip,
        auth_token: resp.auth_token,
        last_endpoint: None,
        last_handshake_at: None,
        known_peers: vec![],
    };
    state.save(dir)?;
    println!("Registered. node_id={} ip={}", state.node_id, state.ip);
    println!("Next: naboscale up");
    Ok(())
}

async fn cmd_peers(dir: &Path) -> Result<()> {
    let identity = identity::load_identity(dir)?;
    let cfg = Config::load(dir)?;
    let state = State::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    let peers = client.peers(&state.auth_token).await?;
    let mut updated = state.clone();
    updated.known_peers = peers
        .iter()
        .map(|p| PeerInfo {
            node_id: p.node_id.clone(),
            wg_pubkey_b64: p.wg_pubkey.clone(),
            ip: p.ip.clone(),
            last_endpoint: p.last_endpoint.clone(),
            via_relay: p.via_relay.clone(),
        })
        .collect();
    updated.save(dir)?;
    println!("{} peer(s) known:", updated.known_peers.len());
    for p in &updated.known_peers {
        println!(
            "  ip={:<15} endpoint={:<22} pubkey={}",
            p.ip,
            p.last_endpoint.as_deref().unwrap_or("?"),
            &p.wg_pubkey_b64[..16]
        );
    }
    drop(identity);
    Ok(())
}

fn cmd_status(dir: &Path) -> Result<()> {
    if !State::exists(dir) {
        return Err(Error::NotInitialized(dir.display().to_string()));
    }
    let state = State::load(dir)?;
    let cfg = Config::load(dir)?;
    println!("server:     {}", cfg.server.url);
    println!("node_id:    {}", state.node_id);
    println!("ip:         {}", state.ip);
    println!("endpoint:   {}", state.last_endpoint.as_deref().unwrap_or("(none)"));
    println!("last hs:    {}", state.last_handshake_at.unwrap_or(0));
    println!("peers:      {}", state.known_peers.len());
    for p in &state.known_peers {
        println!("  {} @ {} ({})", p.ip, p.last_endpoint.as_deref().unwrap_or("?"), p.node_id);
    }
    Ok(())
}

async fn cmd_heartbeat(dir: &Path, endpoint: &str, via_relay: Option<&str>) -> Result<()> {
    let identity = identity::load_identity(dir)?;
    let cfg = Config::load(dir)?;
    let mut state = State::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    client
        .heartbeat(&identity, &state.auth_token, endpoint, via_relay)
        .await?;
    state.last_endpoint = Some(endpoint.to_string());
    state.last_handshake_at = Some(chrono::Utc::now().timestamp());
    state.save(dir)?;
    println!("heartbeat sent: {} (via_relay: {:?})", endpoint, via_relay);
    Ok(())
}

fn cmd_down(_dir: &Path) -> Result<()> {
    let _ = identity::ensure_config_dir()?;
    let pid_path = identity::ensure_config_dir()?.join(identity::DAEMON_PID_FILE);
    if !pid_path.exists() {
        println!("No daemon PID file found; nothing to stop.");
        return Ok(());
    }
    let text = std::fs::read_to_string(&pid_path)?;
    let pid: i32 = text.trim().parse().map_err(|_| Error::BadConfig("bad PID file".into()))?;
    let status = std::process::Command::new("kill").arg(pid.to_string()).status()?;
    if !status.success() {
        return Err(Error::Server(format!("kill {pid} failed")));
    }
    let _ = std::fs::remove_file(&pid_path);
    println!("Sent SIGTERM to pid {pid}");
    Ok(())
}

async fn cmd_up(
    dir: &Path,
    tun_name: &str,
    bind_port: u16,
    relay: Option<String>,
    advertise_endpoint: Option<String>,
) -> Result<()> {
    let identity = identity::load_identity(dir)?;
    let wg = identity::load_wg_key(dir)?;
    let cfg = Config::load(dir)?;
    let mut state = State::load(dir)?;

    let client = CoordClient::new(&cfg.server.url);
    let peers = client.peers(&state.auth_token).await?;
    if peers.is_empty() {
        tracing::warn!("no peers registered on coord server — starting with empty peer set; will discover peers on next up");
    }

    let relay_endpoint: Option<SocketAddr> = match relay.as_deref() {
        Some(s) => Some(
            s.parse()
                .map_err(|_| Error::Server(format!("invalid --relay endpoint: {s}")))?,
        ),
        None => None,
    };

    let mut peer_cfgs: Vec<naboscale_tunnel::PeerConfig> = Vec::with_capacity(peers.len());
    let mut skipped: Vec<&str> = Vec::new();
    for (i, peer) in peers.iter().enumerate() {
        let peer_pub: [u8; 32] = B64
            .decode(&peer.wg_pubkey)?
            .try_into()
            .map_err(|_| Error::Server("peer wg_pubkey is not 32 bytes".into()))?;
        let peer_endpoint_str = peer.last_endpoint.as_deref();
        let is_wildcard_endpoint = peer_endpoint_str.is_some_and(|s| {
            s.starts_with("0.0.0.0:") || s.starts_with("[::]:")
        });
        let peer_via_relay: Option<SocketAddr> = match peer.via_relay.as_deref() {
            Some(s) => match s.parse() {
                Ok(a) => Some(a),
                Err(_) => {
                    return Err(Error::Server(format!(
                        "peer {} via_relay {s:?} is not a valid ip:port",
                        peer.node_id
                    )))
                }
            },
            None => None,
        };
        // A peer is usable if it has a real endpoint, OR if it has a via_relay
        // (we wrap outgoing traffic in RELAY and send to the relay, which then
        // forwards). Peers with neither (no heartbeat yet) or with a wildcard
        // endpoint AND no via_relay are unreachable — skip them.
        if peer_endpoint_str.is_none() {
            tracing::warn!(
                node_id = %peer.node_id,
                ip = %peer.ip,
                "peer has no last_endpoint yet (no heartbeat); skipping — will be added on next up"
            );
            skipped.push(peer.ip.as_str());
            continue;
        }
        if is_wildcard_endpoint && peer_via_relay.is_none() {
            tracing::warn!(
                node_id = %peer.node_id,
                ip = %peer.ip,
                endpoint = %peer_endpoint_str.unwrap(),
                "peer advertised a wildcard endpoint (bound to 0.0.0.0 without --advertise-endpoint) and has no via_relay; skipping"
            );
            skipped.push(peer.ip.as_str());
            continue;
        }
        // If we have a via_relay for this peer, the peer_endpoint is just a
        // placeholder (the actual destination is via the relay). Use the
        // wildcard-parsed address so parsing doesn't fail.
        let peer_endpoint: SocketAddr = if is_wildcard_endpoint {
            "0.0.0.0:0".parse().unwrap()
        } else {
            peer_endpoint_str
                .unwrap()
                .parse()
                .map_err(|_| Error::Server("peer endpoint is not a valid socket address".into()))?
        };
        let peer_ip: Ipv4Addr = peer
            .ip
            .parse()
            .map_err(|_| Error::Server(format!("peer ip is not a valid IPv4: {}", peer.ip)))?;
        // Per-peer via_relay: prefer the value coord reported for this peer
        // (set by the peer itself when it has --relay). If coord has none, fall
        // back to the local --relay flag (used when WE are behind a relay and
        // want all our outgoing traffic to be relayed).
        let via_relay = peer_via_relay.or(relay_endpoint);
        // Role override to break deadlocks across relays:
        //   - if WE have --relay set, we are NAT'd; we always initiate (we
        //     can send via the relay; our peers may not be able to reach us
        //     directly).
        //   - else if the PEER has a via_relay set, the peer is NAT'd; we
        //     are always responder (the peer initiates and reaches us via
        //     its relay; our init to the peer's relay address may hairpin
        //     or otherwise fail).
        //   - otherwise fall back to pubkey comparison (classic WG-style).
        let is_initiator = if relay_endpoint.is_some() {
            true
        } else if peer_via_relay.is_some() {
            false
        } else {
            *wg.public() > peer_pub
        };
        peer_cfgs.push(naboscale_tunnel::PeerConfig {
            peer_pub,
            psk: [0u8; 32],
            local_sender_id: (i as u32) + 1,
            is_initiator,
            peer_endpoint,
            peer_ip,
            via_relay,
        });
    }

    let device = TunDevice::create(tun_name)?;
    let actual_tun_name = device.name().to_string();
    let my_ip = state.ip.clone();
    let dummy_peer_ip = peer_cfgs
        .first()
        .map(|p| p.peer_ip.to_string())
        .unwrap_or_else(|| my_ip.clone());
    platform::configure_tun(&actual_tun_name, &my_ip, &dummy_peer_ip)?;
    platform::add_route("100.100.0.0/16", &actual_tun_name)?;

    let transport = UdpTransport::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        bind_port,
    ))?;
    let bound_endpoint = transport.local_addr()?.to_string();
    // Priority: --advertise-endpoint > --relay > env > bound. When behind NAT
    // and --relay is set, the relay's address is what coord should advertise
    // (peers reach us through the relay, not via our local bind).
    let advertised = advertise_endpoint
        .clone()
        .or_else(|| relay_endpoint.map(|r| r.to_string()))
        .or_else(|| std::env::var("NABOSCALE_ADVERTISE_ENDPOINT").ok())
        .unwrap_or_else(|| bound_endpoint.clone());
    let via_relay_for_heartbeat = relay_endpoint.map(|r| r.to_string());
    if advertised.parse::<SocketAddr>().is_err() {
        return Err(Error::Server(format!(
            "advertise-endpoint {advertised:?} is not a valid ip:port"
        )));
    }
    if advertised.starts_with("0.0.0.0:") || advertised.starts_with("[::]:") {
        tracing::warn!(
            bound = %bound_endpoint,
            advertised = %advertised,
            "advertised endpoint is wildcard — peers will not be able to reach you. \
             pass --advertise-endpoint <public-ip:port> when behind NAT."
        );
    }

    let mgr_cfg = ManagerConfig {
        local_keypair: wg,
        local_ip: state
            .ip
            .parse()
            .map_err(|_| Error::Server(format!("my own ip is not a valid IPv4: {}", state.ip)))?,
    };
    println!(
        "naboscale up: tun={} my_ip={} peers={} bind={} advertise={}",
        actual_tun_name,
        my_ip,
        peer_cfgs.len(),
        bound_endpoint,
        advertised,
    );
    for (i, pc) in peer_cfgs.iter().enumerate() {
        println!(
            "  peer[{}] ip={} endpoint={} role={}",
            i,
            pc.peer_ip,
            pc.peer_endpoint,
            if pc.is_initiator { "initiator" } else { "responder" }
        );
    }
    let mut manager =
        TunnelManager::new(Box::new(device), transport, mgr_cfg, peer_cfgs)?;

    let _ = client
        .heartbeat(
            &identity,
            &state.auth_token,
            &advertised,
            via_relay_for_heartbeat.as_deref(),
        )
        .await;
    state.last_endpoint = Some(advertised.clone());
    state.last_handshake_at = Some(Tai64N::now().seconds() as i64);
    state.save(dir)?;

    println!("Press Ctrl+C to stop.");

    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);

    let heartbeat_handle = {
        let identity = identity.clone();
        let cfg_url = cfg.server.url.clone();
        let auth_token = state.auth_token.clone();
        let endpoint = advertised.clone();
        let via_relay = via_relay_for_heartbeat.clone();
        let dir = dir.to_path_buf();
        tokio::spawn(async move {
            let client = CoordClient::new(&cfg_url);
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if let Err(e) = client
                    .heartbeat(
                        &identity,
                        &auth_token,
                        &endpoint,
                        via_relay.as_deref(),
                    )
                    .await
                {
                    tracing::warn!(?e, "heartbeat failed");
                }
                if let Ok(mut s) = State::load(&dir) {
                    s.last_endpoint = Some(endpoint.clone());
                    s.last_handshake_at = Some(Tai64N::now().seconds() as i64);
                    let _ = s.save(&dir);
                }
            }
        })
    };

    loop {
        tokio::select! {
            _ = &mut stop => {
                println!("\nShutting down...");
                heartbeat_handle.abort();
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if let Err(e) = manager.step() {
                    tracing::warn!(?e, "manager step failed (will retry)");
                }
            }
        }
    }
}
