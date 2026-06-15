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
    Up {
        #[arg(long, default_value = "utun99")]
        tun: String,
        #[arg(long, default_value_t = 0)]
        peer_index: usize,
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
        Commands::Up { tun, peer_index } => cmd_up(&dir, &tun, peer_index).await,
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

async fn cmd_up(dir: &Path, tun_name: &str, peer_index: usize) -> Result<()> {
    let identity = identity::load_identity(dir)?;
    let wg = identity::load_wg_key(dir)?;
    let cfg = Config::load(dir)?;
    let mut state = State::load(dir)?;

    let client = CoordClient::new(&cfg.server.url);
    let mut peers = client.peers(&state.auth_token).await?;
    if peers.is_empty() {
        return Err(Error::Server("no peers registered on coord server".into()));
    }
    if peer_index >= peers.len() {
        return Err(Error::Server(format!(
            "peer_index {} out of bounds (have {} peers)",
            peer_index,
            peers.len()
        )));
    }
    let peer = peers.remove(peer_index);
    let peer_pub = B64
        .decode(&peer.wg_pubkey)?
        .try_into()
        .map_err(|_| Error::Server("peer wg_pubkey is not 32 bytes".into()))?;
    let peer_endpoint: SocketAddr = peer
        .last_endpoint
        .as_deref()
        .ok_or_else(|| Error::Server(format!("peer {} has no last_endpoint; needs to send a heartbeat", peer.node_id)))?
        .parse()
        .map_err(|_| Error::Server("peer endpoint is not a valid socket address".into()))?;

    let device = TunDevice::create(tun_name)?;
    let actual_tun_name = device.name().to_string();
    let my_ip = state.ip.clone();
    let peer_ip = peer.ip.clone();
    platform::configure_tun(&actual_tun_name, &my_ip, &peer_ip)?;
    platform::add_route("100.100.0.0/16", &actual_tun_name)?;

    let bind_port = 51820;
    let transport = UdpTransport::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), bind_port),
        peer_endpoint,
    )?;
    let local_endpoint = transport.local_addr()?.to_string();

    let mgr_cfg = ManagerConfig {
        local_keypair: wg,
        peer_pub,
        psk: [0u8; 32],
        local_sender_id: 1,
        is_initiator: true,
    };
    let mut manager = TunnelManager::new(Box::new(device), transport, mgr_cfg)?;

    let _ = client
        .heartbeat(&identity, &state.auth_token, &local_endpoint)
        .await;
    state.last_endpoint = Some(local_endpoint.clone());
    state.last_handshake_at = Some(Tai64N::now().seconds() as i64);
    state.save(dir)?;

    println!("naboscale up: tun={} my_ip={} peer_ip={} via {}", actual_tun_name, my_ip, peer_ip, peer_endpoint);
    println!("Local endpoint: {}", local_endpoint);
    println!("Press Ctrl+C to stop.");

    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);

    let heartbeat_handle = {
        let identity = identity.clone();
        let cfg_url = cfg.server.url.clone();
        let auth_token = state.auth_token.clone();
        let endpoint = local_endpoint.clone();
        let dir = dir.to_path_buf();
        tokio::spawn(async move {
            let client = CoordClient::new(&cfg_url);
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if let Err(e) = client.heartbeat(&identity, &auth_token, &endpoint).await {
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
                    tracing::error!(?e, "manager step failed");
                    return Err(crate::Error::Tunnel(e));
                }
            }
        }
    }
}
