//! CLI entry point: clap parser + command dispatch.

use crate::client::CoordClient;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::identity;
use crate::keystore::{self, KeyKind, OpenedKeys, PassphraseSource};
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

    /// Read the keystore passphrase from a file (first line, trailing newline stripped).
    /// Falls back to the `NABOSCALE_PASSPHRASE` environment variable.
    #[arg(long, global = true)]
    pub passphrase_file: Option<PathBuf>,

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
    /// Rotate the auth token. The old token is revoked immediately.
    RefreshToken,
    /// Self-de-register: delete this node from coord and release its mesh IP.
    Deregister,
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
    let pp_source = resolve_passphrase_source(cli.passphrase_file.as_deref());
    match cli.command {
        Commands::Init { server, force } => cmd_init(&dir, &server, force, &pp_source),
        Commands::Register => cmd_register(&dir, &pp_source).await,
        Commands::Peers => cmd_peers(&dir, &pp_source).await,
        Commands::Status => cmd_status(&dir),
        Commands::Heartbeat {
            endpoint,
            via_relay,
        } => cmd_heartbeat(&dir, &endpoint, via_relay.as_deref(), &pp_source).await,
        Commands::RefreshToken => cmd_refresh_token(&dir, &pp_source).await,
        Commands::Deregister => cmd_deregister(&dir, &pp_source).await,
        Commands::Up {
            tun,
            bind_port,
            relay,
            advertise_endpoint,
        } => cmd_up(&dir, &tun, bind_port, relay, advertise_endpoint, &pp_source).await,
        Commands::Down => cmd_down(&dir),
    }
}

fn resolve_passphrase_source(file: Option<&Path>) -> PassphraseSource {
    match file {
        Some(p) => match keystore::read_passphrase_file(p) {
            Ok(b) => PassphraseSource::Bytes(b),
            Err(e) => {
                eprintln!(
                    "warning: could not read --passphrase-file {}: {e}",
                    p.display()
                );
                PassphraseSource::Env
            }
        },
        None => PassphraseSource::Env,
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

fn cmd_init(dir: &Path, server: &str, force: bool, pp: &PassphraseSource) -> Result<()> {
    ensure_dir(dir)?;
    if identity::identity_exists(dir) && !force {
        return Err(Error::BadConfig(
            "identity already exists; use --force to overwrite".into(),
        ));
    }
    let passphrase = pp.resolve()?.ok_or_else(|| {
        Error::BadConfig(format!(
            "initializing an encrypted keystore requires a passphrase. \
             set {} or pass --passphrase-file <path>",
            pp_env(),
        ))
    })?;
    let identity = Identity::generate();
    let wg = Keypair::generate();
    keystore::save_key(
        dir,
        KeyKind::Identity,
        &identity.private_bytes(),
        &passphrase,
    )?;
    keystore::save_key(dir, KeyKind::Wg, &wg.secret_bytes(), &passphrase)?;
    let cfg = Config::default_with_server(server);
    cfg.save(dir)?;
    println!("Initialized in {}", dir.display());
    println!("  keystore:    encrypted (Argon2id + XChaCha20-Poly1305, chmod 0600)");
    println!("  identity pub: {}", identity.public_base64());
    println!("  wg pub:      {}", B64.encode(wg.public()));
    println!("Next: naboscale register");
    Ok(())
}

fn pp_env() -> &'static str {
    "NABOSCALE_PASSPHRASE"
}

async fn cmd_register(dir: &Path, pp: &PassphraseSource) -> Result<()> {
    ensure_dir(dir)?;
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
    let cfg = Config::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    let resp = client.register(&ks.identity, ks.wg.public()).await?;
    let state = State {
        node_id: resp.node_id,
        ip: resp.ip,
        auth_token: resp.auth_token,
        auth_token_expires_at: Some(resp.auth_token_expires_at),
        last_endpoint: None,
        last_handshake_at: None,
        known_peers: vec![],
    };
    state.save(dir)?;
    println!("Registered. node_id={} ip={}", state.node_id, state.ip);
    if let Some(exp) = state.auth_token_expires_at {
        println!("  token expires at: {} (UTC epoch)", exp);
    }
    println!("Next: naboscale up");
    Ok(())
}

async fn cmd_peers(dir: &Path, pp: &PassphraseSource) -> Result<()> {
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
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
    drop(ks);
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
    println!(
        "endpoint:   {}",
        state.last_endpoint.as_deref().unwrap_or("(none)")
    );
    println!("last hs:    {}", state.last_handshake_at.unwrap_or(0));
    println!("peers:      {}", state.known_peers.len());
    match state.auth_token_expires_at {
        Some(exp) if exp > chrono::Utc::now().timestamp() => {
            println!(
                "token exp:  {} (UTC, {}s remaining)",
                exp,
                exp - chrono::Utc::now().timestamp()
            );
        }
        Some(_) => println!("token exp:  EXPIRED — run `naboscale refresh-token`"),
        None => println!("token exp:  unknown (state pre-expiry tracking)"),
    }
    for p in &state.known_peers {
        println!(
            "  {} @ {} ({})",
            p.ip,
            p.last_endpoint.as_deref().unwrap_or("?"),
            p.node_id
        );
    }
    Ok(())
}

async fn cmd_heartbeat(
    dir: &Path,
    endpoint: &str,
    via_relay: Option<&str>,
    pp: &PassphraseSource,
) -> Result<()> {
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
    let cfg = Config::load(dir)?;
    let mut state = State::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    // If the saved token is past its expiry, refresh transparently before
    // sending the heartbeat so the call doesn't fail with 401.
    if is_token_expired(state.auth_token_expires_at) {
        eprintln!(
            "token expired at {:?} — refreshing",
            state.auth_token_expires_at
        );
        let refreshed = client
            .refresh_token(&ks.identity, &state.auth_token)
            .await?;
        state.auth_token = refreshed.auth_token;
        state.auth_token_expires_at = Some(refreshed.auth_token_expires_at);
    }
    client
        .heartbeat(&ks.identity, &state.auth_token, endpoint, via_relay)
        .await?;
    state.last_endpoint = Some(endpoint.to_string());
    state.last_handshake_at = Some(chrono::Utc::now().timestamp());
    state.save(dir)?;
    println!("heartbeat sent: {} (via_relay: {:?})", endpoint, via_relay);
    Ok(())
}

async fn cmd_refresh_token(dir: &Path, pp: &PassphraseSource) -> Result<()> {
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
    let cfg = Config::load(dir)?;
    let mut state = State::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    let resp = client
        .refresh_token(&ks.identity, &state.auth_token)
        .await?;
    state.auth_token = resp.auth_token;
    state.auth_token_expires_at = Some(resp.auth_token_expires_at);
    state.save(dir)?;
    println!(
        "token refreshed; new expiry: {} (UTC epoch)",
        state.auth_token_expires_at.unwrap_or(0)
    );
    Ok(())
}

async fn cmd_deregister(dir: &Path, pp: &PassphraseSource) -> Result<()> {
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
    let cfg = Config::load(dir)?;
    let state = State::load(dir)?;
    let client = CoordClient::new(&cfg.server.url);
    client.delete_node(&ks.identity, &state.auth_token).await?;
    println!(
        "De-registered node_id={}; mesh IP released back to pool.",
        state.node_id
    );
    Ok(())
}

/// Returns true if `expires_at` is in the past (or unknown, which we treat
/// as expired so a stored-but-stale token gets refreshed). Caller is
/// expected to refresh before the next protected call.
fn is_token_expired(expires_at: Option<i64>) -> bool {
    let now = chrono::Utc::now().timestamp();
    expires_at.is_none_or(|exp| exp <= now)
}

/// Returns true if the token expires within `grace_secs` from now (or is
/// already expired / unknown). Used by the daemon heartbeat loop to
/// proactively refresh before the token actually expires.
fn is_token_expired_soon(expires_at: Option<i64>, grace_secs: i64) -> bool {
    let now = chrono::Utc::now().timestamp();
    expires_at.is_none_or(|exp| exp <= now + grace_secs)
}

fn cmd_down(_dir: &Path) -> Result<()> {
    let _ = identity::ensure_config_dir()?;
    let pid_path = identity::ensure_config_dir()?.join(identity::DAEMON_PID_FILE);
    if !pid_path.exists() {
        println!("No daemon PID file found; nothing to stop.");
        return Ok(());
    }
    let text = std::fs::read_to_string(&pid_path)?;
    let pid: i32 = text
        .trim()
        .parse()
        .map_err(|_| Error::BadConfig("bad PID file".into()))?;
    let status = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()?;
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
    pp: &PassphraseSource,
) -> Result<()> {
    let passphrase = pp.resolve()?;
    let ks = OpenedKeys::open(dir, passphrase.as_deref())?;
    let identity = ks.identity.clone();
    let wg = ks.wg.clone();
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
        let is_wildcard_endpoint =
            peer_endpoint_str.is_some_and(|s| s.starts_with("0.0.0.0:") || s.starts_with("[::]:"));
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

    let local_pub = *wg.public();
    let mgr_cfg = ManagerConfig {
        local_keypair: wg,
        local_ip: state
            .ip
            .parse()
            .map_err(|_| Error::Server(format!("my own ip is not a valid IPv4: {}", state.ip)))?,
        ..Default::default()
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
            if pc.is_initiator {
                "initiator"
            } else {
                "responder"
            }
        );
    }
    // Capture known pubkeys before peer_cfgs is moved into TunnelManager.
    let mut known_pubkeys: std::collections::HashSet<[u8; 32]> =
        peer_cfgs.iter().map(|pc| pc.peer_pub).collect();

    let mut manager = TunnelManager::new(Box::new(device), transport, mgr_cfg, peer_cfgs)?;

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
        let mut auth_token = state.auth_token.clone();
        let endpoint = advertised.clone();
        let via_relay = via_relay_for_heartbeat.clone();
        let dir = dir.to_path_buf();
        tokio::spawn(async move {
            let client = CoordClient::new(&cfg_url);
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;

                // Refresh token if expired or expiring within 60 s.
                if let Ok(s) = State::load(&dir) {
                    if is_token_expired_soon(s.auth_token_expires_at, 60) {
                        tracing::info!("auth token expired or expiring; refreshing");
                        match client.refresh_token(&identity, &auth_token).await {
                            Ok(resp) => {
                                auth_token = resp.auth_token;
                                if let Ok(mut s) = State::load(&dir) {
                                    s.auth_token = auth_token.clone();
                                    s.auth_token_expires_at = Some(resp.auth_token_expires_at);
                                    let _ = s.save(&dir);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(?e, "token refresh failed; heartbeat will likely fail");
                            }
                        }
                    }
                }

                if let Err(e) = client
                    .heartbeat(&identity, &auth_token, &endpoint, via_relay.as_deref())
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

    // Track known pubkeys to detect newly registered peers at runtime.
    let mut peer_discovery = tokio::time::interval(Duration::from_secs(60));
    peer_discovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let discovery_client = CoordClient::new(&cfg.server.url);
    let discovery_dir = dir.to_path_buf();

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
            _ = peer_discovery.tick() => {
                // Read the latest token from state (may have been refreshed by
                // the heartbeat task). If state is unreadable, skip this tick.
                let token = match State::load(&discovery_dir) {
                    Ok(s) => s.auth_token,
                    Err(_) => continue,
                };
                match discovery_client.peers(&token).await {
                    Ok(peers) => {
                        for peer in &peers {
                            let Some(peer_pub) = B64.decode(&peer.wg_pubkey).ok()
                                .and_then(|v| v.try_into().ok())
                            else { continue };
                            if known_pubkeys.contains(&peer_pub) {
                                continue;
                            }
                            // Build PeerConfig for the new peer.
                            let peer_ip: Ipv4Addr = match peer.ip.parse() {
                                Ok(ip) => ip,
                                Err(_) => continue,
                            };
                            let peer_via_relay: Option<SocketAddr> = peer.via_relay
                                .as_deref()
                                .and_then(|s| s.parse().ok());
                            let peer_endpoint: SocketAddr = match peer.last_endpoint.as_deref() {
                                Some(s) if !s.starts_with("0.0.0.0:") && !s.starts_with("[::]:") => {
                                    s.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                                }
                                _ => {
                                    if peer_via_relay.is_some() {
                                        "0.0.0.0:0".parse().unwrap()
                                    } else {
                                        tracing::debug!(
                                            node_id = %peer.node_id,
                                            "new peer has no reachable endpoint; skipping"
                                        );
                                        continue;
                                    }
                                }
                            };
                            let via_relay = peer_via_relay.or(relay_endpoint);
                            let is_initiator = if relay_endpoint.is_some() {
                                true
                            } else if peer_via_relay.is_some() {
                                false
                            } else {
                                local_pub > peer_pub
                            };
                            let sender_id = (manager.peer_count() as u32) + 1;
                            let cfg = naboscale_tunnel::PeerConfig {
                                peer_pub,
                                psk: [0u8; 32],
                                local_sender_id: sender_id,
                                is_initiator,
                                peer_endpoint,
                                peer_ip,
                                via_relay,
                            };
                            match manager.add_peer(cfg) {
                                Ok(true) => {
                                    known_pubkeys.insert(peer_pub);
                                    tracing::info!(
                                        node_id = %peer.node_id,
                                        ip = %peer.ip,
                                        "discovered new peer at runtime"
                                    );
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    tracing::warn!(?e, node_id = %peer.node_id, "failed to add discovered peer");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(?e, "peer discovery fetch failed");
                    }
                }
            }
        }
    }
}
