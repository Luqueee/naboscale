use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::UdpTransport;
use naboscale_crypto::mac::{compute_mac1, mac1_key};
use naboscale_crypto::{
    Initiator, Keypair, Responder, Tai64N, Transport as CryptoTransport, INIT_SIZE,
    MESSAGE_TYPE_INIT, MESSAGE_TYPE_RELAY, MESSAGE_TYPE_RESPONSE, MESSAGE_TYPE_TRANSPORT,
    RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const INIT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// WireGuard-style rekey / keepalive timings. Defaults match the values in the
/// reference implementation: keepalive every 10 s, rekey every 2 min, mark
/// stale after 3 min of silence. Tests override these to drive fast ticks.
#[derive(Debug, Clone, Copy)]
pub struct ManagerTimings {
    pub keepalive: Duration,
    pub rekey_after: Duration,
    pub reject_after: Duration,
    pub maintenance_tick: Duration,
}

impl Default for ManagerTimings {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(10),
            rekey_after: Duration::from_secs(120),
            reject_after: Duration::from_secs(180),
            maintenance_tick: Duration::from_millis(500),
        }
    }
}

pub struct ManagerConfig {
    pub local_keypair: Keypair,
    pub local_ip: Ipv4Addr,
    pub timings: ManagerTimings,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            local_keypair: Keypair::generate(),
            local_ip: Ipv4Addr::UNSPECIFIED,
            timings: ManagerTimings::default(),
        }
    }
}

pub struct PeerConfig {
    pub peer_pub: [u8; 32],
    pub psk: [u8; 32],
    pub local_sender_id: u32,
    pub is_initiator: bool,
    pub peer_endpoint: SocketAddr,
    pub peer_ip: Ipv4Addr,
    /// If `Some`, all transport packets to this peer are wrapped in
    /// `MESSAGE_TYPE_RELAY` and sent to this address. The relay forwards
    /// the bytes verbatim to `peer_endpoint`; the final destination uses the
    /// `from_pub` field in the RELAY header to pick the right session.
    pub via_relay: Option<SocketAddr>,
}

pub struct TunnelManager {
    device: Box<dyn Device>,
    transport: UdpTransport,
    config: ManagerConfig,
    peers: Vec<PeerSession>,
    endpoint_to_peer: HashMap<SocketAddr, usize>,
    pubkey_to_peer: HashMap<[u8; 32], usize>,
    /// Learned source addresses keyed by peer pubkey. Populated when a RELAY
    /// packet arrives from a new source (i.e. a peer behind NAT whose stored
    /// endpoint was a relay placeholder). Used to forward subsequent RELAY
    /// packets back to the peer's actual NAT-mapped address, avoiding
    /// loopback when the peer's stored endpoint equals the relay itself.
    learned_endpoints: HashMap<[u8; 32], SocketAddr>,
    last_maintenance_at: Instant,
}

struct PeerSession {
    config: PeerConfig,
    state: PeerState,
    next_init_at: Option<Instant>,
    cached_init: Option<Vec<u8>>,
    /// Instant of the most recent packet received from this peer (over the
    /// tunnel, RELAY, or handshake). Drives stale detection.
    last_rx_at: Option<Instant>,
    /// Instant of the most recent packet we sent to this peer (tunnel data,
    /// keepalive, handshake, RELAY-wrapped). Drives keepalive scheduling.
    last_tx_at: Option<Instant>,
    /// Instant of the most recent successful handshake → Ready transition.
    /// Drives rekey scheduling.
    last_handshake_at: Option<Instant>,
    /// True once `now - last_rx_at > reject_after`. While true we drop tunnel
    /// data from this peer (re-handshake is required to recover).
    stale: bool,
}

struct Rehandshake {
    /// Fresh Noise initiator for the in-flight rekey. Becomes the new
    /// transport once the RESPONSE arrives.
    initiator: Initiator,
    /// Cached INIT message bytes for retry on `next_retry_at`.
    init_msg: Vec<u8>,
    /// When this rekey started. Currently only used for log diagnostics;
    /// reserved for a future hard timeout that aborts stuck rekeys.
    #[expect(dead_code)]
    started_at: Instant,
    next_retry_at: Instant,
}

enum PeerState {
    Init,
    HandshakingAsInitiator(Initiator),
    HandshakingAsResponder(Responder),
    Ready {
        transport: CryptoTransport,
        peer_sender_id: u32,
        /// `Some(_)` while a rekey initiated by us is in progress. The existing
        /// `transport` keeps working until the new transport is installed on
        /// RESPONSE; `None` in steady state.
        rehandshake: Option<Box<Rehandshake>>,
    },
}

const RELAY_HEADER_SIZE: usize = 1 + 32 + 4; // type + from_pub + dest_ip
const MAC1_OFFSET_INIT: usize = 132;
const MAC1_LEN: usize = 16;

impl TunnelManager {
    pub fn new(
        device: Box<dyn Device>,
        transport: UdpTransport,
        config: ManagerConfig,
        peer_cfgs: Vec<PeerConfig>,
    ) -> Result<Self> {
        let mut peers = Vec::with_capacity(peer_cfgs.len());
        let mut endpoint_to_peer = HashMap::new();
        let mut pubkey_to_peer = HashMap::new();
        for (i, peer_cfg) in peer_cfgs.into_iter().enumerate() {
            let state = if peer_cfg.is_initiator {
                let initiator = Initiator::new(
                    &config.local_keypair,
                    &peer_cfg.peer_pub,
                    peer_cfg.psk,
                    peer_cfg.local_sender_id,
                    Tai64N::now(),
                )?;
                PeerState::HandshakingAsInitiator(initiator)
            } else {
                let responder = Responder::new(
                    &config.local_keypair,
                    peer_cfg.psk,
                    peer_cfg.local_sender_id,
                    Tai64N::now(),
                )?;
                PeerState::HandshakingAsResponder(responder)
            };
            endpoint_to_peer.insert(peer_cfg.peer_endpoint, i);
            pubkey_to_peer.insert(peer_cfg.peer_pub, i);
            let next_init_at = if peer_cfg.is_initiator {
                Some(Instant::now())
            } else {
                None
            };
            peers.push(PeerSession {
                config: peer_cfg,
                state,
                next_init_at,
                cached_init: None,
                last_rx_at: None,
                last_tx_at: None,
                last_handshake_at: None,
                stale: false,
            });
        }
        Ok(Self {
            device,
            transport,
            config,
            peers,
            endpoint_to_peer,
            pubkey_to_peer,
            learned_endpoints: HashMap::new(),
            last_maintenance_at: Instant::now(),
        })
    }

    pub fn is_ready(&self) -> bool {
        !self.peers.is_empty()
            && self
                .peers
                .iter()
                .all(|p| matches!(p.state, PeerState::Ready { .. }))
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn ready_peer_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| matches!(p.state, PeerState::Ready { .. }))
            .count()
    }

    /// Returns true once a Ready peer has been silent for more than
    /// `timings.reject_after`. Stale peers' incoming transport data is
    /// dropped until a fresh handshake recovers the session.
    pub fn is_peer_stale(&self, idx: usize) -> bool {
        self.peers.get(idx).map(|p| p.stale).unwrap_or(false)
    }

    /// Seconds elapsed since the most recent successful handshake for `idx`.
    /// `None` if the peer has never reached Ready. Used by tests to assert
    /// rekey happened after the configured `rekey_after`.
    pub fn peer_handshake_age_secs(&self, idx: usize) -> Option<f64> {
        self.peers
            .get(idx)
            .and_then(|p| p.last_handshake_at)
            .map(|t| t.elapsed().as_secs_f64())
    }

    /// Seconds elapsed since the most recent packet we sent to `idx`.
    pub fn peer_tx_age_secs(&self, idx: usize) -> Option<f64> {
        self.peers
            .get(idx)
            .and_then(|p| p.last_tx_at)
            .map(|t| t.elapsed().as_secs_f64())
    }

    pub fn step(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            match self.transport.try_recv_from(&mut buf) {
                Ok(Some((n, source))) => {
                    self.handle_incoming(source, &buf[..n])?;
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }

        let now = Instant::now();
        for i in 0..self.peers.len() {
            let (via_relay, endpoint, peer_ip, from_pub, msg) = {
                let peer = &mut self.peers[i];
                let due = peer.next_init_at.is_some_and(|t| now >= t);
                if due {
                    if matches!(peer.state, PeerState::HandshakingAsInitiator(_)) {
                        if peer.cached_init.is_none() {
                            if let PeerState::HandshakingAsInitiator(init) = &mut peer.state {
                                let init_msg = init.write_init()?;
                                peer.cached_init = Some(init_msg.to_vec());
                            }
                        }
                        (
                            peer.config.via_relay,
                            peer.config.peer_endpoint,
                            peer.config.peer_ip,
                            *self.config.local_keypair.public(),
                            peer.cached_init.clone(),
                        )
                    } else {
                        peer.next_init_at = None;
                        peer.cached_init = None;
                        (
                            None,
                            peer.config.peer_endpoint,
                            peer.config.peer_ip,
                            [0u8; 32],
                            None,
                        )
                    }
                } else {
                    (
                        None,
                        peer.config.peer_endpoint,
                        peer.config.peer_ip,
                        [0u8; 32],
                        None,
                    )
                }
            };
            if let Some(init_msg) = msg {
                tracing::info!(?endpoint, ?via_relay, ?peer_ip, "sending handshake INIT");
                self.send_maybe_relay(endpoint, via_relay, peer_ip, &from_pub, &init_msg)?;
                self.peers[i].next_init_at = Some(now + INIT_RETRY_INTERVAL);
            }
        }

        if self.any_peer_ready() {
            let mut dev_buf = vec![0u8; 1500];
            if let Some(n) = self.device.try_read(&mut dev_buf)? {
                self.dispatch_tun_packet(&dev_buf[..n])?;
            }
        }

        self.maintenance(now)?;
        Ok(())
    }

    pub fn run_until_ready(&mut self, max_steps: usize) -> Result<()> {
        for _ in 0..max_steps {
            if self.is_ready() {
                return Ok(());
            }
            self.step()?;
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err(Error::HandshakeTimeout)
    }

    pub fn run(&mut self) -> Result<()> {
        loop {
            self.step()?;
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn any_peer_ready(&self) -> bool {
        self.peers
            .iter()
            .any(|p| matches!(p.state, PeerState::Ready { .. }))
    }

    fn dispatch_tun_packet(&mut self, pkt: &[u8]) -> Result<()> {
        let peer_idx = match self.lookup_peer_by_dest_ip(pkt) {
            Some(i) => i,
            None => return Ok(()),
        };
        let (peer_ip, peer_endpoint, via_relay) = {
            let peer = &self.peers[peer_idx];
            (
                peer.config.peer_ip,
                peer.config.peer_endpoint,
                peer.config.via_relay,
            )
        };
        let from_pub = *self.config.local_keypair.public();
        if let PeerState::Ready {
            transport,
            peer_sender_id,
            ..
        } = &mut self.peers[peer_idx].state
        {
            let mut out = vec![0u8; 1600];
            let ct = match transport.encrypt(pkt, *peer_sender_id, &mut out) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        peer_ip = ?self.peers[peer_idx].config.peer_ip,
                        "tunnel: encrypt failed"
                    );
                    return Err(Error::Crypto(e));
                }
            };
            match via_relay {
                Some(relay) => {
                    let mut relay_pkt = vec![0u8; RELAY_HEADER_SIZE + ct];
                    relay_pkt[0] = MESSAGE_TYPE_RELAY;
                    relay_pkt[1..33].copy_from_slice(&from_pub);
                    relay_pkt[33..37].copy_from_slice(&peer_ip.octets());
                    relay_pkt[RELAY_HEADER_SIZE..].copy_from_slice(&out[..ct]);
                    self.transport.send_to(relay, &relay_pkt)?;
                }
                None => {
                    self.transport.send_to(peer_endpoint, &out[..ct])?;
                }
            }
            self.peers[peer_idx].last_tx_at = Some(Instant::now());
        }
        Ok(())
    }

    fn lookup_peer_by_dest_ip(&self, pkt: &[u8]) -> Option<usize> {
        if pkt.is_empty() {
            return None;
        }
        let version = pkt[0] >> 4;
        if version != 4 || pkt.len() < 20 {
            return None;
        }
        let dest_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.config.peer_ip == dest_ip {
                return Some(i);
            }
        }
        None
    }

    fn identify_initiator_by_mac1(&self, init_pkt: &[u8]) -> Option<usize> {
        // mac1 is at offset MAC1_OFFSET_INIT, 16 bytes.
        let mac1 = &init_pkt[MAC1_OFFSET_INIT..MAC1_OFFSET_INIT + MAC1_LEN];
        let msg_before_mac = &init_pkt[..MAC1_OFFSET_INIT];
        // Brute-force: for each known peer pubkey, see if it matches as the
        // responder of this init. Returns the peer_idx of the responder.
        for (i, peer) in self.peers.iter().enumerate() {
            let key = mac1_key(&peer.config.peer_pub);
            if compute_mac1(&key, msg_before_mac).as_slice() == mac1 {
                return Some(i);
            }
        }
        None
    }

    fn handle_incoming(&mut self, source: SocketAddr, pkt: &[u8]) -> Result<()> {
        if pkt.is_empty() {
            return Ok(());
        }
        if pkt[0] == MESSAGE_TYPE_RELAY {
            // RELAY packets carry the original sender's pubkey in cleartext
            // in the RELAY header. Accept the packet if the from_pub is one
            // of our known peers — even if the packet's source endpoint is
            // not (yet) in endpoint_to_peer. This is what allows a peer
            // behind NAT to be reached: the relay sees the packet, learns
            // the from_pub ↔ source mapping, and can forward subsequent
            // traffic to that learned address.
            if pkt.len() < RELAY_HEADER_SIZE {
                return Ok(());
            }
            let from_pub: [u8; 32] = pkt[1..33].try_into().expect("checked length");
            if let Some(&peer_idx) = self.pubkey_to_peer.get(&from_pub) {
                if !self.endpoint_to_peer.contains_key(&source) {
                    tracing::info!(?source, "learning new endpoint from RELAY source");
                    self.learned_endpoints.insert(from_pub, source);
                }
                self.peers[peer_idx].last_rx_at = Some(Instant::now());
                return self.handle_relay(source, pkt);
            }
            tracing::info!(?source, "dropping relay packet: from_pub not a known peer");
            return Ok(());
        }
        let peer_idx = match self.endpoint_to_peer.get(&source) {
            Some(&i) => i,
            None => {
                // Try to identify the sender. For INIT messages the responder's
                // pubkey is implicitly encoded via mac1 (the initiator puts the
                // responder_pub in the first message, and mac1 is computed with
                // mac1_key(responder_pub)). Brute-force over our known peer
                // pubkeys; a mac1 match identifies the responder — meaning the
                // source is the INITIATOR of that responder's session. Learn
                // the source ↔ initiator mapping and continue processing.
                if pkt[0] == MESSAGE_TYPE_INIT
                    && pkt.len() >= INIT_SIZE
                    && pkt.len() >= MAC1_OFFSET_INIT + MAC1_LEN
                {
                    if let Some(peer_idx) = self.identify_initiator_by_mac1(pkt) {
                        tracing::info!(
                            ?source,
                            "identified INIT initiator via mac1; learning endpoint"
                        );
                        // Update the peer's stored endpoint to the actual
                        // source. Skip the "is_initiator" check on the role —
                        // whoever the initiator is, we now know its address.
                        let peer = &mut self.peers[peer_idx];
                        if peer.config.peer_endpoint != source {
                            self.endpoint_to_peer.remove(&peer.config.peer_endpoint);
                            peer.config.peer_endpoint = source;
                            self.endpoint_to_peer.insert(source, peer_idx);
                        }
                        // Fall through to normal INIT handling below.
                        let msg_type = pkt[0];
                        match msg_type {
                            MESSAGE_TYPE_INIT => self.handle_init(peer_idx, source, pkt)?,
                            _ => unreachable!(),
                        }
                        return Ok(());
                    }
                }
                tracing::info!(
                    ?source,
                    pkt0 = pkt[0],
                    "ignoring packet from unknown source"
                );
                return Ok(());
            }
        };
        // Refresh the peer's stored endpoint to the actual source of this
        // packet. For direct peers this is a no-op; for NAT'd peers whose
        // stored endpoint is a relay placeholder, this updates to the real
        // NAT-mapped address so that subsequent responses (and any
        // retries/keepalives) reach the peer.
        {
            let peer = &mut self.peers[peer_idx];
            if peer.config.peer_endpoint != source {
                self.endpoint_to_peer.remove(&peer.config.peer_endpoint);
                peer.config.peer_endpoint = source;
                self.endpoint_to_peer.insert(source, peer_idx);
            }
            peer.last_rx_at = Some(Instant::now());
        }
        let msg_type = pkt[0];
        match msg_type {
            MESSAGE_TYPE_INIT => self.handle_init(peer_idx, source, pkt)?,
            MESSAGE_TYPE_RESPONSE => self.handle_response(peer_idx, source, pkt)?,
            MESSAGE_TYPE_TRANSPORT => self.handle_transport(peer_idx, pkt)?,
            _ => {
                tracing::debug!(?msg_type, "ignoring unknown message type");
            }
        }
        Ok(())
    }

    fn handle_relay(&mut self, source: SocketAddr, pkt: &[u8]) -> Result<()> {
        if pkt.len() < RELAY_HEADER_SIZE {
            return Err(Error::InvalidConfig("relay packet too short".into()));
        }
        let from_pub: [u8; 32] = pkt[1..33].try_into().expect("checked length");
        let dest_ip = Ipv4Addr::new(pkt[33], pkt[34], pkt[35], pkt[36]);
        let inner = &pkt[RELAY_HEADER_SIZE..];

        if dest_ip == self.config.local_ip {
            // We are the final destination. Look up the session by from_pub
            // (the original sender), not by source endpoint (which is the relay).
            let peer_idx =
                self.pubkey_to_peer.get(&from_pub).copied().ok_or_else(|| {
                    Error::InvalidConfig("relay from_pub not a known peer".into())
                })?;
            // Handshake messages (INIT/RESPONSE) addressed to us via the relay
            // need to be unwrapped and processed by the local handshake state
            // machine. TRANSPORT messages (already encrypted) need to be
            // decrypted with the peer's transport keys. Both paths run
            // synchronously here; we dispatch based on the inner first byte.
            if !inner.is_empty() && inner[0] == MESSAGE_TYPE_TRANSPORT {
                let peer = &mut self.peers[peer_idx];
                if let PeerState::Ready { transport, .. } = &mut peer.state {
                    if inner.len() < TRANSPORT_HEADER_SIZE + 16 {
                        return Err(Error::InvalidConfig(
                            "relay inner transport packet too short".into(),
                        ));
                    }
                    let mut out = vec![0u8; 1500];
                    let n = transport.decrypt(inner, &mut out)?;
                    if n > 0 {
                        self.device.write(&out[..n])?;
                    }
                }
            } else if !inner.is_empty() && inner[0] == MESSAGE_TYPE_INIT {
                self.handle_init_via_relay(peer_idx, from_pub, source, inner)?;
            } else if !inner.is_empty() && inner[0] == MESSAGE_TYPE_RESPONSE {
                self.handle_response(peer_idx, source, inner)?;
            } else {
                return Err(Error::InvalidConfig(
                    "relay inner is not a recognized message type".into(),
                ));
            }
            Ok(())
        } else {
            // We are an intermediate relay. Forward the entire RELAY packet
            // (the dest needs the from_pub in the header to decrypt). Prefer
            // a learned NAT address for the destination peer over its
            // configured peer_endpoint (which may be a relay placeholder or
            // our own address, causing loopback).
            let dest_peer = self
                .peers
                .iter()
                .find(|p| p.config.peer_ip == dest_ip)
                .ok_or_else(|| {
                    Error::InvalidConfig(format!("relay dest {dest_ip} not a known peer"))
                })?;
            let learned = self
                .learned_endpoints
                .get(&dest_peer.config.peer_pub)
                .copied();
            let endpoint = learned.unwrap_or(dest_peer.config.peer_endpoint);
            tracing::info!(
                ?dest_ip,
                ?endpoint,
                used_learned = learned.is_some(),
                "forwarding RELAY pkt"
            );
            self.transport.send_to(endpoint, pkt)?;
            Ok(())
        }
    }

    fn handle_init(&mut self, peer_idx: usize, source: SocketAddr, pkt: &[u8]) -> Result<()> {
        if pkt.len() < INIT_SIZE {
            return Err(Error::InvalidConfig("init message too short".into()));
        }
        let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
        // Two paths:
        //   (a) Initial handshake: state is HandshakingAsResponder, we have a
        //       pre-built Responder waiting for the INIT.
        //   (b) Incoming rekey: state is Ready (peer is rekeying us). Build a
        //       fresh Responder, consume the INIT, send RESPONSE, then swap
        //       in the new transport atomically — old transport kept working
        //       until this point.
        let is_rekey = matches!(self.peers[peer_idx].state, PeerState::Ready { .. });
        if is_rekey {
            let psk = self.peers[peer_idx].config.psk;
            let local_sid = self.peers[peer_idx].config.local_sender_id;
            let mut responder =
                Responder::new(&self.config.local_keypair, psk, local_sid, Tai64N::now())?;
            responder.set_current_time(Tai64N::now());
            let response = match responder.consume_init(pkt) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        peer_ip = ?self.peers[peer_idx].config.peer_ip,
                        "incoming rekey consume_init failed; ignoring"
                    );
                    return Ok(());
                }
            };
            let new_transport = responder.into_transport()?;
            self.transport.send_to(source, &response)?;
            let peer = &mut self.peers[peer_idx];
            if let PeerState::Ready {
                transport,
                peer_sender_id: sid,
                rehandshake: _,
            } = &mut peer.state
            {
                *transport = new_transport;
                *sid = peer_sender_id;
            }
            peer.last_handshake_at = Some(Instant::now());
            peer.stale = false;
            tracing::info!(
                peer_ip = ?peer.config.peer_ip,
                "rekey (responder) complete: new transport installed"
            );
            return Ok(());
        }
        let peer_sender_id = {
            let peer = &mut self.peers[peer_idx];
            let PeerState::HandshakingAsResponder(responder) = &mut peer.state else {
                return Ok(());
            };
            responder.set_current_time(Tai64N::now());
            let response = match responder.consume_init(pkt) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(?e, peer_ip = ?peer.config.peer_ip, "consume_init failed; recreating Responder");
                    let fresh = Responder::new(
                        &self.config.local_keypair,
                        peer.config.psk,
                        peer.config.local_sender_id,
                        Tai64N::now(),
                    )?;
                    peer.state = PeerState::HandshakingAsResponder(fresh);
                    return Ok(());
                }
            };
            self.transport.send_to(source, &response)?;
            u32::from_le_bytes(pkt[4..8].try_into().expect("checked"))
        };
        let peer = &mut self.peers[peer_idx];
        let responder = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsResponder(r) = responder {
            let transport = r.into_transport()?;
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
                rehandshake: None,
            };
            peer.last_handshake_at = Some(Instant::now());
            peer.last_rx_at = Some(Instant::now());
            tracing::info!(peer_ip = ?peer.config.peer_ip, "handshake (responder) complete -> Ready");
        }
        Ok(())
    }

    /// Handle an INIT that arrived wrapped in a RELAY packet. The original
    /// init was sent by `initiator_pub` (the pubkey in the RELAY header).
    /// `source` is the UDP source of the RELAY packet we just received —
    /// which is EITHER the initiator directly (when we ourselves are the
    /// relay it dialed) OR the relay that forwarded the init to us.
    ///
    /// We respond by wrapping the RESPONSE in a RELAY header addressed to
    /// the initiator's mesh IP, and sending it back to `source`. This works
    /// in both topologies:
    ///   - source == initiator: the initiator receives the RELAY, sees
    ///     dest_ip == its own local_ip, unwraps and processes the RESPONSE
    ///     (the initiator already knows source as a peer endpoint).
    ///   - source == intermediate relay: the relay receives the RELAY,
    ///     sees dest_ip == initiator's IP, forwards to the initiator's
    ///     learned NAT address (which the relay learned when it received
    ///     the initiator's outgoing INIT).
    ///     Sending the raw RESPONSE to `source` would be wrong in the second
    ///     case: the relay would process it against its own (already-Ready)
    ///     session with us and drop it.
    fn handle_init_via_relay(
        &mut self,
        peer_idx: usize,
        initiator_pub: [u8; 32],
        source: SocketAddr,
        pkt: &[u8],
    ) -> Result<()> {
        if pkt.len() < INIT_SIZE {
            return Err(Error::InvalidConfig("init message too short".into()));
        }
        let initiator_ip = self.peers[peer_idx].config.peer_ip;
        let from_pub = *self.config.local_keypair.public();
        let peer_sender_id = {
            let peer = &mut self.peers[peer_idx];
            let PeerState::HandshakingAsResponder(responder) = &mut peer.state else {
                tracing::warn!(
                    ?initiator_pub,
                    state = match &peer.state {
                        PeerState::Init => "Init",
                        PeerState::HandshakingAsInitiator(_) => "HandshakingAsInitiator",
                        PeerState::HandshakingAsResponder(_) => "HandshakingAsResponder",
                        PeerState::Ready { .. } => "Ready",
                    },
                    "RELAY'd INIT for peer not in Responder state; dropping"
                );
                return Ok(());
            };
            responder.set_current_time(Tai64N::now());
            let response = match responder.consume_init(pkt) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(?e, peer_ip = ?peer.config.peer_ip, "consume_init failed; recreating Responder");
                    let fresh = Responder::new(
                        &self.config.local_keypair,
                        peer.config.psk,
                        peer.config.local_sender_id,
                        Tai64N::now(),
                    )?;
                    peer.state = PeerState::HandshakingAsResponder(fresh);
                    return Ok(());
                }
            };
            let mut out = vec![0u8; RELAY_HEADER_SIZE + response.len()];
            out[0] = MESSAGE_TYPE_RELAY;
            out[1..33].copy_from_slice(&from_pub);
            out[33..37].copy_from_slice(&initiator_ip.octets());
            out[RELAY_HEADER_SIZE..].copy_from_slice(&response);
            tracing::info!(
                ?source,
                ?initiator_ip,
                "RELAY'd INIT processed; sending RELAY-wrapped RESPONSE back via source"
            );
            self.transport.send_to(source, &out)?;
            u32::from_le_bytes(pkt[4..8].try_into().expect("checked"))
        };
        let peer = &mut self.peers[peer_idx];
        let responder = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsResponder(r) = responder {
            let transport = r.into_transport()?;
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
                rehandshake: None,
            };
            peer.last_handshake_at = Some(Instant::now());
            peer.last_rx_at = Some(Instant::now());
            tracing::info!(peer_ip = ?peer.config.peer_ip, "handshake (responder) complete -> Ready");
        }
        Ok(())
    }

    /// Send `inner` to `endpoint`, optionally wrapped in a RELAY header
    /// addressed to the relay. Used by handshake handlers so that responses
    /// to a peer behind a relay go back through the relay, not directly.
    fn send_maybe_relay(
        &self,
        endpoint: SocketAddr,
        via_relay: Option<SocketAddr>,
        dest_ip: Ipv4Addr,
        from_pub: &[u8; 32],
        inner: &[u8],
    ) -> Result<()> {
        if let Some(relay) = via_relay {
            let mut out = vec![0u8; RELAY_HEADER_SIZE + inner.len()];
            out[0] = MESSAGE_TYPE_RELAY;
            out[1..33].copy_from_slice(from_pub);
            out[33..37].copy_from_slice(&dest_ip.octets());
            out[RELAY_HEADER_SIZE..].copy_from_slice(inner);
            self.transport.send_to(relay, &out)?;
        } else {
            self.transport.send_to(endpoint, inner)?;
        }
        Ok(())
    }

    fn handle_response(&mut self, peer_idx: usize, source: SocketAddr, pkt: &[u8]) -> Result<()> {
        if pkt.len() < RESPONSE_SIZE {
            return Err(Error::InvalidConfig("response message too short".into()));
        }
        let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
        // The response comes from the responder. If we're an initiator
        // behind a relay, the response was sent to the relay and forwarded
        // to us (source == relay's address). We don't need to update the
        // peer's endpoint from the source here — that happens via the
        // first TRANSPORT packet or another handshake packet.
        let _ = source;
        let peer = &mut self.peers[peer_idx];

        // Path A: in-flight rekey (we initiated a rekey and the responder
        // sent back a RESPONSE). The old transport stays Ready until we swap
        // in the new one — done atomically here.
        let in_rehandshake = matches!(
            peer.state,
            PeerState::Ready {
                rehandshake: Some(_),
                ..
            }
        );
        if in_rehandshake {
            let new_transport = {
                let PeerState::Ready { rehandshake, .. } = &mut peer.state else {
                    unreachable!()
                };
                let rs = rehandshake.take().expect("checked: in_rehandshake above");
                match rs.initiator.consume_response(pkt) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(
                            ?e,
                            peer_ip = ?peer.config.peer_ip,
                            "rekey: initiator.consume_response failed; rekey aborted, will retry next tick"
                        );
                        return Err(e.into());
                    }
                }
            };
            if let PeerState::Ready {
                transport,
                peer_sender_id: sid,
                ..
            } = &mut peer.state
            {
                *transport = new_transport;
                *sid = peer_sender_id;
            }
            peer.last_handshake_at = Some(Instant::now());
            tracing::info!(
                peer_ip = ?peer.config.peer_ip,
                "rekey (initiator) complete: new transport installed"
            );
            return Ok(());
        }

        // Path B: initial handshake completion.
        let initiator = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsInitiator(i) = initiator {
            let transport = i.consume_response(pkt)?;
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
                rehandshake: None,
            };
            peer.last_handshake_at = Some(Instant::now());
            tracing::info!(peer_ip = ?peer.config.peer_ip, "handshake (initiator) complete -> Ready");
        }
        Ok(())
    }

    fn handle_transport(&mut self, peer_idx: usize, pkt: &[u8]) -> Result<()> {
        if pkt.len() < TRANSPORT_HEADER_SIZE + 16 {
            return Err(Error::InvalidConfig("transport packet too short".into()));
        }
        let peer = &mut self.peers[peer_idx];
        if peer.stale {
            tracing::debug!(
                peer_ip = ?peer.config.peer_ip,
                "dropping transport packet from stale peer (re-handshake required to recover)"
            );
            return Ok(());
        }
        if let PeerState::Ready { transport, .. } = &mut peer.state {
            let mut out = vec![0u8; 1500];
            match transport.decrypt(pkt, &mut out) {
                Ok(n) if n > 0 => {
                    self.device.write(&out[..n])?;
                }
                Ok(_) => {} // keepalive: empty payload, nothing to write
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        peer_ip = ?peer.config.peer_ip,
                        "tunnel: decrypt failed (likely transient: peer just rekeyed)"
                    );
                }
            }
        }
        Ok(())
    }

    /// Periodic maintenance: per-peer keepalive, rekey, and stale marking.
    /// Runs at most once per `config.timings.maintenance_tick`. Cheap no-op
    /// when called more often.
    fn maintenance(&mut self, now: Instant) -> Result<()> {
        if now.duration_since(self.last_maintenance_at) < self.config.timings.maintenance_tick {
            return Ok(());
        }
        self.last_maintenance_at = now;

        enum Action {
            MarkStale,
            SendKeepalive,
            StartRekey {
                initiator: Box<Initiator>,
                init_msg: Vec<u8>,
            },
            RetryRekey,
        }
        let mut actions: Vec<(usize, Action)> = Vec::new();
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.stale {
                continue;
            }
            if let PeerState::Ready {
                rehandshake: Some(rs),
                ..
            } = &peer.state
            {
                if now >= rs.next_retry_at {
                    actions.push((i, Action::RetryRekey));
                }
                continue;
            }
            if !matches!(peer.state, PeerState::Ready { .. }) {
                continue;
            }
            // Stale: no rx for reject_after.
            if let Some(last_rx) = peer.last_rx_at {
                if now.duration_since(last_rx) > self.config.timings.reject_after {
                    actions.push((i, Action::MarkStale));
                    continue;
                }
            }
            // Keepalive: no tx for keepalive interval, OR we just entered
            // Ready and have never sent anything. The `None` branch handles
            // the latter so the first keepalive fires after `keepalive`.
            let needs_keepalive = match peer.last_tx_at {
                None => true,
                Some(t) => now.duration_since(t) > self.config.timings.keepalive,
            };
            if needs_keepalive {
                actions.push((i, Action::SendKeepalive));
            }
            // Rekey: only as initiator, only after rekey_after since last hs.
            if peer.config.is_initiator {
                let due = peer
                    .last_handshake_at
                    .map(|t| now.duration_since(t) > self.config.timings.rekey_after)
                    .unwrap_or(false);
                if due && !peer.config.peer_endpoint.ip().is_unspecified() {
                    // Build the Initiator now; `write_init` mutates it in
                    // place. We capture the initiator in `Action::StartRekey`
                    // and use the SAME instance later when consuming the
                    // RESPONSE — a fresh `Initiator::new` would carry a
                    // different ephemeral key and fail decryption.
                    let res = Initiator::new(
                        &self.config.local_keypair,
                        &peer.config.peer_pub,
                        peer.config.psk,
                        peer.config.local_sender_id,
                        Tai64N::now(),
                    )
                    .and_then(|mut init| {
                        let msg = init.write_init()?.to_vec();
                        Ok((init, msg))
                    });
                    match res {
                        Ok((initiator, init_msg)) => actions.push((
                            i,
                            Action::StartRekey {
                                initiator: Box::new(initiator),
                                init_msg,
                            },
                        )),
                        Err(e) => tracing::warn!(
                            ?e,
                            peer_ip = ?peer.config.peer_ip,
                            "rekey: build/initiator failed; will retry next tick"
                        ),
                    }
                }
            }
        }

        let local_pub = *self.config.local_keypair.public();
        for (i, action) in actions {
            match action {
                Action::MarkStale => {
                    let peer = &mut self.peers[i];
                    tracing::warn!(
                        peer_ip = ?peer.config.peer_ip,
                        reject_after = ?self.config.timings.reject_after,
                        "peer marked STALE: no traffic for > reject_after; \
                         dropping tunnel data until re-handshake recovers"
                    );
                    peer.stale = true;
                }
                Action::SendKeepalive => {
                    let (via_relay, endpoint, peer_ip, sender_id, transport_present) = {
                        let peer = &self.peers[i];
                        (
                            peer.config.via_relay,
                            peer.config.peer_endpoint,
                            peer.config.peer_ip,
                            if let PeerState::Ready { peer_sender_id, .. } = peer.state {
                                peer_sender_id
                            } else {
                                0
                            },
                            matches!(peer.state, PeerState::Ready { .. }),
                        )
                    };
                    if !transport_present {
                        continue;
                    }
                    if let PeerState::Ready {
                        transport,
                        peer_sender_id,
                        ..
                    } = &mut self.peers[i].state
                    {
                        let mut out = vec![0u8; TRANSPORT_HEADER_SIZE + 16];
                        let ct = transport.encrypt(&[], *peer_sender_id, &mut out)?;
                        if let Some(relay) = via_relay {
                            let mut relay_pkt = vec![0u8; RELAY_HEADER_SIZE + ct];
                            relay_pkt[0] = MESSAGE_TYPE_RELAY;
                            relay_pkt[1..33].copy_from_slice(&local_pub);
                            relay_pkt[33..37].copy_from_slice(&peer_ip.octets());
                            relay_pkt[RELAY_HEADER_SIZE..].copy_from_slice(&out[..ct]);
                            self.transport.send_to(relay, &relay_pkt)?;
                        } else {
                            self.transport.send_to(endpoint, &out[..ct])?;
                        }
                        let _ = sender_id;
                        self.peers[i].last_tx_at = Some(now);
                    }
                }
                Action::StartRekey {
                    initiator,
                    init_msg,
                } => {
                    let (via_relay, endpoint, peer_ip) = {
                        let peer = &self.peers[i];
                        (
                            peer.config.via_relay,
                            peer.config.peer_endpoint,
                            peer.config.peer_ip,
                        )
                    };
                    self.send_maybe_relay(endpoint, via_relay, peer_ip, &local_pub, &init_msg)?;
                    if let PeerState::Ready { rehandshake, .. } = &mut self.peers[i].state {
                        *rehandshake = Some(Box::new(Rehandshake {
                            initiator: *initiator,
                            init_msg,
                            started_at: now,
                            next_retry_at: now + INIT_RETRY_INTERVAL,
                        }));
                        tracing::info!(
                            peer_ip = ?self.peers[i].config.peer_ip,
                            rekey_after = ?self.config.timings.rekey_after,
                            "rekey (initiator) triggered: sent INIT, awaiting RESPONSE"
                        );
                    }
                }
                Action::RetryRekey => {
                    let (via_relay, endpoint, peer_ip, init_msg) = {
                        let peer = &self.peers[i];
                        let rs = match &peer.state {
                            PeerState::Ready {
                                rehandshake: Some(rs),
                                ..
                            } => rs,
                            _ => continue,
                        };
                        (
                            peer.config.via_relay,
                            peer.config.peer_endpoint,
                            peer.config.peer_ip,
                            rs.init_msg.clone(),
                        )
                    };
                    self.send_maybe_relay(endpoint, via_relay, peer_ip, &local_pub, &init_msg)?;
                    if let PeerState::Ready {
                        rehandshake: Some(rs),
                        ..
                    } = &mut self.peers[i].state
                    {
                        rs.next_retry_at = now + INIT_RETRY_INTERVAL;
                    }
                    tracing::debug!(
                        peer_ip = ?self.peers[i].config.peer_ip,
                        "rekey: re-sent INIT (no RESPONSE yet)"
                    );
                }
            }
        }
        Ok(())
    }
}
