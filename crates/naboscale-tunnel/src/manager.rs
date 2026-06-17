use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::UdpTransport;
use naboscale_crypto::mac::{compute_mac1, mac1_key};
use naboscale_crypto::{
    Initiator, Keypair, MESSAGE_TYPE_INIT, MESSAGE_TYPE_RELAY, MESSAGE_TYPE_RESPONSE,
    MESSAGE_TYPE_TRANSPORT, Responder, Tai64N, Transport as CryptoTransport, INIT_SIZE,
    RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const INIT_RETRY_INTERVAL: Duration = Duration::from_secs(2);

pub struct ManagerConfig {
    pub local_keypair: Keypair,
    pub local_ip: Ipv4Addr,
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
}

struct PeerSession {
    config: PeerConfig,
    state: PeerState,
    next_init_at: Option<Instant>,
    cached_init: Option<Vec<u8>>,
}

enum PeerState {
    Init,
    HandshakingAsInitiator(Initiator),
    HandshakingAsResponder(Responder),
    Ready {
        transport: CryptoTransport,
        peer_sender_id: u32,
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
                        (None, peer.config.peer_endpoint, peer.config.peer_ip, [0u8; 32], None)
                    }
                } else {
                    (None, peer.config.peer_endpoint, peer.config.peer_ip, [0u8; 32], None)
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
        } = &mut self.peers[peer_idx].state
        {
            let mut out = vec![0u8; 1600];
            let ct = transport.encrypt(pkt, *peer_sender_id, &mut out)?;
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
            if self.pubkey_to_peer.contains_key(&from_pub) {
                if !self.endpoint_to_peer.contains_key(&source) {
                    tracing::info!(?source, "learning new endpoint from RELAY source");
                    self.learned_endpoints.insert(from_pub, source);
                }
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
                    if let Some(peer_idx) =
                        self.identify_initiator_by_mac1(pkt)
                    {
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
                tracing::info!(?source, pkt0 = pkt[0], "ignoring packet from unknown source");
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
            let peer_idx = self
                .pubkey_to_peer
                .get(&from_pub)
                .copied()
                .ok_or_else(|| {
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
                    self.device.write(&out[..n])?;
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
                    Error::InvalidConfig(format!("relay dest {dest_ip} not a known peer").into())
                })?;
            let learned = self.learned_endpoints.get(&dest_peer.config.peer_pub).copied();
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
            };
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
    /// Sending the raw RESPONSE to `source` would be wrong in the second
    /// case: the relay would process it against its own (already-Ready)
    /// session with us and drop it.
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
            };
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
        let initiator = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsInitiator(i) = initiator {
            let transport = i.consume_response(pkt)?;
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
            };
            tracing::info!(peer_ip = ?peer.config.peer_ip, "handshake (initiator) complete -> Ready");
        }
        Ok(())
    }

    fn handle_transport(&mut self, peer_idx: usize, pkt: &[u8]) -> Result<()> {
        if pkt.len() < TRANSPORT_HEADER_SIZE + 16 {
            return Err(Error::InvalidConfig("transport packet too short".into()));
        }
        let peer = &mut self.peers[peer_idx];
        if let PeerState::Ready { transport, .. } = &mut peer.state {
            let mut out = vec![0u8; 1500];
            let n = transport.decrypt(pkt, &mut out)?;
            self.device.write(&out[..n])?;
        }
        Ok(())
    }
}
