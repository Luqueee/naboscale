use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::UdpTransport;
use naboscale_crypto::{
    Initiator, Keypair, MESSAGE_TYPE_INIT, MESSAGE_TYPE_RELAY, MESSAGE_TYPE_RESPONSE,
    MESSAGE_TYPE_TRANSPORT, Responder, Tai64N, Transport as CryptoTransport, INIT_SIZE,
    RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

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
}

struct PeerSession {
    config: PeerConfig,
    state: PeerState,
    init_sent: bool,
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
            peers.push(PeerSession {
                config: peer_cfg,
                state,
                init_sent: false,
            });
        }
        Ok(Self {
            device,
            transport,
            config,
            peers,
            endpoint_to_peer,
            pubkey_to_peer,
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

        for i in 0..self.peers.len() {
            let peer = &mut self.peers[i];
            if !peer.init_sent {
                if let PeerState::HandshakingAsInitiator(init) = &mut peer.state {
                    let init_msg = init.write_init()?;
                    let endpoint = peer.config.peer_endpoint;
                    self.transport.send_to(endpoint, &init_msg)?;
                    peer.init_sent = true;
                }
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

    fn handle_incoming(&mut self, source: SocketAddr, pkt: &[u8]) -> Result<()> {
        if pkt.is_empty() {
            return Ok(());
        }
        if pkt[0] == MESSAGE_TYPE_RELAY {
            // The source must be a known direct peer (otherwise we'd be an
            // open relay). The actual sender is inside the RELAY header.
            if self.endpoint_to_peer.contains_key(&source) {
                return self.handle_relay(pkt);
            } else {
                tracing::debug!(?source, "dropping relay packet from unknown source");
                return Ok(());
            }
        }
        let peer_idx = match self.endpoint_to_peer.get(&source) {
            Some(&i) => i,
            None => {
                tracing::debug!(?source, "ignoring packet from unknown source");
                return Ok(());
            }
        };
        let msg_type = pkt[0];
        match msg_type {
            MESSAGE_TYPE_INIT => self.handle_init(peer_idx, pkt)?,
            MESSAGE_TYPE_RESPONSE => self.handle_response(peer_idx, pkt)?,
            MESSAGE_TYPE_TRANSPORT => self.handle_transport(peer_idx, pkt)?,
            _ => {
                tracing::debug!(?msg_type, "ignoring unknown message type");
            }
        }
        Ok(())
    }

    fn handle_relay(&mut self, pkt: &[u8]) -> Result<()> {
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
            let peer = &mut self.peers[peer_idx];
            if let PeerState::Ready { transport, .. } = &mut peer.state {
                if inner.is_empty() || inner[0] != MESSAGE_TYPE_TRANSPORT {
                    return Err(Error::InvalidConfig(
                        "relay inner is not a transport packet".into(),
                    ));
                }
                if inner.len() < TRANSPORT_HEADER_SIZE + 16 {
                    return Err(Error::InvalidConfig(
                        "relay inner transport packet too short".into(),
                    ));
                }
                let mut out = vec![0u8; 1500];
                let n = transport.decrypt(inner, &mut out)?;
                self.device.write(&out[..n])?;
            }
            Ok(())
        } else {
            // We are an intermediate relay. Forward the entire RELAY packet
            // (the dest needs the from_pub in the header to decrypt).
            let endpoint = self
                .peers
                .iter()
                .find(|p| p.config.peer_ip == dest_ip)
                .map(|p| p.config.peer_endpoint)
                .ok_or_else(|| {
                    Error::InvalidConfig(format!("relay dest {dest_ip} not a known peer").into())
                })?;
            self.transport.send_to(endpoint, pkt)?;
            Ok(())
        }
    }

    fn handle_init(&mut self, peer_idx: usize, pkt: &[u8]) -> Result<()> {
        if pkt.len() < INIT_SIZE {
            return Err(Error::InvalidConfig("init message too short".into()));
        }
        let peer = &mut self.peers[peer_idx];
        let PeerState::HandshakingAsResponder(responder) = &mut peer.state else {
            return Ok(());
        };
        let response = responder.consume_init(pkt)?;
        let endpoint = peer.config.peer_endpoint;
        self.transport.send_to(endpoint, &response)?;
        let responder = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsResponder(r) = responder {
            let transport = r.into_transport()?;
            let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
            };
        }
        Ok(())
    }

    fn handle_response(&mut self, peer_idx: usize, pkt: &[u8]) -> Result<()> {
        if pkt.len() < RESPONSE_SIZE {
            return Err(Error::InvalidConfig("response message too short".into()));
        }
        let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
        let peer = &mut self.peers[peer_idx];
        let initiator = std::mem::replace(&mut peer.state, PeerState::Init);
        if let PeerState::HandshakingAsInitiator(i) = initiator {
            let transport = i.consume_response(pkt)?;
            peer.state = PeerState::Ready {
                transport,
                peer_sender_id,
            };
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
