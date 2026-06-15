use crate::device::Device;
use crate::error::{Error, Result};
use crate::transport::UdpTransport;
use naboscale_crypto::{
    Initiator, Keypair, MESSAGE_TYPE_INIT, MESSAGE_TYPE_RESPONSE, MESSAGE_TYPE_TRANSPORT, Responder,
    Tai64N, Transport as CryptoTransport, INIT_SIZE, RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};

pub struct ManagerConfig {
    pub local_keypair: Keypair,
    pub peer_pub: [u8; 32],
    pub psk: [u8; 32],
    pub local_sender_id: u32,
    pub is_initiator: bool,
}

pub struct TunnelManager {
    device: Box<dyn Device>,
    transport: UdpTransport,
    config: ManagerConfig,
    state: State,
}

enum State {
    HandshakingAsResponder(Responder),
    HandshakingAsInitiator(Initiator),
    Ready {
        transport: CryptoTransport,
        peer_sender_id: u32,
    },
    Init,
}

impl TunnelManager {
    pub fn new(device: Box<dyn Device>, transport: UdpTransport, config: ManagerConfig) -> Result<Self> {
        let state = if config.is_initiator {
            let initiator = Initiator::new(
                &config.local_keypair,
                &config.peer_pub,
                config.psk,
                config.local_sender_id,
                Tai64N::now(),
            )?;
            State::HandshakingAsInitiator(initiator)
        } else {
            let responder = Responder::new(
                &config.local_keypair,
                config.psk,
                config.local_sender_id,
                Tai64N::now(),
            )?;
            State::HandshakingAsResponder(responder)
        };
        let mut mgr = Self {
            device,
            transport,
            config,
            state: State::Init,
        };
        mgr.state = state;
        if mgr.config.is_initiator {
            mgr.send_init()?;
        }
        Ok(mgr)
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready { .. })
    }

    pub fn peer_sender_id(&self) -> Option<u32> {
        match &self.state {
            State::Ready { peer_sender_id, .. } => Some(*peer_sender_id),
            _ => None,
        }
    }

    pub fn step(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        if let Some(n) = self.transport.try_recv(&mut buf)? {
            self.handle_incoming(&buf[..n])?;
        }

        if let State::Ready { transport, peer_sender_id } = &mut self.state {
            let mut dev_buf = vec![0u8; 1500];
            match self.device.try_read(&mut dev_buf) {
                Ok(Some(n)) => {
                    let mut out = vec![0u8; 1600];
                    let ct = transport.encrypt(&dev_buf[..n], *peer_sender_id, &mut out)?;
                    self.transport.send(&out[..ct])?;
                }
                Ok(None) => {}
                Err(e) => return Err(e),
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

    fn send_init(&mut self) -> Result<()> {
        if let State::HandshakingAsInitiator(init) = &mut self.state {
            let init_msg = init.write_init()?;
            self.transport.send(&init_msg)?;
        }
        Ok(())
    }

    fn handle_incoming(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.is_empty() {
            return Ok(());
        }
        let msg_type = pkt[0];
        match msg_type {
            MESSAGE_TYPE_INIT => {
                self.handle_init(pkt)?;
            }
            MESSAGE_TYPE_RESPONSE => {
                self.handle_response(pkt)?;
            }
            MESSAGE_TYPE_TRANSPORT => {
                self.handle_transport(pkt)?;
            }
            _ => {
                tracing::debug!(?msg_type, "ignoring unknown message type");
            }
        }
        Ok(())
    }

    fn handle_init(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < INIT_SIZE {
            return Err(Error::InvalidConfig("init message too short".into()));
        }
        let State::HandshakingAsResponder(responder) = &mut self.state else {
            return Ok(());
        };
        let response = responder.consume_init(pkt)?;
        self.transport.send(&response)?;
        let responder = std::mem::replace(&mut self.state, State::Init);
        if let State::HandshakingAsResponder(r) = responder {
            let transport = r.into_transport()?;
            let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
            self.state = State::Ready { transport, peer_sender_id };
        }
        Ok(())
    }

    fn handle_response(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < RESPONSE_SIZE {
            return Err(Error::InvalidConfig("response message too short".into()));
        }
        let peer_sender_id = u32::from_le_bytes(pkt[4..8].try_into().expect("checked"));
        let initiator = std::mem::replace(&mut self.state, State::Init);
        if let State::HandshakingAsInitiator(i) = initiator {
            let transport = i.consume_response(pkt)?;
            self.state = State::Ready { transport, peer_sender_id };
        }
        Ok(())
    }

    fn handle_transport(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() < TRANSPORT_HEADER_SIZE + 16 {
            return Err(Error::InvalidConfig("transport packet too short".into()));
        }
        if let State::Ready { transport, .. } = &mut self.state {
            let mut out = vec![0u8; 1500];
            let n = transport.decrypt(pkt, &mut out)?;
            self.device.write(&out[..n])?;
        }
        Ok(())
    }
}
