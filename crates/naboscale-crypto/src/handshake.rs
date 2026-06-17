use crate::error::{Error, Result};
use crate::keys::Keypair;
use crate::mac::{compute_mac1, mac1_key};
use crate::timestamp::Tai64N;
use crate::transport::Transport;
use snow::params::NoiseParams;
use snow::HandshakeState;

pub const INIT_SIZE: usize = 148;
pub const RESPONSE_SIZE: usize = 92;
pub const COOKIE_SIZE: usize = 64;
pub const TRANSPORT_HEADER_SIZE: usize = 16;

pub const MESSAGE_TYPE_INIT: u8 = 0x01;
pub const MESSAGE_TYPE_RESPONSE: u8 = 0x02;
pub const MESSAGE_TYPE_COOKIE: u8 = 0x03;
pub const MESSAGE_TYPE_TRANSPORT: u8 = 0x04;
pub const MESSAGE_TYPE_RELAY: u8 = 0x05;

const REPLAY_WINDOW_SECONDS: u64 = 120;
const NOISE_INIT_PAYLOAD_OFFSET: usize = 8;
const NOISE_INIT_PAYLOAD_SIZE: usize = 108;
const NOISE_RESPONSE_PAYLOAD_OFFSET: usize = 12;
const NOISE_RESPONSE_PAYLOAD_SIZE: usize = 48;
const MAC1_OFFSET_INIT: usize = 132;
const MAC1_OFFSET_RESPONSE: usize = 76;

const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const PROTOCOL_NAME: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

fn params() -> Result<NoiseParams> {
    Ok(PROTOCOL_NAME.parse()?)
}

fn read_u32(slice: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&slice[..4]);
    out
}

pub struct Initiator {
    state: HandshakeState,
    sender_id: u32,
    local_pub: [u8; 32],
    responder_pub: [u8; 32],
    timestamp: Tai64N,
}

pub struct Responder {
    state: HandshakeState,
    sender_id: u32,
    local_pub: [u8; 32],
    current_time: Tai64N,
}

impl Initiator {
    pub fn new(
        local: &Keypair,
        remote_pub: &[u8; 32],
        psk: [u8; 32],
        sender_id: u32,
        timestamp: Tai64N,
    ) -> Result<Self> {
        let state = snow::Builder::new(params()?)
            .local_private_key(&local.secret_bytes())
            .remote_public_key(remote_pub)
            .prologue(WG_IDENTIFIER)
            .psk(2, &psk)
            .build_initiator()?;
        let mut local_pub = [0u8; 32];
        local_pub.copy_from_slice(local.public());
        Ok(Self {
            state,
            sender_id,
            local_pub,
            responder_pub: *remote_pub,
            timestamp,
        })
    }

    pub fn sender_id(&self) -> u32 {
        self.sender_id
    }

    pub fn write_init(&mut self) -> Result<[u8; INIT_SIZE]> {
        let mut out = [0u8; INIT_SIZE];
        out[0] = MESSAGE_TYPE_INIT;
        out[4..8].copy_from_slice(&self.sender_id.to_le_bytes());
        let len = self.state.write_message(
            &self.timestamp.to_bytes(),
            &mut out[NOISE_INIT_PAYLOAD_OFFSET..NOISE_INIT_PAYLOAD_OFFSET + NOISE_INIT_PAYLOAD_SIZE],
        )?;
        if len != NOISE_INIT_PAYLOAD_SIZE {
            return Err(Error::InvalidLength {
                expected: NOISE_INIT_PAYLOAD_SIZE,
                actual: len,
            });
        }
        let key = mac1_key(&self.responder_pub);
        let mac1 = compute_mac1(&key, &out[..MAC1_OFFSET_INIT]);
        out[MAC1_OFFSET_INIT..MAC1_OFFSET_INIT + 16].copy_from_slice(&mac1);
        Ok(out)
    }

    pub fn consume_response(mut self, response: &[u8]) -> Result<Transport> {
        if response.len() < RESPONSE_SIZE {
            return Err(Error::InvalidLength {
                expected: RESPONSE_SIZE,
                actual: response.len(),
            });
        }
        if response[0] != MESSAGE_TYPE_RESPONSE {
            return Err(Error::InvalidMessageType(response[0]));
        }
        let receiver_id = u32::from_le_bytes(read_u32(&response[8..12]));
        if receiver_id != self.sender_id {
            return Err(Error::InvalidMessageType(response[0]));
        }
        let key = mac1_key(&self.local_pub);
        let expected_mac1 = compute_mac1(&key, &response[..MAC1_OFFSET_RESPONSE]);
        if response[MAC1_OFFSET_RESPONSE..MAC1_OFFSET_RESPONSE + 16] != expected_mac1 {
            return Err(Error::MacInvalid);
        }
        let mut payload = [0u8; 256];
        self.state.read_message(
            &response[NOISE_RESPONSE_PAYLOAD_OFFSET..NOISE_RESPONSE_PAYLOAD_OFFSET + NOISE_RESPONSE_PAYLOAD_SIZE],
            &mut payload,
        )?;
        let transport = self.state.into_transport_mode()?;
        Ok(Transport::new(transport, self.sender_id))
    }
}

impl Responder {
    pub fn new(
        local: &Keypair,
        psk: [u8; 32],
        sender_id: u32,
        current_time: Tai64N,
    ) -> Result<Self> {
        let state = snow::Builder::new(params()?)
            .local_private_key(&local.secret_bytes())
            .prologue(WG_IDENTIFIER)
            .psk(2, &psk)
            .build_responder()?;
        let mut local_pub = [0u8; 32];
        local_pub.copy_from_slice(local.public());
        Ok(Self { state, sender_id, local_pub, current_time })
    }

    pub fn sender_id(&self) -> u32 {
        self.sender_id
    }

    pub fn set_current_time(&mut self, t: Tai64N) {
        self.current_time = t;
    }

    pub fn consume_init(&mut self, init_msg: &[u8]) -> Result<[u8; RESPONSE_SIZE]> {
        if init_msg.len() < INIT_SIZE {
            return Err(Error::InvalidLength {
                expected: INIT_SIZE,
                actual: init_msg.len(),
            });
        }
        if init_msg[0] != MESSAGE_TYPE_INIT {
            return Err(Error::InvalidMessageType(init_msg[0]));
        }
        let mut payload = [0u8; 256];
        let len = self.state.read_message(
            &init_msg[NOISE_INIT_PAYLOAD_OFFSET..NOISE_INIT_PAYLOAD_OFFSET + NOISE_INIT_PAYLOAD_SIZE],
            &mut payload,
        )?;
        if len != Tai64N::SIZE {
            return Err(Error::InvalidLength {
                expected: Tai64N::SIZE,
                actual: len,
            });
        }
        let timestamp = Tai64N::from_bytes(payload[..len].try_into().expect("len checked"));
        let diff = self.current_time.seconds() as i64 - timestamp.seconds() as i64;
        if diff.abs() > REPLAY_WINDOW_SECONDS as i64 {
            return Err(Error::InvalidTimestamp);
        }

        let key = mac1_key(&self.local_pub);
        let expected_mac1 = compute_mac1(&key, &init_msg[..MAC1_OFFSET_INIT]);
        if init_msg[MAC1_OFFSET_INIT..MAC1_OFFSET_INIT + 16] != expected_mac1 {
            return Err(Error::MacInvalid);
        }

        let initiator_static = self
            .state
            .get_remote_static()
            .ok_or(Error::HandshakeIncomplete)?;
        if initiator_static.len() != 32 {
            return Err(Error::HandshakeIncomplete);
        }
        let mut initiator_pub = [0u8; 32];
        initiator_pub.copy_from_slice(initiator_static);
        let response_key = mac1_key(&initiator_pub);

        let mut out = [0u8; RESPONSE_SIZE];
        out[0] = MESSAGE_TYPE_RESPONSE;
        out[4..8].copy_from_slice(&self.sender_id.to_le_bytes());
        out[8..12].copy_from_slice(&read_u32(&init_msg[4..8]));
        let noise_len = self.state.write_message(
            &[],
            &mut out[NOISE_RESPONSE_PAYLOAD_OFFSET..NOISE_RESPONSE_PAYLOAD_OFFSET + NOISE_RESPONSE_PAYLOAD_SIZE],
        )?;
        if noise_len != NOISE_RESPONSE_PAYLOAD_SIZE {
            return Err(Error::InvalidLength {
                expected: NOISE_RESPONSE_PAYLOAD_SIZE,
                actual: noise_len,
            });
        }
        let mac1 = compute_mac1(&response_key, &out[..MAC1_OFFSET_RESPONSE]);
        out[MAC1_OFFSET_RESPONSE..MAC1_OFFSET_RESPONSE + 16].copy_from_slice(&mac1);
        Ok(out)
    }

    pub fn into_transport(self) -> Result<Transport> {
        let transport = self.state.into_transport_mode()?;
        Ok(Transport::new(transport, self.sender_id))
    }
}
