use crate::error::{Error, Result};
use crate::handshake::MESSAGE_TYPE_TRANSPORT;
use snow::TransportState;

pub const TRANSPORT_HEADER_SIZE: usize = 16;

pub struct Transport {
    inner: TransportState,
    sender_id: u32,
    send_counter: u64,
}

impl Transport {
    pub(crate) fn new(inner: TransportState, sender_id: u32) -> Self {
        Self {
            inner,
            sender_id,
            send_counter: 0,
        }
    }

    pub fn sender_id(&self) -> u32 {
        self.sender_id
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        receiver_id: u32,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.len() < TRANSPORT_HEADER_SIZE + plaintext.len() + 16 {
            return Err(Error::BufferTooSmall {
                needed: TRANSPORT_HEADER_SIZE + plaintext.len() + 16,
                actual: out.len(),
            });
        }
        let counter = self.send_counter;
        self.send_counter += 1;

        out[0] = MESSAGE_TYPE_TRANSPORT;
        out[1..4].copy_from_slice(&[0u8; 3]);
        out[4..8].copy_from_slice(&receiver_id.to_le_bytes());
        out[8..16].copy_from_slice(&counter.to_le_bytes());

        let len = self.inner.write_message(plaintext, &mut out[TRANSPORT_HEADER_SIZE..])?;
        Ok(TRANSPORT_HEADER_SIZE + len)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
        if ciphertext.len() < TRANSPORT_HEADER_SIZE + 16 {
            return Err(Error::InvalidLength {
                expected: TRANSPORT_HEADER_SIZE + 16,
                actual: ciphertext.len(),
            });
        }
        if ciphertext[0] != MESSAGE_TYPE_TRANSPORT {
            return Err(Error::InvalidMessageType(ciphertext[0]));
        }
        let len = self.inner.read_message(
            &ciphertext[TRANSPORT_HEADER_SIZE..],
            out,
        )?;
        Ok(len)
    }
}
