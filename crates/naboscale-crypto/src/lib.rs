//! naboscale-crypto: Noise IKpsk2 handshake + transport crypto for the naboscale protocol.
//!
//! Phase 1 deliverable: a WireGuard-compatible handshake that derives matching
//! transport keys on both sides, enabling end-to-end encrypted communication.

pub mod error;
pub mod handshake;
pub mod identity;
pub mod keys;
pub mod mac;
pub mod timestamp;
pub mod transport;

pub use error::{Error, Result};
pub use handshake::{
    Initiator, Responder, COOKIE_SIZE, INIT_SIZE, MESSAGE_TYPE_COOKIE, MESSAGE_TYPE_INIT,
    MESSAGE_TYPE_RELAY, MESSAGE_TYPE_RESPONSE, MESSAGE_TYPE_TRANSPORT, RESPONSE_SIZE,
    TRANSPORT_HEADER_SIZE,
};
pub use identity::Identity;
pub use keys::Keypair;
pub use timestamp::Tai64N;
pub use transport::Transport;
