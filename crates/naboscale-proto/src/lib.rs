//! naboscale-proto: wire-level message types and framing.
//!
//! Reserved for Phase 2 (TUN/transport packets) and Phase 3 (coord server API).
//! Phase 1 only uses naboscale-crypto.

#![allow(dead_code)]

pub mod message;

pub use message::*;
