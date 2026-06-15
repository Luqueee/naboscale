//! naboscale-coord: coordination server for naboscale.
//!
//! The server is intentionally minimal: register, list peers, heartbeat.
//! There is no SSO, no rate limiting, no fancy auth — just pubkey-signed
//! requests plus a per-node auth token.

pub mod auth;
pub mod db;
pub mod error;
pub mod ip_alloc;
pub mod routes;
pub mod server;
pub mod state;

pub use error::{Error, Result};
pub use server::build_router;
pub use state::AppState;
