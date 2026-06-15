//! naboscale CLI: identity, coord server registration, tunnel daemon.

pub mod cli;
pub mod client;
pub mod config;
pub mod error;
pub mod identity;
pub mod platform;
pub mod state;

pub use cli::{run, Cli, Commands};

pub const NABOSCALE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub use error::{Error, Result};
