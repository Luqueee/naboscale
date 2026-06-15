//! naboscale-tunnel: TUN device + UDP transport, combined with naboscale-crypto to
//! form an actual mesh VPN tunnel.

pub mod device;
pub mod error;
pub mod manager;
pub mod transport;

pub use device::{Device, LoopbackDevice, TunDevice};
pub use error::{Error, Result};
pub use manager::{ManagerConfig, TunnelManager};
pub use transport::UdpTransport;
