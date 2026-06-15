use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("tun device error: {0}")]
    Tun(#[from] tun::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] naboscale_crypto::Error),

    #[error("buffer too small: need {needed} bytes, have {actual}")]
    BufferTooSmall { needed: usize, actual: usize },

    #[error("handshake timeout")]
    HandshakeTimeout,

    #[error("tunnel not ready")]
    NotReady,

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, Error>;
