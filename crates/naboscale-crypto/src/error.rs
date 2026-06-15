use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("handshake incomplete")]
    HandshakeIncomplete,

    #[error("invalid message length: expected at least {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid message type byte: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("timestamp is too old or invalid")]
    InvalidTimestamp,

    #[error("replay detected")]
    ReplayDetected,

    #[error("mac validation failed")]
    MacInvalid,

    #[error("cookie required")]
    CookieRequired,

    #[error("buffer too small: need {needed} bytes, have {actual}")]
    BufferTooSmall { needed: usize, actual: usize },

    #[error("transport error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, Error>;
