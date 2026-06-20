use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("ip pool exhausted")]
    IpPoolExhausted,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid timestamp: drift exceeds {0} seconds")]
    InvalidTimestamp(i64),

    #[error("invalid public key")]
    InvalidPubkey,

    #[error("invalid auth token")]
    InvalidAuthToken,

    #[error("token expired at {0}")]
    TokenExpired(i64),

    #[error("rate limit exceeded; retry after {0}s")]
    RateLimited(u64),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("node not found")]
    NodeNotFound,

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] naboscale_crypto::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
