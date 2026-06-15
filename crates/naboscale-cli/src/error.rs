use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] naboscale_crypto::Error),

    #[error("tunnel error: {0}")]
    Tunnel(#[from] naboscale_tunnel::Error),

    #[error("config directory not found")]
    NoConfigDir,

    #[error("config file malformed: {0}")]
    BadConfig(String),

    #[error("identity not initialized in {0}: run `naboscale --config-dir {0} init` first")]
    NotInitialized(String),

    #[error("server error: {0}")]
    Server(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("toml deserialize error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("config not initialized: run `naboscale init` first")]
    ConfigMissing,
}

pub type Result<T> = std::result::Result<T, Error>;
