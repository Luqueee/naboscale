use crate::db::{self, Db, DEFAULT_TOKEN_TTL_SECS};
use crate::error::Result;
use crate::ip_alloc::IpAllocator;
use crate::rate_limit::RateLimiter;
use std::sync::Arc;

pub struct AppState {
    pub db: Db,
    pub ip_alloc: Arc<IpAllocator>,
    /// Auth-token lifetime in seconds. New tokens (issued by `register` or
    /// `refresh_token`) live this long before they must be refreshed.
    pub token_ttl_secs: i64,
    /// Per-(IP, bucket) sliding-window rate limiter. Shared across requests
    /// via `Arc` so the router can hand it to middleware.
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn open(path: &str) -> Result<Self> {
        let db = db::open(path)?;
        let ip_alloc = Arc::new(IpAllocator::new(&db)?);
        Ok(Self {
            db,
            ip_alloc,
            token_ttl_secs: token_ttl_from_env(),
            rate_limiter: Arc::new(RateLimiter::new()),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let db = db::open_in_memory()?;
        let ip_alloc = Arc::new(IpAllocator::new(&db)?);
        Ok(Self {
            db,
            ip_alloc,
            token_ttl_secs: token_ttl_from_env(),
            rate_limiter: Arc::new(RateLimiter::new()),
        })
    }

    /// Construct with an explicit TTL (used by tests to drive short-lived
    /// tokens without touching env vars).
    pub fn in_memory_with_ttl(ttl_secs: i64) -> Result<Self> {
        let db = db::open_in_memory()?;
        let ip_alloc = Arc::new(IpAllocator::new(&db)?);
        Ok(Self {
            db,
            ip_alloc,
            token_ttl_secs: ttl_secs,
            rate_limiter: Arc::new(RateLimiter::new()),
        })
    }
}

fn token_ttl_from_env() -> i64 {
    match std::env::var("NABOSCALE_COORD_TOKEN_TTL_SECS") {
        Ok(s) => s.parse().unwrap_or(DEFAULT_TOKEN_TTL_SECS),
        Err(_) => DEFAULT_TOKEN_TTL_SECS,
    }
}
