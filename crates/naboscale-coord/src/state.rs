use crate::db::{self, Db};
use crate::error::Result;
use crate::ip_alloc::IpAllocator;
use std::sync::Arc;

pub struct AppState {
    pub db: Db,
    pub ip_alloc: Arc<IpAllocator>,
}

impl AppState {
    pub fn open(path: &str) -> Result<Self> {
        let db = db::open(path)?;
        let ip_alloc = Arc::new(IpAllocator::new(&db)?);
        Ok(Self { db, ip_alloc })
    }

    pub fn in_memory() -> Result<Self> {
        let db = db::open_in_memory()?;
        let ip_alloc = Arc::new(IpAllocator::new(&db)?);
        Ok(Self { db, ip_alloc })
    }
}
