use crate::db::{self, Db};
use crate::error::{Error, Result};
use std::collections::HashSet;
use std::sync::Mutex;

pub const IP_POOL_NETWORK: [u8; 4] = [100, 100, 0, 0];
pub const IP_POOL_PREFIX: u8 = 16;
pub const IP_POOL_HOST_COUNT: u32 = 65534;
const IP_POOL_FIRST_HOST: u32 = u32_from_be_bytes(100, 100, 0, 1);

pub struct IpAllocator {
    used: Mutex<HashSet<u32>>,
}

impl IpAllocator {
    pub fn new(db: &Db) -> Result<Self> {
        let peers = db::list_peers(db, None)?;
        let mut used = HashSet::new();
        for peer in peers {
            used.insert(ipv4_str_to_u32(&peer.ip));
        }
        Ok(Self { used: Mutex::new(used) })
    }

    pub fn allocate(&self) -> Result<[u8; 4]> {
        let mut used = self.used.lock().expect("ip allocator poisoned");
        for i in 0..IP_POOL_HOST_COUNT {
            let candidate = IP_POOL_FIRST_HOST + i;
            if !used.contains(&candidate) {
                used.insert(candidate);
                return Ok(u32_to_ipv4(candidate));
            }
        }
        Err(Error::IpPoolExhausted)
    }
}

const fn u32_from_be_bytes(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

fn u32_to_ipv4(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn ipv4_str_to_u32(s: &str) -> u32 {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').enumerate() {
        if i >= 4 {
            break;
        }
        out[i] = part.parse().unwrap_or(0);
    }
    u32::from_be_bytes(out)
}
