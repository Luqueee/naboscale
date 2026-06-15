//! TAI64N timestamp: 8 bytes TAI seconds + 4 bytes nanoseconds, big-endian.
//!
//! WireGuard uses TAI64N for anti-replay protection on the Init message.
//! We use the current TAI-UTC offset of 37 seconds (as of 2026). This is
//! a best-effort offset — for real use, a leap-second table should be
//! consulted. For the MVP, an approximate offset is fine because
//! anti-replay windows are large (minutes).

const TAI_OFFSET_SECONDS: u64 = 37;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tai64N {
    seconds: u64,
    nanos: u32,
}

impl Tai64N {
    pub const SIZE: usize = 12;

    pub fn now() -> Self {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch");
        Self {
            seconds: dur.as_secs() + TAI_OFFSET_SECONDS,
            nanos: dur.subsec_nanos(),
        }
    }

    pub fn from_unix(secs: u64, nanos: u32) -> Self {
        Self {
            seconds: secs + TAI_OFFSET_SECONDS,
            nanos,
        }
    }

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..8].copy_from_slice(&self.seconds.to_be_bytes());
        out[8..].copy_from_slice(&self.nanos.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        let seconds = u64::from_be_bytes(bytes[..8].try_into().expect("12 bytes"));
        let nanos = u32::from_be_bytes(bytes[8..].try_into().expect("12 bytes"));
        Self { seconds, nanos }
    }

    pub fn seconds(self) -> u64 {
        self.seconds
    }
}
