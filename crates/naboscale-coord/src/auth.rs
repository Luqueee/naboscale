use crate::error::{Error, Result};
use naboscale_crypto::Identity;

pub const REGISTER_TAG: &[u8] = b"register";
pub const HEARTBEAT_TAG: &[u8] = b"heartbeat";
pub const TIMESTAMP_WINDOW_SECONDS: i64 = 300;

pub fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs() as i64
}

pub fn validate_timestamp(timestamp: i64, now: i64) -> Result<()> {
    let diff = (now - timestamp).abs();
    if diff > TIMESTAMP_WINDOW_SECONDS {
        return Err(Error::InvalidTimestamp(TIMESTAMP_WINDOW_SECONDS));
    }
    Ok(())
}

pub fn build_register_message(
    timestamp: i64,
    identity_pubkey: &[u8; 32],
    wg_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 32 + 32);
    msg.extend_from_slice(REGISTER_TAG);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(identity_pubkey);
    msg.extend_from_slice(wg_pubkey);
    msg
}

pub fn build_heartbeat_message(timestamp: i64, endpoint: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(9 + 8 + endpoint.len());
    msg.extend_from_slice(HEARTBEAT_TAG);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(endpoint.as_bytes());
    msg
}

pub fn verify_register_signature(
    identity_pubkey: &[u8; 32],
    wg_pubkey: &[u8; 32],
    timestamp: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let msg = build_register_message(timestamp, identity_pubkey, wg_pubkey);
    if !Identity::verify(identity_pubkey, &msg, signature) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

pub fn verify_heartbeat_signature(
    identity_pubkey: &[u8; 32],
    endpoint: &str,
    timestamp: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let msg = build_heartbeat_message(timestamp, endpoint);
    if !Identity::verify(identity_pubkey, &msg, signature) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}
