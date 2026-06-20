use blake2::digest::typenum::U16;
use blake2::digest::{KeyInit, Mac, Update};
use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::Digest;

const LABEL_MAC1: &[u8; 8] = b"mac1----";
const LABEL_COOKIE: &[u8; 8] = b"cookie--";

pub fn hash1(label_and_responder_pub: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Update::update(&mut hasher, label_and_responder_pub);
    hasher.finalize().into()
}

pub fn mac1_key(responder_pub: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 8 + 32];
    buf[..8].copy_from_slice(LABEL_MAC1);
    buf[8..].copy_from_slice(responder_pub);
    hash1(&buf)
}

#[allow(dead_code)]
pub fn cookie_key(responder_pub: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 8 + 32];
    buf[..8].copy_from_slice(LABEL_COOKIE);
    buf[8..].copy_from_slice(responder_pub);
    hash1(&buf)
}

pub fn compute_mac1(key: &[u8; 32], msg_before_mac: &[u8]) -> [u8; 16] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new(key.into());
    Update::update(&mut mac, msg_before_mac);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// mac2 is the cookie echo: MAC(cookie, msg). Used for DoS protection.
pub fn compute_mac2(cookie: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(cookie)
        .expect("16-byte cookie fits Blake2sMac<U16> key");
    Update::update(&mut mac, msg);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

#[allow(dead_code)]
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Update::update(&mut hasher, input);
    hasher.finalize().into()
}
