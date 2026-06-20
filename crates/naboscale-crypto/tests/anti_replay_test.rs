use naboscale_crypto::{Error, Initiator, Keypair, Responder, Tai64N};

const REPLAY_WINDOW_SECONDS: u64 = 120;

#[test]
fn responder_rejects_init_with_timestamp_too_old() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let psk = [42u8; 32];

    let now = Tai64N::from_unix(2_000_000_000, 0);
    let stale = Tai64N::from_unix(2_000_000_000 - REPLAY_WINDOW_SECONDS - 1, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), psk, 1, stale).unwrap();
    let mut bob_hs = Responder::new(&bob, psk, 2, now).unwrap();

    let msg1 = alice_hs.write_init().unwrap();
    let result = bob_hs.consume_init(&msg1);

    assert!(
        matches!(result, Err(Error::InvalidTimestamp)),
        "expected InvalidTimestamp, got {:?}",
        result
    );
}

#[test]
fn responder_rejects_init_with_timestamp_in_future() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let psk = [42u8; 32];

    let now = Tai64N::from_unix(2_000_000_000, 0);
    let future = Tai64N::from_unix(2_000_000_000 + REPLAY_WINDOW_SECONDS + 1, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), psk, 1, future).unwrap();
    let mut bob_hs = Responder::new(&bob, psk, 2, now).unwrap();

    let msg1 = alice_hs.write_init().unwrap();
    let result = bob_hs.consume_init(&msg1);

    assert!(matches!(result, Err(Error::InvalidTimestamp)));
}

#[test]
fn responder_accepts_init_within_replay_window() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let psk = [42u8; 32];

    let now = Tai64N::from_unix(2_000_000_000, 0);
    let recent = Tai64N::from_unix(2_000_000_000 - 30, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), psk, 1, recent).unwrap();
    let mut bob_hs = Responder::new(&bob, psk, 2, now).unwrap();

    let msg1 = alice_hs.write_init().unwrap();
    let result = bob_hs.consume_init(&msg1);

    assert!(result.is_ok(), "expected ok, got {:?}", result);
}
