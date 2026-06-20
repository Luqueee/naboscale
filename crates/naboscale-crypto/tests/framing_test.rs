use naboscale_crypto::{Initiator, Keypair, Responder, Tai64N, INIT_SIZE, RESPONSE_SIZE};

const MESSAGE_TYPE_INIT: u8 = 0x01;
const MESSAGE_TYPE_RESPONSE: u8 = 0x02;
const PSK: [u8; 32] = [42u8; 32];

#[test]
fn init_message_is_wireguard_compatible_size() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 0x11223344, now).unwrap();
    let init = alice_hs.write_init().unwrap();

    assert_eq!(init.len(), INIT_SIZE);
    assert_eq!(init[0], MESSAGE_TYPE_INIT);
    assert_eq!(&init[1..4], &[0u8, 0, 0], "reserved_zero must be zero");
    let sender_id = u32::from_le_bytes(init[4..8].try_into().unwrap());
    assert_eq!(sender_id, 0x11223344);
}

#[test]
fn response_message_is_wireguard_compatible_size() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let init = alice_hs.write_init().unwrap();
    let response = bob_hs.consume_init(&init).unwrap();

    assert_eq!(response.len(), RESPONSE_SIZE);
    assert_eq!(response[0], MESSAGE_TYPE_RESPONSE);
    assert_eq!(&response[1..4], &[0u8, 0, 0]);
    let resp_sender_id = u32::from_le_bytes(response[4..8].try_into().unwrap());
    assert_eq!(resp_sender_id, 2);
    let resp_receiver_id = u32::from_le_bytes(response[8..12].try_into().unwrap());
    assert_eq!(
        resp_receiver_id, 1,
        "receiver_id must echo initiator's sender_id"
    );
}

#[test]
fn responder_rejects_init_with_wrong_message_type() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let mut init = alice_hs.write_init().unwrap();
    init[0] = 0x99;

    let result = bob_hs.consume_init(&init);
    assert!(
        result.is_err(),
        "responder must reject unknown message types"
    );
}

#[test]
fn initiator_rejects_response_with_wrong_receiver_id() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let init = alice_hs.write_init().unwrap();
    let mut response = bob_hs.consume_init(&init).unwrap();
    response[8..12].copy_from_slice(&0xdeadbeefu32.to_le_bytes());

    let result = alice_hs.consume_response(&response);
    assert!(
        result.is_err(),
        "initiator must reject responses not addressed to it"
    );
}

#[test]
fn responder_rejects_init_with_tampered_mac1() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let mut init = alice_hs.write_init().unwrap();
    init[140] ^= 0x01;

    let result = bob_hs.consume_init(&init);
    assert!(matches!(result, Err(naboscale_crypto::Error::MacInvalid)));
}

#[test]
fn initiator_rejects_response_with_tampered_mac1() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let init = alice_hs.write_init().unwrap();
    let mut response = bob_hs.consume_init(&init).unwrap();
    response[80] ^= 0x01;

    let result = alice_hs.consume_response(&response);
    assert!(matches!(result, Err(naboscale_crypto::Error::MacInvalid)));
}
