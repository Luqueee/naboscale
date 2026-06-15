use naboscale_crypto::{Initiator, Keypair, Responder, Tai64N};

const PSK: [u8; 32] = [42u8; 32];
const MESSAGE_TYPE_TRANSPORT: u8 = 0x04;

fn handshake_pair() -> (TransportPair, u32, u32) {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let init = alice_hs.write_init().unwrap();
    let response = bob_hs.consume_init(&init).unwrap();
    let alice_t = alice_hs.consume_response(&response).unwrap();
    let bob_t = bob_hs.into_transport().unwrap();
    (TransportPair { alice_t, bob_t }, 1, 2)
}

struct TransportPair {
    alice_t: naboscale_crypto::Transport,
    bob_t: naboscale_crypto::Transport,
}

#[test]
fn transport_encrypts_with_wireguard_framing() {
    let (mut pair, _, bob_sender_id) = handshake_pair();

    let plaintext = b"hello over the wire";
    let mut ciphertext = vec![0u8; 32 + plaintext.len() + 16];
    let ct_len = pair.alice_t.encrypt(plaintext, bob_sender_id, &mut ciphertext).unwrap();

    assert_eq!(ciphertext[0], MESSAGE_TYPE_TRANSPORT);
    assert_eq!(&ciphertext[1..4], &[0u8, 0, 0]);
    let receiver_id = u32::from_le_bytes(ciphertext[4..8].try_into().unwrap());
    assert_eq!(receiver_id, bob_sender_id);
    let counter = u64::from_le_bytes(ciphertext[8..16].try_into().unwrap());
    assert_eq!(counter, 0);

    let mut decrypted = vec![0u8; plaintext.len() + 16];
    let pt_len = pair.bob_t.decrypt(&ciphertext[..ct_len], &mut decrypted).unwrap();
    assert_eq!(&decrypted[..pt_len], plaintext);
}

#[test]
fn send_counter_increments_per_packet() {
    let (mut pair, _, bob_sender_id) = handshake_pair();

    let mut out1 = [0u8; 64];
    let mut out2 = [0u8; 64];
    let mut out3 = [0u8; 64];

    pair.alice_t.encrypt(b"pkt0", bob_sender_id, &mut out1).unwrap();
    pair.alice_t.encrypt(b"pkt1", bob_sender_id, &mut out2).unwrap();
    pair.alice_t.encrypt(b"pkt2", bob_sender_id, &mut out3).unwrap();

    assert_eq!(u64::from_le_bytes(out1[8..16].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(out2[8..16].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(out3[8..16].try_into().unwrap()), 2);
}

#[test]
fn bidirectional_transport_round_trip() {
    let (mut pair, alice_sender_id, bob_sender_id) = handshake_pair();

    let mut c1 = [0u8; 64];
    let mut c2 = [0u8; 64];
    let l1 = pair.alice_t.encrypt(b"from alice", bob_sender_id, &mut c1).unwrap();
    let l2 = pair.bob_t.encrypt(b"from bob", alice_sender_id, &mut c2).unwrap();

    let mut d1 = [0u8; 32];
    let mut d2 = [0u8; 32];
    let p1 = pair.bob_t.decrypt(&c1[..l1], &mut d1).unwrap();
    let p2 = pair.alice_t.decrypt(&c2[..l2], &mut d2).unwrap();
    assert_eq!(&d1[..p1], b"from alice");
    assert_eq!(&d2[..p2], b"from bob");
}

#[test]
fn transport_rejects_packet_with_wrong_message_type() {
    let (mut pair, _, _) = handshake_pair();

    let mut garbage = [0u8; 64];
    garbage[0] = 0x99;
    let mut out = [0u8; 32];
    let result = pair.bob_t.decrypt(&garbage, &mut out);
    assert!(result.is_err());
}
