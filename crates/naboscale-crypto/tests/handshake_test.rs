use naboscale_crypto::{Initiator, Keypair, Responder, Tai64N};

const PSK: [u8; 32] = [42u8; 32];

#[test]
fn noise_ikpsk2_handshake_derives_matching_transport_keys() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let now = Tai64N::from_unix(1_700_000_000, 0);

    let mut alice_hs = Initiator::new(&alice, bob.public(), PSK, 1, now).unwrap();
    let mut bob_hs = Responder::new(&bob, PSK, 2, now).unwrap();

    let msg1 = alice_hs.write_init().unwrap();
    let msg2 = bob_hs.consume_init(&msg1).unwrap();
    let mut alice_t = alice_hs.consume_response(&msg2).unwrap();
    let mut bob_t = bob_hs.into_transport().unwrap();

    let plaintext = b"hello from alice";
    let mut ciphertext = [0u8; 1024];
    let ct_len = alice_t.encrypt(plaintext, 2, &mut ciphertext).unwrap();
    let mut decrypted = [0u8; 1024];
    let pt_len = bob_t.decrypt(&ciphertext[..ct_len], &mut decrypted).unwrap();
    assert_eq!(&decrypted[..pt_len], plaintext);

    let mut ciphertext2 = [0u8; 1024];
    let ct2_len = bob_t.encrypt(b"reply from bob", 1, &mut ciphertext2).unwrap();
    let mut decrypted2 = [0u8; 1024];
    let pt2_len = alice_t.decrypt(&ciphertext2[..ct2_len], &mut decrypted2).unwrap();
    assert_eq!(&decrypted2[..pt2_len], b"reply from bob");
}
