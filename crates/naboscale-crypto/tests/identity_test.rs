use naboscale_crypto::Identity;

#[test]
fn sign_and_verify_round_trip() {
    let id = Identity::generate();
    let msg = b"hello world";
    let sig = id.sign(msg);
    assert!(Identity::verify(&id.public(), msg, &sig));
}

#[test]
fn verify_rejects_tampered_message() {
    let id = Identity::generate();
    let mut msg = b"hello world".to_vec();
    let sig = id.sign(&msg);
    msg[0] ^= 0x01;
    assert!(!Identity::verify(&id.public(), &msg, &sig));
}

#[test]
fn verify_rejects_wrong_key() {
    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let msg = b"hello world";
    let sig = id1.sign(msg);
    assert!(!Identity::verify(&id2.public(), msg, &sig));
}

#[test]
fn identity_can_be_recovered_from_private_bytes() {
    let id1 = Identity::generate();
    let bytes = id1.private_bytes();
    let id2 = Identity::from_bytes(bytes);
    assert_eq!(id1.public(), id2.public());

    let msg = b"recovered";
    let sig = id2.sign(msg);
    assert!(Identity::verify(&id1.public(), msg, &sig));
}
