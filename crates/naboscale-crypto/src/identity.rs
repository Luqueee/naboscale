use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Identity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    pub fn from_bytes(private: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    pub fn from_public(pubkey: [u8; 32]) -> Option<Self> {
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey) else {
            return None;
        };
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        Some(Self { signing_key, verifying_key })
    }

    pub fn public(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn public_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(self.public())
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(msg);
        sig.to_bytes()
    }

    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let signature = Signature::from_bytes(sig);
        vk.verify(msg, &signature).is_ok()
    }
}

impl Zeroize for Identity {
    fn zeroize(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
        self.signing_key = SigningKey::from_bytes(&bytes);
    }
}
