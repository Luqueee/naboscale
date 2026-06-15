use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct Keypair {
    #[zeroize(skip)]
    secret: StaticSecret,
    public: [u8; 32],
}

impl Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = *PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    pub fn from_bytes(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = *PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}
