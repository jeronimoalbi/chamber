use crate::key::{PrivKey, PubKey};

/// Produces Gno.land secp256k1 signatures.
pub trait Signer {
    /// The public key signatures will verify against.
    fn pub_key(&self) -> PubKey;

    /// Sign an arbitrary message (SHA-256 hashed internally).
    /// Returns 64-byte `R || S`.
    fn sign_arbitrary(&self, msg: &[u8]) -> [u8; 64];
}

impl Signer for PrivKey {
    fn pub_key(&self) -> PubKey {
        PrivKey::pub_key(self)
    }

    fn sign_arbitrary(&self, msg: &[u8]) -> [u8; 64] {
        PrivKey::sign_arbitrary(self, msg)
    }
}
