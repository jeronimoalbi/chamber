use crate::key::{PrivKey, PubKey};

/// Produces Gno.land secp256k1 signatures.
pub trait Signer {
    /// The public key signatures will verify against.
    fn pub_key(&self) -> PubKey;

    /// Sign a message (SHA-256 hashed internally). Returns 64-byte `R || S`.
    fn sign(&self, msg: &[u8]) -> [u8; 64];

    /// Sign a pre-computed 32-byte digest with no further hashing.
    fn sign_prehashed(&self, digest32: &[u8; 32]) -> [u8; 64];
}

impl Signer for PrivKey {
    fn pub_key(&self) -> PubKey {
        PrivKey::pub_key(self)
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        PrivKey::sign(self, msg)
    }

    fn sign_prehashed(&self, digest32: &[u8; 32]) -> [u8; 64] {
        PrivKey::sign_prehashed(self, digest32)
    }
}
