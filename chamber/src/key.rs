use k256::SecretKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::address::Address;
use crate::error::{Error, Result};
use crate::hdpath::{self, Bip44Path};
use crate::mnemonic::Mnemonic;

/// A secp256k1 private key (32 bytes).
#[derive(Clone)]
pub struct PrivKey([u8; 32]);

impl PrivKey {
    /// Init private key from an encoded secret scalar passed as a byte slice.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        SecretKey::from_slice(&bytes).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// Derive the key at `path` from a mnemonic.
    pub fn from_mnemonic(mnemonic: &Mnemonic, path: Bip44Path) -> Result<Self> {
        let seed = mnemonic.to_seed();
        let raw = hdpath::derive_bip44(&seed, path)?;
        Self::from_bytes(raw)
    }

    /// The 32 raw private-key bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Lowercase hex of the private key.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The compressed public key.
    /// Uses SEC1 encoded point w/ point compression.
    pub fn pub_key(&self) -> PubKey {
        let priv_key = SecretKey::from_slice(&self.0).unwrap();
        let public_key = priv_key.public_key().to_encoded_point(true);

        let mut out = [0u8; 33];
        out.copy_from_slice(public_key.as_bytes());
        PubKey(out)
    }

    /// Sign an arbitrary message.
    /// Returns a 64-byte `R || S` signature in low-S form.
    pub fn sign_arbitrary(&self, msg: &[u8]) -> [u8; 64] {
        // Hash to match gno's secp256k1 signer
        let digest = Sha256::digest(msg);
        self.sign_prehashed(&digest.into())
    }

    /// Sign a Gno.land transaction `SignDoc`.
    ///
    /// **Not implemented yet.**
    pub fn sign_tx(&self) -> Result<[u8; 64]> {
        // This crate doesn't support Amino encoding yet, and building a `SignDoc`'s
        // canonical sign bytes requires it.
        //
        // TODO: take a `SignDoc` (or its canonical Amino-JSON sign bytes) once Amino
        // is supported, and sign it via the crate-private `sign_prehashed`.
        Err(Error::Unimplemented(
            "transaction signing requires Amino support, not implemented yet".into(),
        ))
    }

    /// Sign a pre-computed 32-byte digest, with no further hashing.
    ///
    /// Crate-private: this signs whatever 32 bytes it's given, with no framing or
    /// context, so it must never be reachable from outside `chamber` — an external
    /// caller with direct access to it could sign a real transaction's sign-bytes just
    /// as easily as anything else. Used by [`sign_arbitrary`](Self::sign_arbitrary) and,
    /// once implemented, by [`sign_tx`](Self::sign_tx).
    pub(crate) fn sign_prehashed(&self, digest32: &[u8; 32]) -> [u8; 64] {
        // A 32-byte prehash is always signable
        let priv_key = SigningKey::from_slice(&self.0).unwrap();
        let signature: Signature = priv_key.sign_prehash(digest32).unwrap();

        // Use the low-S form and reject the high-S one, to prevent
        // signature malleability attacks, same as Gno.land.
        let signature = signature.normalize_s().unwrap_or(signature);
        signature.to_bytes().into()
    }
}

impl Drop for PrivKey {
    fn drop(&mut self) {
        // Securely zero private key memory
        self.0.zeroize();
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivKey()")
    }
}

/// A secp256k1 public key, 33-byte compressed SEC1.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PubKey([u8; 33]);

impl PubKey {
    /// Init public key from a compressed SEC1 point passed as a byte array.
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self> {
        k256::PublicKey::from_sec1_bytes(&bytes).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// The 33 raw public key compressed bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0
    }

    /// Lowercase hex of the public key.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The Gno.land address.
    pub fn address(&self) -> Address {
        let hash = Sha256::digest(self.0);
        let ripe = Ripemd160::digest(hash);
        let mut out = [0u8; 20];
        out.copy_from_slice(&ripe);
        Address::from_bytes(out)
    }

    /// Verify a 64-byte `R || S` signature over `msg` (SHA-256 hashed
    /// internally). Rejects non-canonical (high-S) signatures.
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let Ok(key) = k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.0) else {
            return false;
        };

        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };

        // When normalization returns some it means signature was high-S
        if signature.normalize_s().is_some() {
            return false;
        }

        // Check that the signature for the current message is authentic
        let digest = Sha256::digest(msg);
        key.verify_prehash(&digest, &signature).is_ok()
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PubKey({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official BIP39 English zero-entropy 24-word mnemonic
    const ZERO_ENTROPY_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon art";

    // Derived at the default path 44'/118'/0'/0/0.
    const KNOWN_PRIV_HEX: &str = "8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7";
    const KNOWN_PUB_HEX: &str =
        "02ba66a84cf7839af172a13e7fc9f5e7008cb8bca1585f8f3bafb3039eda3c1fdd";
    const KNOWN_ADDRESS: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";

    const SIGN_MSG: &str = "gnochamber signing test vector";
    const SIGN_HEX: &str = "c8016beff930a8072792f0accc41b615040eaeb94d76daba2b24cdbf7c12e2\
        1a3f9e9b1ec3cea14cde11c73588e4e623e88ad17d61d98f5d9dec05314186db0d";

    fn known_priv_key() -> PrivKey {
        let bytes: [u8; 32] = hex::decode(KNOWN_PRIV_HEX).unwrap().try_into().unwrap();
        PrivKey::from_bytes(bytes).unwrap()
    }

    #[test]
    fn from_bytes_round_trips() {
        // Arrange
        let bytes: [u8; 32] = hex::decode(KNOWN_PRIV_HEX).unwrap().try_into().unwrap();

        // Act
        let key = PrivKey::from_bytes(bytes).unwrap();

        // Assert
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn from_bytes_rejects_zero_scalar() {
        //! The all-zero scalar is not a valid secp256k1 private key (it must
        //! be in range `1..n-1`).

        // Act
        let err = PrivKey::from_bytes([0u8; 32]).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "invalid key: crypto error");
    }

    #[test]
    fn from_bytes_rejects_value_at_or_above_curve_order() {
        //! All 0xFF bytes are numerically larger, so this is not a valid scalar

        // Act
        let err = PrivKey::from_bytes([0xFFu8; 32]).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "invalid key: crypto error");
    }

    #[test]
    fn from_mnemonic_matches_known_vector() {
        // Arrange
        let mnemonic = Mnemonic::parse(ZERO_ENTROPY_MNEMONIC).unwrap();

        // Act
        let key = PrivKey::from_mnemonic(&mnemonic, Bip44Path::default()).unwrap();

        // Assert
        assert_eq!(key.to_hex(), KNOWN_PRIV_HEX);
        assert_eq!(key.pub_key().to_hex(), KNOWN_PUB_HEX);
        assert_eq!(key.pub_key().address().to_bech32(), KNOWN_ADDRESS);
    }

    #[test]
    fn to_hex_is_lowercase_and_64_chars() {
        // Act
        let hex = known_priv_key().to_hex();

        // Assert
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex.to_lowercase());
        assert_eq!(hex, KNOWN_PRIV_HEX);
    }

    #[test]
    fn pub_key_is_compressed_sec1() {
        // Act
        let bytes = known_priv_key().pub_key().to_bytes();

        // Assert
        assert_eq!(bytes.len(), 33);
        assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    }

    #[test]
    fn pub_key_to_hex_matches_known_vector() {
        // Act
        let hex = known_priv_key().pub_key().to_hex();

        // Assert
        assert_eq!(hex, KNOWN_PUB_HEX);
    }

    #[test]
    fn pub_key_from_bytes_round_trips() {
        // Arrange
        let bytes = known_priv_key().pub_key().to_bytes();

        // Act
        let pub_key = PubKey::from_bytes(bytes).unwrap();

        // Assert
        assert_eq!(pub_key.to_bytes(), bytes);
    }

    #[test]
    fn pub_key_from_bytes_rejects_invalid_point() {
        //! A prefix byte of `0x02`/`0x03` with an x-coordinate
        //! that isn't on the curve is not a valid SEC1 point.

        // Act
        let err = PubKey::from_bytes([0u8; 33]).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "invalid key: crypto error");
    }

    #[test]
    fn address_matches_known_vector() {
        // Act
        let address = known_priv_key().pub_key().address();

        // Assert
        assert_eq!(address.to_bech32(), KNOWN_ADDRESS);
    }

    #[test]
    fn sign_matches_known_vector() {
        // Act
        let sig = known_priv_key().sign_arbitrary(SIGN_MSG.as_bytes());

        // Assert
        assert_eq!(hex::encode(sig), SIGN_HEX);
    }

    #[test]
    fn sign_is_deterministic() {
        // Arrange
        let key = known_priv_key();

        // Act
        let first = key.sign_arbitrary(b"some message");
        let second = key.sign_arbitrary(b"some message");

        // Assert
        assert_eq!(first, second);
    }

    #[test]
    fn sign_prehashed_matches_sign() {
        //! The `sign_arbitrary` method is just SHA-256 followed by `sign_prehashed`

        // Arrange
        let key = known_priv_key();
        let digest = Sha256::digest(SIGN_MSG.as_bytes());

        // Act
        let via_sign = key.sign_arbitrary(SIGN_MSG.as_bytes());
        let via_prehashed = key.sign_prehashed(&digest.into());

        // Assert
        assert_eq!(via_sign, via_prehashed);
    }

    #[test]
    fn sign_round_trips_through_verify() {
        // Arrange
        let key = known_priv_key();

        // Act
        let sig = key.sign_arbitrary(b"round trip message");

        // Assert
        assert!(key.pub_key().verify(b"round trip message", &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        // Arrange
        let key = known_priv_key();
        let sig = key.sign_arbitrary(b"the real message");

        // Act / Assert
        assert!(!key.pub_key().verify(b"a different message", &sig));
    }

    #[test]
    fn verify_rejects_signature_from_different_key() {
        // Arrange
        let key = known_priv_key();
        let other_bytes: [u8; 32] =
            hex::decode("f8c948bd5551a44d403853db6e3fb68bf9099adb3557220de38cdea322a9bc48")
                .unwrap()
                .try_into()
                .unwrap();
        let other = PrivKey::from_bytes(other_bytes).unwrap();
        let sig = other.sign_arbitrary(b"shared message");

        // Act / Assert
        assert!(!key.pub_key().verify(b"shared message", &sig));
    }

    #[test]
    fn verify_rejects_high_s_signature() {
        //! The `verify` method must reject the BIP-62 "malleable" counterpart
        //! `(r, n - s)` of a valid low-S signature, not just outright garbage.

        // Arrange
        let key = known_priv_key();
        let low_s = key.sign_arbitrary(b"malleability check");
        let sig = Signature::from_slice(&low_s).unwrap();

        // Act
        let high_sig = Signature::from_scalars(sig.r(), -sig.s()).unwrap();
        let tampered: [u8; 64] = high_sig.to_bytes().into();

        // Assert
        assert!(!key.pub_key().verify(b"malleability check", &tampered));
    }

    #[test]
    fn sign_tx_is_not_implemented_yet() {
        //! `sign_tx` is a placeholder until Amino support lands (see `PLAN.md`, Phase B).
        //! It must fail loudly with a `Result`, not silently misbehave or panic.

        // Act
        let err = known_priv_key().sign_tx().unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "not implemented: transaction signing requires Amino support, not implemented yet"
        );
    }

    #[test]
    fn debug_does_not_leak_private_key_bytes() {
        // Act
        let debug_output = format!("{:?}", known_priv_key());

        // Assert
        assert_eq!(debug_output, "PrivKey()");
        assert!(!debug_output.contains(KNOWN_PRIV_HEX));
    }

    #[test]
    fn pubkey_debug_includes_hex() {
        // Act
        let debug_output = format!("{:?}", known_priv_key().pub_key());

        // Assert
        assert_eq!(debug_output, format!("PubKey({KNOWN_PUB_HEX})"));
    }

    #[test]
    fn pubkey_equality() {
        // Arrange
        let a = known_priv_key().pub_key();
        let b = known_priv_key().pub_key();
        let c = PrivKey::from_bytes([1u8; 32]).unwrap().pub_key();

        // Assert
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
