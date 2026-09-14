use hmac::{Hmac, Mac};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, Scalar, SecretKey, U256};
use sha2::Sha512;

use crate::error::{Error, Result};

/// SLIP-0044 coin type used by Gno.land.
pub const COIN_TYPE: u32 = 118;

type HmacSha512 = Hmac<Sha512>;

/// A BIP44 derivation path of the shape Gno.land uses:
/// `44' / 118' / account' / 0 / index`.
///
/// Path elements are fixed, except `account` and `index` that vary.
/// String representation has no leading "m/".
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip44Path {
    /// The `account'` level (hardened).
    pub account: u32,

    /// The `index` level (address index, non-hardened).
    pub index: u32,
}

impl Bip44Path {
    /// Construct a path with the given account and address index.
    pub fn new(account: u32, index: u32) -> Self {
        Self { account, index }
    }
}

impl std::fmt::Display for Bip44Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "44'/{}'/{}'/0/{}", COIN_TYPE, self.account, self.index)
    }
}

/// Split a HMAC-SHA512 of data keyed with `key` into BIP32's IL and IR halves.
fn split_hmac_sha512(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    // NOTE: HMAC accepts keys with any size for new_from_slice()
    let mut mac = HmacSha512::new_from_slice(key).unwrap();
    mac.update(data);

    let out = mac.finalize().into_bytes();
    let mut il = [0u8; 32];
    let mut ir = [0u8; 32];
    il.copy_from_slice(&out[..32]);
    ir.copy_from_slice(&out[32..]);
    (il, ir)
}

/// Return the master private key and chain code for a BIP39 seed.
pub fn master_from_seed(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    split_hmac_sha512(b"Bitcoin seed", seed)
}

fn scalar_from_bigendian(bytes: &[u8; 32]) -> Scalar {
    let fb = FieldBytes::from_slice(bytes);
    <Scalar as Reduce<U256>>::reduce_bytes(fb)
}

fn derive_child(
    priv_key: &[u8; 32],
    chain_code: &[u8; 32],
    index: u32,
    harden: bool,
) -> ([u8; 32], [u8; 32]) {
    let mut data: Vec<u8> = Vec::with_capacity(37);
    let idx = if harden { index | 0x8000_0000 } else { index };

    if harden {
        data.push(0x00);
        data.extend_from_slice(priv_key);
    } else {
        // Non-hardened: use the compressed public key of the parent.
        // Parent private key is always a valid secp256k1 scalar.
        let pk = SecretKey::from_slice(priv_key).unwrap();
        let public_key = pk.public_key().to_encoded_point(true);
        data.extend_from_slice(public_key.as_bytes());
    }

    data.extend_from_slice(&idx.to_be_bytes());

    let (il, chain_code2) = split_hmac_sha512(chain_code, &data);

    // No "next index" retry, strict BIP32 says that if the HMAC left-half is
    // `>= n`, or the resulting child scalar is zero, you must skip to the next
    // index, Go.land does neither, it just computes `(parent + IL) mod n`, done
    // here via k256's Scalar arithmetic.
    let child = scalar_from_bigendian(priv_key) + scalar_from_bigendian(&il);
    let child_bytes: [u8; 32] = child.to_bytes().into();

    (child_bytes, chain_code2)
}

/// Follow a slash-separated BIP32 path (elements optionally suffixed with `'` for
/// hardening) from `master_priv` / `chain_code`, returning the leaf private key.
pub fn derive_private_key_for_path(
    master_priv: &[u8; 32],
    chain_code: &[u8; 32],
    path: &str,
) -> Result<[u8; 32]> {
    let mut key = *master_priv;
    let mut chain_code = *chain_code;

    for part in path.split('/') {
        if part.is_empty() {
            return Err(Error::Path(format!("empty path element in {path:?}")));
        }

        let (num, harden) = match part.strip_suffix('\'') {
            Some(n) => (n, true),
            None => (part, false),
        };
        let idx: u32 = num
            .parse()
            .map_err(|_| Error::Path(format!("invalid BIP32 path element {part:?}")))?;
        let (k, c) = derive_child(&key, &chain_code, idx, harden);
        key = k;
        chain_code = c;
    }

    Ok(key)
}

/// Derive the leaf private key for a path directly from a BIP39 seed.
pub fn derive_bip44(seed: &[u8], path: Bip44Path) -> Result<[u8; 32]> {
    let (master, chain_code) = master_from_seed(seed);
    derive_private_key_for_path(&master, &chain_code, &path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Seed for the official BIP39 English zero-entropy 24-word mnemonic
    // ("abandon"... "art") with empty passphrase.
    const SEED_HEX: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf\
        705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";

    // Derived from SEED_HEX (account, index, expected priv key hex)
    const KNOWN_VECTORS: &[(u32, u32, &str)] = &[
        (
            0,
            0,
            "8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7",
        ),
        (
            0,
            1,
            "f8c948bd5551a44d403853db6e3fb68bf9099adb3557220de38cdea322a9bc48",
        ),
        (
            1,
            0,
            "19d03936e7933e2a19103f0f1b34e9bd7f7060f597a614721624c5fce64d01c1",
        ),
        (
            5,
            7,
            "562355942ce3850c571a9b9fd15a0211485d3802ad445fc1b0aa72309d2da7c1",
        ),
    ];

    #[test]
    fn coin_type_is_118() {
        // Assert
        assert_eq!(COIN_TYPE, 118);
    }

    #[test]
    fn new_sets_account_and_index() {
        // Act
        let path = Bip44Path::new(5, 7);

        // Assert
        assert_eq!(path.account, 5);
        assert_eq!(path.index, 7);
    }

    #[test]
    fn default_is_account_zero_index_zero() {
        // Act
        let path = Bip44Path::default();

        // Assert
        assert_eq!(path, Bip44Path::new(0, 0));
    }

    #[test]
    fn display_formats_bip44_path() {
        // Act
        let formatted = Bip44Path::new(5, 7).to_string();

        // Assert
        assert_eq!(formatted, "44'/118'/5'/0/7");
        assert!(!formatted.starts_with('m'));
    }

    #[test]
    fn master_from_seed_is_deterministic() {
        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();

        // Act
        let first = master_from_seed(&seed);
        let second = master_from_seed(&seed);

        // Assert
        assert_eq!(first, second);
    }

    #[test]
    fn master_from_seed_differs_for_different_seeds() {
        // Arrange
        let seed_a = hex::decode(SEED_HEX).unwrap();
        let seed_b = [0u8; 64];

        // Act
        let (priv_a, chain_a) = master_from_seed(&seed_a);
        let (priv_b, chain_b) = master_from_seed(&seed_b);

        // Assert
        assert_ne!(priv_a, priv_b);
        assert_ne!(chain_a, chain_b);
    }

    #[test]
    fn derive_bip44_matches_known_vectors() {
        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();

        for (account, index, priv_hex) in KNOWN_VECTORS {
            // Act
            let path = Bip44Path::new(*account, *index);
            let raw = derive_bip44(&seed, path).unwrap();

            // Assert
            assert_eq!(hex::encode(raw), *priv_hex, "path {path}");
        }
    }

    #[test]
    fn derive_private_key_for_path_is_deterministic() {
        //! Deriving the same path twice from the same master key
        //! and chain code must produce byte-identical results.

        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();
        let (master, chain_code) = master_from_seed(&seed);

        // Act
        let first = derive_private_key_for_path(&master, &chain_code, "44'/118'/0'/0/0").unwrap();
        let second = derive_private_key_for_path(&master, &chain_code, "44'/118'/0'/0/0").unwrap();

        // Assert
        assert_eq!(first, second);
    }

    #[test]
    fn derive_private_key_for_path_hardened_and_nonhardened_differ() {
        //! The same numeric index derives to a different child key depending
        //! on whether it is hardened (`'` suffix), since hardened derivation
        //! hashes the parent private key while non-hardened derivation
        //! hashes the parent public key.

        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();
        let (master, chain_code) = master_from_seed(&seed);

        // Act
        let hardened = derive_private_key_for_path(&master, &chain_code, "0'").unwrap();
        let non_hardened = derive_private_key_for_path(&master, &chain_code, "0").unwrap();

        // Assert
        assert_ne!(hardened, non_hardened);
    }

    #[test]
    #[should_panic(expected = "empty path element")]
    fn derive_private_key_for_path_rejects_empty_element() {
        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();
        let (master, chain_code) = master_from_seed(&seed);

        // Act
        derive_private_key_for_path(&master, &chain_code, "44'//0").unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid BIP32 path element")]
    fn derive_private_key_for_path_rejects_non_numeric_element() {
        // Arrange
        let seed = hex::decode(SEED_HEX).unwrap();
        let (master, chain_code) = master_from_seed(&seed);

        // Act
        derive_private_key_for_path(&master, &chain_code, "abc'").unwrap();
    }
}
