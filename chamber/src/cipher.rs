//! Passphrase-based encryption: Argon2id key derivation + XChaCha20-Poly1305.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const ARGON2_M_COST_KIB: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

/// A passphrase-encrypted secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    #[serde(with = "b64")]
    salt: [u8; 16],

    #[serde(with = "b64")]
    nonce: [u8; 24],

    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` under `passphrase`.
pub(crate) fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<EncryptedBlob> {
    if passphrase.is_empty() {
        return Err(Error::EmptyPassphrase);
    }

    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<24>()?;
    let key = derive_key(passphrase, &salt);
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::KeystoreFormat("aead encrypt failed".into()))?;

    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt `blob`.
/// Return [`Error::Decrypt`] on a wrong passphrase or tampered ciphertext.
pub(crate) fn decrypt(blob: &EncryptedBlob, passphrase: &str) -> Result<Vec<u8>> {
    let key = derive_key(passphrase, &blob.salt);
    XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .decrypt(XNonce::from_slice(&blob.nonce), blob.ciphertext.as_slice())
        .map_err(|_| Error::Decrypt)
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32)).unwrap();
    let mut key = Zeroizing::new([0u8; 32]);

    // The 16-byte salt and 32-byte output are within argon2 limits
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .unwrap();

    key
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Key(format!("csprng unavailable: {e}")))?;
    Ok(b)
}

mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(bytes: impl AsRef<[u8]>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: TryFrom<Vec<u8>>,
    {
        let bytes = STANDARD
            .decode(String::deserialize(d)?)
            .map_err(de::Error::custom)?;
        let len = bytes.len();
        T::try_from(bytes).map_err(|_| de::Error::custom(format!("unexpected length {len}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        // Arrange
        let secret = b"This is a secret";
        let blob = encrypt(secret, "correct phrase").unwrap();

        // Act
        let plain = decrypt(&blob, "correct phrase").unwrap();

        // Assert
        assert_eq!(plain, secret);
    }

    #[test]
    fn decrypt_with_wrong_passphrase_fails() {
        // Arrange
        let blob = encrypt(b"secret", "correct phrase").unwrap();

        // Act
        let err = decrypt(&blob, "wrong phrase").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
    }

    #[test]
    fn encrypt_rejects_empty_passphrase() {
        // Act
        let err = encrypt(b"secret", "").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "passphrase must not be empty");
    }

    #[test]
    fn encrypt_uses_fresh_salt_and_nonce() {
        // Act
        let a = encrypt(b"secret", "correct horse").unwrap();
        let b = encrypt(b"secret", "correct horse").unwrap();

        // Assert
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
    }
}
