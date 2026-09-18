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

// Upper bounds for parameters read back out of a blob. Argon2's own maximums
// are `u32::MAX`, so without these a blob could ask for a lot of memory.
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 10;
const MAX_P_COST: u32 = 4;

/// Argon2id cost parameters, stored with the data they derived a key for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

/// A passphrase-encrypted secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    kdf: KdfParams,

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

    let kdf = KdfParams {
        m_cost: ARGON2_M_COST_KIB,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
    };
    let salt = random_bytes::<16>()?;
    let nonce = random_bytes::<24>()?;
    let key = derive_key(passphrase, &salt, kdf)?;
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::KeystoreFormat("aead encrypt failed".into()))?;

    Ok(EncryptedBlob {
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt `blob`.
/// Return [`Error::Decrypt`] on a wrong passphrase or tampered ciphertext.
pub(crate) fn decrypt(blob: &EncryptedBlob, passphrase: &str) -> Result<Vec<u8>> {
    let key = derive_key(passphrase, &blob.salt, blob.kdf)?;
    XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .decrypt(XNonce::from_slice(&blob.nonce), blob.ciphertext.as_slice())
        .map_err(|_| Error::Decrypt)
}

fn derive_key(passphrase: &str, salt: &[u8; 16], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    // When decrypting these come from the file, so they're untrusted,
    // cap them before anything is allocated.
    if kdf.m_cost > MAX_M_COST_KIB || kdf.t_cost > MAX_T_COST || kdf.p_cost > MAX_P_COST {
        return Err(Error::KeystoreFormat(format!(
            "kdf parameters out of range: {kdf:?}"
        )));
    }

    // Rejects values below argon2's own minimums, so it can't panic here
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| Error::KeystoreFormat(format!("invalid kdf parameters: {e}")))?;

    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|e| Error::KeystoreFormat(format!("key derivation failed: {e}")))?;

    Ok(key)
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
    fn decrypt_derives_from_the_blob_parameters() {
        //! Changing a stored parameter must change the derived key. If decrypt
        //! still used the constants this would succeed, and the whole point of
        //! recording the parameters would be lost.

        // Arrange
        let mut blob = encrypt(b"secret", "correct phrase").unwrap();
        blob.kdf.t_cost -= 1;

        // Act
        let err = decrypt(&blob, "correct phrase").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
    }

    #[test]
    fn decrypt_rejects_parameters_outside_the_allowed_range() {
        // Arrange
        let mut blob = encrypt(b"secret", "correct phrase").unwrap();

        // Act / Assert
        blob.kdf.m_cost = u32::MAX;
        let err = decrypt(&blob, "correct phrase").unwrap_err();
        assert!(err.to_string().contains("kdf parameters out of range"));

        blob.kdf.m_cost = ARGON2_M_COST_KIB;
        blob.kdf.t_cost = 0;
        let err = decrypt(&blob, "correct phrase").unwrap_err();
        assert!(err.to_string().contains("invalid kdf parameters"));
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
