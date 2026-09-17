//! Storage backends for [`crate::store::Store`].

#[cfg(not(target_arch = "wasm32"))]
mod fs;
mod memory;

#[cfg(not(target_arch = "wasm32"))]
pub use fs::FsBackend;
pub use memory::MemoryBackend;

use serde::{Deserialize, Serialize};

use crate::cipher::EncryptedBlob;
use crate::error::Result;
use crate::hdpath::Bip44Path;

/// Record contains data of a single key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Local name of the key.
    pub name: String,

    /// Bech32 address.
    pub address: String,

    /// Compressed public key as base64.
    pub pubkey_b64: String,

    /// Derivation path used, when this key was added from a mnemonic,
    /// or `None` when key was added from raw bytes.
    pub path: Option<Bip44Path>,

    /// Encrypted (Argon2id + XChaCha20-Poly1305) private key.
    /// Encrypts the raw 32-byte private key.
    pub privkey_encrypted: EncryptedBlob,
}

/// Persists [`Record`]s for a [`crate::store::Store`].
pub trait Backend: Send {
    /// Insert a record.
    fn insert(&mut self, record: Record) -> Result<()>;

    /// Replace a record.
    fn update(&mut self, record: Record) -> Result<()>;

    /// Look up a record by name.
    fn get(&self, name: &str) -> Result<Option<Record>>;

    /// Remove a record.
    fn remove(&mut self, name: &str) -> Result<()>;

    /// return every stored record, in unspecified order.
    fn list(&self) -> Result<Vec<Record>>;
}

/// Common test helpers used within this crate.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    use crate::cipher;
    use crate::key::PrivKey;

    /// Build a valid [`Record`] named `name`, for tests that only care
    /// about a record's identity/shape, not its cryptographic content.
    pub(crate) fn record(name: &str) -> Record {
        let key = PrivKey::from_bytes([7u8; 32]).unwrap();
        let blob = cipher::encrypt(&key.to_bytes(), "pass").unwrap();
        Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pubkey_b64: B64.encode(key.pub_key().to_bytes()),
            path: None,
            privkey_encrypted: blob,
        }
    }
}
