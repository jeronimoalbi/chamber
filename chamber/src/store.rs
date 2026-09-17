#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

#[cfg(not(target_arch = "wasm32"))]
use crate::backend::FsBackend;
use crate::backend::MemoryBackend;
use crate::backend::{Backend, Record};
use crate::cipher;
use crate::error::{Error, Result};
use crate::hdpath::Bip44Path;
use crate::key::PrivKey;
use crate::mnemonic::Mnemonic;

/// Maximum length allowed for a key name.
const MAX_KEY_NAME_LEN: usize = 64;

/// A key/value-backed keystore.
pub struct Store {
    backend: Box<dyn Backend>,
}

impl Store {
    /// Create a new store that uses a custom data storage backend.
    pub fn new(backend: impl Backend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }

    /// Create a new in-memory store.
    pub fn new_in_memory() -> Self {
        Self::new(MemoryBackend::new())
    }

    /// Add a key derived from `mnemonic` at `path`.
    /// Only the derived 32-byte private key is encrypted under `passphrase`
    /// and persisted, the mnemonic itself is used just long enough to derive
    /// the key and is never written to disk.
    pub fn add(
        &mut self,
        name: &str,
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: Bip44Path,
    ) -> Result<Record> {
        ensure_valid_key_name(name)?;

        let key = PrivKey::from_mnemonic(mnemonic, path)?;
        let blob = cipher::encrypt(&key.to_bytes(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pubkey_b64: B64.encode(key.pub_key().to_bytes()),
            path: Some(path),
            privkey_encrypted: blob,
        };
        self.backend.insert(record.clone())?;
        Ok(record)
    }

    /// Add a key from a raw private key, encrypting the 32 bytes under `passphrase`.
    /// Derivation path is not saved in the store.
    pub fn add_privkey(&mut self, name: &str, key: &PrivKey, passphrase: &str) -> Result<Record> {
        ensure_valid_key_name(name)?;

        let blob = cipher::encrypt(&key.to_bytes(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pubkey_b64: B64.encode(key.pub_key().to_bytes()),
            path: None,
            privkey_encrypted: blob,
        };
        self.backend.insert(record.clone())?;
        Ok(record)
    }

    /// List every key in the store, sorted by name.
    pub fn list(&self) -> Result<Vec<Record>> {
        let mut entries = self.backend.list()?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Read a key record by local name.
    pub fn get_by_name(&self, name: &str) -> Result<Record> {
        ensure_valid_key_name(name)?;

        self.backend
            .get(name)?
            .ok_or_else(|| Error::NotFound(name.to_string()))
    }

    /// Read a key record by bech32 address.
    pub fn get_by_address(&self, address: &str) -> Result<Record> {
        self.backend
            .list()?
            .into_iter()
            .find(|r| r.address == address)
            .ok_or_else(|| Error::NotFound(address.to_string()))
    }

    /// Decrypt a key and return a [`PrivKey`].
    pub fn unlock(&self, name: &str, passphrase: &str) -> Result<PrivKey> {
        let record = self.get_by_name(name)?;
        let plain = Zeroizing::new(cipher::decrypt(&record.privkey_encrypted, passphrase)?);
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| Error::KeystoreFormat("privkey blob must be 32 bytes".into()))?;
        PrivKey::from_bytes(bytes)
    }

    /// Re-encrypt a key's secret under a new passphrase.
    /// The stored plaintext is unchanged.
    pub fn rotate(&mut self, name: &str, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        ensure_valid_key_name(name)?;

        let mut record = self.get_by_name(name)?;
        let plain = Zeroizing::new(cipher::decrypt(&record.privkey_encrypted, old_passphrase)?);
        record.privkey_encrypted = cipher::encrypt(&plain, new_passphrase)?;
        self.backend.update(record)
    }

    /// Delete a key record.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        ensure_valid_key_name(name)?;
        self.backend.remove(name)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Store {
    /// Open a directory-backed store rooted at `dir`, creating it if needed.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(FsBackend::open(dir)?))
    }
}

fn ensure_valid_key_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_KEY_NAME_LEN {
        return Err(Error::InvalidName(format!(
            "name must not be empty and have a max of {MAX_KEY_NAME_LEN} characters, got {}",
            name.len()
        )));
    }

    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::InvalidName(format!(
            "name {name:?} may only contain ASCII letters, digits, '_' and '-'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> PrivKey {
        PrivKey::from_bytes([7u8; 32]).unwrap()
    }

    fn test_mnemonic() -> Mnemonic {
        Mnemonic::generate().unwrap()
    }

    #[test]
    fn add_populates_record_with_derivation_path() {
        // Arrange
        let mut store = Store::new_in_memory();
        let path = Bip44Path::new(3, 2);

        // Act
        let record = store.add("alice", &test_mnemonic(), "pass", path).unwrap();

        // Assert
        assert_eq!(record.name, "alice");
        assert_eq!(record.path, Some(path));
        assert!(record.address.starts_with("g1"));
        assert_eq!(B64.decode(&record.pubkey_b64).unwrap().len(), 33);
    }

    #[test]
    fn add_rejects_duplicate_name() {
        // Arrange
        let mut store = Store::new_in_memory();
        let m = test_mnemonic();
        store.add("dup", &m, "pass", Bip44Path::default()).unwrap();

        // Act
        let err = store
            .add("dup", &m, "pass", Bip44Path::default())
            .unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: dup");
    }

    #[test]
    fn add_rejects_name_with_path_traversal_characters() {
        //! Names never reach a backend's storage path directly, but the
        //! charset is still restricted as basic data hygiene.

        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let err = store
            .add("../escape", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "invalid key name: name \"../escape\" may only contain ASCII letters, \
             digits, '_' and '-'"
        );
    }

    #[test]
    fn add_rejects_empty_name() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let err = store
            .add("", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "invalid key name: name must not be empty and have a max of 64 characters, got 0"
        );
    }

    #[test]
    fn add_rejects_overlong_name() {
        // Arrange
        let mut store = Store::new_in_memory();
        let name = "a".repeat(65);

        // Act
        let err = store
            .add(&name, &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "invalid key name: name must not be empty and have a max of 64 characters, got 65"
        );
    }

    #[test]
    fn get_by_name_rejects_invalid_name() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store.get_by_name("../etc/passwd").unwrap_err();

        // Assert
        assert!(err.to_string().starts_with("invalid key name:"));
    }

    #[test]
    fn delete_rejects_invalid_name() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let err = store.delete("../etc/passwd").unwrap_err();

        // Assert
        assert!(err.to_string().starts_with("invalid key name:"));
    }

    #[test]
    fn valid_names_allow_letters_digits_underscore_and_dash() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act / Assert
        store
            .add_privkey("Alice_Key-2", &test_key(), "pass")
            .unwrap();
    }

    #[test]
    fn add_privkey_records_no_derivation_path() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let record = store.add_privkey("raw", &test_key(), "pass").unwrap();

        // Assert
        assert!(record.path.is_none());
    }

    #[test]
    fn add_privkey_rejects_duplicate_name() {
        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("dup", &test_key(), "pass").unwrap();

        // Act
        let err = store.add_privkey("dup", &test_key(), "pass").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: dup");
    }

    #[test]
    fn list_on_empty_store_is_empty() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let entries = store.list().unwrap();

        // Assert
        assert!(entries.is_empty());
    }

    #[test]
    fn list_returns_entries_sorted_by_name() {
        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("zeta", &test_key(), "pass").unwrap();
        store
            .add_privkey("alpha", &PrivKey::from_bytes([9u8; 32]).unwrap(), "pass")
            .unwrap();

        // Act
        let entries = store.list().unwrap();

        // Assert
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn get_by_name_not_found() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store.get_by_name("ghost").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn get_by_address_not_found() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store.get_by_address("g1doesnotexist").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: g1doesnotexist");
    }

    #[test]
    fn unlock_wrong_passphrase_fails() {
        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("main", &test_key(), "right").unwrap();

        // Act
        let err = store.unlock("main", "wrong").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
    }

    #[test]
    fn rotate_changes_passphrase() {
        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("main", &test_key(), "old").unwrap();

        // Act
        store.rotate("main", "old", "new").unwrap();

        // Assert
        assert!(store.unlock("main", "old").is_err());
        assert_eq!(
            store.unlock("main", "new").unwrap().to_bytes(),
            test_key().to_bytes()
        );
    }

    #[test]
    fn rotate_wrong_old_passphrase_leaves_record_untouched() {
        //! A failed rotate (wrong old passphrase) must not corrupt or
        //! replace the stored record, the key must still unlock under
        //! its original passphrase afterward.

        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("main", &test_key(), "old").unwrap();

        // Act
        let err = store.rotate("main", "wrong", "new").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
        assert_eq!(
            store.unlock("main", "old").unwrap().to_bytes(),
            test_key().to_bytes()
        );
    }

    #[test]
    fn rotate_not_found() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let err = store.rotate("ghost", "old", "new").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn delete_removes_record() {
        // Arrange
        let mut store = Store::new_in_memory();
        store.add_privkey("main", &test_key(), "pass").unwrap();

        // Act
        store.delete("main").unwrap();

        // Assert
        assert!(store.get_by_name("main").is_err());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn delete_not_found() {
        // Arrange
        let mut store = Store::new_in_memory();

        // Act
        let err = store.delete("ghost").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }
}
