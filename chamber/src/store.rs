#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::Backend;
#[cfg(not(target_arch = "wasm32"))]
use crate::backend::FsBackend;
use crate::backend::MemoryBackend;
use crate::cipher::{self, EncryptedBlob};
use crate::error::{Error, Result};
use crate::hdpath::Bip44Path;
use crate::key::PrivKey;
use crate::mnemonic::Mnemonic;

/// Backend key under which the regenerable index cache is stored.
const INDEX_KEY: &str = "index";

/// Maximum length allowed for a key name.
const MAX_KEY_NAME_LEN: usize = 64;

/// Record contains data of a single key.
/// It's usually stored as a single `<name>.json` file.
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

/// Single entry (row) for the `index.json`.
/// Used for fast list/lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Local name of the key.
    pub name: String,

    /// Bech32 address.
    pub address: String,

    /// Compressed public key as base64.
    pub pubkey_b64: String,
}

impl From<&Record> for IndexEntry {
    fn from(r: &Record) -> Self {
        Self {
            name: r.name.clone(),
            address: r.address.clone(),
            pubkey_b64: r.pubkey_b64.clone(),
        }
    }
}

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
        &self,
        name: &str,
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: Bip44Path,
    ) -> Result<Record> {
        ensure_valid_key_name(name)?;
        self.ensure_key_absent(name)?;

        let key = PrivKey::from_mnemonic(mnemonic, path)?;
        let blob = cipher::encrypt(&key.to_bytes(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pubkey_b64: B64.encode(key.pub_key().to_bytes()),
            path: Some(path),
            privkey_encrypted: blob,
        };
        self.write_record(&record)?;
        self.rebuild_index()?;
        Ok(record)
    }

    /// Add a key from a raw private key, encrypting the 32 bytes under `passphrase`.
    /// Derivation path is not saved in the store.
    pub fn add_privkey(&self, name: &str, key: &PrivKey, passphrase: &str) -> Result<Record> {
        ensure_valid_key_name(name)?;
        self.ensure_key_absent(name)?;

        let blob = cipher::encrypt(&key.to_bytes(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pubkey_b64: B64.encode(key.pub_key().to_bytes()),
            path: None,
            privkey_encrypted: blob,
        };
        self.write_record(&record)?;
        self.rebuild_index()?;
        Ok(record)
    }

    /// List keys from the `index` cache entry.
    /// Rebuilds it from every key record if it's missing before returning.
    pub fn list(&self) -> Result<Vec<IndexEntry>> {
        match self.backend.get(INDEX_KEY)? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => self.rebuild_index(),
        }
    }

    /// Rebuild the `index` cache entry from every key record and return the entries.
    pub fn rebuild_index(&self) -> Result<Vec<IndexEntry>> {
        let mut entries: Vec<IndexEntry> = self.records()?.iter().map(IndexEntry::from).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let json = serde_json::to_vec_pretty(&entries)?;
        self.backend.set(INDEX_KEY, &json)?;
        Ok(entries)
    }

    /// Read a key record by local name.
    pub fn get_by_name(&self, name: &str) -> Result<Record> {
        ensure_valid_key_name(name)?;

        let bytes = self
            .backend
            .get(name)?
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Read a key record by bech32 address.
    pub fn get_by_address(&self, address: &str) -> Result<Record> {
        self.records()?
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
    pub fn rotate(&self, name: &str, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let mut record = self.get_by_name(name)?;
        let plain = Zeroizing::new(cipher::decrypt(&record.privkey_encrypted, old_passphrase)?);
        record.privkey_encrypted = cipher::encrypt(&plain, new_passphrase)?;
        self.write_record(&record)?;
        Ok(())
    }

    /// Delete a key record and refresh the index.
    pub fn delete(&self, name: &str) -> Result<()> {
        ensure_valid_key_name(name)?;

        if !self.backend.exists(name)? {
            return Err(Error::NotFound(name.to_string()));
        }

        self.backend.remove(name)?;
        self.rebuild_index()?;
        Ok(())
    }

    fn ensure_key_absent(&self, name: &str) -> Result<()> {
        if self.backend.exists(name)? {
            return Err(Error::AlreadyExists(name.to_string()));
        }
        Ok(())
    }

    fn write_record(&self, record: &Record) -> Result<()> {
        let json = serde_json::to_vec_pretty(record)?;
        self.backend.set(&record.name, &json)
    }

    fn records(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for key in self.backend.keys()? {
            if key == INDEX_KEY {
                continue;
            }

            let bytes = self
                .backend
                .get(&key)?
                .ok_or_else(|| Error::Backend(format!("{key}: listed but not found")))?;
            match serde_json::from_slice::<Record>(&bytes) {
                Ok(record) => out.push(record),
                Err(e) => return Err(Error::KeystoreFormat(format!("{key}: {e}"))),
            }
        }
        Ok(out)
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

    if name == INDEX_KEY {
        return Err(Error::InvalidName(format!("{name:?} is a reserved name")));
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
        let store = Store::new_in_memory();
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
        let store = Store::new_in_memory();
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
    fn add_rejects_reserved_index_name() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store
            .add("index", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "invalid key name: \"index\" is a reserved name"
        );
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn add_privkey_rejects_reserved_index_name() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store.add_privkey("index", &test_key(), "pass").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "invalid key name: \"index\" is a reserved name"
        );
    }

    #[test]
    fn add_rejects_name_with_path_traversal_characters() {
        // Arrange
        let store = Store::new_in_memory();

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
        let store = Store::new_in_memory();

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
        let store = Store::new_in_memory();
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
        let store = Store::new_in_memory();

        // Act
        let err = store.delete("../etc/passwd").unwrap_err();

        // Assert
        assert!(err.to_string().starts_with("invalid key name:"));
    }

    #[test]
    fn valid_names_allow_letters_digits_underscore_and_dash() {
        // Arrange
        let store = Store::new_in_memory();

        // Act / Assert
        store
            .add_privkey("Alice_Key-2", &test_key(), "pass")
            .unwrap();
    }

    #[test]
    fn add_privkey_records_no_derivation_path() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let record = store.add_privkey("raw", &test_key(), "pass").unwrap();

        // Assert
        assert!(record.path.is_none());
    }

    #[test]
    fn add_privkey_rejects_duplicate_name() {
        // Arrange
        let store = Store::new_in_memory();
        store.add_privkey("dup", &test_key(), "pass").unwrap();

        // Act
        let err = store.add_privkey("dup", &test_key(), "pass").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: dup");
    }

    #[test]
    fn ensure_key_absent_ok_when_name_unused() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let result = store.ensure_key_absent("nobody");

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_key_absent_rejects_existing_key_file() {
        // Arrange
        let store = Store::new_in_memory();
        store.backend.set("alice", b"value").unwrap();

        // Act
        let err = store.ensure_key_absent("alice").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: alice");
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
    fn list_rebuilds_index_when_missing() {
        // Arrange
        let store = Store::new_in_memory();
        store
            .add("main", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap();
        store.backend.remove(INDEX_KEY).unwrap();

        // Act
        let entries = store.list().unwrap();

        // Assert
        assert!(store.backend.exists(INDEX_KEY).unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "main");
    }

    #[test]
    fn rebuild_index_sorts_entries_by_name() {
        // Arrange
        let store = Store::new_in_memory();
        store.add_privkey("zeta", &test_key(), "pass").unwrap();
        store
            .add_privkey("alpha", &PrivKey::from_bytes([9u8; 32]).unwrap(), "pass")
            .unwrap();

        // Act
        let entries = store.rebuild_index().unwrap();

        // Assert
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    #[should_panic(expected = "KeystoreFormat")]
    fn records_rejects_corrupt_json_file() {
        // Arrange
        let store = Store::new_in_memory();
        store.backend.set("broken", b"{ not json").unwrap();

        // Act
        store.records().unwrap();
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
        let store = Store::new_in_memory();
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
        let store = Store::new_in_memory();
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
    fn rotate_not_found() {
        // Arrange
        let store = Store::new_in_memory();

        // Act
        let err = store.rotate("ghost", "old", "new").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn delete_removes_record_and_rebuilds_index() {
        // Arrange
        let store = Store::new_in_memory();
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
        let store = Store::new_in_memory();

        // Act
        let err = store.delete("ghost").unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }
}
