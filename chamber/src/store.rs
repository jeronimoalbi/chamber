#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

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
use crate::tx::{AnyPubKey, MultisigPubKey};

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
        let blob = cipher::encrypt(key.to_bytes().as_slice(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pub_key: key.pub_key().into(),
            path: Some(path),
            privkey_encrypted: Some(blob),
        };
        self.backend.insert(record.clone())?;
        Ok(record)
    }

    /// Add a key from a raw private key, encrypting the 32 bytes under `passphrase`.
    /// Derivation path is not saved in the store.
    pub fn add_privkey(&mut self, name: &str, key: &PrivKey, passphrase: &str) -> Result<Record> {
        ensure_valid_key_name(name)?;

        let blob = cipher::encrypt(key.to_bytes().as_slice(), passphrase)?;
        let record = Record {
            name: name.to_string(),
            address: key.pub_key().address().to_bech32(),
            pub_key: key.pub_key().into(),
            path: None,
            privkey_encrypted: Some(blob),
        };
        self.backend.insert(record.clone())?;
        Ok(record)
    }

    /// Add a k-of-n multisig key over keys already in the store, like
    /// `gnokey add --multisig`. With `sort`, members are ordered by address
    /// (gnokey's default); every party must build the key the same way to
    /// get the same address. Only public keys are stored, so the result
    /// can't sign by itself: members sign and `Tx::multisign` combines.
    pub fn add_multisig(
        &mut self,
        name: &str,
        threshold: u64,
        member_names: &[&str],
        sort: bool,
    ) -> Result<Record> {
        ensure_valid_key_name(name)?;

        let members = member_names
            .iter()
            .map(|member| self.get_by_name(member).map(|r| r.pub_key))
            .collect::<Result<Vec<_>>>()?;
        let pub_key = AnyPubKey::Multisig(MultisigPubKey::new(threshold, members, sort)?);
        let record = Record {
            name: name.to_string(),
            address: pub_key.address().to_bech32(),
            pub_key,
            path: None,
            privkey_encrypted: None,
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
        decrypt_and_verify(&record, passphrase)
    }

    /// Re-encrypt a key's secret under a new passphrase.
    pub fn rotate(&mut self, name: &str, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        ensure_valid_key_name(name)?;

        let mut record = self.get_by_name(name)?;
        let key = decrypt_and_verify(&record, old_passphrase)?;
        record.privkey_encrypted =
            Some(cipher::encrypt(key.to_bytes().as_slice(), new_passphrase)?);
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

pub(crate) fn decrypt_and_verify(record: &Record, passphrase: &str) -> Result<PrivKey> {
    let blob = record
        .privkey_encrypted
        .as_ref()
        .ok_or_else(|| Error::NoPrivateKey(record.name.clone()))?;

    // Decrypt
    let plain = Zeroizing::new(cipher::decrypt(blob, passphrase)?);
    let bytes: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::KeystoreFormat("privkey blob must be 32 bytes".into()))?;
    let key = PrivKey::from_bytes(bytes)?;

    // Verify that public key and address are right
    let pub_key = key.pub_key();
    let address = pub_key.address().to_bech32();
    if record.pub_key != pub_key || address != record.address {
        return Err(Error::Tampered(format!(
            "record {:?} claims pubkey {} / address {}, but the decrypted key is {} / {}",
            record.name, record.pub_key, record.address, pub_key, address
        )));
    }

    Ok(key)
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
        assert!(matches!(record.pub_key, AnyPubKey::Secp256k1(_)));
        assert!(record.has_private_key());
    }

    #[test]
    fn add_multisig_builds_a_sorted_key_over_stored_members() {
        // Arrange
        let mut store = Store::new_in_memory();
        let m = test_mnemonic();
        let a = store.add("a", &m, "pass", Bip44Path::new(0, 0)).unwrap();
        let b = store.add("b", &m, "pass", Bip44Path::new(0, 1)).unwrap();
        let c = store.add("c", &m, "pass", Bip44Path::new(1, 0)).unwrap();

        // Act
        let record = store
            .add_multisig("team", 2, &["c", "a", "b"], true)
            .unwrap();

        // Assert
        let AnyPubKey::Multisig(key) = &record.pub_key else {
            panic!("expected a multisig key")
        };
        let mut expected = vec![a.pub_key, b.pub_key, c.pub_key];
        expected.sort_by_key(|k| k.address().to_bytes());
        assert_eq!(key.threshold, 2);
        assert_eq!(key.pubkeys, expected);
        assert_eq!(record.address, record.pub_key.address().to_bech32());
        assert!(!record.has_private_key());
        assert_eq!(store.get_by_name("team").unwrap().address, record.address);
        assert_eq!(store.list().unwrap().len(), 4);
    }

    #[test]
    fn add_multisig_rejects_unknown_members_and_bad_thresholds() {
        // Arrange
        let mut store = Store::new_in_memory();
        store
            .add("a", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap();

        // Assert
        let err = store
            .add_multisig("team", 1, &["a", "ghost"], true)
            .unwrap_err();
        assert_eq!(err.to_string(), "key not found: ghost");
        let err = store.add_multisig("team", 2, &["a"], true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid key: threshold k of n multisignature: 1 < 2"
        );
        assert!(store.get_by_name("team").is_err());
    }

    #[test]
    fn multisig_keys_cannot_be_unlocked_or_rotated() {
        // Arrange
        let mut store = Store::new_in_memory();
        store
            .add("a", &test_mnemonic(), "pass", Bip44Path::default())
            .unwrap();
        store.add_multisig("team", 1, &["a"], true).unwrap();

        // Assert
        let expected = "key team has no private key stored (a multisig key can't sign by itself)";
        assert_eq!(
            store.unlock("team", "pass").unwrap_err().to_string(),
            expected
        );
        assert_eq!(
            store.rotate("team", "pass", "new").unwrap_err().to_string(),
            expected
        );
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
    fn unlock_detects_tampered_address() {
        // Arrange
        let key = test_key();
        let blob = cipher::encrypt(key.to_bytes().as_slice(), "pass").unwrap();
        let tampered = Record {
            name: "main".to_string(),
            address: "g1attackercontrolledaddress00000000000".to_string(),
            pub_key: key.pub_key().into(),
            path: None,
            privkey_encrypted: Some(blob),
        };
        let mut backend = MemoryBackend::new();
        backend.insert(tampered).unwrap();
        let store = Store::new(backend);

        // Act
        let err = store.unlock("main", "pass").unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .starts_with("keystore record tampered with:")
        );
    }

    #[test]
    fn unlock_detects_tampered_pubkey() {
        // Arrange
        let key = test_key();
        let other_pubkey = PrivKey::from_bytes([9u8; 32]).unwrap().pub_key();
        let blob = cipher::encrypt(key.to_bytes().as_slice(), "pass").unwrap();
        let tampered = Record {
            name: "main".to_string(),
            address: key.pub_key().address().to_bech32(),
            pub_key: other_pubkey.into(),
            path: None,
            privkey_encrypted: Some(blob),
        };
        let mut backend = MemoryBackend::new();
        backend.insert(tampered).unwrap();
        let store = Store::new(backend);

        // Act
        let err = store.unlock("main", "pass").unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .starts_with("keystore record tampered with:")
        );
    }

    #[test]
    fn rotate_detects_tampered_record_and_leaves_it_untouched() {
        // Arrange
        let key = test_key();
        let blob = cipher::encrypt(key.to_bytes().as_slice(), "old").unwrap();
        let tampered = Record {
            name: "main".to_string(),
            address: "g1attackercontrolledaddress00000000000".to_string(),
            pub_key: key.pub_key().into(),
            path: None,
            privkey_encrypted: Some(blob),
        };
        let mut backend = MemoryBackend::new();
        backend.insert(tampered).unwrap();
        let mut store = Store::new(backend);

        // Act
        let err = store.rotate("main", "old", "new").unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .starts_with("keystore record tampered with:")
        );
        assert_eq!(
            store.get_by_name("main").unwrap().address,
            "g1attackercontrolledaddress00000000000"
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
