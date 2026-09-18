//! Chamber ⇄ chamber key transfer, wrapped in a PEM-style armor envelope
//! for safe copy/paste.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::Record;
use crate::cipher::{self, EncryptedBlob};
use crate::error::{Error, Result};
use crate::hdpath::Bip44Path;
use crate::key::PrivKey;
use crate::store::Store;

pub const EXPORT_FORMAT: &str = "chamber-keyexport-v1";

const ARMOR_BEGIN: &str = "-----BEGIN CHAMBER PRIVATE KEY EXPORT-----";
const ARMOR_END: &str = "-----END CHAMBER PRIVATE KEY EXPORT-----";
const ARMOR_LINE_WIDTH: usize = 64;

/// Export bundle contains a key moved out of a [`Store`] for transfers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBundle {
    /// Export format.
    pub format: String,

    /// The name the key had in the source store.
    pub name: String,

    /// Bech32 address.
    pub address: String,

    /// Compressed public key as base64.
    pub pubkey_b64: String,

    /// Key derivation path, when known.
    pub path: Option<Bip44Path>,

    /// Encrypted (Argon2id + XChaCha20-Poly1305) private key.
    /// Encrypts the raw 32-byte private key.
    pub privkey_encrypted: EncryptedBlob,
}

impl Store {
    /// Export a key.
    /// Key is decrypted with the store's own passphrase and re-encrypted
    /// under an optional transfer passphrase. The store passphrase is reused
    /// when there is no transfer one.
    pub fn export_key(
        &self,
        name: &str,
        store_passphrase: &str,
        transfer_passphrase: Option<&str>,
    ) -> Result<ExportBundle> {
        let record = self.get_by_name(name)?;
        let plain = Zeroizing::new(cipher::decrypt(
            &record.privkey_encrypted,
            store_passphrase,
        )?);
        let transfer_passphrase = transfer_passphrase.unwrap_or(store_passphrase);
        Ok(ExportBundle {
            format: EXPORT_FORMAT.to_string(),
            name: record.name,
            address: record.address,
            pubkey_b64: record.pubkey_b64,
            path: record.path,
            privkey_encrypted: cipher::encrypt(&plain, transfer_passphrase)?,
        })
    }

    /// Import a key into the store.
    /// Key is decrypted with the optional transfer passphrase, or with the
    /// store passphrase when the former is not specified. Store passphrase
    /// is used to encript the key before saving it into the store.
    pub fn import_key(
        &mut self,
        name: &str,
        bundle: &ExportBundle,
        transfer_passphrase: Option<&str>,
        store_passphrase: &str,
    ) -> Result<Record> {
        ensure_valid_export_format(&bundle.format)?;

        let transfer_passphrase = transfer_passphrase.unwrap_or(store_passphrase);
        let plain = Zeroizing::new(cipher::decrypt(
            &bundle.privkey_encrypted,
            transfer_passphrase,
        )?);
        let bytes: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| Error::ExportFormat("privkey blob must be 32 bytes".into()))?;
        let key = PrivKey::from_bytes(bytes)?;
        self.add_privkey(name, &key, store_passphrase)
    }
}

fn ensure_valid_export_format(format: &str) -> Result<()> {
    if format != EXPORT_FORMAT {
        return Err(Error::ExportFormat(format!(
            "unsupported export format {format:?} (expected {EXPORT_FORMAT:?})"
        )));
    }
    Ok(())
}

/// Encode `bundle` as PEM-style armor text you can safely paste into a
/// terminal, chat, or email.
///
/// The output is just base64 of the bundle's JSON, wrapped at 64 characters
/// and framed by `-----BEGIN/END CHAMBER PRIVATE KEY EXPORT-----` banners.
/// There's no separate checksum line: the private key is already encrypted
/// with authenticated encryption, so a corrupted or tampered bundle simply
/// fails to decrypt later instead of silently producing garbage.
pub fn encode_armor(bundle: &ExportBundle) -> Result<String> {
    let json_bytes = serde_json::to_vec(bundle)?;
    let b64 = B64.encode(json_bytes);

    let mut out = String::new();
    out.push_str(ARMOR_BEGIN);
    out.push('\n');
    for line in b64.as_bytes().chunks(ARMOR_LINE_WIDTH) {
        // Base64 output is ASCII
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(ARMOR_END);
    out.push('\n');
    Ok(out)
}

/// Decode armor text produced by [`encode_armor`] back into a bundle.
///
/// Anything that doesn't start with the chamber banner is rejected right
/// away, before any decoding is attempted. The bundle's own `format` field
/// is checked separately, after decoding.
pub fn decode_armor(text: &str) -> Result<ExportBundle> {
    let text = text.trim();
    let body = text
        .strip_prefix(ARMOR_BEGIN)
        .and_then(|rest| rest.trim().strip_suffix(ARMOR_END))
        .ok_or_else(|| {
            Error::ExportFormat("not a chamber private key export (banner mismatch)".into())
        })?;

    let b64: String = body.split_whitespace().collect();
    let json = B64
        .decode(b64)
        .map_err(|e| Error::ExportFormat(format!("bad base64 body: {e}")))?;
    let bundle: ExportBundle = serde_json::from_slice(&json)?;
    ensure_valid_export_format(&bundle.format)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> PrivKey {
        PrivKey::from_bytes([7u8; 32]).unwrap()
    }

    fn seeded_store() -> Store {
        let mut store = Store::new_in_memory();
        store
            .add_privkey("alice", &test_key(), "store-pass")
            .unwrap();
        store
    }

    #[test]
    fn ensure_valid_export_format_accepts_matching_value() {
        // Act / Assert
        assert!(ensure_valid_export_format(EXPORT_FORMAT).is_ok());
    }

    #[test]
    fn check_format_rejects_mismatched_value() {
        //! Any other tag is rejected with a message naming both the bad
        //! value and the expected one.

        // Act
        let err = ensure_valid_export_format("bogus").unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "key export format error: unsupported export format \"bogus\" \
             (expected \"chamber-keyexport-v1\")"
        );
    }

    #[test]
    fn export_key_copies_record_fields_and_reencrypts() {
        //! The bundle mirrors the store record's public fields, and its
        //! privkey blob decrypts under the transfer passphrase to the same
        //! raw key that was stored.

        // Arrange
        let store = seeded_store();
        let record = store.get_by_name("alice").unwrap();

        // Act
        let bundle = store
            .export_key("alice", "store-pass", Some("transfer-pass"))
            .unwrap();

        // Assert
        assert_eq!(bundle.format, EXPORT_FORMAT);
        assert_eq!(bundle.name, record.name);
        assert_eq!(bundle.address, record.address);
        assert_eq!(bundle.pubkey_b64, record.pubkey_b64);
        assert!(bundle.path.is_none());

        let plain = cipher::decrypt(&bundle.privkey_encrypted, "transfer-pass").unwrap();
        assert_eq!(plain.as_slice(), test_key().to_bytes().as_slice());
    }

    #[test]
    fn export_key_missing_name_errors() {
        // Arrange
        let store = seeded_store();

        // Act
        let err = store.export_key("ghost", "store-pass", None).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key not found: ghost");
    }

    #[test]
    fn export_key_wrong_store_passphrase_errors() {
        // Arrange
        let store = seeded_store();

        // Act
        let err = store.export_key("alice", "wrong-pass", None).unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
    }

    #[test]
    fn export_key_defaults_transfer_passphrase_to_store_passphrase() {
        // Arrange
        let store = seeded_store();

        // Act
        let bundle = store.export_key("alice", "store-pass", None).unwrap();

        // Assert
        let plain = cipher::decrypt(&bundle.privkey_encrypted, "store-pass").unwrap();
        assert_eq!(plain.as_slice(), test_key().to_bytes().as_slice());
    }

    #[test]
    fn import_key_round_trip_into_new_store() {
        //! A bundle exported from one store can be imported into a
        //! completely different store, under its own store passphrase, and
        //! the resulting key unlocks to the same address.

        // Arrange
        let src = seeded_store();
        let bundle = src
            .export_key("alice", "store-pass", Some("transfer-pass"))
            .unwrap();
        let mut dst = Store::new_in_memory();

        // Act
        let record = dst
            .import_key("copy", &bundle, Some("transfer-pass"), "dst-pass")
            .unwrap();

        // Assert
        assert_eq!(record.address, bundle.address);

        let key = dst.unlock("copy", "dst-pass").unwrap();
        assert_eq!(key.pub_key().address().to_bech32(), bundle.address);
    }

    #[test]
    fn import_key_wrong_transfer_passphrase_errors() {
        //! The transfer passphrase, not the destination store's passphrase,
        //! gates decrypting the bundle.

        // Arrange
        let src = seeded_store();
        let bundle = src
            .export_key("alice", "store-pass", Some("transfer-pass"))
            .unwrap();
        let mut dst = Store::new_in_memory();

        // Act
        let err = dst
            .import_key("copy", &bundle, Some("wrong-pass"), "dst-pass")
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "keystore decryption failed (wrong passphrase or corrupted data)"
        );
    }

    #[test]
    fn import_key_defaults_transfer_passphrase_to_store_passphrase() {
        //! A bundle exported with no transfer passphrase is encrypted under
        //! the source store's own passphrase, so the recipient must have
        //! been told that passphrase. Importing it by also omitting the
        //! transfer passphrase decrypts the bundle with the destination
        //! store's passphrase, which must therefore be that same shared
        //! value.

        // Arrange
        let src = seeded_store();
        let bundle = src.export_key("alice", "store-pass", None).unwrap();
        let mut dst = Store::new_in_memory();

        // Act
        let record = dst.import_key("copy", &bundle, None, "store-pass").unwrap();

        // Assert
        assert_eq!(record.address, bundle.address);

        let key = dst.unlock("copy", "store-pass").unwrap();
        assert_eq!(key.pub_key().address().to_bech32(), bundle.address);
    }

    #[test]
    fn import_key_rejects_unsupported_format() {
        //! A bundle whose `format` tag isn't ours is rejected before any
        //! decryption is attempted.

        // Arrange
        let src = seeded_store();
        let mut bundle = src
            .export_key("alice", "store-pass", Some("transfer-pass"))
            .unwrap();
        bundle.format = "gnokey-armor-v1".to_string();
        let mut dst = Store::new_in_memory();

        // Act
        let err = dst
            .import_key("copy", &bundle, Some("transfer-pass"), "dst-pass")
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "key export format error: unsupported export format \"gnokey-armor-v1\" \
             (expected \"chamber-keyexport-v1\")"
        );
    }

    #[test]
    fn import_key_rejects_duplicate_name() {
        // Arrange
        let mut store = seeded_store();
        let bundle = store.export_key("alice", "store-pass", None).unwrap();

        // Act
        let err = store
            .import_key("alice", &bundle, None, "store-pass")
            .unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "key already exists: alice");
    }

    #[test]
    fn import_key_rejects_wrong_length_privkey() {
        //! A bundle that decrypts cleanly but doesn't hold a 32-byte key
        //! (e.g. hand-crafted or from a corrupted source) is rejected with
        //! a descriptive format error, not a panic.

        // Arrange
        let bundle = ExportBundle {
            format: EXPORT_FORMAT.to_string(),
            name: "alice".to_string(),
            address: "g1bogus".to_string(),
            pubkey_b64: "bogus".to_string(),
            path: None,
            privkey_encrypted: cipher::encrypt(&[1u8; 31], "transfer-pass").unwrap(),
        };
        let mut store = Store::new_in_memory();

        // Act
        let err = store
            .import_key("copy", &bundle, Some("transfer-pass"), "dst-pass")
            .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "key export format error: privkey blob must be 32 bytes"
        );
    }

    #[test]
    fn encode_armor_wraps_body_at_64_chars() {
        //! Every base64 body line is wrapped at `ARMOR_LINE_WIDTH`, except
        //! possibly the last.

        // Arrange
        let store = seeded_store();
        let bundle = store.export_key("alice", "store-pass", None).unwrap();

        // Act
        let armored = encode_armor(&bundle).unwrap();

        // Assert
        let body_lines: Vec<&str> = armored
            .lines()
            .filter(|l| *l != ARMOR_BEGIN && *l != ARMOR_END)
            .collect();
        let (last, rest) = body_lines.split_last().unwrap();
        assert!(rest.iter().all(|l| l.len() == ARMOR_LINE_WIDTH));
        assert!(last.len() <= ARMOR_LINE_WIDTH);
    }

    #[test]
    fn encode_then_decode_armor_round_trips_all_fields() {
        //! Every field of a hand-built bundle, including a `Some` path,
        //! survives an encode/decode round trip unchanged.

        // Arrange
        let bundle = ExportBundle {
            format: EXPORT_FORMAT.to_string(),
            name: "alice".to_string(),
            address: "g1example".to_string(),
            pubkey_b64: "cGxhY2Vob2xkZXI=".to_string(),
            path: Some(Bip44Path::new(3, 2)),
            privkey_encrypted: cipher::encrypt(&[9u8; 32], "transfer-pass").unwrap(),
        };

        // Act
        let armored = encode_armor(&bundle).unwrap();
        let decoded = decode_armor(&armored).unwrap();

        // Assert
        assert_eq!(decoded.format, bundle.format);
        assert_eq!(decoded.name, bundle.name);
        assert_eq!(decoded.address, bundle.address);
        assert_eq!(decoded.pubkey_b64, bundle.pubkey_b64);
        assert_eq!(decoded.path, bundle.path);

        let original = cipher::decrypt(&bundle.privkey_encrypted, "transfer-pass").unwrap();
        let round_tripped = cipher::decrypt(&decoded.privkey_encrypted, "transfer-pass").unwrap();
        assert_eq!(original, round_tripped);
    }

    #[test]
    fn decode_armor_rejects_invalid_base64_body() {
        // Arrange
        let text = format!("{ARMOR_BEGIN}\nnot-valid-base64!!!\n{ARMOR_END}\n");

        // Act
        let err = decode_armor(&text).unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .starts_with("key export format error: bad base64 body:")
        );
    }

    #[test]
    fn decode_armor_rejects_valid_base64_invalid_json() {
        // Arrange
        let b64 = B64.encode(b"not json");
        let text = format!("{ARMOR_BEGIN}\n{b64}\n{ARMOR_END}\n");

        // Act
        let err = decode_armor(&text).unwrap_err();

        // Assert
        assert!(matches!(err, Error::Json(_)));
    }

    #[test]
    fn decode_armor_rejects_banner_mismatch() {
        // Act
        let err = decode_armor(
            "-----BEGIN TENDERMINT PRIVATE KEY-----\nabc\n-----END TENDERMINT PRIVATE KEY-----\n",
        )
        .unwrap_err();

        // Assert
        assert_eq!(
            err.to_string(),
            "key export format error: not a chamber private key export (banner mismatch)"
        );
    }

    #[test]
    fn decode_armor_tolerates_surrounding_whitespace() {
        // Arrange
        let store = seeded_store();
        let bundle = store.export_key("alice", "store-pass", None).unwrap();
        let armored = encode_armor(&bundle).unwrap();
        let padded = format!("\n\n  {armored}\n\n\t\n");

        // Act
        let decoded = decode_armor(&padded).unwrap();

        // Assert
        assert_eq!(decoded.address, bundle.address);
    }
}
