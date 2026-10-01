use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The BIP39 mnemonic could not be parsed or has an invalid checksum.
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),

    /// A BIP32/BIP44 derivation path was malformed.
    #[error("invalid derivation path: {0}")]
    Path(String),

    /// Key had the wrong length or was not a valid secp256k1 scalar/point.
    #[error("invalid key: {0}")]
    Key(String),

    /// A bech32 string could not be decoded.
    #[error("invalid bech32: {0}")]
    Bech32(String),

    /// Keystore decryption failed.
    #[error("keystore decryption failed (wrong passphrase or corrupted data)")]
    Decrypt,

    /// A passphrase must not be empty.
    #[error("passphrase must not be empty")]
    EmptyPassphrase,

    /// A keystore file or index was invalid.
    #[error("keystore format error: {0}")]
    KeystoreFormat(String),

    /// Keystore data has been tampered with.
    #[error("keystore record tampered with: {0}")]
    Tampered(String),

    /// A storage [`crate::backend::Backend`] failed for a reason of its own.
    #[error("storage backend error: {0}")]
    Backend(String),

    /// A key-export bundle/armor was malformed, had the wrong banner, or
    /// carried an unsupported `format` tag (e.g. it was not produced by
    /// `chamber`, or is from a newer/older incompatible export version).
    #[error("key export format error: {0}")]
    ExportFormat(String),

    /// A key with the same name or address was not found in the store.
    #[error("key not found: {0}")]
    NotFound(String),

    /// A key with the same name already exists in the store.
    #[error("key already exists: {0}")]
    AlreadyExists(String),

    /// A key name was empty, too long or invalid.
    #[error("invalid key name: {0}")]
    InvalidName(String),

    /// A coin or coins string was malformed or invalid (bad denom, negative
    /// or zero amount, unsorted or duplicate denoms).
    #[error("invalid coin: {0}")]
    Coin(String),

    /// A Gno package could not be built from files (bad path, inconsistent
    /// or missing package clause, no files).
    #[error("invalid package: {0}")]
    Package(String),

    /// A transaction or message failed basic validation.
    #[error("invalid transaction: {0}")]
    Tx(String),

    /// Amino-encoded data was malformed or of an unsupported type.
    #[error("amino error: {0}")]
    Amino(String),

    /// Underlying filesystem error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
