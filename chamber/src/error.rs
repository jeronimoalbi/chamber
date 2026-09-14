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
}

pub type Result<T> = std::result::Result<T, Error>;
