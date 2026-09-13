//! BIP39 mnemonic generation, parsing, and seed derivation.
//!
//! Uses a 256-bit-entropy (24 word) English BIP39 mnemonic and always
//! derives the seed with an empty passphrase. It uses PBKDF2 for key deviation
//! and HMAC-SHA512 as pseudorandom underlying function which is run 2048 rounds.
//! PBKDF2 salt is a literal "mnemonic" string (without concatenated password).
//!
//! The size of the derived seed is 64 bytes (512 bits).

use getrandom::getrandom;

use crate::error::{Error, Result};

/// A validated BIP39 mnemonic phrase.
#[derive(Clone)]
pub struct Mnemonic(bip39::Mnemonic);

impl Mnemonic {
    /// Number of words in a mnemonic.
    pub const WORDS: usize = 24;

    /// Generate a fresh 24-word English mnemonic.
    /// It does it though the OS cryptographically secure pseudorandom number generator.
    pub fn generate() -> Result<Self> {
        let mut entropy = [0u8; 32]; // size = 256 bits -> 24 words
        getrandom(&mut entropy).map_err(|e| Error::Key(e.to_string()))?;

        let mnemonic = bip39::Mnemonic::from_entropy(&entropy);
        let mnemonic = mnemonic.map_err(|e| Error::Mnemonic(e.to_string()))?;
        Ok(Self(mnemonic))
    }

    /// Parse and validate an existing 24-word phrase mnemonic phrase.
    pub fn parse(phrase: &str) -> Result<Self> {
        let mnemonic = bip39::Mnemonic::parse_normalized(phrase.trim());
        let mnemonic = mnemonic.map_err(|e| Error::Mnemonic(e.to_string()))?;

        let count = mnemonic.word_count();
        if count != Self::WORDS {
            return Err(Error::Mnemonic(format!(
                "expected a {} words phrase, got {count} words",
                Self::WORDS
            )));
        }

        Ok(Self(mnemonic))
    }

    /// The 64-byte BIP39 seed.
    pub fn to_seed(&self) -> [u8; 64] {
        // Use an empty passphrase to match gnokey's implementation
        self.0.to_seed("")
    }

    /// The mnemonic phrase as single-space separated lowercase words.
    pub fn phrase(&self) -> String {
        self.0.to_string()
    }

    /// Word count of this mnemonic.
    pub fn word_count(&self) -> usize {
        self.0.word_count()
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.phrase())
    }
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mnemonic({} words)", self.word_count())
    }
}
