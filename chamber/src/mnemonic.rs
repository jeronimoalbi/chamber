//! BIP39 mnemonic generation, parsing, and seed derivation.
//!
//! Uses a 256-bit-entropy (24 word) English BIP39 mnemonic and always
//! derives the seed with an empty passphrase. It uses PBKDF2 for key deviation
//! and HMAC-SHA512 as pseudorandom underlying function which is run 2048 rounds.
//! PBKDF2 salt is a literal "mnemonic" string (without concatenated password).
//!
//! The size of the derived seed is 64 bytes (512 bits).

use getrandom::getrandom;
use zeroize::{Zeroize, Zeroizing};

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

        // TODO: Support other languages
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy);
        entropy.zeroize();
        let mnemonic = mnemonic.map_err(|e| Error::Mnemonic(e.to_string()))?;
        Ok(Self(mnemonic))
    }

    /// Parse and validate an existing 24-word English phrase mnemonic phrase.
    pub fn parse(phrase: &str) -> Result<Self> {
        // TODO: Support other languages
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
    pub fn to_seed(&self) -> Zeroizing<[u8; 64]> {
        // Use an empty passphrase to match gnokey's implementation
        Zeroizing::new(self.0.to_seed(""))
    }

    /// The mnemonic phrase as single-space separated lowercase words.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    // Official BIP39 English test vector 0x00 entropy, with checksum word "art".
    // Used to check that `parse` accepts a known-good phrase without needing to
    // go through `generate`'s randomness.
    const ZERO_ENTROPY_24_WORDS: &str = "abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon art";

    // Official BIP39 English test vector 0xff entropy, with checksum word "vote".
    const MAX_ENTROPY_24_WORDS: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
        zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

    // Official BIP39 English test vector of 12-word mnemonic, with checksum word "about".
    const ZERO_ENTROPY_12_WORDS: &str = "abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon about";

    #[test]
    fn generate_produces_24_words() {
        // Act
        let mnemonic = Mnemonic::generate().unwrap();

        // Assert
        assert_eq!(mnemonic.word_count(), Mnemonic::WORDS);
    }

    #[test]
    fn generate_produces_unique_mnemonics() {
        // Act
        let a = Mnemonic::generate().unwrap();
        let b = Mnemonic::generate().unwrap();

        // Assert
        assert_ne!(a.phrase(), b.phrase());
    }

    #[test]
    fn generate_round_trips_through_parse() {
        //! A generated mnemonic's phrase can be fed back through `parse` and
        //! yields an equivalent mnemonic (same seed), confirming `generate`
        //! produces output that `parse` accepts and that both agree on seed
        //! derivation.

        // Arrange
        let mnemonic = Mnemonic::generate().unwrap();

        // Act
        let reparsed = Mnemonic::parse(&mnemonic.phrase()).unwrap();

        // Assert
        assert_eq!(reparsed.to_seed(), mnemonic.to_seed());
    }

    #[test]
    fn to_seed_is_deterministic() {
        // Arrange
        let mnemonic = Mnemonic::generate().unwrap();

        // Act
        let first = mnemonic.to_seed();
        let second = mnemonic.to_seed();

        // Assert
        assert_eq!(first, second);
    }

    #[test]
    fn to_seed_differs_for_different_mnemonics() {
        // Arrange
        let a = Mnemonic::generate().unwrap();
        let b = Mnemonic::generate().unwrap();

        // Act
        let seed_a = a.to_seed();
        let seed_b = b.to_seed();

        // Assert
        assert_ne!(seed_a, seed_b);
    }

    #[test]
    fn parse_accepts_official_bip39_vectors() {
        for phrase in [ZERO_ENTROPY_24_WORDS, MAX_ENTROPY_24_WORDS] {
            // Act
            let mnemonic = Mnemonic::parse(phrase).unwrap();

            // Assert
            assert_eq!(mnemonic.word_count(), Mnemonic::WORDS);
            assert_eq!(mnemonic.phrase().as_str(), phrase);
        }
    }

    #[test]
    fn parse_ignores_surrounding_and_repeated_whitespace() {
        // Arrange
        let padded = format!("  {}  ", ZERO_ENTROPY_24_WORDS.replace(' ', "  "));

        // Act
        let mnemonic = Mnemonic::parse(&padded).unwrap();

        // Assert
        assert_eq!(mnemonic.phrase().as_str(), ZERO_ENTROPY_24_WORDS);
    }

    #[test]
    #[should_panic(expected = "unknown word")]
    fn parse_is_case_sensitive() {
        //! Unlike whitespace, word casing is significant: the BIP39 English
        //! wordlist lookup used by the underlying `bip39` crate is
        //! case-sensitive, so an otherwise-valid phrase in the wrong case is
        //! rejected rather than silently lowercased.

        // Arrange
        let uppercased = ZERO_ENTROPY_24_WORDS.to_uppercase();

        // Act
        Mnemonic::parse(&uppercased).unwrap();
    }

    #[test]
    #[should_panic(expected = "got 12 words")]
    fn parse_rejects_wrong_word_count() {
        //! A checksum-valid 12-word phrase is rejected because
        //! this crate only accepts the 24-word form.

        // Act
        Mnemonic::parse(ZERO_ENTROPY_12_WORDS).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid checksum")]
    fn parse_rejects_bad_checksum() {
        //! Swapping the last (checksum) word for another valid wordlist word
        //! breaks the BIP39 checksum and must be rejected.

        // Arrange
        let mut words: Vec<&str> = ZERO_ENTROPY_24_WORDS.split(' ').collect();
        *words.last_mut().unwrap() = "abandon";
        let broken = words.join(" ");

        // Act
        Mnemonic::parse(&broken).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown word")]
    fn parse_rejects_unknown_word() {
        //! A word that isn't in the BIP39 English wordlist at all is rejected

        // Arrange
        let mut words: Vec<&str> = ZERO_ENTROPY_24_WORDS.split(' ').collect();
        words[0] = "notarealbip39word";
        let broken = words.join(" ");

        // Act
        Mnemonic::parse(&broken).unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid word count: 0")]
    fn parse_rejects_empty_string() {
        //! An empty phrase is rejected rather than panicking.

        // Act
        Mnemonic::parse("").unwrap();
    }

    #[test]
    fn word_count_constant_matches_generated() {
        // Act
        let mnemonic = Mnemonic::generate().unwrap();

        // Assert
        assert_eq!(Mnemonic::WORDS, 24);
        assert_eq!(mnemonic.word_count(), Mnemonic::WORDS);
    }

    #[test]
    fn display_matches_phrase() {
        // Arrange
        let mnemonic = Mnemonic::generate().unwrap();

        // Act
        let displayed = mnemonic.to_string();

        // Assert
        assert_eq!(displayed, mnemonic.phrase().as_str());
    }

    #[test]
    fn debug_does_not_leak_phrase() {
        // Arrange
        let mnemonic = Mnemonic::parse(ZERO_ENTROPY_24_WORDS).unwrap();

        // Act
        let debug_output = format!("{mnemonic:?}");

        // Assert
        assert!(debug_output.contains("24"));
        assert!(!debug_output.contains(mnemonic.phrase().as_str()));
        assert!(!debug_output.contains("abandon"));
    }

    #[test]
    fn clone_preserves_phrase_and_seed() {
        //! Cloning a mnemonic produces an independent value
        //! with the same phrase and seed as the original.

        // Arrange
        let mnemonic = Mnemonic::generate().unwrap();

        // Act
        let cloned = mnemonic.clone();

        // Assert
        assert_eq!(cloned.phrase(), mnemonic.phrase());
        assert_eq!(cloned.to_seed(), mnemonic.to_seed());
    }
}
