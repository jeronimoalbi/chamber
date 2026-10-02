use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// A single amount of one denomination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coin {
    pub denom: String,
    pub amount: i64,
}

impl Coin {
    /// A coin with a validated denomination. Any amount is accepted here;
    /// use [`Coin::is_valid`] / [`Coins`] for the positivity rules.
    pub fn new(denom: impl Into<String>, amount: i64) -> Result<Self> {
        let denom = denom.into();
        validate_denom(&denom)?;
        Ok(Self { denom, amount })
    }

    /// Parse `"<amount><denom>"`: surrounding whitespace is
    /// ignored and whitespace is allowed between amount and denom. The empty
    /// string is not a coin; see [`Coins::parse`] for the "no coins" case.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let digits = s.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(Error::Coin(format!("invalid coin expression: {s:?}")));
        }

        let amount: i64 = s[..digits].parse().map_err(|e| {
            Error::Coin(format!(
                "failed to parse coin amount {:?}: {e}",
                &s[..digits]
            ))
        })?;
        let denom = s[digits..].trim_start();
        if denom.is_empty() || denom.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(Error::Coin(format!("invalid coin expression: {s:?}")));
        }

        Self::new(denom, amount)
    }

    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    pub fn is_positive(&self) -> bool {
        self.amount > 0
    }

    /// `Coin.IsValid`: a valid denomination and a non-negative amount.
    pub fn is_valid(&self) -> bool {
        validate_denom(&self.denom).is_ok() && self.amount >= 0
    }
}

/// `Coin.String`: `"<amount><denom>"`, or `""` for a zero amount.
impl fmt::Display for Coin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            Ok(())
        } else {
            write!(f, "{}{}", self.amount, self.denom)
        }
    }
}

impl FromStr for Coin {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for Coin {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Like `Coin.UnmarshalAmino`, an empty string is the zero coin.
impl<'de> Deserialize<'de> for Coin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Self::default());
        }

        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A valid set of coins: sorted by denomination, no duplicates, all amounts
/// positive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coins(Vec<Coin>);

impl Coins {
    /// No coins at all.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from any order of coins; sorts them and validates the set.
    pub fn new(mut coins: Vec<Coin>) -> Result<Self> {
        coins.sort_by(|a, b| a.denom.cmp(&b.denom));
        validate_coins(&coins)?;
        Ok(Self(coins))
    }

    /// Parse a comma-separated coin list. Whitespace
    /// around the whole string is ignored and an empty string is no coins.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::empty());
        }

        let coins = s.split(',').map(Coin::parse).collect::<Result<Vec<_>>>()?;
        Self::new(coins)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Coin> {
        self.0.iter()
    }

    pub fn as_slice(&self) -> &[Coin] {
        &self.0
    }
}

/// `Coins.String`: comma-joined coins, `""` when empty.
impl fmt::Display for Coins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, coin) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }

            write!(f, "{coin}")?;
        }

        Ok(())
    }
}

impl FromStr for Coins {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for Coins {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Coins {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl<'a> IntoIterator for &'a Coins {
    type Item = &'a Coin;
    type IntoIter = std::slice::Iter<'a, Coin>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Check a denomination against `^[a-z/][a-z0-9_.:/]{2,}$`.
fn validate_denom(denom: &str) -> Result<()> {
    let mut chars = denom.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '/');
    let rest: Vec<char> = chars.collect();
    let rest_ok = rest.len() >= 2
        && rest.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '/')
        });
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(Error::Coin(format!("invalid denom: {denom:?}")))
    }
}

/// `Coins.validate` over an already sorted list.
fn validate_coins(coins: &[Coin]) -> Result<()> {
    for (i, coin) in coins.iter().enumerate() {
        validate_denom(&coin.denom)?;
        if !coin.is_positive() {
            return Err(Error::Coin(format!(
                "non-positive coin amount: {}",
                coin.amount
            )));
        }

        if i > 0 && coins[i - 1].denom == coin.denom {
            return Err(Error::Coin(format!("duplicate denom: {}", coin.denom)));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_parse_accepts_amount_denom() {
        // Act
        let coin = Coin::parse("1000000ugnot").unwrap();

        // Assert
        assert_eq!(
            coin,
            Coin {
                denom: "ugnot".into(),
                amount: 1_000_000
            }
        );
    }

    #[test]
    fn coin_parse_ignores_surrounding_and_inner_whitespace() {
        //! `std.ParseCoin` trims the input and allows spaces between amount and denom

        // Act
        let coin = Coin::parse("  42 \t atom ").unwrap();

        // Assert
        assert_eq!(
            coin,
            Coin {
                denom: "atom".into(),
                amount: 42
            }
        );
    }

    #[test]
    fn coin_parse_accepts_zero_amount() {
        // Act
        let coin = Coin::parse("0ugnot").unwrap();

        // Assert
        assert!(coin.is_zero());
        assert!(coin.is_valid());
        assert!(!coin.is_positive());
    }

    #[test]
    #[should_panic(expected = "invalid coin expression")]
    fn coin_parse_rejects_empty() {
        Coin::parse("").unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid coin expression")]
    fn coin_parse_rejects_negative() {
        Coin::parse("-5ugnot").unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid coin expression")]
    fn coin_parse_rejects_spaces_inside_denom() {
        Coin::parse("5ugnot extra").unwrap();
    }

    #[test]
    #[should_panic(expected = "failed to parse coin amount")]
    fn coin_parse_rejects_amount_overflow() {
        Coin::parse("99999999999999999999ugnot").unwrap();
    }

    #[test]
    fn denom_rules_match_gno() {
        //! `^[a-z/][a-z0-9_.:/]{2,}$`: lowercase start (or `/`), at least three chars

        // Assert
        for ok in ["ugnot", "/ok", "a1_", "gno.land/r/x:y"] {
            assert!(Coin::new(ok, 1).is_ok(), "{ok:?} should be valid");
        }

        for bad in ["", "ab", "Ugnot", "1abc", "ug not", "ugnöt", "_abc"] {
            let err = Coin::new(bad, 1).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("invalid coin: invalid denom: {bad:?}")
            );
        }
    }

    #[test]
    fn coin_display_is_amount_then_denom_or_empty_when_zero() {
        // Assert
        assert_eq!(Coin::parse("7atom").unwrap().to_string(), "7atom");
        assert_eq!(Coin::parse("0atom").unwrap().to_string(), "");
        assert_eq!(Coin::default().to_string(), "");
    }

    #[test]
    fn coin_serde_uses_string_form_and_empty_means_zero() {
        // Act
        let json = serde_json::to_string(&Coin::parse("5ugnot").unwrap()).unwrap();
        let zero: Coin = serde_json::from_str("\"\"").unwrap();
        let parsed: Coin = serde_json::from_str("\"5ugnot\"").unwrap();

        // Assert
        assert_eq!(json, "\"5ugnot\"");
        assert_eq!(zero, Coin::default());
        assert_eq!(parsed.amount, 5);
    }

    #[test]
    fn coins_parse_sorts_by_denom() {
        //! `std.ParseCoins` sorts for determinism, so the string form is canonical

        // Act
        let coins = Coins::parse("1000000ugnot,5000atom").unwrap();

        // Assert
        assert_eq!(coins.to_string(), "5000atom,1000000ugnot");
        assert_eq!(coins.len(), 2);
    }

    #[test]
    fn coins_parse_empty_or_blank_is_no_coins() {
        // Assert
        assert!(Coins::parse("").unwrap().is_empty());
        assert!(Coins::parse("   ").unwrap().is_empty());
        assert_eq!(Coins::empty().to_string(), "");
    }

    #[test]
    #[should_panic(expected = "duplicate denom: ugnot")]
    fn coins_rejects_duplicate_denoms() {
        Coins::parse("1ugnot,2ugnot").unwrap();
    }

    #[test]
    #[should_panic(expected = "non-positive coin amount: 0")]
    fn coins_rejects_zero_amounts() {
        Coins::parse("0ugnot").unwrap();
    }

    #[test]
    #[should_panic(expected = "invalid coin expression")]
    fn coins_rejects_trailing_comma() {
        Coins::parse("1ugnot,").unwrap();
    }

    #[test]
    fn coins_new_sorts_and_validates() {
        // Arrange
        let unsorted = vec![
            Coin::new("ugnot", 1).unwrap(),
            Coin::new("atom", 2).unwrap(),
        ];

        // Act
        let coins = Coins::new(unsorted).unwrap();

        // Assert
        assert_eq!(coins.to_string(), "2atom,1ugnot");
        assert_eq!(
            coins.iter().map(|c| c.denom.as_str()).collect::<Vec<_>>(),
            ["atom", "ugnot"]
        );
    }

    #[test]
    fn coins_serde_round_trips_string_form() {
        // Act
        let json = serde_json::to_string(&Coins::parse("1ugnot").unwrap()).unwrap();
        let empty: Coins = serde_json::from_str("\"\"").unwrap();
        let parsed: Coins = serde_json::from_str("\"2atom,1ugnot\"").unwrap();

        // Assert
        assert_eq!(json, "\"1ugnot\"");
        assert!(empty.is_empty());
        assert_eq!(parsed.len(), 2);
    }
}
