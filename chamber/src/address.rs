use bech32::{Bech32, Hrp};

use crate::error::{Error, Result};

/// The human-readable part of a Gno.land address before the "1" separator.
pub const HRP: &str = "g";

/// A 20-byte Gno.land account address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    /// Encode address as `g1...` string.
    pub fn to_bech32(&self) -> String {
        let hrp = Hrp::parse(HRP).unwrap();
        bech32::encode::<Bech32>(hrp, &self.0).unwrap()
    }

    /// Parse a `g1...` address string.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s).map_err(|e| Error::Bech32(e.to_string()))?;
        if hrp.as_str() != HRP {
            return Err(Error::Bech32(format!(
                "expected prefix {HRP:?}, got {:?}",
                hrp.as_str()
            )));
        }

        let bytes: [u8; 20] = data
            .as_slice()
            .try_into()
            .map_err(|_| Error::Bech32(format!("expected 20-byte payload, got {}", data.len())))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_bech32())
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({})", self.to_bech32())
    }
}

impl std::str::FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_bech32(s)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bech32::Hrp;

    use super::*;

    // Generated from path 44'/118'/0'/0/0 using official all "abandon" vector
    const KNOWN_ADDRESS: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";

    #[test]
    fn from_bytes_and_to_bytes_round_trip() {
        // Arrange
        let bytes: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];

        // Act
        let address = Address::from_bytes(bytes);

        // Assert
        assert_eq!(address.to_bytes(), bytes);
    }

    #[test]
    fn bech32_round_trip_arbitrary_bytes() {
        // Arrange
        let bytes: [u8; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let address = Address::from_bytes(bytes);

        // Act
        let encoded = address.to_bech32();
        let decoded = Address::from_bech32(&encoded).unwrap();

        // Assert
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn bech32_round_trip_handles_boundary_byte_values() {
        //! The 0x00 and 0xFF payloads must round-trip just like any other address

        for bytes in [[0u8; 20], [0xFFu8; 20]] {
            // Act
            let encoded = Address::from_bytes(bytes).to_bech32();
            let decoded = Address::from_bech32(&encoded).unwrap();

            // Assert
            assert_eq!(decoded.to_bytes(), bytes);
        }
    }

    #[test]
    fn to_bech32_uses_g_prefix() {
        // Act
        let encoded = Address::from_bytes([0u8; 20]).to_bech32();

        // Assert
        assert!(encoded.starts_with("g1"));
    }

    #[test]
    fn display_matches_to_bech32() {
        // Arrange
        let address = Address::from_bech32(KNOWN_ADDRESS).unwrap();

        // Act
        let displayed = address.to_string();

        // Assert
        assert_eq!(displayed, address.to_bech32());
    }

    #[test]
    fn debug_wraps_bech32_in_address() {
        // Arrange
        let address = Address::from_bech32(KNOWN_ADDRESS).unwrap();

        // Act
        let debug_output = format!("{address:?}");

        // Assert
        assert_eq!(debug_output, format!("Address({})", address.to_bech32()));
    }

    #[test]
    fn from_str_matches_from_bech32() {
        // Act
        let parsed: Address = KNOWN_ADDRESS.parse().unwrap();
        let decoded = Address::from_bech32(KNOWN_ADDRESS).unwrap();

        // Assert
        assert_eq!(parsed, decoded);
    }

    #[test]
    #[should_panic(expected = r#"expected prefix \"g\", got \"cosmos\""#)]
    fn from_bech32_rejects_wrong_hrp() {
        // Arrange
        let hrp = Hrp::parse("cosmos").unwrap();
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &[0u8; 20]).unwrap();

        // Act
        Address::from_bech32(&encoded).unwrap();
    }

    #[test]
    #[should_panic(expected = "expected 20-byte payload")]
    fn from_bech32_rejects_wrong_payload_length() {
        //! A payload of any length other than 20 bytes must be rejected

        // Arrange
        let hrp = Hrp::parse(HRP).unwrap();
        let encoded = bech32::encode::<bech32::Bech32>(hrp, &[0u8; 10]).unwrap();

        // Act
        Address::from_bech32(&encoded).unwrap();
    }

    #[test]
    #[should_panic(expected = "parsing failed")]
    fn from_bech32_rejects_malformed_string() {
        // Act
        Address::from_bech32("").unwrap();
    }

    #[test]
    #[should_panic(expected = "parsing failed")]
    fn from_bech32_rejects_mixed_case() {
        // Arrange
        let mid = KNOWN_ADDRESS.len() / 2;
        let mixed = format!(
            "{}{}",
            &KNOWN_ADDRESS[..mid],
            KNOWN_ADDRESS[mid..].to_uppercase()
        );

        // Act
        Address::from_bech32(&mixed).unwrap();
    }

    #[test]
    fn equal_addresses_from_same_bytes_are_equal_and_hash_equal() {
        // Arrange
        let a = Address::from_bytes([7u8; 20]);
        let b = Address::from_bytes([7u8; 20]);
        let c = Address::from_bytes([9u8; 20]);

        // Assert
        assert_eq!(a, b);
        assert_ne!(a, c);

        let set: HashSet<Address> = [a, b, c].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn copy_produces_equal_independent_value() {
        // Arrange
        let address = Address::from_bytes([3u8; 20]);

        // Act
        let copied = address;

        // Assert
        assert_eq!(copied, address);
    }
}
