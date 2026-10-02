use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::address::Address;
use crate::amino::TYPE_URL_PUBKEY_SECP256K1;
use crate::amino::binary::{self, AminoBinary, Reader, Writer};
use crate::amino::json::quoted_u64;
use crate::error::{Error, Result};
use crate::key::{PUBKEY_HRP, PubKey};

/// Amino type URL of a [`MultisigPubKey`].
pub const TYPE_URL_PUBKEY_MULTISIG: &str = "/tm.PubKeyMultisig";

/// Any public key a transaction signature can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyPubKey {
    Secp256k1(PubKey),
    Multisig(MultisigPubKey),
}

/// A k-of-n threshold key (`multisig.PubKeyMultisigThreshold`): a
/// transaction from its address needs signatures from `threshold` of the
/// member keys, assembled into a [`crate::tx::Multisignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultisigPubKey {
    #[serde(with = "quoted_u64")]
    pub threshold: u64,
    pub pubkeys: Vec<AnyPubKey>,
}

impl AnyPubKey {
    pub fn type_url(&self) -> &'static str {
        match self {
            AnyPubKey::Secp256k1(_) => TYPE_URL_PUBKEY_SECP256K1,
            AnyPubKey::Multisig(_) => TYPE_URL_PUBKEY_MULTISIG,
        }
    }

    /// The account address: `RIPEMD160(SHA256(bytes))` for a secp256k1 key,
    /// the first 20 bytes of `SHA256(Any bytes)` for a multisig key.
    pub fn address(&self) -> Address {
        match self {
            AnyPubKey::Secp256k1(key) => key.address(),
            AnyPubKey::Multisig(_) => {
                let digest = Sha256::digest(self.to_amino_any());
                let mut out = [0u8; 20];
                out.copy_from_slice(&digest[..20]);
                Address::from_bytes(out)
            }
        }
    }

    /// The Amino-binary `Any` encoding (`amino.MarshalAny`, `PubKey.Bytes()`).
    pub fn to_amino_any(&self) -> Vec<u8> {
        match self {
            AnyPubKey::Secp256k1(key) => binary::encode_any(self.type_url(), &Secp256k1Bytes(key)),
            AnyPubKey::Multisig(key) => binary::encode_any(self.type_url(), key),
        }
    }

    /// Decode an `Any` produced by [`to_amino_any`](Self::to_amino_any).
    pub fn from_amino_any(bytes: &[u8]) -> Result<Self> {
        let (type_url, value) = binary::decode_any(bytes)?;
        match type_url.as_str() {
            TYPE_URL_PUBKEY_SECP256K1 => {
                let mut reader = Reader::new(&value);
                if reader.key()? != (1, 2) {
                    return Err(Error::Amino("malformed secp256k1 key".into()));
                }

                let raw: [u8; 33] = reader
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::Amino("expected a 33-byte secp256k1 public key".into()))?;
                Ok(AnyPubKey::Secp256k1(PubKey::from_bytes(raw)?))
            }
            TYPE_URL_PUBKEY_MULTISIG => {
                let mut reader = Reader::new(&value);
                let mut threshold = 0;
                let mut pubkeys = Vec::new();
                while !reader.is_empty() {
                    match reader.key()? {
                        (1, 0) => threshold = reader.uvarint()?,
                        (2, 2) => pubkeys.push(Self::from_amino_any(reader.bytes()?)?),
                        (field, wire) => {
                            return Err(Error::Amino(format!(
                                "unexpected field {field} (wire type {wire}) in multisig key"
                            )));
                        }
                    }
                }

                Ok(AnyPubKey::Multisig(MultisigPubKey::new(
                    threshold, pubkeys, false,
                )?))
            }
            other => Err(Error::Amino(format!(
                "unsupported public key type {other:?}"
            ))),
        }
    }

    /// The `gpub1…` string: bech32 over the `Any` bytes.
    pub fn to_bech32(&self) -> String {
        let hrp = Hrp::parse(PUBKEY_HRP).unwrap();
        bech32::encode::<Bech32>(hrp, &self.to_amino_any()).unwrap()
    }

    /// Parse a `gpub1…` string.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let checked =
            CheckedHrpstring::new::<Bech32>(s).map_err(|e| Error::Bech32(e.to_string()))?;
        let hrp = checked.hrp();
        if hrp.as_str() != PUBKEY_HRP {
            return Err(Error::Bech32(format!(
                "expected prefix {PUBKEY_HRP:?}, got {:?}",
                hrp.as_str()
            )));
        }

        let data: Vec<u8> = checked.byte_iter().collect();
        Self::from_amino_any(&data)
    }
}

impl From<PubKey> for AnyPubKey {
    fn from(key: PubKey) -> Self {
        AnyPubKey::Secp256k1(key)
    }
}

impl From<MultisigPubKey> for AnyPubKey {
    fn from(key: MultisigPubKey) -> Self {
        AnyPubKey::Multisig(key)
    }
}

/// A secp256k1 key compares equal to its wrapped form, so code holding a
/// plain [`PubKey`] can check a signature's key without wrapping it.
impl PartialEq<PubKey> for AnyPubKey {
    fn eq(&self, other: &PubKey) -> bool {
        matches!(self, AnyPubKey::Secp256k1(key) if key == other)
    }
}

impl std::fmt::Display for AnyPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_bech32())
    }
}

impl MultisigPubKey {
    /// A k-of-n key over `pubkeys`. With `sort`, members are ordered by address;
    /// the order is part of the key (and so of its address), so it must match what
    /// the other members use.
    pub fn new(threshold: u64, mut pubkeys: Vec<AnyPubKey>, sort: bool) -> Result<Self> {
        if threshold == 0 {
            return Err(Error::Key("multisig threshold must be positive".into()));
        }

        if (pubkeys.len() as u64) < threshold {
            return Err(Error::Key(format!(
                "threshold k of n multisignature: {} < {threshold}",
                pubkeys.len()
            )));
        }

        if sort {
            pubkeys.sort_by_key(|k| k.address().to_bytes());
        }

        Ok(Self { threshold, pubkeys })
    }

    /// The position of `key` among the members, if it is one.
    pub fn find_member_index(&self, key: &AnyPubKey) -> Option<usize> {
        self.pubkeys.iter().position(|k| k == key)
    }
}

impl AminoBinary for MultisigPubKey {
    fn encode_fields(&self, w: &mut Writer) {
        w.uint64(1, self.threshold);
        for key in &self.pubkeys {
            w.pub_key(2, key);
        }
    }
}

/// The `Any` value of a secp256k1 key: an implicit struct holding the bytes.
struct Secp256k1Bytes<'a>(&'a PubKey);

impl AminoBinary for Secp256k1Bytes<'_> {
    fn encode_fields(&self, w: &mut Writer) {
        w.bytes(1, &self.0.to_bytes());
    }
}

impl Writer {
    /// A `crypto.PubKey` interface field, as an `Any` of the concrete key.
    pub(crate) fn pub_key(&mut self, field: u32, key: &AnyPubKey) {
        match key {
            AnyPubKey::Secp256k1(k) => self.any(field, key.type_url(), &Secp256k1Bytes(k)),
            AnyPubKey::Multisig(k) => self.any(field, key.type_url(), k),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "@type")]
enum Raw {
    #[serde(rename = "/tm.PubKeySecp256k1")]
    Secp256k1(RawSecp256k1),

    #[serde(rename = "/tm.PubKeyMultisig")]
    Multisig(MultisigPubKey),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSecp256k1 {
    #[serde(with = "crate::amino::json::base64_bytes")]
    value: Vec<u8>,
}

impl Serialize for AnyPubKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            AnyPubKey::Secp256k1(key) => Raw::Secp256k1(RawSecp256k1 {
                value: key.to_bytes().to_vec(),
            })
            .serialize(serializer),
            AnyPubKey::Multisig(key) => Raw::Multisig(key.clone()).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AnyPubKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        match Raw::deserialize(deserializer)? {
            Raw::Secp256k1(raw) => {
                let bytes: [u8; 33] = raw.value.try_into().map_err(|v: Vec<u8>| {
                    D::Error::custom(format!(
                        "expected a 33-byte compressed public key, got {} bytes",
                        v.len()
                    ))
                })?;
                PubKey::from_bytes(bytes)
                    .map(AnyPubKey::Secp256k1)
                    .map_err(D::Error::custom)
            }
            Raw::Multisig(key) => MultisigPubKey::new(key.threshold, key.pubkeys, false)
                .map(AnyPubKey::Multisig)
                .map_err(D::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivKey;
    use crate::amino::json;

    fn key(seed: u8) -> PubKey {
        PrivKey::from_bytes([seed; 32]).unwrap().pub_key()
    }

    fn multisig() -> MultisigPubKey {
        MultisigPubKey::new(2, vec![key(1).into(), key(2).into(), key(3).into()], true).unwrap()
    }

    #[test]
    fn secp256k1_json_is_the_value_form() {
        // Arrange
        let any = AnyPubKey::Secp256k1(key(1));

        // Act
        let out = json::to_string(&any).unwrap();
        let back: AnyPubKey = json::from_str(&out).unwrap();

        // Assert
        assert!(out.starts_with(r#"{"@type":"/tm.PubKeySecp256k1","value":""#));
        assert_eq!(back, any);
        assert_eq!(out, json::to_string(&key(1)).unwrap());
    }

    #[test]
    fn multisig_json_inlines_threshold_and_members() {
        // Arrange
        let any = AnyPubKey::Multisig(multisig());

        // Act
        let out = json::to_string(&any).unwrap();
        let back: AnyPubKey = json::from_str(&out).unwrap();

        // Assert
        assert!(out.starts_with(r#"{"@type":"/tm.PubKeyMultisig","threshold":"2","pubkeys":[{"@type":"/tm.PubKeySecp256k1","value":""#));
        assert_eq!(back, any);
    }

    #[test]
    fn new_sorts_members_by_address_when_asked() {
        // Arrange: the reverse of address order, so sorting must change it
        let mut expected: Vec<AnyPubKey> = vec![key(1).into(), key(2).into(), key(3).into()];
        expected.sort_by_key(|k| k.address().to_bytes());
        let unsorted: Vec<AnyPubKey> = expected.iter().rev().cloned().collect();

        // Act
        let sorted = MultisigPubKey::new(2, unsorted.clone(), true).unwrap();
        let kept = MultisigPubKey::new(2, unsorted.clone(), false).unwrap();

        // Assert
        assert_eq!(sorted.pubkeys, expected);
        assert_eq!(kept.pubkeys, unsorted);
        assert_ne!(sorted, kept);
    }

    #[test]
    fn new_validates_the_threshold() {
        // Assert
        let err = MultisigPubKey::new(0, vec![key(1).into()], true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid key: multisig threshold must be positive"
        );
        let err = MultisigPubKey::new(3, vec![key(1).into(), key(2).into()], true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid key: threshold k of n multisignature: 2 < 3"
        );
    }

    #[test]
    fn any_bytes_bech32_and_address_round_trip_for_both_kinds() {
        for any in [
            AnyPubKey::Secp256k1(key(1)),
            AnyPubKey::Multisig(multisig()),
        ] {
            // Act
            let bytes = any.to_amino_any();
            let gpub = any.to_bech32();

            // Assert
            assert_eq!(AnyPubKey::from_amino_any(&bytes).unwrap(), any);
            assert_eq!(AnyPubKey::from_bech32(&gpub).unwrap(), any);
            assert!(gpub.starts_with("gpub1"));
            assert_eq!(any.to_string(), gpub);
            assert!(!any.address().is_zero());
        }
        assert_eq!(AnyPubKey::Secp256k1(key(1)).address(), key(1).address());
        assert_ne!(AnyPubKey::Multisig(multisig()).address(), key(1).address());
    }

    #[test]
    fn multisig_address_is_truncated_sha256_of_its_any() {
        // Act
        let any = AnyPubKey::Multisig(multisig());
        let digest = Sha256::digest(any.to_amino_any());

        // Assert
        assert_eq!(any.address().to_bytes(), digest[..20]);
    }

    #[test]
    fn nested_multisig_round_trips() {
        // Arrange
        let inner = AnyPubKey::Multisig(multisig());
        let outer =
            AnyPubKey::Multisig(MultisigPubKey::new(1, vec![inner, key(9).into()], true).unwrap());

        // Assert
        assert_eq!(
            AnyPubKey::from_amino_any(&outer.to_amino_any()).unwrap(),
            outer
        );
        let back: AnyPubKey = json::from_str(&json::to_string(&outer).unwrap()).unwrap();
        assert_eq!(back, outer);
    }

    #[test]
    fn from_amino_any_rejects_other_types_and_bad_keys() {
        // Assert
        let err = AnyPubKey::from_amino_any(&binary::encode_any("/tm.PubKeyEd25519", &multisig()))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "amino error: unsupported public key type \"/tm.PubKeyEd25519\""
        );
        let err = PubKey::from_bech32(&AnyPubKey::Multisig(multisig()).to_bech32()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "amino error: expected a secp256k1 public key, got /tm.PubKeyMultisig"
        );
        let err = AnyPubKey::from_bech32("g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid bech32: expected prefix \"gpub\", got \"g\""
        );
    }

    #[test]
    #[should_panic(expected = "unknown variant `/tm.PubKeyEd25519`")]
    fn json_rejects_unknown_key_types() {
        let _: AnyPubKey =
            json::from_str(r#"{"@type":"/tm.PubKeyEd25519","value":"AAAA"}"#).unwrap();
    }

    #[test]
    #[should_panic(expected = "multisig threshold must be positive")]
    fn json_validates_multisig_threshold() {
        let _: AnyPubKey =
            json::from_str(r#"{"@type":"/tm.PubKeyMultisig","threshold":"0","pubkeys":[]}"#)
                .unwrap();
    }

    #[test]
    fn compares_equal_to_a_plain_key() {
        // Assert
        assert_eq!(AnyPubKey::Secp256k1(key(1)), key(1));
        assert_ne!(AnyPubKey::Secp256k1(key(1)), key(2));
        assert_ne!(AnyPubKey::Multisig(multisig()), key(1));
        assert_eq!(
            multisig().find_member_index(&key(2).into()),
            multisig().pubkeys.iter().position(|k| *k == key(2))
        );
        assert_eq!(multisig().find_member_index(&key(7).into()), None);
    }
}
