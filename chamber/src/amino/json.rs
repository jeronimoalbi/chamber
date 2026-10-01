use std::fmt::Write as _;
use std::io;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::ser::Formatter;

use crate::amino::TYPE_URL_PUBKEY_SECP256K1;
use crate::error::Result;
use crate::key::PubKey;

/// Serialize `value` as Amino-JSON. Compact, fields in declaration order, with
/// `<`, `>`, `&` and the U+2028 / U+2029 line separators escaped.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoEscape);
    value.serialize(&mut ser)?;

    // serde_json only ever writes UTF-8, and every escape is ASCII
    Ok(String::from_utf8(out).expect("serialized JSON is UTF-8"))
}

/// Parse Amino-JSON, such as the output of [`to_string`].
pub fn from_str<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T> {
    Ok(serde_json::from_str(json)?)
}

/// A `serde_json` formatter that escapes strings the way Go's `encoding/json`
/// does, on top of the JSON-mandated escapes (which serde_json already
/// applies), `<`, `>` and `&` become `<`, `>`, `&` and the U+2028 / U+2029
/// line separators become ` ` / ` `.
pub(crate) struct GoEscape;

impl Formatter for GoEscape {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        // serde_json hands over runs it considers safe, so only the
        // Go-specific escapes can trigger here; the rest is copied as-is.
        if !fragment.chars().any(needs_go_escape) {
            return writer.write_all(fragment.as_bytes());
        }

        let mut buf = String::with_capacity(fragment.len() + 16);
        push_go_escaped(&mut buf, fragment);
        writer.write_all(buf.as_bytes())
    }
}

/// Checks wether `c` is a char Go escapes and serde_json doesn't.
fn needs_go_escape(c: char) -> bool {
    matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}')
}

/// Append `s` to `out` escaped exactly like Go's `encoding/json` string
/// encoder (Go ≥ 1.22): `\" \\ \n \r \t \b \f`, other control chars as
/// `\u00XX`, plus the HTML/line-separator escapes. Everything else,
/// including non-ASCII, is copied verbatim.
pub(crate) fn push_go_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || needs_go_escape(c) => {
                // Infallible: writing to a String never fails
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Serde adapter for signed 64-bit integers, which Amino-JSON quotes.
/// Deserialization also accepts a bare number.
pub mod quoted_i64 {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &i64,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<i64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(i64),
            Str(String),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Num(n) => Ok(n),
            Raw::Str(s) => s.parse().map_err(D::Error::custom),
        }
    }
}

/// Serde adapter for unsigned 64-bit integers, which Amino-JSON quotes.
/// Deserialization also accepts a bare number.
pub mod quoted_u64 {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &u64,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }

        match Raw::deserialize(deserializer)? {
            Raw::Num(n) => Ok(n),
            Raw::Str(s) => s.parse().map_err(D::Error::custom),
        }
    }
}

/// Serde adapter for byte strings: standard base64 with padding.
pub mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &[u8],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(s).map_err(D::Error::custom)
    }
}

/// Serde adapter for lists that are `null` when empty.
/// Serializes an empty `Vec` as `null` (as in an unsigned transaction's
/// `"signatures":null`) and reads `null` back as empty.
pub mod nullable_vec {
    use super::*;

    pub fn serialize<S: Serializer, T: Serialize>(
        value: &Vec<T>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if value.is_empty() {
            serializer.serialize_none()
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<T>, D::Error> {
        Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
    }
}

/// The Amino-JSON `Any` form of a non-struct value: `{"@type": …, "value": …}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyValue {
    #[serde(rename = "@type")]
    type_url: String,
    value: String,
}

/// Serialize a string-shaped registered value as `{"@type": type_url, "value": value}`.
pub(crate) fn serialize_any_string<S: Serializer>(
    type_url: &str,
    value: &str,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    AnyValue {
        type_url: type_url.to_owned(),
        value: value.to_owned(),
    }
    .serialize(serializer)
}

/// Deserialize `{"@type": …, "value": …}`, requiring the given type URL, and
/// return the raw `value` string.
pub(crate) fn deserialize_any_string<'de, D: Deserializer<'de>>(
    expected_type_url: &str,
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let any = AnyValue::deserialize(deserializer)?;
    if any.type_url != expected_type_url {
        return Err(D::Error::custom(format!(
            "unsupported type {:?}, expected {expected_type_url:?}",
            any.type_url
        )));
    }
    Ok(any.value)
}

/// A public key is an Amino interface (`crypto.PubKey`) whose secp256k1
/// concrete type is a byte array, so it's encoded as
/// `{"@type":"/tm.PubKeySecp256k1","value":"<base64 of the 33 bytes>"}`.
impl Serialize for PubKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_any_string(
            TYPE_URL_PUBKEY_SECP256K1,
            &BASE64.encode(self.to_bytes()),
            serializer,
        )
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = deserialize_any_string(TYPE_URL_PUBKEY_SECP256K1, deserializer)
            .map_err(|e| D::Error::custom(format!("public key: {e}")))?;
        let bytes = BASE64.decode(&value).map_err(D::Error::custom)?;
        let bytes: [u8; 33] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!(
                "expected a 33-byte compressed public key, got {} bytes",
                bytes.len()
            ))
        })?;
        PubKey::from_bytes(bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_PUB_HEX: &str =
        "02ba66a84cf7839af172a13e7fc9f5e7008cb8bca1585f8f3bafb3039eda3c1fdd";
    const KNOWN_PUB_JSON: &str =
        r#"{"@type":"/tm.PubKeySecp256k1","value":"ArpmqEz3g5rxcqE+f8n15wCMuLyhWF+PO6+zA57aPB/d"}"#;

    fn known_pub_key() -> PubKey {
        let bytes: [u8; 33] = hex::decode(KNOWN_PUB_HEX).unwrap().try_into().unwrap();
        PubKey::from_bytes(bytes).unwrap()
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Doc {
        #[serde(with = "quoted_i64")]
        signed: i64,
        #[serde(with = "quoted_u64")]
        unsigned: u64,
        #[serde(with = "base64_bytes")]
        bytes: Vec<u8>,
        #[serde(with = "nullable_vec")]
        list: Vec<String>,
        text: String,
    }

    #[test]
    fn to_string_quotes_64_bit_ints_and_base64_encodes_bytes() {
        // Arrange
        let doc = Doc {
            signed: -5,
            unsigned: u64::MAX,
            bytes: vec![0xff, 0x00, 0x10],
            list: vec!["a".into()],
            text: "plain".into(),
        };

        // Act
        let json = to_string(&doc).unwrap();

        // Assert
        assert_eq!(
            json,
            r#"{"signed":"-5","unsigned":"18446744073709551615","bytes":"/wAQ","list":["a"],"text":"plain"}"#
        );
    }

    #[test]
    fn to_string_escapes_like_go() {
        //! Go's `encoding/json` HTML-escapes `<`, `>`, `&` and the U+2028/9 line
        //! separators on top of the mandatory JSON escapes.

        // Arrange
        let doc = Doc {
            signed: 0,
            unsigned: 0,
            bytes: vec![],
            list: vec![],
            text: "a<b && c>d \"q\" \\ \n\t\r\u{8}\u{c}\u{1b} \u{2028}\u{2029} ünï ☃".into(),
        };

        // Act
        let json = to_string(&doc).unwrap();

        // Assert
        assert_eq!(
            json,
            "{\"signed\":\"0\",\"unsigned\":\"0\",\"bytes\":\"\",\"list\":null,\"text\":\
             \"a\\u003cb \\u0026\\u0026 c\\u003ed \\\"q\\\" \\\\ \\n\\t\\r\\b\\f\\u001b \\u2028\\u2029 ünï ☃\"}"
        );
    }

    #[test]
    fn to_string_escapes_object_keys_too() {
        // Arrange
        let mut map = std::collections::BTreeMap::new();
        map.insert("a<b".to_string(), 1u8);

        // Act
        let json = to_string(&map).unwrap();

        // Assert
        assert_eq!(json, "{\"a\\u003cb\":1}");
    }

    #[test]
    fn from_str_round_trips_and_accepts_bare_numbers() {
        // Arrange
        let doc = Doc {
            signed: -7,
            unsigned: 42,
            bytes: b"hello".to_vec(),
            list: vec![],
            text: "<x>".into(),
        };
        let json = to_string(&doc).unwrap();

        // Act
        let parsed: Doc = from_str(&json).unwrap();
        let bare: Doc =
            from_str(r#"{"signed":-7,"unsigned":42,"bytes":"aGVsbG8=","list":null,"text":"<x>"}"#)
                .unwrap();

        // Assert
        assert_eq!(parsed, doc);
        assert_eq!(bare, doc);
    }

    #[test]
    #[should_panic(expected = "invalid digit")]
    fn from_str_rejects_non_numeric_quoted_int() {
        // Act
        let _: Doc =
            from_str(r#"{"signed":"abc","unsigned":"0","bytes":"","list":null,"text":""}"#)
                .unwrap();
    }

    #[test]
    fn pub_key_serializes_as_any_value() {
        // Act
        let json = to_string(&known_pub_key()).unwrap();

        // Assert
        assert_eq!(json, KNOWN_PUB_JSON);
    }

    #[test]
    fn pub_key_deserializes_from_any_value() {
        // Act
        let key: PubKey = from_str(KNOWN_PUB_JSON).unwrap();

        // Assert
        assert_eq!(key, known_pub_key());
    }

    #[test]
    #[should_panic(expected = "public key: unsupported type")]
    fn pub_key_rejects_other_key_types() {
        // Act
        let _: PubKey = from_str(r#"{"@type":"/tm.PubKeyEd25519","value":"AAAA"}"#).unwrap();
    }

    #[test]
    #[should_panic(expected = "expected a 33-byte compressed public key, got 3 bytes")]
    fn pub_key_rejects_wrong_length() {
        // Act
        let _: PubKey = from_str(r#"{"@type":"/tm.PubKeySecp256k1","value":"AAAA"}"#).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown field `extra`")]
    fn pub_key_rejects_unknown_fields() {
        // Act
        let _: PubKey = from_str(
            r#"{"@type":"/tm.PubKeySecp256k1","value":"ArpmqEz3g5rxcqE+f8n15wCMuLyhWF+PO6+zA57aPB/d","extra":1}"#,
        )
        .unwrap();
    }
}
