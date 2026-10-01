//! Canonical JSON, the form of a `SignDoc` that gets signed.
//!
//! It is the Amino-JSON encoding of the document with:
//!
//! - every object's keys sorted by byte order, recursively (`"@type"` sorts
//!   before any letter, so it always comes first),
//! - no insignificant whitespace,
//! - strings escaped as in [`json`](crate::amino::json), HTML escaping included.
//!
//! Numbers are written as-is; the transaction types have none, because 64-bit
//! integers are quoted strings.

use serde::Serialize;
use serde_json::Value;

use crate::amino::json::push_go_escaped;
use crate::error::Result;

/// Serialize `value` to canonical JSON.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    let mut out = String::new();
    write_value(&mut out, &value);
    Ok(out)
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sorted explicitly rather than relying on serde_json's map type,
            // which keeps insertion order if its `preserve_order` feature is
            // enabled anywhere in the dependency graph.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (key, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    push_go_escaped(out, s);
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_recursively_by_byte_order() {
        //! `@type` (0x40) sorts before letters, uppercase before lowercase

        // Arrange
        let value: Value = serde_json::from_str(
            r#"{"z":1,"b":{"y":[{"k":1,"@type":"t","a":2}],"B":0},"a":null,"@x":true}"#,
        )
        .unwrap();

        // Act
        let json = to_string(&value).unwrap();

        // Assert
        assert_eq!(
            json,
            r#"{"@x":true,"a":null,"b":{"B":0,"y":[{"@type":"t","a":2,"k":1}]},"z":1}"#
        );
    }

    #[test]
    fn strips_whitespace_and_keeps_array_order() {
        // Arrange
        let value: Value =
            serde_json::from_str("[ 3 , 1 ,  {\"b\" : 1, \"a\" : 2 } , false ]").unwrap();

        // Act
        let json = to_string(&value).unwrap();

        // Assert
        assert_eq!(json, r#"[3,1,{"a":2,"b":1},false]"#);
    }

    #[test]
    fn escapes_strings_like_go_in_values_and_keys() {
        // Arrange
        let value: Value = serde_json::from_str(r#"{"k<":"a<b & c>d\n"}"#).unwrap();

        // Act
        let json = to_string(&value).unwrap();

        // Assert
        assert_eq!(json, "{\"k\\u003c\":\"a\\u003cb \\u0026 c\\u003ed\\n\"}");
    }
}
