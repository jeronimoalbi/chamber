//! Amino-binary: proto3 wire format with `google.protobuf.Any` for interface
//! values.
//!
//! Rules that matter for the transaction types:
//!
//! - Field numbers are the field declaration order, 1-based; wire types are
//!   varint for ints and length-delimited for everything else.
//! - Signed 64-bit integers are zigzag varints (proto `sint64`); unsigned ones
//!   are plain varints.
//! - Addresses and coins are encoded in their string form.
//! - Default values are not written: empty strings/bytes/lists, zero ints, and
//!   embedded structs that encode to nothing, except that an optional struct
//!   that is present is always written (an empty one as a zero length).
//! - Repeated fields are unpacked: one length-delimited entry per element,
//!   always written, even for an empty element.
//! - An interface value is an `Any`: field 1 the type URL, field 2 the bare
//!   encoding of the concrete value (an implicit single-field struct for a
//!   non-struct value such as a public key), omitted when empty.
//! - The top-level value is bare: no length prefix, no outer `Any`.

use crate::error::{Error, Result};

const WIRE_VARINT: u8 = 0;
const WIRE_BYTES: u8 = 2;

/// Something with an Amino-binary encoding as a struct, i.e. a sequence of
/// numbered fields.
pub(crate) trait AminoBinary {
    /// Write the struct's fields, in order, without any framing.
    fn encode_fields(&self, w: &mut Writer);
}

/// An Amino-binary encoder for one struct level.
/// Every field method applies the "don't write default values" rule.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The bare encoding of one struct.
    pub(crate) fn encode(value: &impl AminoBinary) -> Vec<u8> {
        Self::encode_with(|w| value.encode_fields(w))
    }

    /// The bytes written by `f` on a fresh writer.
    pub(crate) fn encode_with(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new();
        f(&mut w);
        w.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// A `string` field; nothing for `""`.
    pub fn string(&mut self, field: u32, value: &str) {
        self.bytes(field, value.as_bytes());
    }

    /// A `bytes` field; nothing when empty.
    pub fn bytes(&mut self, field: u32, value: &[u8]) {
        if value.is_empty() {
            return;
        }

        self.write_bytes(field, value);
    }

    /// A zigzag varint (`sint64`) field; nothing for zero.
    pub fn sint64(&mut self, field: u32, value: i64) {
        if value == 0 {
            return;
        }

        self.key(field, WIRE_VARINT);
        self.uvarint(zigzag(value));
    }

    /// A plain varint (`uint64`) field; nothing for zero.
    pub fn uint64(&mut self, field: u32, value: u64) {
        if value == 0 {
            return;
        }

        self.key(field, WIRE_VARINT);
        self.uvarint(value);
    }

    /// An embedded struct field. An empty encoding is skipped, unless
    /// `write_empty` (the struct is present, though empty), in which case a
    /// zero-length entry is written.
    pub(crate) fn message(&mut self, field: u32, write_empty: bool, value: &impl AminoBinary) {
        self.message_with(field, write_empty, |w| value.encode_fields(w));
    }

    fn message_with(&mut self, field: u32, write_empty: bool, f: impl FnOnce(&mut Writer)) {
        let inner = Self::encode_with(f);
        if inner.is_empty() && !write_empty {
            return;
        }

        self.write_bytes(field, &inner);
    }

    /// A repeated struct field: one entry per element, each always written.
    pub(crate) fn repeated_message<'a, T: AminoBinary + 'a>(
        &mut self,
        field: u32,
        items: impl IntoIterator<Item = &'a T>,
    ) {
        for item in items {
            self.message(field, true, item);
        }
    }

    /// A repeated string field: one entry per element, each always written.
    pub fn repeated_string<'a>(&mut self, field: u32, items: impl IntoIterator<Item = &'a str>) {
        for item in items {
            self.write_bytes(field, item.as_bytes());
        }
    }

    /// A repeated bytes field (a list of byte strings): one entry per element, each always written.
    pub fn repeated_bytes<'a>(&mut self, field: u32, items: impl IntoIterator<Item = &'a [u8]>) {
        for item in items {
            self.write_bytes(field, item);
        }
    }

    /// An interface field holding a struct value, as an `Any`.
    pub(crate) fn any(&mut self, field: u32, type_url: &str, value: &impl AminoBinary) {
        self.message_with(field, true, |w| {
            w.any_fields(type_url, &Self::encode(value))
        });
    }

    /// An interface field holding a registered string type (e.g. a
    /// `MemPackageType`), as an `Any` whose value is the implicit struct
    /// `{1: string}`.
    pub(crate) fn any_string(&mut self, field: u32, type_url: &str, value: &str) {
        let inner = Self::encode_with(|w| w.string(1, value));
        self.message_with(field, true, |w| w.any_fields(type_url, &inner));
    }

    /// The two fields of an `Any` whose value is already encoded bare.
    pub(crate) fn any_fields(&mut self, type_url: &str, value: &[u8]) {
        self.string(1, type_url);
        if !(value.is_empty() || value == [0x00]) {
            self.write_bytes(2, value);
        }
    }

    fn write_bytes(&mut self, field: u32, value: &[u8]) {
        self.key(field, WIRE_BYTES);
        self.uvarint(value.len() as u64);
        self.buf.extend_from_slice(value);
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.uvarint((u64::from(field) << 3) | u64::from(wire));
    }

    fn uvarint(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                self.buf.push(byte);
                return;
            }

            self.buf.push(byte | 0x80);
        }
    }
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

/// A bare `Any` (`amino.MarshalAny`) of a struct value.
pub(crate) fn encode_any(type_url: &str, value: &impl AminoBinary) -> Vec<u8> {
    let bare = Writer::encode(value);
    Writer::encode_with(|w| w.any_fields(type_url, &bare))
}

/// Split a bare `Any` into its type URL and bare value bytes.
pub(crate) fn decode_any(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut reader = Reader::new(bytes);
    let mut type_url = None;
    let mut value = Vec::new();
    while !reader.is_empty() {
        match reader.key()? {
            (1, WIRE_BYTES) => {
                type_url = Some(
                    String::from_utf8(reader.bytes()?.to_vec())
                        .map_err(|_| Error::Amino("Any type URL is not UTF-8".into()))?,
                );
            }
            (2, WIRE_BYTES) => {
                value = reader.bytes()?.to_vec();
            }
            (field, wire) => {
                return Err(Error::Amino(format!(
                    "unexpected field {field} (wire type {wire}) in Any"
                )));
            }
        }
    }

    let type_url = type_url.ok_or_else(|| Error::Amino("Any without a type URL".into()))?;
    Ok((type_url, value))
}

/// A minimal proto3 reader, enough to decode the few Amino-binary values
/// chamber accepts as input (public keys inside `gpub` strings).
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The next field's number and wire type.
    pub(crate) fn key(&mut self) -> Result<(u32, u8)> {
        let key = self.uvarint()?;
        Ok(((key >> 3) as u32, (key & 0x07) as u8))
    }

    pub(crate) fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| Error::Amino("truncated varint".into()))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::Amino("varint too long".into()))
    }

    /// A length-delimited value.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.uvarint()?)
            .map_err(|_| Error::Amino("length too large".into()))?;
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.buf.len())
            .ok_or_else(|| Error::Amino("truncated length-delimited field".into()))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fields<F: Fn(&mut Writer)>(F);

    impl<F: Fn(&mut Writer)> AminoBinary for Fields<F> {
        fn encode_fields(&self, w: &mut Writer) {
            (self.0)(w)
        }
    }

    fn encode(f: impl Fn(&mut Writer)) -> Vec<u8> {
        Writer::encode(&Fields(f))
    }

    #[test]
    fn uvarint_uses_seven_bit_groups_little_endian() {
        // Act
        let mut w = Writer::new();
        w.uvarint(300);
        w.uvarint(0);
        w.uvarint(u64::MAX);

        // Assert
        assert_eq!(
            w.into_bytes(),
            [
                0xac, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
            ]
        );
    }

    #[test]
    fn sint64_is_zigzag_encoded() {
        //! Amino encodes int64 with Go's `binary.PutVarint`, which is zigzag

        // Assert
        assert_eq!(zigzag(0), 0);
        assert_eq!(zigzag(-1), 1);
        assert_eq!(zigzag(1), 2);
        assert_eq!(zigzag(-2), 3);
        assert_eq!(zigzag(i64::MAX), u64::MAX - 1);
        assert_eq!(zigzag(i64::MIN), u64::MAX);
        assert_eq!(encode(|w| w.sint64(1, 200_000)), [0x08, 0x80, 0xb5, 0x18]);
        assert_eq!(encode(|w| w.sint64(1, -3)), [0x08, 0x05]);
    }

    #[test]
    fn default_scalars_are_omitted() {
        // Assert
        assert!(encode(|w| w.string(1, "")).is_empty());
        assert!(encode(|w| w.bytes(2, &[])).is_empty());
        assert!(encode(|w| w.sint64(3, 0)).is_empty());
        assert!(encode(|w| w.uint64(4, 0)).is_empty());
        assert_eq!(encode(|w| w.string(1, "hi")), [0x0a, 0x02, b'h', b'i']);
        assert_eq!(encode(|w| w.uint64(4, 1)), [0x20, 0x01]);
    }

    #[test]
    fn empty_message_is_omitted_unless_write_empty() {
        // Arrange
        let empty = Fields(|_: &mut Writer| {});
        let full = Fields(|w: &mut Writer| w.string(1, "x"));

        // Assert
        assert!(encode(|w| w.message(2, false, &empty)).is_empty());
        assert_eq!(encode(|w| w.message(2, true, &empty)), [0x12, 0x00]);
        assert_eq!(
            encode(|w| w.message(2, false, &full)),
            [0x12, 0x03, 0x0a, 0x01, b'x']
        );
    }

    #[test]
    fn repeated_entries_are_always_written() {
        // Arrange
        let empty = Fields(|_: &mut Writer| {});

        // Assert
        assert_eq!(
            encode(|w| w.repeated_string(6, ["a", ""])),
            [0x32, 0x01, b'a', 0x32, 0x00]
        );
        assert_eq!(
            encode(|w| w.repeated_message(3, [&empty, &empty])),
            [0x1a, 0x00, 0x1a, 0x00]
        );
    }

    #[test]
    fn any_writes_type_url_and_bare_value() {
        // Arrange
        let value = Fields(|w: &mut Writer| w.string(1, "v"));
        let empty = Fields(|_: &mut Writer| {});

        // Act
        let full = encode(|w| w.any(1, "/t.T", &value));
        let no_value = encode(|w| w.any(1, "/t.T", &empty));

        // Assert
        assert_eq!(
            full,
            [
                0x0a, 0x0b, 0x0a, 0x04, b'/', b't', b'.', b'T', 0x12, 0x03, 0x0a, 0x01, b'v'
            ]
        );
        assert_eq!(no_value, [0x0a, 0x06, 0x0a, 0x04, b'/', b't', b'.', b'T']);
    }

    #[test]
    fn encode_any_and_decode_any_round_trip() {
        // Arrange
        let value = Fields(|w: &mut Writer| w.string(1, "v"));

        // Act
        let any = encode_any("/t.T", &value);
        let (url, bare) = decode_any(&any).unwrap();

        // Assert
        assert_eq!(
            any,
            [
                0x0a, 0x04, b'/', b't', b'.', b'T', 0x12, 0x03, 0x0a, 0x01, b'v'
            ]
        );
        assert_eq!(url, "/t.T");
        assert_eq!(bare, [0x0a, 0x01, b'v']);
        let (url, bare) = decode_any(&[0x0a, 0x01, b'x']).unwrap();
        assert_eq!((url.as_str(), bare.len()), ("x", 0));
    }

    #[test]
    fn decode_any_rejects_malformed_input() {
        // Assert
        assert_eq!(
            decode_any(&[]).unwrap_err().to_string(),
            "amino error: Any without a type URL"
        );
        assert_eq!(
            decode_any(&[0x0a, 0x05, b'x']).unwrap_err().to_string(),
            "amino error: truncated length-delimited field"
        );
        assert_eq!(
            decode_any(&[0x18, 0x01]).unwrap_err().to_string(),
            "amino error: unexpected field 3 (wire type 0) in Any"
        );
        assert_eq!(
            decode_any(&[0x80]).unwrap_err().to_string(),
            "amino error: truncated varint"
        );
    }

    #[test]
    fn reader_parses_varints_and_keys() {
        // Arrange
        let mut r = Reader::new(&[0xac, 0x02, 0x12, 0x02, 0xaa, 0xbb]);

        // Assert
        assert_eq!(r.uvarint().unwrap(), 300);
        assert_eq!(r.key().unwrap(), (2, WIRE_BYTES));
        assert_eq!(r.bytes().unwrap(), [0xaa, 0xbb]);
        assert!(r.is_empty());
    }
}
