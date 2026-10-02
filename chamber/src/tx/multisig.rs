//! Assembling member signatures into one multisig signature.

use crate::amino::binary::{AminoBinary, Writer};
use crate::error::{Error, Result};
use crate::tx::pubkey::{AnyPubKey, MultisigPubKey};
use crate::tx::{Signature, Tx};

/// Which members signed (`bitarray.CompactBitArray`): bit `i` of the array
/// is bit `7 - i%8` of byte `i/8`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactBitArray {
    extra_bits: u8,
    elems: Vec<u8>,
}

impl CompactBitArray {
    /// An all-zero array of `bits` bits.
    pub fn new(bits: usize) -> Self {
        Self {
            extra_bits: (bits % 8) as u8,
            elems: vec![0; bits.div_ceil(8)],
        }
    }

    pub fn size(&self) -> usize {
        if self.extra_bits == 0 {
            self.elems.len() * 8
        } else {
            (self.elems.len() - 1) * 8 + usize::from(self.extra_bits)
        }
    }

    pub fn get(&self, i: usize) -> bool {
        i < self.size() && self.elems[i / 8] & (1 << (7 - i % 8)) != 0
    }

    pub fn set(&mut self, i: usize) {
        assert!(
            i < self.size(),
            "bit {i} out of range for {} bits",
            self.size()
        );
        self.elems[i / 8] |= 1 << (7 - i % 8);
    }

    /// How many bits before `i` are set.
    pub fn count_before(&self, i: usize) -> usize {
        (0..i).filter(|&j| self.get(j)).count()
    }
}

impl AminoBinary for CompactBitArray {
    fn encode_fields(&self, w: &mut Writer) {
        w.uint64(1, u64::from(self.extra_bits));
        w.bytes(2, &self.elems);
    }
}

/// The signatures of some members of a multisig key, in member order, plus
/// the bit array saying which members they belong to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multisignature {
    bit_array: CompactBitArray,
    sigs: Vec<Vec<u8>>,
}

impl Multisignature {
    /// An empty multisignature for a key with `members` members.
    pub fn new(members: usize) -> Self {
        Self {
            bit_array: CompactBitArray::new(members),
            sigs: Vec::new(),
        }
    }

    /// Record member `index`'s signature, replacing an earlier one.
    pub fn add_signature(&mut self, index: usize, signature: Vec<u8>) {
        let position = self.bit_array.count_before(index);
        if self.bit_array.get(index) {
            self.sigs[position] = signature;
        } else {
            self.bit_array.set(index);
            self.sigs.insert(position, signature);
        }
    }

    /// How many members have signed.
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// The bytes that go into a [`Signature`].
    pub fn to_amino_binary(&self) -> Vec<u8> {
        Writer::encode(self)
    }
}

impl AminoBinary for Multisignature {
    fn encode_fields(&self, w: &mut Writer) {
        // Always written, even when empty
        w.message(1, true, &self.bit_array);
        w.repeated_bytes(2, self.sigs.iter().map(Vec::as_slice));
    }
}

impl MultisigPubKey {
    /// Combine member signature documents.
    pub fn combine(&self, member_signatures: &[Signature]) -> Result<Signature> {
        let mut multisig = Multisignature::new(self.pubkeys.len());
        for sig in member_signatures {
            let index = self.find_member_index(&sig.pub_key).ok_or_else(|| {
                Error::Tx(format!(
                    "signature by {} is not from a member of this multisig",
                    sig.pub_key.address()
                ))
            })?;
            multisig.add_signature(index, sig.signature.clone());
        }

        if (multisig.len() as u64) < self.threshold {
            return Err(Error::Tx(format!(
                "multisig needs {} signatures, got {}",
                self.threshold,
                multisig.len()
            )));
        }

        Ok(Signature::new(
            AnyPubKey::Multisig(self.clone()),
            multisig.to_amino_binary(),
        ))
    }
}

impl Tx {
    /// Combine member signatures for the multisig account `key` and record the result.
    pub fn multisign(
        &mut self,
        key: &MultisigPubKey,
        member_signatures: &[Signature],
    ) -> Result<Signature> {
        let signature = key.combine(member_signatures)?;
        self.add_signature(signature.clone());
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivKey;

    fn key(seed: u8) -> AnyPubKey {
        PrivKey::from_bytes([seed; 32]).unwrap().pub_key().into()
    }

    fn sig(pub_key: AnyPubKey, byte: u8) -> Signature {
        Signature {
            pub_key,
            signature: vec![byte; 64],
            session_addr: crate::address::Address::default(),
        }
    }

    #[test]
    fn bit_array_layout_is_msb_first_with_extra_bits() {
        // Arrange
        let mut bits = CompactBitArray::new(11);

        // Act
        bits.set(0);
        bits.set(9);

        // Assert
        assert_eq!(bits.size(), 11);
        assert_eq!(bits.elems, [0b1000_0000, 0b0100_0000]);
        assert_eq!(bits.extra_bits, 3);
        assert!(bits.get(0) && bits.get(9) && !bits.get(1) && !bits.get(11));
        assert_eq!(bits.count_before(10), 2);
        assert_eq!(CompactBitArray::new(8).size(), 8);
        assert_eq!(CompactBitArray::new(8).extra_bits, 0);
    }

    #[test]
    fn bit_array_encodes_as_uvarint_and_bytes() {
        // Arrange
        let mut bits = CompactBitArray::new(3);
        bits.set(1);

        // Assert
        assert_eq!(Writer::encode(&bits), [0x08, 0x03, 0x12, 0x01, 0b0100_0000]);
        assert_eq!(Writer::encode(&CompactBitArray::new(8)), [0x12, 0x01, 0x00]);
    }

    #[test]
    fn signatures_are_kept_in_member_order_and_replaced_by_index() {
        // Arrange
        let mut multisig = Multisignature::new(3);

        // Act
        multisig.add_signature(2, vec![2]);
        multisig.add_signature(0, vec![0]);
        multisig.add_signature(2, vec![22]);

        // Assert
        assert_eq!(multisig.sigs, vec![vec![0], vec![22]]);
        assert_eq!(multisig.len(), 2);
        assert!(
            multisig.bit_array.get(0) && !multisig.bit_array.get(1) && multisig.bit_array.get(2)
        );
        assert_eq!(
            multisig.to_amino_binary(),
            [
                0x0a,
                0x05,
                0x08,
                0x03,
                0x12,
                0x01,
                0b1010_0000,
                0x12,
                0x01,
                0x00,
                0x12,
                0x01,
                22
            ]
        );
    }

    #[test]
    fn combine_requires_members_and_the_threshold() {
        // Arrange
        let multisig = MultisigPubKey::new(2, vec![key(1), key(2), key(3)], true).unwrap();
        let member = |i: usize| multisig.pubkeys[i].clone();

        // Act
        let combined = multisig
            .combine(&[sig(member(2), 0xcc), sig(member(0), 0xaa)])
            .unwrap();

        // Assert
        assert_eq!(combined.pub_key, AnyPubKey::Multisig(multisig.clone()));
        assert!(combined.signature.starts_with(&[
            0x0a,
            0x05,
            0x08,
            0x03,
            0x12,
            0x01,
            0b1010_0000,
            0x12,
            0x40,
            0xaa
        ]));

        let err = multisig.combine(&[sig(member(0), 1)]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid transaction: multisig needs 2 signatures, got 1"
        );
        let err = multisig
            .combine(&[sig(member(0), 1), sig(key(9), 2)])
            .unwrap_err();
        assert!(
            err.to_string()
                .ends_with("is not from a member of this multisig")
        );
    }
}
