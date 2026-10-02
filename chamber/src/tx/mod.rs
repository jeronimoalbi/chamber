use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::amino::binary::{AminoBinary, Writer};
use crate::amino::canonical;
use crate::amino::json::{self, nullable_vec, quoted_i64, quoted_u64};
use crate::error::{Error, Result};
use crate::signer::Signer;

pub mod coin;
pub mod mem_package;
pub mod msg;
pub mod multisig;
pub mod pubkey;
pub mod session;

pub use coin::{Coin, Coins};
pub use msg::{
    MemFile, MemPackage, MemPackageType, Msg, MsgAddPackage, MsgCall, MsgCreateSession,
    MsgRevokeAllSessions, MsgRevokeSession, MsgRun, MsgSend,
};
pub use multisig::Multisignature;
pub use pubkey::{AnyPubKey, MultisigPubKey};

/// Largest `gas_wanted` a node accepts.
pub const MAX_GAS_WANTED: i64 = (1 << 60) - 1;

/// A transaction: messages, the fee, the signatures of every signer and a
/// memo. A new transaction is unsigned; [`Tx::sign`] adds the signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tx {
    #[serde(rename = "msg", deserialize_with = "nullable_vec::deserialize")]
    pub msgs: Vec<Msg>,
    pub fee: Fee,
    #[serde(with = "nullable_vec")]
    pub signatures: Vec<Signature>,
    pub memo: String,
}

/// The gas budget and the fee paid for it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fee {
    #[serde(with = "quoted_i64")]
    pub gas_wanted: i64,
    pub gas_fee: Coin,
}

impl Fee {
    pub fn new(gas_wanted: i64, gas_fee: Coin) -> Self {
        Self {
            gas_wanted,
            gas_fee,
        }
    }
}

/// A signer's public key and its signature over the [`SignDoc`] bytes. For a
/// multisig account the key is the multisig key and the bytes are the
/// assembled [`Multisignature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub pub_key: AnyPubKey,
    #[serde(with = "json::base64_bytes")]
    pub signature: Vec<u8>,
    /// The session account this signature was made with, for delegated
    /// signing; the zero address means the account's own key signed. Omitted
    /// from JSON when zero, but always present in the binary encoding.
    #[serde(default, skip_serializing_if = "Address::is_zero")]
    pub session_addr: Address,
}

impl Signature {
    /// A signature made with an account's own key (no session).
    pub fn new(pub_key: impl Into<AnyPubKey>, signature: Vec<u8>) -> Self {
        Self {
            pub_key: pub_key.into(),
            signature,
            session_addr: Address::default(),
        }
    }
}

/// What actually gets signed: the transaction contents plus
/// the chain and the signer's replay-protection values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignDoc {
    pub chain_id: String,
    #[serde(with = "quoted_u64")]
    pub account_number: u64,
    #[serde(with = "quoted_u64")]
    pub sequence: u64,
    pub fee: Fee,
    pub msgs: Vec<Msg>,
    pub memo: String,
}

/// The per-signer values a [`SignDoc`] needs besides the transaction itself.
/// They come from the chain (the signer's account, or the session account for
/// a session signature); chamber does no RPC, so the caller supplies them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SignOpts {
    pub chain_id: String,
    pub account_number: u64,
    pub sequence: u64,
    /// Sign the older `{"gas_fee":…,"gas_wanted":…}` rendering of the fee
    /// ([`SignDoc::sign_bytes_legacy`]) instead of the default one
    /// ([`SignDoc::sign_bytes`]). Older nodes verify only this rendering.
    pub legacy: bool,
}

impl Tx {
    /// An unsigned transaction.
    pub fn new(msgs: Vec<Msg>, fee: Fee, memo: impl Into<String>) -> Self {
        Self {
            msgs,
            fee,
            signatures: Vec::new(),
            memo: memo.into(),
        }
    }

    /// The accounts that must sign, in order and without duplicates.
    pub fn signers(&self) -> Vec<Address> {
        let mut signers = Vec::new();
        for msg in &self.msgs {
            for addr in msg.signers() {
                if !signers.contains(&addr) {
                    signers.push(addr);
                }
            }
        }

        signers
    }

    /// The stateless checks a node runs, which require the transaction to be fully signed.
    pub fn validate_basic(&self) -> Result<()> {
        if self.fee.gas_wanted > MAX_GAS_WANTED {
            return Err(Error::Tx(format!(
                "invalid gas supplied; {} > {MAX_GAS_WANTED}",
                self.fee.gas_wanted
            )));
        }

        if !self.fee.gas_fee.is_valid() {
            return Err(Error::Tx(format!(
                "invalid fee {} amount provided",
                self.fee.gas_fee
            )));
        }

        if self.signatures.is_empty() {
            return Err(Error::Tx("no signers".into()));
        }

        if self.signatures.len() != self.signers().len() {
            return Err(Error::Tx("wrong number of signers".into()));
        }

        Ok(())
    }

    /// The document one signer of this transaction signs.
    pub fn build_sign_doc(&self, opts: &SignOpts) -> SignDoc {
        SignDoc {
            chain_id: opts.chain_id.clone(),
            account_number: opts.account_number,
            sequence: opts.sequence,
            fee: self.fee.clone(),
            msgs: self.msgs.clone(),
            memo: self.memo.clone(),
        }
    }

    /// The bytes to sign for `opts`, in the rendering it selects.
    fn build_payload(&self, opts: &SignOpts) -> Result<Vec<u8>> {
        let doc = self.build_sign_doc(opts);
        if opts.legacy {
            doc.sign_bytes_legacy()
        } else {
            doc.sign_bytes()
        }
    }

    /// Sign as one of the signers and record the signature: an existing signature by the same key is replaced,
    /// otherwise the signature is appended. Sign in [`Tx::signers`] order.
    pub fn sign(&mut self, signer: &impl Signer, opts: &SignOpts) -> Result<Signature> {
        let sign_bytes = self.build_payload(opts)?;
        let signature = Signature::new(
            signer.pub_key(),
            signer.sign_arbitrary(&sign_bytes).to_vec(),
        );
        self.add_signature(signature.clone());
        Ok(signature)
    }

    /// Sign as a session account of one of the signers: the signature is made with the session key over the
    /// **session account's** number and sequence in `opts`, and carries the
    /// key's address as `session_addr` so the node looks the session up under
    /// the master it belongs to.
    pub fn sign_session(&mut self, signer: &impl Signer, opts: &SignOpts) -> Result<Signature> {
        let sign_bytes = self.build_payload(opts)?;
        let pub_key = signer.pub_key();
        let signature = Signature {
            pub_key: pub_key.into(),
            signature: signer.sign_arbitrary(&sign_bytes).to_vec(),
            session_addr: pub_key.address(),
        };
        self.add_signature(signature.clone());
        Ok(signature)
    }

    /// Record a signature made elsewhere (e.g. one produced by another tool), replacing any earlier one by the same key.
    pub fn add_signature(&mut self, signature: Signature) {
        match self
            .signatures
            .iter_mut()
            .find(|s| s.pub_key == signature.pub_key)
        {
            Some(existing) => *existing = signature,
            None => self.signatures.push(signature),
        }
    }

    /// Amino-JSON: compact, fields in declaration order, `"signatures":null`
    /// when unsigned.
    pub fn to_amino_json(&self) -> Result<String> {
        json::to_string(self)
    }

    /// Parse an Amino-JSON transaction file.
    pub fn from_amino_json(json: &str) -> Result<Self> {
        json::from_str(json)
    }

    /// Amino-binary: the blob to broadcast to a node.
    pub fn to_amino_binary(&self) -> Vec<u8> {
        Writer::encode(self)
    }
}

impl Signature {
    /// Amino-JSON of the signature.
    pub fn to_amino_json(&self) -> Result<String> {
        json::to_string(self)
    }

    /// Parse an Amino-JSON signature document.
    pub fn from_amino_json(json: &str) -> Result<Self> {
        json::from_str(json)
    }
}

/// The fee as the signature payload renders it: the Cosmos coin-list shape,
/// because the Ledger Cosmos app only signs sign docs whose fee has exactly
/// these keys. A zero fee is an empty list, not a list with an empty coin.
#[derive(Serialize)]
struct PayloadFee {
    amount: Vec<PayloadCoin>,
    gas: String,
}

#[derive(Serialize)]
struct PayloadCoin {
    denom: String,
    amount: String,
}

/// [`SignDoc`] with the fee restated.
#[derive(Serialize)]
struct Payload<'a> {
    chain_id: &'a str,
    #[serde(with = "quoted_u64")]
    account_number: u64,
    #[serde(with = "quoted_u64")]
    sequence: u64,
    fee: PayloadFee,
    msgs: &'a [Msg],
    memo: &'a str,
}

impl SignDoc {
    /// The bytes a signer signs: the canonical JSON of the document with its fee
    /// in the `{"amount":[…],"gas":…}` rendering.
    ///
    /// Older nodes verify only [`sign_bytes_legacy`](Self::sign_bytes_legacy).
    pub fn sign_bytes(&self) -> Result<Vec<u8>> {
        let amount = if self.fee.gas_fee.is_zero() {
            Vec::new()
        } else {
            vec![PayloadCoin {
                denom: self.fee.gas_fee.denom.clone(),
                amount: self.fee.gas_fee.amount.to_string(),
            }]
        };
        let payload = Payload {
            chain_id: &self.chain_id,
            account_number: self.account_number,
            sequence: self.sequence,
            fee: PayloadFee {
                amount,
                gas: self.fee.gas_wanted.to_string(),
            },
            msgs: &self.msgs,
            memo: &self.memo,
        };
        Ok(canonical::to_string(&payload)?.into_bytes())
    }

    /// The older rendering with the fee as `{"gas_fee":…,"gas_wanted":…}`:
    /// Newer nodes verify either rendering, but older nodes verify only this
    /// one, so it is the one to sign for them. See [`SignOpts::legacy`].
    pub fn sign_bytes_legacy(&self) -> Result<Vec<u8>> {
        Ok(canonical::to_string(self)?.into_bytes())
    }
}

impl AminoBinary for Tx {
    fn encode_fields(&self, w: &mut Writer) {
        for msg in &self.msgs {
            w.any(1, msg.type_url(), msg);
        }

        w.message(2, false, &self.fee);
        w.repeated_message(3, &self.signatures);
        w.string(4, &self.memo);
    }
}

impl AminoBinary for Fee {
    fn encode_fields(&self, w: &mut Writer) {
        w.sint64(1, self.gas_wanted);
        w.string(2, &self.gas_fee.to_string());
    }
}

impl AminoBinary for Signature {
    fn encode_fields(&self, w: &mut Writer) {
        w.pub_key(1, &self.pub_key);
        w.bytes(2, &self.signature);
        // A [20]byte array is never a "default value" for Amino, so its
        // bech32 form is written even when the address is zero
        w.string(3, &self.session_addr.to_bech32());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";
    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";
    const PUB_JSON: &str =
        r#"{"@type":"/tm.PubKeySecp256k1","value":"ArpmqEz3g5rxcqE+f8n15wCMuLyhWF+PO6+zA57aPB/d"}"#;

    fn addr(s: &str) -> Address {
        Address::from_bech32(s).unwrap()
    }

    fn send(from: &str, to: &str, amount: &str) -> Msg {
        Msg::Send(MsgSend {
            from_address: addr(from),
            to_address: addr(to),
            amount: Coins::parse(amount).unwrap(),
        })
    }

    fn fee() -> Fee {
        Fee::new(200_000, Coin::parse("1000000ugnot").unwrap())
    }

    fn signature() -> Signature {
        Signature {
            pub_key: json::from_str(PUB_JSON).unwrap(),
            signature: vec![1, 2, 3],
            session_addr: Address::default(),
        }
    }

    #[test]
    fn unsigned_amino_json_matches_gnokey_maketx_output() {
        // Arrange
        let tx = Tx::new(vec![send(ALICE, BOB, "1ugnot")], fee(), "");

        // Act
        let json = tx.to_amino_json().unwrap();

        // Assert
        assert_eq!(
            json,
            format!(
                r#"{{"msg":[{{"@type":"/bank.MsgSend","from_address":"{ALICE}","to_address":"{BOB}","amount":"1ugnot"}}],"fee":{{"gas_wanted":"200000","gas_fee":"1000000ugnot"}},"signatures":null,"memo":""}}"#
            )
        );
    }

    #[test]
    fn amino_json_round_trips_with_signatures() {
        // Arrange
        let mut tx = Tx::new(vec![send(ALICE, BOB, "1ugnot")], fee(), "memo <&>");
        tx.signatures.push(signature());

        // Act
        let json = tx.to_amino_json().unwrap();
        let parsed = Tx::from_amino_json(&json).unwrap();

        // Assert
        assert!(json.contains(&format!(
            r#""signatures":[{{"pub_key":{PUB_JSON},"signature":"AQID"}}]"#
        )));
        assert!(json.ends_with("\"memo\":\"memo \\u003c\\u0026\\u003e\"}"));
        assert_eq!(parsed, tx);
    }

    #[test]
    fn from_amino_json_accepts_null_msg_and_signatures() {
        // Act
        let tx = Tx::from_amino_json(
            r#"{"msg":null,"fee":{"gas_wanted":"0","gas_fee":""},"signatures":null,"memo":""}"#,
        )
        .unwrap();

        // Assert
        assert!(tx.msgs.is_empty());
        assert!(tx.signatures.is_empty());
        assert_eq!(tx.fee, Fee::default());
    }

    #[test]
    #[should_panic(expected = "unknown field `extra`")]
    fn from_amino_json_rejects_unknown_fields() {
        Tx::from_amino_json(r#"{"msg":[],"fee":{"gas_wanted":"0","gas_fee":""},"signatures":null,"memo":"","extra":1}"#).unwrap();
    }

    #[test]
    fn signers_are_deduplicated_in_first_seen_order() {
        // Arrange
        let tx = Tx::new(
            vec![
                send(BOB, ALICE, "1ugnot"),
                send(ALICE, BOB, "2ugnot"),
                send(BOB, ALICE, "3ugnot"),
            ],
            fee(),
            "",
        );

        // Assert
        assert_eq!(tx.signers(), vec![addr(BOB), addr(ALICE)]);
    }

    #[test]
    fn sign_doc_copies_tx_and_opts() {
        // Arrange
        let tx = Tx::new(vec![send(ALICE, BOB, "1ugnot")], fee(), "hi");
        let opts = SignOpts {
            chain_id: "dev".into(),
            account_number: 8,
            sequence: 3,
            ..Default::default()
        };

        // Act
        let doc = tx.build_sign_doc(&opts);

        // Assert
        assert_eq!(
            doc,
            SignDoc {
                chain_id: "dev".into(),
                account_number: 8,
                sequence: 3,
                fee: fee(),
                msgs: tx.msgs.clone(),
                memo: "hi".into()
            }
        );
    }

    #[test]
    fn validate_basic_checks_fee_and_signature_count() {
        // Arrange
        let mut tx = Tx::new(vec![send(ALICE, BOB, "1ugnot")], fee(), "");

        // Assert
        assert_eq!(
            tx.validate_basic().unwrap_err().to_string(),
            "invalid transaction: no signers"
        );
        tx.signatures.push(signature());
        assert!(tx.validate_basic().is_ok());
        tx.signatures.push(signature());
        assert_eq!(
            tx.validate_basic().unwrap_err().to_string(),
            "invalid transaction: wrong number of signers"
        );
        tx.signatures.pop();
        tx.fee.gas_wanted = MAX_GAS_WANTED + 1;
        assert!(
            tx.validate_basic()
                .unwrap_err()
                .to_string()
                .starts_with("invalid transaction: invalid gas supplied")
        );
        tx.fee = Fee::default();
        assert_eq!(
            tx.validate_basic().unwrap_err().to_string(),
            "invalid transaction: invalid fee  amount provided"
        );
    }
}

#[cfg(test)]
mod sign_tests {
    use super::*;
    use crate::PrivKey;

    const ALICE: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";
    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";

    fn key(seed: u8) -> PrivKey {
        PrivKey::from_bytes([seed; 32]).unwrap()
    }

    fn tx() -> Tx {
        let msg = Msg::Send(MsgSend {
            from_address: Address::from_bech32(ALICE).unwrap(),
            to_address: Address::from_bech32(BOB).unwrap(),
            amount: Coins::parse("1ugnot").unwrap(),
        });
        Tx::new(vec![msg], Fee::new(1, Coin::parse("1ugnot").unwrap()), "")
    }

    fn opts(sequence: u64) -> SignOpts {
        SignOpts {
            chain_id: "dev".into(),
            account_number: 1,
            sequence,
            ..Default::default()
        }
    }

    #[test]
    fn sign_bytes_are_sorted_canonical_json() {
        // Act
        let bytes = tx().build_sign_doc(&opts(0)).sign_bytes().unwrap();
        let json = String::from_utf8(bytes).unwrap();

        // Assert
        assert!(json.starts_with(r#"{"account_number":"1","chain_id":"dev","fee":{"amount":[{"amount":"1","denom":"ugnot"}],"gas":"1"},"memo":"","msgs":[{"@type":"/bank.MsgSend","amount":"1ugnot","from_address":"#));
        assert!(json.ends_with(r#""sequence":"0"}"#));
    }

    #[test]
    fn sign_bytes_render_a_zero_fee_as_an_empty_list() {
        // Arrange
        let mut tx = tx();
        tx.fee = Fee::default();

        // Act
        let json = String::from_utf8(tx.build_sign_doc(&opts(0)).sign_bytes().unwrap()).unwrap();

        // Assert
        assert!(json.contains(r#""fee":{"amount":[],"gas":"0"}"#));
    }

    #[test]
    fn legacy_sign_bytes_keep_the_tx_fee_shape() {
        // Act
        let json =
            String::from_utf8(tx().build_sign_doc(&opts(0)).sign_bytes_legacy().unwrap()).unwrap();

        // Assert
        assert!(json.contains(r#""fee":{"gas_fee":"1ugnot","gas_wanted":"1"}"#));
        assert_ne!(
            tx().build_sign_doc(&opts(0)).sign_bytes().unwrap(),
            tx().build_sign_doc(&opts(0)).sign_bytes_legacy().unwrap()
        );
    }

    #[test]
    fn session_addr_is_omitted_from_json_when_zero_but_encoded_in_binary() {
        // Arrange
        let sig = Signature::new(key(1).pub_key(), vec![7; 64]);

        // Act
        let json = json::to_string(&sig).unwrap();
        let bin = Writer::encode(&sig);
        let with_session: Signature = json::from_str(&format!(
            r#"{{"pub_key":{},"signature":"AQID","session_addr":"{ALICE}"}}"#,
            json::to_string(&key(1).pub_key()).unwrap()
        ))
        .unwrap();

        // Assert
        assert!(!json.contains("session_addr"));
        assert!(
            bin.ends_with(&[&[0x1a, 0x28][..], Address::default().to_bech32().as_bytes()].concat())
        );
        assert_eq!(
            with_session.session_addr,
            Address::from_bech32(ALICE).unwrap()
        );
        assert!(
            json::to_string(&with_session)
                .unwrap()
                .ends_with(&format!(r#""session_addr":"{ALICE}"}}"#))
        );
    }

    #[test]
    fn sign_appends_a_verifiable_signature() {
        // Arrange
        let mut tx = tx();
        let key = key(1);

        // Act
        let sig = tx.sign(&key, &opts(0)).unwrap();

        // Assert
        assert_eq!(tx.signatures, vec![sig.clone()]);
        assert_eq!(sig.pub_key, key.pub_key());
        let sign_bytes = tx.build_sign_doc(&opts(0)).sign_bytes().unwrap();
        assert!(
            key.pub_key()
                .verify(&sign_bytes, sig.signature.as_slice().try_into().unwrap())
        );
    }

    #[test]
    fn legacy_option_signs_the_legacy_payload_only() {
        // Arrange
        let mut tx = tx();
        let key = key(1);
        let legacy = SignOpts {
            legacy: true,
            ..opts(0)
        };

        // Act
        let sig = tx.sign(&key, &legacy).unwrap();

        // Assert
        let signature: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        let doc = tx.build_sign_doc(&legacy);
        assert!(
            key.pub_key()
                .verify(&doc.sign_bytes_legacy().unwrap(), &signature)
        );
        assert!(!key.pub_key().verify(&doc.sign_bytes().unwrap(), &signature));
    }

    #[test]
    fn legacy_option_applies_to_session_signatures() {
        // Arrange
        let mut tx = tx();
        let session_key = key(2);
        let legacy = SignOpts {
            legacy: true,
            ..opts(0)
        };

        // Act
        let sig = tx.sign_session(&session_key, &legacy).unwrap();

        // Assert
        let signature: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        let doc = tx.build_sign_doc(&legacy);
        assert!(
            session_key
                .pub_key()
                .verify(&doc.sign_bytes_legacy().unwrap(), &signature)
        );
        assert!(
            !session_key
                .pub_key()
                .verify(&doc.sign_bytes().unwrap(), &signature)
        );
        assert_eq!(sig.session_addr, session_key.pub_key().address());
    }

    #[test]
    fn signing_again_with_the_same_key_replaces_not_appends() {
        // Arrange
        let mut tx = tx();
        let key = key(1);
        let first = tx.sign(&key, &opts(0)).unwrap();

        // Act
        let second = tx.sign(&key, &opts(1)).unwrap();

        // Assert
        assert_ne!(first, second);
        assert_eq!(tx.signatures, vec![second]);
    }

    #[test]
    fn sign_session_sets_the_session_address_to_the_signing_key() {
        // Arrange
        let mut tx = tx();
        let session_key = key(2);

        // Act
        let sig = tx.sign_session(&session_key, &opts(0)).unwrap();

        // Assert
        assert_eq!(sig.session_addr, session_key.pub_key().address());
        assert_eq!(sig.pub_key, session_key.pub_key());
        assert!(tx.validate_basic().is_ok());
        let json = tx.to_amino_json().unwrap();
        assert!(json.contains(&format!(
            r#""session_addr":"{}""#,
            session_key.pub_key().address()
        )));
        assert_eq!(Tx::from_amino_json(&json).unwrap(), tx);
    }

    #[test]
    fn signing_with_another_key_appends_in_order() {
        // Arrange
        let mut tx = tx();

        // Act
        tx.sign(&key(1), &opts(0)).unwrap();
        tx.sign(&key(2), &opts(0)).unwrap();

        // Assert
        let keys: Vec<AnyPubKey> = tx.signatures.iter().map(|s| s.pub_key.clone()).collect();
        assert_eq!(
            keys,
            vec![
                AnyPubKey::Secp256k1(key(1).pub_key()),
                AnyPubKey::Secp256k1(key(2).pub_key())
            ]
        );
    }

    #[test]
    fn amino_binary_is_bare_and_omits_empty_fee_and_memo() {
        // Arrange
        let mut tx = tx();
        tx.fee = Fee::default();

        // Act
        let bytes = tx.to_amino_binary();

        // Assert: one Any for the message (field 1, length-delimited) and nothing else
        assert_eq!(bytes[0], 0x0a);
        let len = usize::from(bytes[1]);
        assert_eq!(bytes.len(), 2 + len);
        assert!(bytes[2..].starts_with(&[0x0a, 0x0d]));
        assert_eq!(&bytes[4..17], b"/bank.MsgSend");
    }
}
