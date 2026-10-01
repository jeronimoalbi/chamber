//! Gno.land Go compatibility tests.
//! Checks are done against golden vectors produced by the Gno.land Go
//! code (see `tests/vectors/keys.json`). Test vectors are (re)generated
//! by `scripts/genvectors/genvectors.sh`.

use chamber::hdpath::{self, Bip44Path};
use chamber::{Mnemonic, PrivKey, Store};
use serde::Deserialize;

#[derive(Deserialize)]
struct Derived {
    path: String,
    priv_hex: String,
    pub_hex: String,
    address: String,
    pub_bech32: String,
    pub_any_hex: String,
}

#[derive(Deserialize)]
struct Vectors {
    mnemonic: String,
    seed_hex: String,
    derived: Vec<Derived>,
}

fn vectors() -> Vectors {
    let raw = include_str!("vectors/keys.json");
    serde_json::from_str(raw).unwrap()
}

fn parse_bip44_path(path: &str) -> Bip44Path {
    // "44'/118'/<account>'/0/<index>"
    let parts: Vec<&str> = path.split('/').collect();
    let account = parts[2].trim_end_matches('\'').parse().unwrap();
    let index = parts[4].parse().unwrap();
    Bip44Path::new(account, index)
}

#[test]
fn seed_matches_gno() {
    let vec = vectors();
    let mnemonic = Mnemonic::parse(&vec.mnemonic).unwrap();
    assert_eq!(hex::encode(mnemonic.to_seed()), vec.seed_hex);
}

#[test]
fn derivation_matches_gno() {
    let vec = vectors();
    let mnemonic = Mnemonic::parse(&vec.mnemonic).unwrap();
    let seed = mnemonic.to_seed();

    for d in &vec.derived {
        let path = parse_bip44_path(&d.path);
        assert_eq!(path.to_string(), d.path, "path string round-trip");

        let raw = hdpath::derive_bip44(seed.as_slice(), path).unwrap();
        assert_eq!(hex::encode(raw), d.priv_hex, "priv key for {}", d.path);

        let key = PrivKey::from_bytes(raw).unwrap();
        assert_eq!(
            hex::encode(key.pub_key().to_bytes()),
            d.pub_hex,
            "pub key for {}",
            d.path
        );
        assert_eq!(
            key.pub_key().address().to_bech32(),
            d.address,
            "address for {}",
            d.path
        );

        // Same result through the high-level helper.
        let key2 = PrivKey::from_mnemonic(&mnemonic, path).unwrap();
        assert_eq!(key2.to_bytes(), key.to_bytes());
    }
}

#[test]
fn address_bech32_round_trips() {
    let vec = vectors();
    for d in &vec.derived {
        let a = chamber::Address::from_bech32(&d.address).unwrap();
        assert_eq!(a.to_bech32(), d.address);
    }
    assert!(chamber::Address::from_bech32("gpub1abc").is_err());
    assert!(chamber::Address::from_bech32("cosmos1xyz").is_err());
}

#[test]
fn store_add_list_rebuild_unlock() {
    //! This test only checks that driving real gno derived keys
    //! through the Store API reproduces the golden addresses.

    let vec = vectors();
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();

    let mnemonic = Mnemonic::parse(&vec.mnemonic).unwrap();
    let rec = store
        .add("main", &mnemonic, "pass1", Bip44Path::default())
        .unwrap();
    assert_eq!(rec.address, vec.derived[0].address);

    let rec2 = store
        .add("secondary", &mnemonic, "pass1", Bip44Path::new(1, 0))
        .unwrap();
    assert_eq!(rec2.address, vec.derived[2].address);

    // Unlock re-derives the same key
    let key = store.unlock("secondary", "pass1").unwrap();
    assert_eq!(key.pub_key().address().to_bech32(), vec.derived[2].address);

    // Address is unchanged under the new passphrase
    store.rotate("main", "pass1", "pass2").unwrap();
    assert_eq!(
        store
            .unlock("main", "pass2")
            .unwrap()
            .pub_key()
            .address()
            .to_bech32(),
        vec.derived[0].address
    );
}

mod tx_vectors {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct SignerVector {
        pub path: String,
        pub address: String,
        pub account_number: u64,
        pub sequence: u64,
        pub sign_bytes_hex: String,
        pub signature_hex: String,
        #[serde(default)]
        pub session: bool,
    }

    #[derive(Deserialize)]
    pub struct TxVector {
        pub name: String,
        pub chain_id: String,
        pub valid: bool,
        pub signers: Vec<String>,
        pub unsigned_json: String,
        pub signatures: Vec<SignerVector>,
        pub signed_json: String,
        pub signed_bin_hex: String,
        #[serde(default)]
        pub multisig: Option<MultisigVector>,
    }

    #[derive(Deserialize)]
    pub struct MemberSignature {
        pub path: String,
        pub address: String,
        pub signature_json: String,
        pub signature_hex: String,
    }

    #[derive(Deserialize)]
    pub struct MultisigVector {
        pub threshold: u64,
        pub member_paths: Vec<String>,
        pub pubkey_json: String,
        pub pubkey_any_hex: String,
        pub address: String,
        pub pub_bech32: String,
        pub account_number: u64,
        pub sequence: u64,
        pub sign_bytes_hex: String,
        pub member_signatures: Vec<MemberSignature>,
        pub combined_signature_hex: String,
    }

    #[derive(Deserialize)]
    pub struct TxVectors {
        pub mnemonic: String,
        pub cases: Vec<TxVector>,
    }

    /// The vectors from the gno line whose sign payload is the one chamber
    /// signs by default, or from the `chain/mainnet` line when `legacy`
    pub fn load(legacy: bool) -> TxVectors {
        let json = if legacy {
            include_str!("vectors/txs_legacy.json")
        } else {
            include_str!("vectors/txs.json")
        };
        serde_json::from_str(json).unwrap()
    }
}

use chamber::{SignDoc, SignOpts, Tx};

/// What a signer signs for the rendering a vector set was generated with
fn payload(doc: &SignDoc, legacy: bool) -> Vec<u8> {
    if legacy {
        doc.sign_bytes_legacy().unwrap()
    } else {
        doc.sign_bytes().unwrap()
    }
}

#[test]
fn tx_amino_json_round_trips_gnokey_files() {
    //! Every unsigned (`gnokey maketx`) and signed (`gnokey sign`) tx file
    //! parses and re-serializes byte-for-byte.

    // Multisig signatures are parsed once C2 lands; until then skip that case
    for case in [false, true].into_iter().flat_map(|legacy| {
        tx_vectors::load(legacy)
            .cases
            .into_iter()
            .filter(|c| c.multisig.is_none())
    }) {
        let unsigned = Tx::from_amino_json(&case.unsigned_json).unwrap();
        assert!(unsigned.signatures.is_empty(), "{}", case.name);
        assert_eq!(
            unsigned.to_amino_json().unwrap(),
            case.unsigned_json,
            "unsigned {}",
            case.name
        );

        let signed = Tx::from_amino_json(&case.signed_json).unwrap();
        assert_eq!(
            signed.signatures.len(),
            case.signatures.len(),
            "{}",
            case.name
        );
        assert_eq!(
            signed.to_amino_json().unwrap(),
            case.signed_json,
            "signed {}",
            case.name
        );
    }
}

#[test]
fn tx_vector_sets_differ_only_in_what_is_signed() {
    //! `txs.json` (gno master) and `txs_legacy.json` (chain/mainnet) hold the
    //! same transactions. Only the sign bytes, so the signatures, may differ;
    //! if they don't, one file was generated from the wrong gno checkout.

    let current = tx_vectors::load(false);
    let legacy = tx_vectors::load(true);
    assert_eq!(current.mnemonic, legacy.mnemonic);
    assert_eq!(current.cases.len(), legacy.cases.len());

    for (c, l) in current.cases.iter().zip(&legacy.cases) {
        assert_eq!(c.name, l.name);
        assert_eq!(c.unsigned_json, l.unsigned_json, "{}", c.name);
        assert_eq!(c.signers, l.signers, "{}", c.name);
        assert_eq!(c.signatures.len(), l.signatures.len(), "{}", c.name);
        for (cs, ls) in c.signatures.iter().zip(&l.signatures) {
            assert_ne!(cs.sign_bytes_hex, ls.sign_bytes_hex, "{}", c.name);
            assert_ne!(cs.signature_hex, ls.signature_hex, "{}", c.name);
        }
    }
}

#[test]
fn tx_signers_match_gno() {
    for case in [false, true]
        .into_iter()
        .flat_map(|legacy| tx_vectors::load(legacy).cases)
    {
        let tx = Tx::from_amino_json(&case.unsigned_json).unwrap();
        let signers: Vec<String> = tx.signers().iter().map(|a| a.to_bech32()).collect();
        assert_eq!(signers, case.signers, "{}", case.name);
    }
}

#[test]
fn tx_validate_basic_matches_gno() {
    for case in [false, true].into_iter().flat_map(|legacy| {
        tx_vectors::load(legacy)
            .cases
            .into_iter()
            .filter(|c| c.multisig.is_none())
    }) {
        let tx = Tx::from_amino_json(&case.signed_json).unwrap();
        assert_eq!(tx.validate_basic().is_ok(), case.valid, "{}", case.name);
    }
}

#[test]
fn pub_key_bech32_and_any_match_gno() {
    //! `gpub…` wraps the Amino `Any` of the key, not the raw bytes

    for d in &vectors().derived {
        let raw: [u8; 32] = hex::decode(&d.priv_hex).unwrap().try_into().unwrap();
        let pub_key = PrivKey::from_bytes(raw).unwrap().pub_key();
        assert_eq!(
            hex::encode(pub_key.to_amino_any()),
            d.pub_any_hex,
            "{}",
            d.path
        );
        assert_eq!(pub_key.to_bech32(), d.pub_bech32, "{}", d.path);
        assert_eq!(
            chamber::PubKey::from_bech32(&d.pub_bech32).unwrap(),
            pub_key,
            "{}",
            d.path
        );
    }
}

#[test]
fn tx_signing_matches_gnokey_sign_and_broadcast() {
    //! For every case: each signer's sign bytes and signature, then the
    //! signed Amino-JSON file and the Amino-binary broadcast blob, are
    //! byte-identical to what the gno implementation produces. Run for both
    //! sign payloads: the default one against `master` vectors, and the
    //! legacy one (`SignOpts::legacy`) against `chain/mainnet` vectors.

    for legacy in [false, true] {
        check_tx_signing(&tx_vectors::load(legacy), legacy);
    }
}

fn check_tx_signing(vec: &tx_vectors::TxVectors, legacy: bool) {
    let mnemonic = Mnemonic::parse(&vec.mnemonic).unwrap();

    for case in vec.cases.iter().filter(|c| c.multisig.is_none()) {
        let mut tx = Tx::from_amino_json(&case.unsigned_json).unwrap();

        for s in &case.signatures {
            let key = PrivKey::from_mnemonic(&mnemonic, parse_bip44_path(&s.path)).unwrap();
            assert_eq!(
                key.pub_key().address().to_bech32(),
                s.address,
                "{}",
                case.name
            );
            let opts = SignOpts {
                chain_id: case.chain_id.clone(),
                account_number: s.account_number,
                sequence: s.sequence,
                legacy,
            };

            let sign_bytes = payload(&tx.sign_doc(&opts), legacy);
            assert_eq!(
                hex::encode(&sign_bytes),
                s.sign_bytes_hex,
                "sign bytes (legacy: {legacy}) {} {}",
                case.name,
                s.address
            );
            assert_eq!(
                hex::encode(key.sign_arbitrary(&sign_bytes)),
                s.signature_hex,
                "(legacy: {legacy}) {}",
                case.name
            );

            let sig = if s.session {
                tx.sign_session(&key, &opts).unwrap()
            } else {
                tx.sign(&key, &opts).unwrap()
            };
            let expected_session = if s.session {
                key.pub_key().address()
            } else {
                chamber::Address::default()
            };
            assert_eq!(
                sig.session_addr, expected_session,
                "session_addr {}",
                case.name
            );
            assert_eq!(
                hex::encode(&sig.signature),
                s.signature_hex,
                "signature (legacy: {legacy}) {} {}",
                case.name,
                s.address
            );
        }

        assert_eq!(
            tx.to_amino_json().unwrap(),
            case.signed_json,
            "signed json (legacy: {legacy}) {}",
            case.name
        );
        assert_eq!(
            hex::encode(tx.to_amino_binary()),
            case.signed_bin_hex,
            "binary (legacy: {legacy}) {}",
            case.name
        );
    }
}

#[test]
fn mem_package_read_dir_matches_gno() {
    //! Reading `tests/fixtures/hello` must give exactly the package gno's
    //! `ReadMemPackage` produced for the `addpkg_dir` vector.

    let case = tx_vectors::load(false)
        .cases
        .into_iter()
        .find(|c| c.name == "addpkg_dir")
        .unwrap();
    let tx = Tx::from_amino_json(&case.unsigned_json).unwrap();
    let chamber::Msg::AddPackage(expected) = &tx.msgs[0] else {
        panic!("addpkg_dir should hold a MsgAddPackage");
    };

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello");
    let pkg = chamber::tx::MemPackage::read_dir(dir, "gno.land/r/demo/hello").unwrap();

    assert_eq!(pkg, expected.package);
}

#[test]
fn multisig_matches_gnokey_add_multisig_and_multisign() {
    //! The 2-of-3 key, its address and `gpub` string, each member's signature
    //! document and the combined signature must equal what gno produces.

    for legacy in [false, true] {
        check_multisig(&tx_vectors::load(legacy), legacy);
    }
}

fn check_multisig(vec: &tx_vectors::TxVectors, legacy: bool) {
    use chamber::tx::{AnyPubKey, MultisigPubKey, Signature};

    let mnemonic = Mnemonic::parse(&vec.mnemonic).unwrap();
    let case = vec.cases.iter().find(|c| c.multisig.is_some()).unwrap();
    let ms = case.multisig.as_ref().unwrap();
    let key_at = |path: &str| PrivKey::from_mnemonic(&mnemonic, parse_bip44_path(path)).unwrap();

    // The key: members given unsorted, sorted by address like gnokey does
    let mut members: Vec<AnyPubKey> = ms
        .member_paths
        .iter()
        .map(|p| key_at(p).pub_key().into())
        .collect();
    members.reverse();
    let multisig = MultisigPubKey::new(ms.threshold, members, true).unwrap();
    let ordered: Vec<AnyPubKey> = ms
        .member_paths
        .iter()
        .map(|p| key_at(p).pub_key().into())
        .collect();
    assert_eq!(multisig.pubkeys, ordered, "member order");

    let any = AnyPubKey::Multisig(multisig.clone());
    assert_eq!(
        chamber::amino::json::to_string(&any).unwrap(),
        ms.pubkey_json
    );
    assert_eq!(hex::encode(any.to_amino_any()), ms.pubkey_any_hex);
    assert_eq!(any.address().to_bech32(), ms.address);
    assert_eq!(any.to_bech32(), ms.pub_bech32);
    assert_eq!(AnyPubKey::from_bech32(&ms.pub_bech32).unwrap(), any);
    assert_eq!(case.signers, vec![ms.address.clone()]);

    // Each member signs with the multisig account's values
    let mut tx = Tx::from_amino_json(&case.unsigned_json).unwrap();
    let opts = SignOpts {
        chain_id: case.chain_id.clone(),
        account_number: ms.account_number,
        sequence: ms.sequence,
        legacy,
    };
    assert_eq!(
        hex::encode(payload(&tx.sign_doc(&opts), legacy)),
        ms.sign_bytes_hex,
        "legacy: {legacy}"
    );

    let mut docs = Vec::new();
    for m in &ms.member_signatures {
        let key = key_at(&m.path);
        assert_eq!(key.pub_key().address().to_bech32(), m.address);
        let mut scratch = tx.clone();
        let sig = scratch.sign(&key, &opts).unwrap();
        assert_eq!(
            hex::encode(&sig.signature),
            m.signature_hex,
            "{}",
            m.address
        );
        assert_eq!(
            sig.to_amino_json().unwrap(),
            m.signature_json,
            "{}",
            m.address
        );
        docs.push(Signature::from_amino_json(&m.signature_json).unwrap());
    }

    // Combined like `gnokey multisign`
    let combined = tx.multisign(&multisig, &docs).unwrap();
    assert_eq!(hex::encode(&combined.signature), ms.combined_signature_hex);
    assert_eq!(tx.to_amino_json().unwrap(), case.signed_json);
    assert_eq!(hex::encode(tx.to_amino_binary()), case.signed_bin_hex);
    assert_eq!(tx.validate_basic().is_ok(), case.valid);
}
