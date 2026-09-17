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

    #[allow(dead_code)]
    pub_bech32: String,
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

        let raw = hdpath::derive_bip44(&seed, path).unwrap();
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
