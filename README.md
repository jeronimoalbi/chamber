# Chamber

A wallet and keychain for [Gno.land](https://gno.land).

[![Work in Progress][wip-badge]][wip-url]
[![Build Status][ci-badge]][ci-url]
[![MIT licensed][mit-badge]][mit-url]

Chamber provides key generation, HD derivation, addresses, secp256k1
signing, an encrypted keystore, and transaction building, signing and
multisig that are byte-for-byte compatible with `gnokey` (`bank.MsgSend`,
`vm.MsgCall`, `vm.MsgRun` and `vm.MsgAddPackage`).

The crate is `#![forbid(unsafe_code)]`.

## Example

```rust
use std::error::Error;

use chamber::{Mnemonic, PrivKey, Store, hdpath::Bip44Path};

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a new address from a fresh 24-word mnemonic
    let mnemonic = Mnemonic::generate()?;
    let key = PrivKey::from_mnemonic(&mnemonic, Bip44Path::default())?;
    println!("{}", key.pub_key().address());

    // Sign arbitrary bytes
    let sig = key.sign_arbitrary(b"hello");
    assert!(key.pub_key().verify(b"hello", &sig));

    // Store the key encrypted on disk
    let store = Store::open("/home/alice/.chamber")?;
    store.add("alice", &mnemonic, "passphrase", Bip44Path::default())?;

    Ok(())
}
```

## Signing transactions

A transaction file produced by `gnokey maketx` can be signed with the library:

```rust
use chamber::{SignOpts, Tx};

let mut tx = Tx::from_amino_json(&std::fs::read_to_string("tx.json")?)?;
let opts = SignOpts {
    chain_id: "dev".into(),
    account_number: 8,
    sequence: 3,
    ..Default::default()
};
tx.sign(&key, &opts)?;

std::fs::write("tx.json", tx.to_amino_json()?)?; // ready for `gnokey broadcast tx.json`
let blob = tx.to_amino_binary();                 // or POST to `broadcast_tx_commit`
```

or with the CLI:

```sh
# Transfer
chamber maketx send alice --to g1... --send 1000000ugnot --gas-fee 1000000ugnot \
    --gas-wanted 200000 -o tx.json

# Realm Function Call
chamber maketx call alice --pkgpath gno.land/r/demo/boards --func CreateBoard \
    --args "my board" ...

# Package Deployment
chamber maketx addpkg alice --pkgpath gno.land/r/demo/hello --pkgdir ./hello ...

# Script Execution
chamber maketx run alice ./script.gno ...

# Sign Transaction
chamber sign alice --tx-path tx.json --chainid dev --account-number 8 \
    --account-sequence 3
```

### Multisig

A k-of-n key over keys in the store works. Members sign the same transaction with
the multisig account's number and sequence into separate signature files,
and `multisign` combines them.

```sh
# Create Multisig w/ Threshold of 2 Signatures
chamber add team --multisig alice --multisig bob --multisig carol --threshold 2

# Transfer
chamber maketx send team --to g1... --send 500ugnot --gas-fee 1000000ugnot \
    --gas-wanted 200000 -o tx.json

# Create Signatures and Sign Transaction
chamber sign alice --tx-path tx.json --account-number 20 --account-sequence 1 \
    --output-document alice.sig.json
chamber sign carol --tx-path tx.json --account-number 20 --account-sequence 1 \
    --output-document carol.sig.json
chamber multisign team --tx-path tx.json --signature alice.sig.json \
    --signature carol.sig.json
```

The library exposes the same pieces: `MultisigPubKey`, `Tx::multisign` and
`Signature::from_amino_json`.

### Sessions

A session is a key your account authorizes to sign for it, within an expiry,
a spend limit and an allow-list of message types (gno ADR-002). Create one
with any stored key as the session key, then sign with that key using the
session account's own number and sequence:

```sh
# Session Key
chamber add example

# Create Session for Alice
chamber maketx session create alice --pubkey example --expires-at 7d \
    --allow-paths "vm/exec:gno.land/r/demo/boards" --allow-paths bank/send \
    --spend-limit 1000000ugnot --spend-period 86400 --gas-fee 1000000ugnot \
    --gas-wanted 200000 -o create.json

# Master authorization
chamber sign alice --tx-path create.json ...

# Use Session
chamber maketx call example --master alice --pkgpath gno.land/r/demo/boards \
    --func CreateBoard ... -o tx.json
chamber sign example --session --tx-path tx.json --account-number <session no> \
    --account-sequence <session seq>

# Revoke Alice Session
chamber maketx session revoke alice --pubkey example ...
```

`Tx::sign_session` and the `MsgCreateSession` / `MsgRevokeSession` /
`MsgRevokeAllSessions` types are the library equivalents.

## License

This project is licensed under the [MIT license][mit-url].

[wip-badge]: https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2
[wip-url]: #chamber
[ci-badge]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/jeronimoalbi/chamber/blob/master/LICENSE
