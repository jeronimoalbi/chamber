# Chamber

A Rust wallet library for [gno.land](https://gno.land).

[![Build Status][ci-badge]][ci-url]
[![MIT licensed][mit-badge]][mit-url]

Chamber provides key generation, HD derivation, addresses, secp256k1
signing, and an encrypted keystore. The crate is `#![forbid(unsafe_code)]`.

> **TODO**: Transaction building and signing

## Features

| | |
|---|---|
| **Mnemonics** | BIP39, 24-word English, empty passphrase |
| **HD derivation** | BIP32/BIP44 `44'/118'/account'/0/index`, byte-compatible with `tm2/pkg/crypto/hd` |
| **Keys** | secp256k1 33-byte compressed public keys |
| **Addresses** | `RIPEMD160(SHA256(pubkey))`, bech32 `g1…` (BIP-173) |
| **Signing** | `ECDSA(SHA-256(msg))`, RFC-6979 deterministic, `gnokey` compatible, low-S, 64-byte `R‖S` |
| **Keystore** | Argon2id + XChaCha20-Poly1305, one JSON file per key |

## Example

```rust
use chamber::{Mnemonic, PrivKey, Store, hdpath::Bip44Path};

// Generate a new address from a fresh 24-word mnemonic
let m = Mnemonic::generate()?;
let key = PrivKey::from_mnemonic(&m, Bip44Path::default())?;
println!("{}", key.pub_key().address());

// Sign arbitrary bytes
let sig = key.sign(b"hello");
assert!(key.pub_key().verify(b"hello", &sig));

// Encrypt on disk
let store = Store::open("~/.chamber")?;
store.add("main", &m, "passphrase", Bip44Path::default())?;
let key = store.unlock("main", "passphrase")?;
```

Keys can be moved to `gnokey` through the mnemonic:

```rust
let phrase = store
    .reveal_mnemonic("main", "passphrase")
    .unwrap()
    .as_str();
println!("Paste phrase into `gnokey add imported --recover`:\n{phrase}");
```

## License

This project is licensed under the [MIT license][mit-url].

[ci-badge]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/jeronimoalbi/chamber/blob/master/LICENSE
