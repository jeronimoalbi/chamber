# Chamber

A Rust wallet library for [gno.land](https://gno.land).

[![Build Status][ci-badge]][ci-url]
[![MIT licensed][mit-badge]][mit-url]

Chamber provides key generation, HD derivation, addresses, secp256k1
signing, and an encrypted keystore. The crate is `#![forbid(unsafe_code)]`.

> **TODO**: Transaction building and signing

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
```

## License

This project is licensed under the [MIT license][mit-url].

[ci-badge]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/jeronimoalbi/chamber/blob/master/LICENSE
