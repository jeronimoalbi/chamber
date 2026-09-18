# Chamber

A wallet and keychain for [Gno.land](https://gno.land).

[![Work in Progress][wip-badge]][wip-url]
[![Build Status][ci-badge]][ci-url]
[![MIT licensed][mit-badge]][mit-url]

Chamber provides key generation, HD derivation, addresses, secp256k1
signing, and an encrypted keystore.

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
    let sig = key.sign(b"hello");
    assert!(key.pub_key().verify(b"hello", &sig));

    // Store the key encrypted on disk
    let store = Store::open("/home/alice/.chamber")?;
    store.add("alice", &mnemonic, "passphrase", Bip44Path::default())?;

    Ok(())
}
```

## License

This project is licensed under the [MIT license][mit-url].

[wip-badge]: https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2
[wip-url]: #chamber
[ci-badge]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/jeronimoalbi/chamber/actions/workflows/ci.yml
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/jeronimoalbi/chamber/blob/master/LICENSE
