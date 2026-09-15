# Integration Test Vectors

Test vectors are used for some integration tests to check `chamber` generated
keys against the canonical **Gno.land** Go implementation.

## Usage

You need a local checkout of <https://github.com/gnolang/gno> and Go installed
to run:

```sh
GNOROOT=/path/to/gnolang/gno ./genvectors.sh
```
The script creates a throwaway Go module that uses the local copy of
`github.com/gnolang/gno` as dependency to run `main.go` and write the
`../../tests/vectors/keys.json` file.

The `main.go` derives keys for a fixed 24-word mnemonic (`abandon ... art`)
at several BIP44 paths and emits:

- The BIP39 seed (empty passphrase) in `seed_hex` field
- Per path `priv_hex`, `pub_hex`, `address` and `pub_bech32`
- Deterministic secp256k1 signature over `sign_msg` in `sign_hex` with the
  `44'/118'/0'/0/0` path.
