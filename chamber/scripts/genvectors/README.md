# Integration Test Vectors

Test vectors are used for some integration tests to check `chamber` generated
keys and signed transactions against the canonical **Gno.land** Go
implementation.

## Usage

You need a local checkout of <https://github.com/gnolang/gno> and Go installed
to run:

```sh
GNOROOT=/path/to/gnolang/gno ./genvectors.sh
```
The script creates a throwaway Go module that uses the local copy of
`github.com/gnolang/gno` as dependency to run `main.go` and write the files in
`../../tests/vectors/`.

gno signs the tx fee differently on its two lines (PR #6173): `master` renders it as
`{"amount":[…],"gas":…}`, while the `chain/mainnet` line (the running chain) still uses
`{"gas_fee":…,"gas_wanted":…}`. Chamber signs both (`chamber sign --legacy` picks the
second), so **run the script once per checkout**. It detects the line from
`$GNOROOT/tm2/pkg/std/doc.go` and writes:

| gno checkout       | files written                  | chamber option          |
|--------------------|--------------------------------|-------------------------|
| `master`           | `keys.json`, `txs.json`        | default                 |
| `chain/mainnet`    | `txs_legacy.json`              | `--legacy`              |

`keys.json` doesn't depend on the payload. A test checks that both `txs` files hold the same
transactions with different signatures, which catches a file generated from the wrong checkout.

## `keys.json`

Derived keys for a fixed 24-word mnemonic (`abandon ... art`) at several
BIP44 paths:

- The BIP39 seed (empty passphrase) in `seed_hex` field
- Per path `priv_hex`, `pub_hex`, `address`, `pub_bech32` and `pub_any_hex`
  (the Amino `Any` bytes the `gpub` bech32 string wraps)
- Deterministic secp256k1 signature over `sign_msg` in `sign_hex` with the
  `44'/118'/0'/0/0` path.

## `txs.json` and `txs_legacy.json`

Transactions built from the same keys and signed exactly like `gnokey sign`
does on the gno line that generated the file. Both files have the same shape and
cases. Each case has:

- `unsigned_json`: Amino JSON of the unsigned tx, as `gnokey maketx` prints it
- `signers`: `tx.GetSigners()` addresses in order
- `signatures`: per signer, the account number/sequence used, the canonical
  sign bytes (`sign_bytes_hex`) and the resulting `signature_hex`
- `signed_json`: Amino JSON of the signed tx, as `gnokey sign` saves it
- `signed_bin_hex`: Amino binary of the signed tx, what `gnokey broadcast` sends
- `valid`: whether the signed tx passes `ValidateBasic`
- a signer with `session: true` signed as a session account (`gnokey sign
  --session`): its numbers are the session account's, and the signature
  carries `session_addr`
- `multisig` (one case): the 2-of-3 key, its address and `gpub` string, each
  member's signature document and the combined signature bytes

The `addpkg_dir` case reads `../../tests/fixtures/hello` with
`gno.MustReadMemPackage`, so the Rust directory reader can be compared with it.
