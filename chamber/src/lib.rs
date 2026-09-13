//! A Rust wallet library for gno.land.
//!
//! It provides:
//! * [`Mnemonic`] — BIP39 (24-word English, empty passphrase).
//! * [`hdpath`] — BIP32/BIP44 derivation (`44'/118'/account'/0/index`).
//! * [`PrivKey`] / [`PubKey`] — secp256k1 keys, `RIPEMD160(SHA256(pubkey))` addresses.
//! * [`Address`] — 20 bytes, bech32 `g1...` (BIP-173).
//! * [`PrivKey::sign`] — `ECDSA(SHA-256(msg))`, RFC-6979`.
//! * [`keystore`] / [`Store`] — Argon2id + XChaCha20-Poly1305 keys on disk.

#![forbid(unsafe_code)]

pub mod error;
pub mod mnemonic;

pub use error::{Error, Result};
pub use mnemonic::Mnemonic;
