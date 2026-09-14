//! A Rust wallet library for gno.land.
//!
//! #### Example
//!
//! ```
//! use chamber::{Mnemonic, PrivKey, hdpath::Bip44Path};
//!
//! let address = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";
//! let mnemonic = Mnemonic::parse(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon \
//!      abandon abandon abandon abandon abandon abandon abandon abandon \
//!      abandon abandon abandon abandon abandon abandon abandon art",
//! ).unwrap();
//!
//! let key = PrivKey::from_mnemonic(&mnemonic, Bip44Path::default()).unwrap();
//! assert_eq!(key.pub_key().address().to_bech32(), address);
//!
//! let sig = key.sign(b"hello");
//! assert!(key.pub_key().verify(b"hello", &sig));
//! ```

#![forbid(unsafe_code)]

pub mod address;
pub mod error;
pub mod mnemonic;

pub use address::Address;
pub use error::{Error, Result};
pub use mnemonic::Mnemonic;
