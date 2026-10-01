//! A Rust wallet library for gno.land.
//!
//! #### Example
//!
//! ```
//! use chamber::{Mnemonic, PrivKey, Store, hdpath::Bip44Path};
//!
//! // Generate a new address from a fresh 24-word mnemonic
//! let mnemonic = Mnemonic::generate().unwrap();
//! let key = PrivKey::from_mnemonic(&mnemonic, Bip44Path::default()).unwrap();
//! println!("{}", key.pub_key().address());
//!
//! // Sign an arbitrary message
//! let sig = key.sign_arbitrary(b"hello");
//! assert!(key.pub_key().verify(b"hello", &sig));
//!
//! // Store the key encrypted on disk
//! let mut store = Store::new_in_memory();
//! store.add("alice", &mnemonic, "passphrase", Bip44Path::default()).unwrap();
//! ```

#![forbid(unsafe_code)]

mod cipher;

pub mod address;
pub mod amino;
pub mod backend;
pub mod error;
pub mod export;
pub mod hdpath;
pub mod key;
pub mod mnemonic;
pub mod signer;
pub mod store;

pub use address::Address;
pub use cipher::EncryptedBlob;
pub use error::{Error, Result};
pub use export::ExportBundle;
pub use key::{PrivKey, PubKey};
pub use mnemonic::Mnemonic;
pub use signer::Signer;
pub use store::Store;
