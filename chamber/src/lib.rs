//! A Rust wallet library for gno.land: keys, addresses, an encrypted keystore,
//! and transaction building, signing and multisig compatible with `gnokey`.
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
//!
//! // Sign a transaction, exactly like `gnokey sign` would
//! use chamber::tx::MsgSend;
//! use chamber::{Coin, Coins, Fee, Msg, SignOpts, Tx};
//!
//! let msg = Msg::Send(MsgSend {
//!     from_address: key.pub_key().address(),
//!     to_address: "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj".parse().unwrap(),
//!     amount: Coins::parse("1000000ugnot").unwrap(),
//! });
//! let fee = Fee::new(200_000, Coin::parse("1000000ugnot").unwrap());
//! let mut tx = Tx::new(vec![msg], fee, "");
//! let opts = SignOpts { chain_id: "dev".into(), ..Default::default() };
//! tx.sign(&key, &opts).unwrap();
//!
//! let tx_file = tx.to_amino_json().unwrap(); // for `gnokey broadcast <file>`
//! let blob = tx.to_amino_binary();           // for a node's `broadcast_tx_commit`
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
pub mod tx;

pub use address::Address;
pub use cipher::EncryptedBlob;
pub use error::{Error, Result};
pub use export::ExportBundle;
pub use key::{PrivKey, PubKey};
pub use mnemonic::Mnemonic;
pub use signer::Signer;
pub use store::Store;
pub use tx::{AnyPubKey, Coin, Coins, Fee, Msg, MultisigPubKey, SignDoc, SignOpts, Signature, Tx};
