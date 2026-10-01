use anyhow::{Context, Result};
use chamber::{AnyPubKey, Store};

use crate::io::Io;

/// List every stored key.
pub fn run(store: &Store, io: &impl Io) -> Result<()> {
    let entries = store.list().context("failed to read stored keys")?;
    if entries.is_empty() {
        io.print_line("Keystore is empty. Use \"chamber add <name>\" to add keys.");
        return Ok(());
    }

    for entry in &entries {
        io.print_line(&format!("\"{}\"", entry.name));
        io.print_line(&format!("  address: {}", entry.address));
        io.print_line(&format!("  pubkey:  {}", entry.pub_key));
        match (&entry.pub_key, entry.path) {
            (AnyPubKey::Multisig(key), _) => io.print_line(&format!(
                "  type:    multisig ({} of {} members must sign)",
                key.threshold,
                key.pubkeys.len()
            )),
            (_, Some(path)) => io.print_line(&format!("  path:    {path}")),
            (_, None) => io.print_line("  path:    n/a (imported from a raw key)"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use chamber::hdpath::Bip44Path;
    use chamber::{Mnemonic, PrivKey, Store};

    use super::*;
    use crate::io::testing::FakeIo;

    #[test]
    fn shows_a_friendly_message_when_the_store_is_empty() {
        // Arrange
        let store = Store::new_in_memory();
        let io = FakeIo::default();

        // Act
        run(&store, &io).unwrap();

        // Assert
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Keystore is empty"))
        );
    }

    #[test]
    fn lists_address_pubkey_and_path_for_a_generated_key() {
        // Arrange
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        let record = store
            .add("alice", &mnemonic, "pass", Bip44Path::new(0, 0))
            .unwrap();
        let io = FakeIo::default();

        // Act
        run(&store, &io).unwrap();

        // Assert
        let printed = io.printed.borrow().join("\n");
        assert!(printed.contains(&record.address));
        assert!(printed.contains(&record.pub_key.to_bech32()));
        assert!(printed.contains("44'/118'/0'/0/0"));
    }

    #[test]
    fn shows_not_available_for_a_key_imported_from_a_raw_key() {
        // Arrange
        let mut store = Store::new_in_memory();
        let key = PrivKey::from_bytes([7u8; 32]).unwrap();
        store.add_privkey("bob", &key, "pass").unwrap();
        let io = FakeIo::default();

        // Act
        run(&store, &io).unwrap();

        // Assert
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("n/a (imported from a raw key)"))
        );
    }

    #[test]
    fn lists_every_stored_key() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::default();
        let m1 = Mnemonic::generate().unwrap();
        let m2 = Mnemonic::generate().unwrap();
        store.add("bob", &m1, "pass", Bip44Path::new(0, 0)).unwrap();
        store
            .add("alice", &m2, "pass", Bip44Path::new(0, 0))
            .unwrap();

        // Act
        run(&store, &io).unwrap();

        // Assert
        let printed = io.printed.borrow().join("\n");
        assert!(printed.contains("bob"));
        assert!(printed.contains("alice"));
    }
}

#[cfg(test)]
mod multisig_tests {
    use chamber::hdpath::Bip44Path;
    use chamber::{Mnemonic, Store};

    use super::*;
    use crate::io::testing::FakeIo;

    #[test]
    fn shows_the_threshold_for_a_multisig_key() {
        // Arrange
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add("a", &mnemonic, "pass", Bip44Path::new(0, 0))
            .unwrap();
        store
            .add("b", &mnemonic, "pass", Bip44Path::new(0, 1))
            .unwrap();
        let record = store.add_multisig("team", 2, &["a", "b"], true).unwrap();
        let io = FakeIo::default();

        // Act
        run(&store, &io).unwrap();

        // Assert
        let printed = io.printed.borrow().join("\n");
        assert!(printed.contains(&record.address));
        assert!(printed.contains("type:    multisig (2 of 2 members must sign)"));
    }
}
