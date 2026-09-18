use anyhow::{Context, Result, bail};
use chamber::{Error as ChamberError, Store};
use clap::Args;

use crate::io::Io;

/// Options for `chamber delete`.
#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Name of the key to delete
    pub name: String,
}

pub fn run(args: &DeleteArgs, store: &mut Store, io: &impl Io) -> Result<()> {
    if store.get_by_name(&args.name).is_err() {
        bail!("no key named \"{}\"", args.name);
    }

    let passphrase = io
        .prompt_password(&format!(
            "Enter the passphrase for \"{}\" to confirm deletion: ",
            args.name
        ))
        .context("failed to read the passphrase")?;

    // Verify the passphrase before removing anything
    match store.unlock(&args.name, &passphrase) {
        // A tampered record still proves the passphrase was right
        Ok(_) | Err(ChamberError::Tampered(_)) => {}
        Err(ChamberError::Decrypt) => bail!("wrong passphrase, nothing deleted"),
        Err(err) => return Err(err.into()),
    }

    store.delete(&args.name)?;
    io.print_line(&format!("Deleted \"{}\"", args.name));

    Ok(())
}

#[cfg(test)]
mod tests {
    use chamber::Mnemonic;
    use chamber::backend::{Backend, MemoryBackend};
    use chamber::hdpath::Bip44Path;

    use super::*;
    use crate::io::testing::FakeIo;

    fn args(name: &str) -> DeleteArgs {
        DeleteArgs {
            name: name.to_string(),
        }
    }

    fn seed(store: &mut Store, name: &str, passphrase: &str) {
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add(name, &mnemonic, passphrase, Bip44Path::new(0, 0))
            .unwrap();
    }

    #[test]
    fn deletes_a_key_with_the_correct_passphrase() {
        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "secret pass");
        let io = FakeIo::with_answers(["secret pass"]);

        // Act
        run(&args("alice"), &mut store, &io).unwrap();

        // Assert
        assert!(store.get_by_name("alice").is_err());
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Deleted \"alice\""))
        );
    }

    #[test]
    fn fails_for_a_nonexistent_key_without_prompting() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::default();

        // Act
        let err = run(&args("ghost"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("no key named \"ghost\""));
        assert!(io.prompted.borrow().is_empty());
    }

    #[test]
    fn deletes_a_tampered_record_given_the_right_passphrase() {
        //! A tampered record is the one a user most needs to remove, and
        //! reaching the tamper check already proves the passphrase was
        //! right, so deletion must still go through.

        // Arrange
        let mut seeded = Store::new_in_memory();
        seed(&mut seeded, "alice", "secret pass");
        let mut record = seeded.get_by_name("alice").unwrap();
        record.address = "g1attackercontrolledaddress00000000000".to_string();

        let mut backend = MemoryBackend::new();
        backend.insert(record).unwrap();
        let mut store = Store::new(backend);
        let io = FakeIo::with_answers(["secret pass"]);

        // Act
        run(&args("alice"), &mut store, &io).unwrap();

        // Assert
        assert!(store.get_by_name("alice").is_err());
    }

    #[test]
    fn a_tampered_record_still_needs_the_right_passphrase_to_delete() {
        // Arrange
        let mut seeded = Store::new_in_memory();
        seed(&mut seeded, "alice", "secret pass");
        let mut record = seeded.get_by_name("alice").unwrap();
        record.address = "g1attackercontrolledaddress00000000000".to_string();

        let mut backend = MemoryBackend::new();
        backend.insert(record).unwrap();
        let mut store = Store::new(backend);
        let io = FakeIo::with_answers(["wrong pass"]);

        // Act
        let err = run(&args("alice"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("wrong passphrase"));
        assert!(store.get_by_name("alice").is_ok());
    }

    #[test]
    fn fails_with_wrong_passphrase_and_leaves_the_key_intact() {
        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "secret pass");
        let io = FakeIo::with_answers(["wrong pass"]);

        // Act
        let err = run(&args("alice"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("wrong passphrase"));
        assert!(store.get_by_name("alice").is_ok());
    }
}
