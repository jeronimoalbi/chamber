use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chamber::{Error as ChamberError, Store, export};
use clap::Args;

use crate::commands::prompt_passphrase;
use crate::io::Io;

/// Options for `chamber import`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// File containing the export bundle to import
    pub input: PathBuf,

    /// Name to give the imported key (defaults to the name it had when exported)
    #[arg(long)]
    pub name: Option<String>,
}

pub fn run(args: &ImportArgs, store: &mut Store, io: &impl Io) -> Result<()> {
    let armored = fs::read_to_string(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;
    let bundle = export::decode_armor(&armored).with_context(|| {
        format!(
            "{} is not a valid chamber export bundle",
            args.input.display()
        )
    })?;

    let name = args.name.clone().unwrap_or_else(|| bundle.name.clone());
    if store.get_by_name(&name).is_ok() {
        bail!("key with name \"{name}\" already exist, pick a different name");
    }

    let transfer_passphrase = io
        .prompt_password("Enter the transfer passphrase chosen at export time: ")
        .context("failed to read the passphrase")?;

    match bundle.verify_transfer_passphrase(&transfer_passphrase) {
        Ok(()) => {}
        Err(ChamberError::Decrypt) => bail!("wrong transfer passphrase, nothing imported"),
        Err(err) => return Err(err.into()),
    }

    let store_passphrase =
        prompt_passphrase(io, "Enter a passphrase to encrypt the key on disk: ")?;

    let record = match store.import_key(&name, &bundle, &transfer_passphrase, &store_passphrase) {
        Ok(record) => record,
        Err(ChamberError::AlreadyExists(name)) => {
            bail!("key with name \"{name}\" already exist, pick a different name");
        }
        Err(ChamberError::Decrypt) => bail!("wrong transfer passphrase, nothing imported"),
        Err(err) => return Err(err.into()),
    };

    io.print_line(&format!("Imported \"{}\"", record.name));
    io.print_line(&format!("  address: {}", record.address));

    Ok(())
}

#[cfg(test)]
mod tests {
    use chamber::hdpath::Bip44Path;
    use chamber::{Mnemonic, Store};

    use super::*;
    use crate::io::testing::FakeIo;

    fn args(input: PathBuf, name: Option<&str>) -> ImportArgs {
        ImportArgs {
            input,
            name: name.map(str::to_string),
        }
    }

    fn bundle_file(name: &str, source_pass: &str, transfer_pass: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add(name, &mnemonic, source_pass, Bip44Path::new(0, 0))
            .unwrap();
        let bundle = store.export_key(name, source_pass, transfer_pass).unwrap();
        let armored = export::encode_armor(&bundle).unwrap();
        std::fs::write(dir.path().join("bundle.chamberkey"), armored).unwrap();
        dir
    }

    #[test]
    fn imports_a_key_from_a_valid_bundle() {
        // Arrange
        let dir = bundle_file("alice", "source-pass", "transfer-pass");
        let path = dir.path().join("bundle.chamberkey");
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["transfer-pass", "dst-pass", "dst-pass"]);

        // Act
        run(&args(path, None), &mut store, &io).unwrap();

        // Assert
        assert!(store.get_by_name("alice").is_ok());
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Imported \"alice\""))
        );
    }

    #[test]
    fn allows_overriding_the_imported_name_via_flag() {
        // Arrange
        let dir = bundle_file("alice", "source-pass", "transfer-pass");
        let path = dir.path().join("bundle.chamberkey");
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["transfer-pass", "dst-pass", "dst-pass"]);

        // Act
        run(&args(path, Some("bob")), &mut store, &io).unwrap();

        // Assert
        assert!(store.get_by_name("bob").is_ok());
        assert!(store.get_by_name("alice").is_err());
    }

    #[test]
    fn fails_for_a_malformed_bundle_file_without_prompting() {
        // Arrange
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bogus.chamberkey");
        std::fs::write(&path, "not an export bundle").unwrap();
        let mut store = Store::new_in_memory();
        let io = FakeIo::default();

        // Act
        let err = run(&args(path, None), &mut store, &io).unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .contains("is not a valid chamber export bundle")
        );
        assert!(io.prompted.borrow().is_empty());
    }

    #[test]
    fn fails_for_duplicate_name_before_prompting() {
        // Arrange
        let dir = bundle_file("alice", "source-pass", "transfer-pass");
        let path = dir.path().join("bundle.chamberkey");
        let mut store = Store::new_in_memory();
        seed_existing(&mut store, "alice");
        let io = FakeIo::default();

        // Act
        let err = run(&args(path, None), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("already exist"));
        assert!(io.prompted.borrow().is_empty());
    }

    #[test]
    fn fails_with_wrong_transfer_passphrase() {
        // Arrange
        let dir = bundle_file("alice", "source-pass", "transfer-pass");
        let path = dir.path().join("bundle.chamberkey");
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["wrong-pass"]);

        // Act
        let err = run(&args(path, None), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("wrong transfer passphrase"));
        assert_eq!(io.prompted.borrow().len(), 1);
        assert!(store.get_by_name("alice").is_err());
    }

    #[test]
    fn fails_when_new_store_passphrase_confirmation_mismatches() {
        // Arrange
        let dir = bundle_file("alice", "source-pass", "transfer-pass");
        let path = dir.path().join("bundle.chamberkey");
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["transfer-pass", "first", "second"]);

        // Act
        let err = run(&args(path, None), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrases don't match"));
        assert!(store.get_by_name("alice").is_err());
    }

    fn seed_existing(store: &mut Store, name: &str) {
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add(name, &mnemonic, "pass", Bip44Path::new(0, 0))
            .unwrap();
    }
}
