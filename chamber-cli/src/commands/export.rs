use std::path::PathBuf;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use chamber::{Error as ChamberError, Store, export};
use clap::Args;

use crate::commands::prompt_passphrase;
use crate::io::Io;

/// Options for `chamber export`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Name of the key to export
    pub name: String,

    /// File to write the encrypted export bundle to
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: PathBuf,
}

pub fn run(args: &ExportArgs, store: &Store, io: &impl Io) -> Result<()> {
    let Ok(record) = store.get_by_name(&args.name) else {
        bail!("no key named \"{}\"", args.name);
    };

    if !record.has_private_key() {
        bail!(
            "\"{}\" is a multisig key; it has no private key to export",
            args.name
        );
    }

    let store_passphrase = io
        .prompt_password(&format!("Enter the passphrase for \"{}\": ", args.name))
        .context("failed to read the passphrase")?;

    match store.unlock(&args.name, &store_passphrase) {
        Ok(_) => {}
        Err(ChamberError::Decrypt) => bail!("wrong passphrase, nothing exported"),
        Err(err) => return Err(err.into()),
    }

    let transfer_passphrase =
        prompt_passphrase(io, "Choose a transfer passphrase for the export: ")?;

    let bundle = match store.export_key(&args.name, &store_passphrase, &transfer_passphrase) {
        Ok(bundle) => bundle,
        Err(ChamberError::NotFound(name)) => bail!("no key named \"{name}\""),
        Err(ChamberError::Decrypt) => bail!("wrong passphrase, nothing exported"),
        Err(err) => return Err(err.into()),
    };

    let armored = export::encode_armor(&bundle).context("failed to encode the export bundle")?;
    write_key_file(&args.output, &armored)
        .with_context(|| format!("failed to write {}", args.output.display()))?;

    let cur_dir = env::current_dir().unwrap_or_default();
    io.print_line(&format!(
        "Exported \"{}\" to {}",
        args.name,
        cur_dir.join(&args.output).display()
    ));
    io.print_line(&format!("  address: {}", bundle.address));

    Ok(())
}

/// Write `contents` to `path`, readable only by the current user.
#[cfg(unix)]
fn write_key_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    const OWNER_ONLY: u32 = 0o600;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(OWNER_ONLY)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.set_permissions(fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use chamber::hdpath::Bip44Path;
    use chamber::{Mnemonic, Store};

    use super::*;
    use crate::io::testing::FakeIo;

    fn args(name: &str, output: PathBuf) -> ExportArgs {
        ExportArgs {
            name: name.to_string(),
            output,
        }
    }

    fn seed(store: &mut Store, name: &str, passphrase: &str) {
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add(name, &mnemonic, passphrase, Bip44Path::new(0, 0))
            .unwrap();
    }

    #[test]
    fn exports_a_key_to_the_given_path() {
        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "store-pass");
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("alice.chamberkey");
        let io = FakeIo::with_answers(["store-pass", "transfer-pass", "transfer-pass"]);

        // Act
        run(&args("alice", output.clone()), &store, &io).unwrap();

        // Assert
        let armored = std::fs::read_to_string(&output).unwrap();
        let bundle = export::decode_armor(&armored).unwrap();
        assert_eq!(bundle.address, store.get_by_name("alice").unwrap().address);
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Exported \"alice\""))
        );
    }

    #[test]
    #[cfg(unix)]
    fn written_bundle_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "store-pass");

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("alice.chamberkey");
        std::fs::write(&output, "stale").unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o644)).unwrap();

        let io = FakeIo::with_answers(["store-pass", "transfer-pass", "transfer-pass"]);

        // Act
        run(&args("alice", output.clone()), &store, &io).unwrap();

        // Assert
        let mode = std::fs::metadata(&output).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn fails_for_a_nonexistent_key_without_prompting() {
        // Arrange
        let store = Store::new_in_memory();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("ghost.chamberkey");
        let io = FakeIo::default();

        // Act
        let err = run(&args("ghost", output.clone()), &store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("no key named \"ghost\""));
        assert!(io.prompted.borrow().is_empty());
        assert!(!output.exists());
    }

    #[test]
    fn fails_with_wrong_store_passphrase_and_writes_nothing() {
        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "store-pass");
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("alice.chamberkey");
        let io = FakeIo::with_answers(["wrong-pass"]);

        // Act
        let err = run(&args("alice", output.clone()), &store, &io).unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .contains("wrong passphrase, nothing exported")
        );
        assert_eq!(io.prompted.borrow().len(), 1);
        assert!(!output.exists());
    }

    #[test]
    fn fails_when_transfer_passphrases_dont_match_and_writes_nothing() {
        // Arrange
        let mut store = Store::new_in_memory();
        seed(&mut store, "alice", "store-pass");
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("alice.chamberkey");
        let io = FakeIo::with_answers(["store-pass", "first", "second"]);

        // Act
        let err = run(&args("alice", output.clone()), &store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrases don't match"));
        assert!(!output.exists());
    }
}
