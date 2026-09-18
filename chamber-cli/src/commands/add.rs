use anyhow::{Context, Result, bail};
use chamber::hdpath::Bip44Path;
use chamber::{Error as ChamberError, Mnemonic, Store};
use clap::Args;

use crate::io::Io;

/// Options for `chamber add`.
#[derive(Debug, Args)]
pub struct AddArgs {
    /// A name for this key, so you can refer to it later (e.g. "alice")
    pub name: String,

    /// Import in a key you already have using its recovery phrase instead
    /// of creating a brand new one
    #[arg(long)]
    pub recover: bool,

    /// Account number to use, only needed if you keep more than one key
    /// under the same recovery phrase
    #[arg(long, default_value_t = 0)]
    pub account: u32,

    /// Key number to use within an account, anly needed if you keep more
    /// than one key under the same recovery phrase
    #[arg(long, default_value_t = 0)]
    pub index: u32,
}

pub fn run(args: &AddArgs, store: &mut Store, io: &impl Io) -> Result<()> {
    if store.get_by_name(&args.name).is_ok() {
        bail!(
            "key with name \"{}\" already exist, pick a different name",
            args.name
        );
    }

    let (mnemonic, is_memonic_generated) = if args.recover {
        let phrase = io
            .prompt_line("Enter your 24 words recovery phrase: ")
            .context("failed to read the recovery phrase")?;
        let mnemonic = Mnemonic::parse(&phrase).context("invalid recovery phrase")?;
        (mnemonic, false)
    } else {
        let mnemonic = Mnemonic::generate().context("failed to generate mnemonic for new key")?;
        (mnemonic, true)
    };

    let passphrase =
        crate::commands::prompt_passphrase(io, "Enter a passphrase to encrypt your key on disk: ")?;
    let path = Bip44Path::new(args.account, args.index);

    let record = match store.add(&args.name, &mnemonic, &passphrase, path) {
        Ok(record) => record,
        Err(ChamberError::AlreadyExists(name)) => {
            bail!("key with name \"{name}\" already exist, pick a different name");
        }
        Err(err) => return Err(err.into()),
    };

    io.print_line(&format!("Added \"{}\"", record.name));
    io.print_line(&format!("  address: {}", record.address));

    if is_memonic_generated {
        print_mnemonic_warning(io, &mnemonic);
    }

    Ok(())
}

/// Show the recovery phrase with a warning.
fn print_mnemonic_warning(io: &impl Io, mnemonic: &Mnemonic) {
    io.print_line("");
    io.print_line("------------------------------------------------------------------");
    io.print_line("⚠  Write this recovery phrase down and keep it somewhere safe.");
    io.print_line("");
    io.print_line(&mnemonic.to_string());
    io.print_line("");
    io.print_line("This phrase is the ONLY way to recover this key if you lose access");
    io.print_line("to this computer. Anyone who gets hold of it can take everything it");
    io.print_line("protects, so never share it, screenshot it, or type it into anything");
    io.print_line("other than a trusted wallet. It will not be shown again.");
    io.print_line("------------------------------------------------------------------");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::testing::FakeIo;

    fn args(name: &str) -> AddArgs {
        AddArgs {
            name: name.to_string(),
            recover: false,
            account: 0,
            index: 0,
        }
    }

    fn recover_args(name: &str) -> AddArgs {
        AddArgs {
            recover: true,
            ..args(name)
        }
    }

    #[test]
    fn generates_a_new_key_by_default() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["secret pass", "secret pass"]);

        // Act
        run(&args("alice"), &mut store, &io).unwrap();

        // Assert
        let record = store.get_by_name("alice").unwrap();
        assert!(record.address.starts_with("g1"));
        assert!(
            io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Write this recovery phrase down"))
        );
    }

    #[test]
    fn recovers_from_an_existing_phrase_without_reprinting_it() {
        // Arrange
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        let io = FakeIo::with_answers([mnemonic.to_string(), "pass".into(), "pass".into()]);

        // Act
        run(&recover_args("bob"), &mut store, &io).unwrap();

        // Assert
        assert!(store.get_by_name("bob").is_ok());
        assert!(
            !io.printed
                .borrow()
                .iter()
                .any(|l| l.contains("Write this recovery phrase down"))
        );
    }

    #[test]
    fn rejects_an_invalid_recovery_phrase() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["not a real phrase"]);

        // Act
        let err = run(&recover_args("bob"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("invalid recovery phrase"));
    }

    #[test]
    fn rejects_a_duplicate_name_before_prompting_for_anything() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["secret pass", "secret pass"]);
        run(&args("alice"), &mut store, &io).unwrap();

        // Act
        let empty_io = FakeIo::default();
        let err = run(&args("alice"), &mut store, &empty_io).unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .contains("key with name \"alice\" already exist")
        );
        assert!(empty_io.prompted.borrow().is_empty());
    }

    #[test]
    fn fails_when_passphrases_dont_match() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers(["first", "second"]);

        // Act
        let err = run(&args("alice"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrases don't match"));
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn fails_when_passphrase_is_empty() {
        // Arrange
        let mut store = Store::new_in_memory();
        let io = FakeIo::with_answers([""]);

        // Act
        let err = run(&args("alice"), &mut store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrase is required"));
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn account_and_index_change_the_derived_address() {
        // Arrange
        let mnemonic = Mnemonic::generate().unwrap();

        let mut store_a = Store::new_in_memory();
        let io_a = FakeIo::with_answers([mnemonic.to_string(), "pass".into(), "pass".into()]);
        run(&recover_args("bob"), &mut store_a, &io_a).unwrap();

        let mut store_b = Store::new_in_memory();
        let io_b = FakeIo::with_answers([mnemonic.to_string(), "pass".into(), "pass".into()]);
        run(
            &AddArgs {
                account: 1,
                ..recover_args("bob")
            },
            &mut store_b,
            &io_b,
        )
        .unwrap();

        // Assert
        assert_ne!(
            store_a.get_by_name("bob").unwrap().address,
            store_b.get_by_name("bob").unwrap().address,
        );
    }
}
