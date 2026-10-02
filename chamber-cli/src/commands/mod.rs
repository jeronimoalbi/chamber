pub mod add;
pub mod delete;
pub mod export;
pub mod import;
pub mod list;
pub mod maketx;
pub mod multisign;
pub mod sign;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::io::Io;

/// Ask for a new passphrase twice, failing if it's empty or the two entries don't match.
pub(crate) fn prompt_passphrase(io: &impl Io, prompt: &str) -> Result<Zeroizing<String>> {
    let first = io
        .prompt_password(prompt)
        .context("failed to read the passphrase")?;
    if first.is_empty() {
        bail!("a passphrase is required to protect this key");
    }

    let second = io
        .prompt_password("Repeat the passphrase: ")
        .context("failed to read the passphrase")?;
    if first != second {
        bail!("passphrases don't match");
    }

    Ok(first)
}

#[cfg(test)]
mod tests {
    use chamber::Store;

    use super::*;
    use crate::commands::{export, import};
    use crate::io::testing::FakeIo;

    #[test]
    fn prompt_password_rejects_empty_input() {
        // Arrange
        let io = FakeIo::with_answers([""]);

        // Act
        let err = prompt_passphrase(&io, "Enter a passphrase: ").unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrase is required"));
    }

    #[test]
    fn prompt_password_rejects_mismatch() {
        // Arrange
        let io = FakeIo::with_answers(["first", "second"]);

        // Act
        let err = prompt_passphrase(&io, "Enter a passphrase: ").unwrap_err();

        // Assert
        assert!(err.to_string().contains("passphrases don't match"));
    }

    #[test]
    fn prompt_password_returns_the_matching_value() {
        // Arrange
        let io = FakeIo::with_answers(["secret", "secret"]);

        // Act
        let passphrase = prompt_passphrase(&io, "Enter a passphrase: ").unwrap();

        // Assert
        assert_eq!(passphrase.as_str(), "secret");
    }

    #[test]
    fn round_trips_a_key_from_export_to_a_fresh_store() {
        // Arrange
        let mut src = Store::new_in_memory();
        let mnemonic = chamber::Mnemonic::generate().unwrap();
        src.add(
            "alice",
            &mnemonic,
            "store-pass",
            chamber::hdpath::Bip44Path::new(0, 0),
        )
        .unwrap();

        let original_address = src.get_by_name("alice").unwrap().address;

        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("alice.chamberkey");

        let export_io = FakeIo::with_answers(["store-pass", "transfer-pass", "transfer-pass"]);
        export::run(
            &export::ExportArgs {
                name: "alice".to_string(),
                output: bundle_path.clone(),
            },
            &src,
            &export_io,
        )
        .unwrap();

        let mut dst = Store::new_in_memory();
        let import_io = FakeIo::with_answers(["transfer-pass", "dst-pass", "dst-pass"]);

        // Act
        import::run(
            &import::ImportArgs {
                input: bundle_path,
                name: None,
            },
            &mut dst,
            &import_io,
        )
        .unwrap();

        // Assert
        assert_eq!(dst.get_by_name("alice").unwrap().address, original_address);
    }
}
