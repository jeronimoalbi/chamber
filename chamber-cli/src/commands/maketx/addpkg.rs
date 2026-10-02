use std::path::PathBuf;

use anyhow::{Context, Result};
use chamber::tx::{MemPackage, MsgAddPackage};
use chamber::{Coins, Msg, Store};
use clap::Args;

use super::{CommonArgs, caller_address, emit};
use crate::io::Io;

/// Options for `chamber maketx addpkg`.
#[derive(Debug, Args)]
pub struct AddPkgArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Package path to publish at, e.g. "gno.land/r/demo/hello"
    #[arg(long, value_name = "PATH")]
    pub pkgpath: String,

    /// Directory holding the package files
    #[arg(long, value_name = "DIR")]
    pub pkgdir: PathBuf,

    /// Coins to send along
    #[arg(long, value_name = "COINS", default_value = "")]
    pub send: String,

    /// Maximum storage deposit
    #[arg(long, value_name = "COINS", default_value = "")]
    pub max_deposit: String,
}

pub fn run(args: &AddPkgArgs, store: &Store, io: &impl Io) -> Result<()> {
    let package = MemPackage::read_dir(&args.pkgdir, &args.pkgpath)
        .with_context(|| format!("failed to read package at {}", args.pkgdir.display()))?;
    let msg = Msg::AddPackage(MsgAddPackage {
        creator: caller_address(store, &args.common)?,
        package,
        send: Coins::parse(&args.send).context("invalid --send amount")?,
        max_deposit: Coins::parse(&args.max_deposit).context("invalid --max-deposit amount")?,
    });
    emit(&args.common, msg, io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::maketx::testing::*;
    use crate::io::testing::FakeIo;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../chamber/tests/fixtures/hello")
    }

    #[test]
    fn builds_an_addpkg_from_a_directory() {
        // Arrange
        let (store, alice) = store_with_alice();
        let args = AddPkgArgs {
            common: common("alice"),
            pkgpath: "gno.land/r/demo/hello".into(),
            pkgdir: fixture(),
            send: "1ugnot".into(),
            max_deposit: String::new(),
        };
        let io = FakeIo::default();

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let tx = printed_tx(&io);
        let Msg::AddPackage(msg) = &tx.msgs[0] else {
            panic!("expected MsgAddPackage")
        };
        assert_eq!(msg.creator, alice);
        assert_eq!(msg.package.name, "hello");
        assert_eq!(msg.package.files.len(), 6);
        assert_eq!(
            msg.package.r#type,
            Some(chamber::tx::MemPackageType::user_all())
        );
        assert_eq!(msg.send, Coins::parse("1ugnot").unwrap());
    }

    #[test]
    fn bad_directory_or_path_is_an_error() {
        // Arrange
        let (store, _) = store_with_alice();
        let io = FakeIo::default();
        let args = AddPkgArgs {
            common: common("alice"),
            pkgpath: "hello".into(),
            pkgdir: fixture(),
            send: String::new(),
            max_deposit: String::new(),
        };

        // Assert
        let err = run(&args, &store, &io).unwrap_err();
        assert!(err.to_string().starts_with("failed to read package at"));
        assert!(format!("{err:#}").contains("expected user package path"));
    }
}
