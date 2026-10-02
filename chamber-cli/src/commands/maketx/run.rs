use anyhow::{Context, Result};
use chamber::tx::{MemPackage, MsgRun};
use chamber::{Coins, Msg, Store};
use clap::Args;

use super::{CommonArgs, caller_address, emit};
use crate::io::Io;

/// Options for `chamber maketx run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// The Gno file to run, or "-" to read it from standard input
    #[arg(value_name = "FILE")]
    pub source: String,

    /// Coins to send along
    #[arg(long, value_name = "COINS", default_value = "")]
    pub send: String,

    /// Maximum storage deposit
    #[arg(long, value_name = "COINS", default_value = "")]
    pub max_deposit: String,
}

pub fn run(args: &RunArgs, store: &Store, io: &impl Io) -> Result<()> {
    let package = if args.source == "-" {
        let body = io.read_stdin().context("failed to read standard input")?;
        MemPackage::run_from_source("stdin.gno", body)
    } else {
        MemPackage::run_from_file(&args.source)
            .with_context(|| format!("failed to read {}", args.source))?
    };

    let msg = Msg::Run(MsgRun {
        caller: caller_address(store, &args.common)?,
        send: Coins::parse(&args.send).context("invalid --send amount")?,
        max_deposit: Coins::parse(&args.max_deposit).context("invalid --max-deposit amount")?,
        package,
    });
    emit(&args.common, msg, io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::maketx::testing::*;
    use crate::io::testing::FakeIo;

    fn args(source: &str) -> RunArgs {
        RunArgs {
            common: common("alice"),
            source: source.to_string(),
            send: String::new(),
            max_deposit: "1000ugnot".to_string(),
        }
    }

    #[test]
    fn builds_a_run_from_a_file() {
        // Arrange
        let (store, alice) = store_with_alice();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.gno");
        std::fs::write(&path, "package main\n\nfunc main() {}\n").unwrap();
        let io = FakeIo::default();

        // Act
        run(&args(path.to_str().unwrap()), &store, &io).unwrap();

        // Assert
        let tx = printed_tx(&io);
        let Msg::Run(msg) = &tx.msgs[0] else {
            panic!("expected MsgRun")
        };
        assert_eq!(msg.caller, alice);
        assert_eq!(msg.package.name, "main");
        assert_eq!(msg.package.files[0].name, "script.gno");
        assert_eq!(msg.package.r#type, None);
        assert_eq!(msg.max_deposit, Coins::parse("1000ugnot").unwrap());
    }

    #[test]
    fn dash_reads_the_source_from_stdin() {
        // Arrange
        let (store, _) = store_with_alice();
        let io = FakeIo::default();
        *io.stdin.borrow_mut() = "package main\n".to_string();

        // Act
        run(&args("-"), &store, &io).unwrap();

        // Assert
        let tx = printed_tx(&io);
        let Msg::Run(msg) = &tx.msgs[0] else {
            panic!("expected MsgRun")
        };
        assert_eq!(msg.package.files[0].name, "stdin.gno");
        assert_eq!(msg.package.files[0].body, "package main\n");
    }

    #[test]
    fn missing_file_is_an_error() {
        // Arrange
        let (store, _) = store_with_alice();
        let io = FakeIo::default();

        // Assert
        let err = run(&args("/nonexistent/x.gno"), &store, &io).unwrap_err();
        assert_eq!(err.to_string(), "failed to read /nonexistent/x.gno");
    }
}
