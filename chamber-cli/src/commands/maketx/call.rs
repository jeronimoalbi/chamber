use anyhow::{Context, Result};
use chamber::tx::MsgCall;
use chamber::{Coins, Msg, Store};
use clap::{ArgAction, Args};

use super::{CommonArgs, emit, resolve_caller_address};
use crate::io::Io;

/// Options for `chamber maketx call`.
#[derive(Debug, Args)]
pub struct CallArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Path of the realm, e.g. "gno.land/r/demo/boards"
    #[arg(long, value_name = "PATH")]
    pub pkgpath: String,

    /// Function to call
    #[arg(long, value_name = "NAME")]
    pub func: String,

    /// Argument for the function; repeat for several
    #[arg(long, value_name = "ARG", action = ArgAction::Append)]
    pub args: Vec<String>,

    /// Coins to send along with the call
    #[arg(long, value_name = "COINS", default_value = "")]
    pub send: String,

    /// Maximum storage deposit
    #[arg(long, value_name = "COINS", default_value = "")]
    pub max_deposit: String,
}

pub fn run(args: &CallArgs, store: &Store, io: &impl Io) -> Result<()> {
    let msg = Msg::Call(MsgCall {
        caller: resolve_caller_address(store, &args.common)?,
        send: Coins::parse(&args.send).context("invalid --send amount")?,
        max_deposit: Coins::parse(&args.max_deposit).context("invalid --max-deposit amount")?,
        pkg_path: args.pkgpath.clone(),
        func: args.func.clone(),
        args: args.args.clone(),
    });
    emit(&args.common, msg, io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::maketx::testing::*;
    use crate::io::testing::FakeIo;

    #[test]
    fn builds_a_call_with_repeated_args() {
        // Arrange
        let (store, alice) = store_with_alice();
        let args = CallArgs {
            common: common("alice"),
            pkgpath: "gno.land/r/demo/boards".into(),
            func: "CreateBoard".into(),
            args: vec!["my board".into(), "<b>".into()],
            send: "100ugnot".into(),
            max_deposit: String::new(),
        };
        let io = FakeIo::default();

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let tx = printed_tx(&io);
        assert_eq!(
            tx.msgs,
            vec![Msg::Call(MsgCall {
                caller: alice,
                send: Coins::parse("100ugnot").unwrap(),
                max_deposit: Coins::empty(),
                pkg_path: "gno.land/r/demo/boards".into(),
                func: "CreateBoard".into(),
                args: vec!["my board".into(), "<b>".into()],
            })]
        );
    }
}
