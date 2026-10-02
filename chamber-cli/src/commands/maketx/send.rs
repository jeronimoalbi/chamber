use anyhow::{Context, Result};
use chamber::tx::MsgSend;
use chamber::{Coins, Msg, Store};
use clap::Args;

use super::{CommonArgs, caller_address, emit};
use crate::io::Io;

/// Options for `chamber maketx send`.
#[derive(Debug, Args)]
pub struct SendArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Destination address
    #[arg(long, value_name = "ADDRESS")]
    pub to: String,

    /// Amount to send, e.g. "1000000ugnot"
    #[arg(long, value_name = "COINS")]
    pub send: String,
}

pub fn run(args: &SendArgs, store: &Store, io: &impl Io) -> Result<()> {
    let msg = Msg::Send(MsgSend {
        from_address: caller_address(store, &args.common)?,
        to_address: args.to.parse().context("invalid --to address")?,
        amount: Coins::parse(&args.send).context("invalid --send amount")?,
    });
    emit(&args.common, msg, io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::maketx::testing::*;
    use crate::io::testing::FakeIo;

    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";

    #[test]
    fn builds_a_send_from_the_stored_key() {
        // Arrange
        let (store, alice) = store_with_alice();
        let args = SendArgs {
            common: common("alice"),
            to: BOB.to_string(),
            send: "1000000ugnot,5atom".to_string(),
        };
        let io = FakeIo::default();

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let tx = printed_tx(&io);
        assert_eq!(
            tx.msgs,
            vec![Msg::Send(MsgSend {
                from_address: alice,
                to_address: BOB.parse().unwrap(),
                amount: Coins::parse("5atom,1000000ugnot").unwrap(),
            })]
        );
        assert_eq!(tx.fee.gas_wanted, 200_000);
        assert!(tx.signatures.is_empty());
    }

    #[test]
    fn rejects_bad_address_and_amount() {
        // Arrange
        let (store, _) = store_with_alice();
        let io = FakeIo::default();
        let bad_to = SendArgs {
            common: common("alice"),
            to: "nope".into(),
            send: "1ugnot".into(),
        };
        let bad_send = SendArgs {
            common: common("alice"),
            to: BOB.into(),
            send: "1".into(),
        };

        // Assert
        assert_eq!(
            run(&bad_to, &store, &io).unwrap_err().to_string(),
            "invalid --to address"
        );
        assert_eq!(
            run(&bad_send, &store, &io).unwrap_err().to_string(),
            "invalid --send amount"
        );
    }
}
