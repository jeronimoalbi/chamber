//! `chamber maketx`: compose an unsigned transaction file.
//!
//! The signer's address comes from the keystore record, so no passphrase is
//! needed. The result goes to stdout or to `--output`, ready for `chamber sign`.

pub mod addpkg;
pub mod call;
pub mod run;
pub mod send;
pub mod session;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chamber::{Address, Coin, Fee, Msg, Store, Tx};
use clap::{Args, Subcommand};

use crate::io::Io;

/// Options for `chamber maketx`.
#[derive(Debug, Args)]
pub struct MakeTxArgs {
    #[command(subcommand)]
    pub command: MakeTxCommand,
}

#[derive(Debug, Subcommand)]
pub enum MakeTxCommand {
    /// Send coins to an address
    Send(send::SendArgs),

    /// Call a function of a realm
    Call(call::CallArgs),

    /// Run a Gno file as a throwaway `main` package
    Run(run::RunArgs),

    /// Publish a package or realm from a directory
    #[command(name = "addpkg")]
    AddPkg(addpkg::AddPkgArgs),

    /// Create or revoke session accounts (keys allowed to sign for you)
    Session(session::SessionArgs),
}

/// Flags every `maketx` subcommand shares.
#[derive(Debug, Args)]
pub struct CommonArgs {
    /// Name or address of the key that will sign the transaction
    pub key: String,

    /// Gas requested for the transaction
    #[arg(long, value_name = "GAS")]
    pub gas_wanted: i64,

    /// Fee paid for the gas, e.g. "1000000ugnot"
    #[arg(long, value_name = "COIN")]
    pub gas_fee: String,

    /// Any descriptive text
    #[arg(long, default_value = "")]
    pub memo: String,

    /// Write the transaction to this file instead of printing it
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Build the transaction for this master account (name or address)
    /// instead of the key, for a session key that will `sign --session` it
    #[arg(long, value_name = "KEY|ADDRESS")]
    pub master: Option<String>,
}

pub fn run(args: &MakeTxArgs, store: &Store, io: &impl Io) -> Result<()> {
    match &args.command {
        MakeTxCommand::Send(a) => send::run(a, store, io),
        MakeTxCommand::Call(a) => call::run(a, store, io),
        MakeTxCommand::Run(a) => run::run(a, store, io),
        MakeTxCommand::AddPkg(a) => addpkg::run(a, store, io),
        MakeTxCommand::Session(a) => session::run(a, store, io),
    }
}

/// The address a message names as its signer: the master account when
/// `--master` is given (a session key will sign), else the key itself.
pub(crate) fn caller_address(store: &Store, common: &CommonArgs) -> Result<Address> {
    match &common.master {
        Some(master) => match master.parse::<Address>() {
            Ok(address) => Ok(address),
            Err(_) => signer_address(store, master).map_err(|_| {
                anyhow::anyhow!("no key named or with address \"{master}\" for --master")
            }),
        },
        None => signer_address(store, &common.key),
    }
}

/// The address of the stored key `name_or_address` refers to.
pub(crate) fn signer_address(store: &Store, name_or_address: &str) -> Result<Address> {
    let record = store
        .get_by_name(name_or_address)
        .or_else(|_| store.get_by_address(name_or_address))
        .map_err(|_| anyhow::anyhow!("no key named or with address \"{name_or_address}\""))?;
    record
        .address
        .parse()
        .with_context(|| format!("stored address of \"{}\" is invalid", record.name))
}

/// Wrap `msg` in an unsigned transaction and print or save it.
pub(crate) fn emit(common: &CommonArgs, msg: Msg, io: &impl Io) -> Result<()> {
    if common.gas_wanted <= 0 {
        bail!("--gas-wanted must be positive");
    }
    let gas_fee = Coin::parse(&common.gas_fee).context("invalid --gas-fee")?;
    let tx = Tx::new(
        vec![msg],
        Fee::new(common.gas_wanted, gas_fee),
        common.memo.clone(),
    );
    let json = tx
        .to_amino_json()
        .context("failed to encode the transaction")?;

    match &common.output {
        Some(path) => {
            fs::write(path, &json)
                .with_context(|| format!("failed to write {}", path.display()))?;
            io.print_line(&format!("Unsigned transaction saved to {}", path.display()));
        }
        None => io.print_line(&json),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    use chamber::hdpath::Bip44Path;
    use chamber::{Mnemonic, Store};

    use super::*;
    use crate::io::testing::FakeIo;

    /// A store with "alice" in it and her address.
    pub fn store_with_alice() -> (Store, Address) {
        let mut store = Store::new_in_memory();
        let record = store
            .add(
                "alice",
                &Mnemonic::generate().unwrap(),
                "pass",
                Bip44Path::default(),
            )
            .unwrap();
        (store, record.address.parse().unwrap())
    }

    pub fn common(key: &str) -> CommonArgs {
        CommonArgs {
            key: key.to_string(),
            gas_wanted: 200_000,
            gas_fee: "1000000ugnot".to_string(),
            memo: "note".to_string(),
            output: None,
            master: None,
        }
    }

    /// The single transaction a command printed.
    pub fn printed_tx(io: &FakeIo) -> Tx {
        let printed = io.printed.borrow();
        assert_eq!(printed.len(), 1, "expected exactly one printed line");
        Tx::from_amino_json(&printed[0]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::io::testing::FakeIo;

    #[test]
    fn emit_rejects_bad_gas_values() {
        // Arrange
        let (store, alice) = store_with_alice();
        let msg = Msg::Send(chamber::tx::MsgSend {
            from_address: alice,
            to_address: alice,
            amount: chamber::Coins::parse("1ugnot").unwrap(),
        });
        let io = FakeIo::default();
        let mut zero_gas = common("alice");
        zero_gas.gas_wanted = 0;
        let mut bad_fee = common("alice");
        bad_fee.gas_fee = "lots".to_string();

        // Assert
        assert_eq!(
            emit(&zero_gas, msg.clone(), &io).unwrap_err().to_string(),
            "--gas-wanted must be positive"
        );
        assert_eq!(
            emit(&bad_fee, msg, &io).unwrap_err().to_string(),
            "invalid --gas-fee"
        );
        drop(store);
    }

    #[test]
    fn emit_writes_to_output_when_asked() {
        // Arrange
        let (_store, alice) = store_with_alice();
        let msg = Msg::Send(chamber::tx::MsgSend {
            from_address: alice,
            to_address: alice,
            amount: chamber::Coins::parse("1ugnot").unwrap(),
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tx.json");
        let mut args = common("alice");
        args.output = Some(path.clone());
        let io = FakeIo::default();

        // Act
        emit(&args, msg.clone(), &io).unwrap();

        // Assert
        let tx = Tx::from_amino_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(tx.msgs, vec![msg]);
        assert_eq!(tx.memo, "note");
        assert!(io.printed.borrow()[0].starts_with("Unsigned transaction saved to"));
    }

    #[test]
    fn master_flag_overrides_the_caller_by_name_or_address() {
        // Arrange
        let (mut store, alice) = store_with_alice();
        let bob = store
            .add(
                "bob",
                &chamber::Mnemonic::generate().unwrap(),
                "pass",
                chamber::hdpath::Bip44Path::default(),
            )
            .unwrap();
        let mut by_name = common("bob");
        by_name.master = Some("alice".to_string());
        let mut by_address = common("bob");
        by_address.master = Some(alice.to_bech32());
        let mut unknown = common("bob");
        unknown.master = Some("nobody".to_string());

        // Assert
        assert_eq!(
            caller_address(&store, &common("bob")).unwrap().to_bech32(),
            bob.address
        );
        assert_eq!(caller_address(&store, &by_name).unwrap(), alice);
        assert_eq!(caller_address(&store, &by_address).unwrap(), alice);
        assert_eq!(
            caller_address(&store, &unknown).unwrap_err().to_string(),
            "no key named or with address \"nobody\" for --master"
        );
    }

    #[test]
    fn signer_address_accepts_name_or_address_and_rejects_unknown() {
        // Arrange
        let (store, alice) = store_with_alice();

        // Assert
        assert_eq!(signer_address(&store, "alice").unwrap(), alice);
        assert_eq!(signer_address(&store, &alice.to_bech32()).unwrap(), alice);
        assert_eq!(
            signer_address(&store, "nobody").unwrap_err().to_string(),
            "no key named or with address \"nobody\""
        );
    }
}
