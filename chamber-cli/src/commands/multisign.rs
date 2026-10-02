use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chamber::{AnyPubKey, Signature, Store, Tx};
use clap::{ArgAction, Args};

use crate::io::Io;

/// Options for `chamber multisign`.
#[derive(Debug, Args)]
pub struct MultisignArgs {
    /// Name or address of the multisig key
    pub key: String,

    /// The Amino JSON transaction file to sign; updated in place
    #[arg(long, value_name = "PATH")]
    pub tx_path: PathBuf,

    /// A member's signature file (from `chamber sign --output-document`);
    /// repeat for each member
    #[arg(long = "signature", value_name = "PATH", action = ArgAction::Append, required = true)]
    pub signatures: Vec<PathBuf>,
}

pub fn run(args: &MultisignArgs, store: &Store, io: &impl Io) -> Result<()> {
    let record = store
        .get_by_name(&args.key)
        .or_else(|_| store.get_by_address(&args.key))
        .map_err(|_| anyhow::anyhow!("no key named or with address \"{}\"", args.key))?;
    let AnyPubKey::Multisig(key) = &record.pub_key else {
        bail!("\"{}\" is not a multisig key", record.name);
    };

    let raw = fs::read_to_string(&args.tx_path)
        .with_context(|| format!("failed to read {}", args.tx_path.display()))?;
    let mut tx = Tx::from_amino_json(&raw)
        .with_context(|| format!("{} is not a valid transaction file", args.tx_path.display()))?;

    let mut docs = Vec::with_capacity(args.signatures.len());
    for path in &args.signatures {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read signature file {}", path.display()))?;
        let doc = Signature::from_amino_json(&raw)
            .with_context(|| format!("{} is not a valid signature file", path.display()))?;
        docs.push(doc);
    }

    tx.multisign(key, &docs)
        .context("failed to combine the signatures")?;
    tx.validate_basic()
        .context("transaction is not valid after signing")?;

    let json = tx
        .to_amino_json()
        .context("failed to encode the signed transaction")?;
    fs::write(&args.tx_path, json)
        .with_context(|| format!("failed to write {}", args.tx_path.display()))?;
    io.print_line(&format!(
        "Transaction signed by {} of {} members and saved to {}",
        docs.len(),
        key.pubkeys.len(),
        args.tx_path.display()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use chamber::hdpath::Bip44Path;
    use chamber::tx::MsgSend;
    use chamber::{Coin, Coins, Fee, Mnemonic, Msg, SignOpts};

    use super::*;
    use crate::commands::sign::{self, SignArgs};
    use crate::io::testing::FakeIo;

    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";

    /// A store with members a, b, c (passphrase "pass") and a 2-of-3 "team"
    /// key, plus an unsigned tx from the team's address on disk.
    fn setup() -> (Store, tempfile::TempDir, PathBuf, Tx) {
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        store
            .add("a", &mnemonic, "pass", Bip44Path::new(0, 0))
            .unwrap();
        store
            .add("b", &mnemonic, "pass", Bip44Path::new(0, 1))
            .unwrap();
        store
            .add("c", &mnemonic, "pass", Bip44Path::new(1, 0))
            .unwrap();
        let team = store
            .add_multisig("team", 2, &["a", "b", "c"], true)
            .unwrap();

        let msg = Msg::Send(MsgSend {
            from_address: team.address.parse().unwrap(),
            to_address: BOB.parse().unwrap(),
            amount: Coins::parse("500ugnot").unwrap(),
        });
        let tx = Tx::new(
            vec![msg],
            Fee::new(200_000, Coin::parse("1000000ugnot").unwrap()),
            "",
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tx.json");
        fs::write(&path, tx.to_amino_json().unwrap()).unwrap();
        (store, dir, path, tx)
    }

    /// Have `member` sign the tx into a signature file, as a member would.
    fn member_signs(
        store: &Store,
        dir: &std::path::Path,
        tx_path: &std::path::Path,
        member: &str,
    ) -> PathBuf {
        let sig_path = dir.join(format!("{member}.sig.json"));
        let args = SignArgs {
            key: member.to_string(),
            tx_path: tx_path.to_path_buf(),
            chainid: "dev".to_string(),
            account_number: 20,
            account_sequence: 1,
            output_document: Some(sig_path.clone()),
            session: false,
            legacy: false,
        };
        sign::run(&args, store, &FakeIo::with_answers(["pass"])).unwrap();
        sig_path
    }

    fn args(key: &str, tx_path: &std::path::Path, signatures: Vec<PathBuf>) -> MultisignArgs {
        MultisignArgs {
            key: key.to_string(),
            tx_path: tx_path.to_path_buf(),
            signatures,
        }
    }

    #[test]
    fn combines_member_signatures_into_the_transaction() {
        // Arrange
        let (store, dir, path, unsigned) = setup();
        let sig_a = member_signs(&store, dir.path(), &path, "a");
        let sig_c = member_signs(&store, dir.path(), &path, "c");
        let io = FakeIo::default();

        // Act
        run(
            &args("team", &path, vec![sig_c.clone(), sig_a.clone()]),
            &store,
            &io,
        )
        .unwrap();

        // Assert
        let signed = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(signed.msgs, unsigned.msgs);
        assert_eq!(signed.signatures.len(), 1);
        let team = store.get_by_name("team").unwrap();
        assert_eq!(signed.signatures[0].pub_key, team.pub_key);
        assert!(signed.validate_basic().is_ok());

        // The combined bytes are what the library produces from the same documents
        let AnyPubKey::Multisig(key) = &team.pub_key else {
            panic!("expected multisig")
        };
        let docs: Vec<Signature> = [sig_c, sig_a]
            .iter()
            .map(|p| Signature::from_amino_json(&fs::read_to_string(p).unwrap()).unwrap())
            .collect();
        assert_eq!(signed.signatures[0], key.combine(&docs).unwrap());
        assert!(io.printed.borrow()[0].starts_with("Transaction signed by 2 of 3 members"));

        // Members signed the multisig account's sign doc
        let opts = SignOpts {
            chain_id: "dev".into(),
            account_number: 20,
            sequence: 1,
            ..Default::default()
        };
        let sign_bytes = unsigned.build_sign_doc(&opts).sign_bytes().unwrap();
        let a = store.unlock("a", "pass").unwrap();
        let doc_a = docs.iter().find(|d| d.pub_key == a.pub_key()).unwrap();
        assert!(
            a.pub_key()
                .verify(&sign_bytes, doc_a.signature.as_slice().try_into().unwrap())
        );
    }

    #[test]
    fn rejects_too_few_signatures_and_leaves_the_file_untouched() {
        // Arrange
        let (store, dir, path, unsigned) = setup();
        let sig_a = member_signs(&store, dir.path(), &path, "a");
        let io = FakeIo::default();

        // Act
        let err = run(&args("team", &path, vec![sig_a]), &store, &io).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "failed to combine the signatures");
        assert!(format!("{err:#}").contains("multisig needs 2 signatures, got 1"));
        assert_eq!(
            Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap(),
            unsigned
        );
    }

    #[test]
    fn rejects_non_multisig_keys_and_bad_signature_files() {
        // Arrange
        let (store, dir, path, _) = setup();
        let garbage = dir.path().join("garbage.json");
        fs::write(&garbage, "{}").unwrap();
        let io = FakeIo::default();

        // Assert
        let err = run(&args("a", &path, vec![garbage.clone()]), &store, &io).unwrap_err();
        assert_eq!(err.to_string(), "\"a\" is not a multisig key");
        let err = run(&args("team", &path, vec![garbage.clone()]), &store, &io).unwrap_err();
        assert!(err.to_string().ends_with("is not a valid signature file"));
        let err = run(&args("nobody", &path, vec![garbage]), &store, &io).unwrap_err();
        assert_eq!(err.to_string(), "no key named or with address \"nobody\"");
    }
}
