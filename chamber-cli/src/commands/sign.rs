use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chamber::backend::Record;
use chamber::{AnyPubKey, Error as ChamberError, SignOpts, Store, Tx};
use clap::Args;

use crate::io::Io;

/// Options for `chamber sign`.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// Name or address of the key to sign with
    pub key: String,

    /// The Amino JSON transaction file to sign, e.g. one written by
    /// `gnokey maketx`. It's updated in place with the signature
    #[arg(long, value_name = "PATH")]
    pub tx_path: PathBuf,

    /// ID of the chain the transaction is for
    #[arg(long, default_value = "dev")]
    pub chainid: String,

    /// Account number of the signing account on that chain
    #[arg(long, default_value_t = 0)]
    pub account_number: u64,

    /// Sequence (transactions sent so far) of the signing account
    #[arg(long, default_value_t = 0)]
    pub account_sequence: u64,

    /// Write just the signature to this file instead of adding it to the
    /// transaction, for transactions that need several signers
    #[arg(long, value_name = "PATH")]
    pub output_document: Option<PathBuf>,

    /// Sign as a session account of the transaction's signer: the key is the
    /// session key, and --account-number/--account-sequence are the session
    /// account's (`gnokey query auth/accounts/<master>/session/<session>`)
    #[arg(long)]
    pub session: bool,

    /// Sign the older payload, with the fee as `gas_fee`/`gas_wanted`, that
    /// `chain/mainnet` nodes verify. By default the Ledger-friendly payload
    /// that newer nodes verify first is signed
    #[arg(long)]
    pub legacy: bool,
}

pub fn run(args: &SignArgs, store: &Store, io: &impl Io) -> Result<()> {
    let record = store
        .get_by_name(&args.key)
        .or_else(|_| store.get_by_address(&args.key))
        .map_err(|_| anyhow::anyhow!("no key named or with address \"{}\"", args.key))?;

    let raw = fs::read_to_string(&args.tx_path)
        .with_context(|| format!("failed to read {}", args.tx_path.display()))?;
    if raw.trim().is_empty() {
        bail!("transaction file {} is empty", args.tx_path.display());
    }
    let mut tx = Tx::from_amino_json(&raw)
        .with_context(|| format!("{} is not a valid transaction file", args.tx_path.display()))?;

    if !record.has_private_key() {
        bail!(
            "\"{}\" is a multisig key and can't sign by itself: have each member run \
             `chamber sign <member> --tx-path <file> --output-document <sig-file>`, then \
             `chamber multisign {} --tx-path <file> --signature <sig-file> ...`",
            record.name,
            record.name
        );
    }

    let address: chamber::Address = record.address.parse()?;
    let signers = tx.signers();
    // A session key never appears among the signers (its master does), so
    // the membership checks below only apply to direct signatures
    if !args.session && !signers.contains(&address) {
        // A member of a stored multisig key that is a signer may contribute
        // a signature document, but never a signature on the tx itself
        let multisig = multisig_signer_for(store, &record, &signers)?;
        match (multisig, &args.output_document) {
            (Some(_), Some(_)) => {}
            (Some(multisig), None) => bail!(
                "\"{}\" is a member of the multisig \"{}\" that signs this transaction; \
                 write its signature with --output-document and combine them with \
                 `chamber multisign {}`",
                record.name,
                multisig.name,
                multisig.name
            ),
            (None, _) => bail!(
                "key \"{}\" ({}) is not a signer of this transaction",
                record.name,
                record.address
            ),
        }
    }

    let passphrase = io
        .prompt_password(&format!("Enter the passphrase for \"{}\": ", record.name))
        .context("failed to read the passphrase")?;
    let key = match store.unlock(&record.name, &passphrase) {
        Ok(key) => key,
        Err(ChamberError::Decrypt) => bail!("wrong passphrase, nothing signed"),
        Err(err) => return Err(err.into()),
    };

    let opts = SignOpts {
        chain_id: args.chainid.clone(),
        account_number: args.account_number,
        sequence: args.account_sequence,
        legacy: args.legacy,
    };
    let signature = if args.session {
        tx.sign_session(&key, &opts)
    } else {
        tx.sign(&key, &opts)
    }
    .context("failed to sign the transaction")?;

    if let Some(path) = &args.output_document {
        let json = signature
            .to_amino_json()
            .context("failed to encode the signature")?;
        fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
        io.print_line(&format!("Signature saved to {}", path.display()));
        return Ok(());
    }

    // Like gnokey, only save a transaction a node would accept
    tx.validate_basic().with_context(|| {
        format!(
            "transaction is not valid after signing (it needs {} signatures, has {}; \
             use --output-document to collect signatures separately)",
            tx.signers().len(),
            tx.signatures.len()
        )
    })?;

    let json = tx
        .to_amino_json()
        .context("failed to encode the signed transaction")?;
    fs::write(&args.tx_path, json)
        .with_context(|| format!("failed to write {}", args.tx_path.display()))?;
    io.print_line(&format!(
        "Transaction signed and saved to {}",
        args.tx_path.display()
    ));

    Ok(())
}

/// The stored multisig key, if any, that signs this transaction and has
/// `record` among its members (at any depth).
fn multisig_signer_for(
    store: &Store,
    record: &Record,
    signers: &[chamber::Address],
) -> Result<Option<Record>> {
    let signer_addresses: Vec<String> = signers.iter().map(|a| a.to_bech32()).collect();
    Ok(store
        .list()
        .context("failed to read stored keys")?
        .into_iter()
        .find(|r| {
            signer_addresses.contains(&r.address) && contains_member(&r.pub_key, &record.pub_key)
        }))
}

fn contains_member(key: &AnyPubKey, member: &AnyPubKey) -> bool {
    match key {
        AnyPubKey::Multisig(multisig) => multisig
            .pubkeys
            .iter()
            .any(|k| k == member || contains_member(k, member)),
        AnyPubKey::Secp256k1(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use chamber::hdpath::Bip44Path;
    use chamber::tx::MsgSend;
    use chamber::{Coin, Coins, Fee, Mnemonic, Msg, Signature};

    use super::*;
    use crate::io::testing::FakeIo;

    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";

    /// A store holding "alice" (passphrase "pass") and an unsigned tx file
    /// she must sign, in a temp dir kept alive by the returned guard.
    fn setup() -> (Store, tempfile::TempDir, PathBuf, Tx) {
        let mut store = Store::new_in_memory();
        let mnemonic = Mnemonic::generate().unwrap();
        let record = store
            .add("alice", &mnemonic, "pass", Bip44Path::default())
            .unwrap();

        let msg = Msg::Send(MsgSend {
            from_address: record.address.parse().unwrap(),
            to_address: BOB.parse().unwrap(),
            amount: Coins::parse("1000000ugnot").unwrap(),
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

    fn args(key: &str, tx_path: &Path) -> SignArgs {
        SignArgs {
            key: key.to_string(),
            tx_path: tx_path.to_path_buf(),
            chainid: "dev".to_string(),
            account_number: 8,
            account_sequence: 3,
            output_document: None,
            session: false,
            legacy: false,
        }
    }

    fn opts() -> SignOpts {
        SignOpts {
            chain_id: "dev".into(),
            account_number: 8,
            sequence: 3,
            ..Default::default()
        }
    }

    #[test]
    fn signs_the_transaction_file_in_place() {
        // Arrange
        let (store, _dir, path, unsigned) = setup();
        let io = FakeIo::with_answers(["pass"]);

        // Act
        run(&args("alice", &path), &store, &io).unwrap();

        // Assert
        let signed = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(signed.msgs, unsigned.msgs);
        assert_eq!(signed.signatures.len(), 1);

        let key = store.unlock("alice", "pass").unwrap();
        let sig = &signed.signatures[0];
        assert_eq!(sig.pub_key, key.pub_key());
        let sign_bytes = unsigned.sign_doc(&opts()).sign_bytes().unwrap();
        assert!(
            key.pub_key()
                .verify(&sign_bytes, sig.signature.as_slice().try_into().unwrap())
        );
        assert!(io.printed.borrow()[0].starts_with("Transaction signed and saved to"));
    }

    #[test]
    fn legacy_flag_signs_the_legacy_payload_instead_of_the_default() {
        // Arrange
        let (store, _dir, path, unsigned) = setup();
        let mut args = args("alice", &path);
        args.legacy = true;
        let io = FakeIo::with_answers(["pass"]);

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let signed = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        let key = store.unlock("alice", "pass").unwrap();
        let signature: [u8; 64] = signed.signatures[0]
            .signature
            .as_slice()
            .try_into()
            .unwrap();
        let doc = unsigned.sign_doc(&opts());
        assert!(
            key.pub_key()
                .verify(&doc.sign_bytes_legacy().unwrap(), &signature)
        );
        assert!(!key.pub_key().verify(&doc.sign_bytes().unwrap(), &signature));
    }

    #[test]
    fn session_flag_signs_with_a_non_signer_key_and_records_its_address() {
        // Arrange: bob's key acts as a session of alice, the tx signer
        let (mut store, _dir, path, unsigned) = setup();
        store
            .add(
                "bob",
                &Mnemonic::generate().unwrap(),
                "pass",
                Bip44Path::default(),
            )
            .unwrap();
        let mut args = args("bob", &path);
        args.session = true;
        args.account_number = 30;
        args.account_sequence = 2;
        let io = FakeIo::with_answers(["pass"]);

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let signed = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        let bob = store.unlock("bob", "pass").unwrap();
        let sig = &signed.signatures[0];
        assert_eq!(sig.pub_key, bob.pub_key());
        assert_eq!(sig.session_addr, bob.pub_key().address());
        let opts = SignOpts {
            chain_id: "dev".into(),
            account_number: 30,
            sequence: 2,
            ..Default::default()
        };
        let sign_bytes = unsigned.sign_doc(&opts).sign_bytes().unwrap();
        assert!(
            bob.pub_key()
                .verify(&sign_bytes, sig.signature.as_slice().try_into().unwrap())
        );
        assert!(signed.validate_basic().is_ok());
    }

    #[test]
    fn accepts_the_address_instead_of_the_name() {
        // Arrange
        let (store, _dir, path, _) = setup();
        let address = store.get_by_name("alice").unwrap().address;
        let io = FakeIo::with_answers(["pass"]);

        // Act
        run(&args(&address, &path), &store, &io).unwrap();

        // Assert
        let signed = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(
            io.prompted.borrow()[0],
            "Enter the passphrase for \"alice\": "
        );
    }

    #[test]
    fn output_document_writes_only_the_signature() {
        // Arrange
        let (store, dir, path, unsigned) = setup();
        let sig_path = dir.path().join("alice.sig.json");
        let mut args = args("alice", &path);
        args.output_document = Some(sig_path.clone());
        let io = FakeIo::with_answers(["pass"]);

        // Act
        run(&args, &store, &io).unwrap();

        // Assert
        let signature =
            Signature::from_amino_json(&fs::read_to_string(&sig_path).unwrap()).unwrap();
        assert_eq!(
            signature.pub_key,
            store.unlock("alice", "pass").unwrap().pub_key()
        );
        assert_eq!(signature.signature.len(), 64);
        let untouched = Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(untouched, unsigned);
        assert!(io.printed.borrow()[0].starts_with("Signature saved to"));
    }

    #[test]
    fn wrong_passphrase_signs_nothing() {
        // Arrange
        let (store, _dir, path, unsigned) = setup();
        let io = FakeIo::with_answers(["nope"]);

        // Act
        let err = run(&args("alice", &path), &store, &io).unwrap_err();

        // Assert
        assert_eq!(err.to_string(), "wrong passphrase, nothing signed");
        assert_eq!(
            Tx::from_amino_json(&fs::read_to_string(&path).unwrap()).unwrap(),
            unsigned
        );
    }

    #[test]
    fn refuses_to_sign_with_a_multisig_key() {
        // Arrange
        let (mut store, _dir, path, _) = setup();
        store.add_multisig("team", 1, &["alice"], true).unwrap();
        let io = FakeIo::default();

        // Act
        let err = run(&args("team", &path), &store, &io).unwrap_err();

        // Assert
        assert!(
            err.to_string()
                .starts_with("\"team\" is a multisig key and can't sign by itself")
        );
        assert!(io.prompted.borrow().is_empty());
    }

    #[test]
    fn a_multisig_member_may_only_write_a_signature_document() {
        // Arrange: a tx from a 1-of-2 multisig alice belongs to
        let (mut store, dir, path, _) = setup();
        store
            .add(
                "carol",
                &Mnemonic::generate().unwrap(),
                "pass",
                Bip44Path::default(),
            )
            .unwrap();
        let team = store
            .add_multisig("team", 1, &["alice", "carol"], true)
            .unwrap();
        let msg = Msg::Send(MsgSend {
            from_address: team.address.parse().unwrap(),
            to_address: BOB.parse().unwrap(),
            amount: Coins::parse("1ugnot").unwrap(),
        });
        let tx = Tx::new(vec![msg], Fee::new(1, Coin::parse("1ugnot").unwrap()), "");
        fs::write(&path, tx.to_amino_json().unwrap()).unwrap();

        // Act
        let in_place = run(&args("alice", &path), &store, &FakeIo::default()).unwrap_err();
        let mut with_doc = args("alice", &path);
        with_doc.output_document = Some(dir.path().join("alice.sig.json"));
        run(&with_doc, &store, &FakeIo::with_answers(["pass"])).unwrap();

        // Assert
        assert!(
            in_place
                .to_string()
                .starts_with("\"alice\" is a member of the multisig \"team\"")
        );
        let doc = Signature::from_amino_json(
            &fs::read_to_string(dir.path().join("alice.sig.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            doc.pub_key,
            store.unlock("alice", "pass").unwrap().pub_key()
        );
    }

    #[test]
    fn rejects_a_key_that_is_not_a_signer() {
        // Arrange
        let (mut store, _dir, path, _) = setup();
        store
            .add(
                "carol",
                &Mnemonic::generate().unwrap(),
                "pass",
                Bip44Path::default(),
            )
            .unwrap();
        let io = FakeIo::with_answers(["pass"]);

        // Act
        let err = run(&args("carol", &path), &store, &io).unwrap_err();

        // Assert
        assert!(err.to_string().starts_with("key \"carol\" ("));
        assert!(
            err.to_string()
                .ends_with(") is not a signer of this transaction")
        );
        assert!(
            io.prompted.borrow().is_empty(),
            "no passphrase should be asked"
        );
    }

    #[test]
    fn rejects_unknown_key_and_bad_files() {
        // Arrange
        let (store, dir, path, _) = setup();
        let empty = dir.path().join("empty.json");
        fs::write(&empty, "  \n").unwrap();
        let garbage = dir.path().join("garbage.json");
        fs::write(&garbage, r#"{"msg":[{"@type":"/bank.MsgMultiSend"}]}"#).unwrap();
        let io = FakeIo::default();

        // Act
        let unknown = run(&args("nobody", &path), &store, &io).unwrap_err();
        let empty_err = run(&args("alice", &empty), &store, &io).unwrap_err();
        let garbage_err = run(&args("alice", &garbage), &store, &io).unwrap_err();

        // Assert
        assert_eq!(
            unknown.to_string(),
            "no key named or with address \"nobody\""
        );
        assert!(empty_err.to_string().ends_with("is empty"));
        assert!(
            garbage_err
                .to_string()
                .ends_with("is not a valid transaction file")
        );
    }
}
