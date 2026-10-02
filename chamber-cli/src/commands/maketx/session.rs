//! `chamber maketx session`: the session lifecycle messages.

use anyhow::{Context, Result, bail};
use chamber::tx::session::{MAX_SESSION_DURATION, validate_allow_paths};
use chamber::tx::{MsgCreateSession, MsgRevokeAllSessions, MsgRevokeSession};
use chamber::{AnyPubKey, Coins, Msg, Store};
use clap::{ArgAction, Args, Subcommand};

use super::{CommonArgs, emit, resolve_signer_address};
use crate::io::Io;

/// Options for `chamber maketx session`.
#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Authorize a key to sign on this account's behalf, within limits
    Create(CreateArgs),

    /// Revoke one session key
    Revoke(RevokeArgs),

    /// Revoke every session of this account
    #[command(name = "revokeall")]
    RevokeAll(RevokeAllArgs),
}

/// Options for `chamber maketx session create`.
#[derive(Debug, Args)]
pub struct CreateArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// The session key: a stored key's name, or a gpub1… public key string
    #[arg(long, value_name = "KEY|GPUB")]
    pub pubkey: String,

    /// When the session expires: a duration (24h, 7d, 4w; at most ~4 years),
    /// a unix timestamp, or "none" for no expiry
    #[arg(long, value_name = "WHEN")]
    pub expires_at: String,

    /// What the session may sign; repeat for several. "*" for anything, or
    /// entries like vm/exec:gno.land/r/demo/boards, vm/run, bank/send
    #[arg(long = "allow-paths", value_name = "ENTRY", action = ArgAction::Append, required = true)]
    pub allow_paths: Vec<String>,

    /// Coins the session may spend per period; none means no spending
    #[arg(long, value_name = "COINS", default_value = "")]
    pub spend_limit: String,

    /// Length of a spend period in seconds; 0 makes the limit a lifetime cap
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    pub spend_period: i64,
}

/// Options for `chamber maketx session revoke`.
#[derive(Debug, Args)]
pub struct RevokeArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// The session key to revoke: a stored key's name, or a gpub1… string
    #[arg(long, value_name = "KEY|GPUB")]
    pub pubkey: String,
}

/// Options for `chamber maketx session revokeall`.
#[derive(Debug, Args)]
pub struct RevokeAllArgs {
    #[command(flatten)]
    pub common: CommonArgs,
}

pub fn run(args: &SessionArgs, store: &Store, io: &impl Io) -> Result<()> {
    match &args.command {
        SessionCommand::Create(a) => create(a, store, io),
        SessionCommand::Revoke(a) => revoke(a, store, io),
        SessionCommand::RevokeAll(a) => revoke_all(a, store, io),
    }
}

/// The master account: session messages are always signed by the master
/// key directly, never through another session.
fn resolve_master_address(store: &Store, common: &CommonArgs) -> Result<chamber::Address> {
    if common.master.is_some() {
        bail!(
            "--master cannot be used with session commands: they must be signed by the master key itself"
        );
    }

    resolve_signer_address(store, &common.key)
}

/// A session public key given as a stored key's name or a bech32 string.
fn resolve_pub_key(store: &Store, key: &str) -> Result<AnyPubKey> {
    if let Ok(pub_key) = AnyPubKey::from_bech32(key) {
        return Ok(pub_key);
    }

    match store.get_by_name(key) {
        Ok(record) => Ok(record.pub_key),
        Err(_) => bail!("\"{key}\" is neither a stored key name nor a gpub1… public key"),
    }
}

fn create(args: &CreateArgs, store: &Store, io: &impl Io) -> Result<()> {
    let creator = resolve_master_address(store, &args.common)?;
    let session_key = resolve_pub_key(store, &args.pubkey)?;
    if args.spend_period < 0 {
        bail!("--spend-period must be non-negative");
    }

    validate_allow_paths(&args.allow_paths).context("invalid --allow-paths")?;

    let expires_at =
        parse_expires_at(&args.expires_at, now_unix()).context("invalid --expires-at")?;
    let spend_limit = Coins::parse(&args.spend_limit).context("invalid --spend-limit")?;

    let msg = Msg::CreateSession(MsgCreateSession {
        creator,
        session_key,
        expires_at,
        allow_paths: args.allow_paths.clone(),
        spend_limit,
        spend_period: args.spend_period,
    });
    emit(&args.common, msg, io)
}

fn revoke(args: &RevokeArgs, store: &Store, io: &impl Io) -> Result<()> {
    let msg = Msg::RevokeSession(MsgRevokeSession {
        creator: resolve_master_address(store, &args.common)?,
        session_key: resolve_pub_key(store, &args.pubkey)?,
    });
    emit(&args.common, msg, io)
}

fn revoke_all(args: &RevokeAllArgs, store: &Store, io: &impl Io) -> Result<()> {
    let msg = Msg::RevokeAllSessions(MsgRevokeAllSessions {
        creator: resolve_master_address(store, &args.common)?,
    });
    emit(&args.common, msg, io)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse expires-at rules: "none" is no expiry (0); a duration is added
/// to now; a bare number is a unix timestamp that must be in the future.
/// Either way the expiry may be at most ~4 years ahead.
fn parse_expires_at(s: &str, now: i64) -> Result<i64> {
    if s == "none" {
        return Ok(0);
    }

    if let Some(secs) = parse_duration_seconds(s) {
        if secs <= 0 {
            bail!("{s:?} must be a positive duration");
        }

        if secs > MAX_SESSION_DURATION {
            bail!(
                "{s:?} exceeds the chain maximum of {} days",
                MAX_SESSION_DURATION / 86400
            );
        }

        return Ok(now + secs);
    }

    let ts: i64 = s.parse().map_err(|_| {
        anyhow::anyhow!("{s:?}: expected a duration (24h, 7d), a unix timestamp, or \"none\"")
    })?;
    if ts <= now {
        bail!("{s:?} must be a future unix timestamp; for a duration, add a unit (e.g. 24h, 7d)");
    }

    if ts - now > MAX_SESSION_DURATION {
        bail!(
            "{s:?} exceeds the chain maximum of {} days from now",
            MAX_SESSION_DURATION / 86400
        );
    }

    Ok(ts)
}

/// A duration such as `24h`, `7d`, `4w`, `1h30m` or `90s`, in seconds.
fn parse_duration_seconds(s: &str) -> Option<i64> {
    let mut total = 0f64;
    let mut number = String::new();
    let mut seen_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            number.push(c);
            continue;
        }

        let unit: f64 = match c {
            'w' => 7.0 * 86400.0,
            'd' => 86400.0,
            'h' => 3600.0,
            'm' => 60.0,
            's' => 1.0,
            _ => return None,
        };
        let value: f64 = number.parse().ok()?;
        number.clear();
        total += value * unit;
        seen_unit = true;
    }

    if !seen_unit || !number.is_empty() || !total.is_finite() {
        return None;
    }

    Some(total as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::maketx::testing::*;
    use crate::io::testing::FakeIo;

    fn create_args(pubkey: &str, expires_at: &str, allow_paths: &[&str]) -> CreateArgs {
        CreateArgs {
            common: common("alice"),
            pubkey: pubkey.to_string(),
            expires_at: expires_at.to_string(),
            allow_paths: allow_paths.iter().map(|s| s.to_string()).collect(),
            spend_limit: String::new(),
            spend_period: 0,
        }
    }

    #[test]
    fn durations_and_timestamps_parse_like_gnokey() {
        // Assert
        assert_eq!(parse_duration_seconds("24h"), Some(86_400));
        assert_eq!(parse_duration_seconds("7d"), Some(7 * 86_400));
        assert_eq!(parse_duration_seconds("4w"), Some(28 * 86_400));
        assert_eq!(parse_duration_seconds("1h30m"), Some(5_400));
        assert_eq!(parse_duration_seconds("1.5h"), Some(5_400));
        assert_eq!(parse_duration_seconds("90"), None);
        assert_eq!(parse_duration_seconds("abc"), None);

        let now = 1_700_000_000;
        assert_eq!(parse_expires_at("none", now).unwrap(), 0);
        assert_eq!(parse_expires_at("24h", now).unwrap(), now + 86_400);
        assert_eq!(parse_expires_at("1800000000", now).unwrap(), 1_800_000_000);
        assert!(
            parse_expires_at("0h", now)
                .unwrap_err()
                .to_string()
                .contains("positive duration")
        );
        assert!(
            parse_expires_at("5y", now)
                .unwrap_err()
                .to_string()
                .contains("expected a duration")
        );
        assert!(
            parse_expires_at("1600000000", now)
                .unwrap_err()
                .to_string()
                .contains("future unix timestamp")
        );
        assert!(
            parse_expires_at("300w", now)
                .unwrap_err()
                .to_string()
                .contains("exceeds the chain maximum")
        );
    }

    #[test]
    fn create_builds_the_message_from_a_stored_session_key() {
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
        let mut args = create_args(
            "bob",
            "none",
            &["vm/exec:gno.land/r/demo/boards", "bank/send"],
        );
        args.spend_limit = "1000000ugnot".to_string();
        args.spend_period = 86_400;
        let io = FakeIo::default();

        // Act
        run(
            &SessionArgs {
                command: SessionCommand::Create(args),
            },
            &store,
            &io,
        )
        .unwrap();

        // Assert
        let tx = printed_tx(&io);
        assert_eq!(
            tx.msgs,
            vec![Msg::CreateSession(MsgCreateSession {
                creator: alice,
                session_key: bob.pub_key,
                expires_at: 0,
                allow_paths: vec!["vm/exec:gno.land/r/demo/boards".into(), "bank/send".into()],
                spend_limit: Coins::parse("1000000ugnot").unwrap(),
                spend_period: 86_400,
            })]
        );
    }

    #[test]
    fn create_accepts_a_gpub_string_and_a_duration() {
        // Arrange
        let (store, _) = store_with_alice();
        let key = chamber::PrivKey::from_bytes([5u8; 32]).unwrap().pub_key();
        let args = create_args(&key.to_bech32(), "24h", &["*"]);
        let io = FakeIo::default();

        // Act
        run(
            &SessionArgs {
                command: SessionCommand::Create(args),
            },
            &store,
            &io,
        )
        .unwrap();

        // Assert
        let tx = printed_tx(&io);
        let Msg::CreateSession(msg) = &tx.msgs[0] else {
            panic!("expected MsgCreateSession")
        };
        assert_eq!(msg.session_key, key);
        assert!(msg.expires_at > now_unix() + 86_000 && msg.expires_at <= now_unix() + 86_400);
    }

    #[test]
    fn create_rejects_bad_paths_keys_and_master_flag() {
        // Arrange
        let (store, _) = store_with_alice();
        let io = FakeIo::default();
        let key = chamber::PrivKey::from_bytes([5u8; 32])
            .unwrap()
            .pub_key()
            .to_bech32();
        let bad_path = create_args(&key, "none", &["bank"]);
        let bad_key = create_args("nobody", "none", &["*"]);
        let mut with_master = create_args(&key, "none", &["*"]);
        with_master.common.master = Some("alice".to_string());

        // Assert
        let err = run(
            &SessionArgs {
                command: SessionCommand::Create(bad_path),
            },
            &store,
            &io,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "invalid --allow-paths");
        assert!(format!("{err:#}").contains("unknown route_type"));
        let err = run(
            &SessionArgs {
                command: SessionCommand::Create(bad_key),
            },
            &store,
            &io,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("\"nobody\" is neither"));
        let err = run(
            &SessionArgs {
                command: SessionCommand::Create(with_master),
            },
            &store,
            &io,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("--master cannot be used with session commands")
        );
    }

    #[test]
    fn revoke_and_revokeall_build_their_messages() {
        // Arrange
        let (store, alice) = store_with_alice();
        let key = chamber::PrivKey::from_bytes([5u8; 32]).unwrap().pub_key();
        let io = FakeIo::default();

        // Act
        run(
            &SessionArgs {
                command: SessionCommand::Revoke(RevokeArgs {
                    common: common("alice"),
                    pubkey: key.to_bech32(),
                }),
            },
            &store,
            &io,
        )
        .unwrap();
        run(
            &SessionArgs {
                command: SessionCommand::RevokeAll(RevokeAllArgs {
                    common: common("alice"),
                }),
            },
            &store,
            &io,
        )
        .unwrap();

        // Assert
        let printed = io.printed.borrow();
        let revoke = chamber::Tx::from_amino_json(&printed[0]).unwrap();
        let revoke_all = chamber::Tx::from_amino_json(&printed[1]).unwrap();
        assert_eq!(
            revoke.msgs,
            vec![Msg::RevokeSession(MsgRevokeSession {
                creator: alice,
                session_key: key.into()
            })]
        );
        assert_eq!(
            revoke_all.msgs,
            vec![Msg::RevokeAllSessions(MsgRevokeAllSessions {
                creator: alice
            })]
        );
    }
}
