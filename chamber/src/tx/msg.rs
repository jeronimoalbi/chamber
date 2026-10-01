//! The Gno.land messages chamber can sign: `bank.MsgSend` and the `vm` and
//! session messages.
//!
//! Field order is the declaration order, which is also the Amino field
//! numbering used by the binary encoding.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::address::Address;
use crate::amino::binary::{AminoBinary, Writer};
use crate::amino::json::{deserialize_any_string, nullable_vec, quoted_i64, serialize_any_string};
use crate::error::{Error, Result};
use crate::tx::coin::Coins;
use crate::tx::pubkey::AnyPubKey;

/// Amino type URL of [`MsgSend`].
pub const TYPE_URL_MSG_SEND: &str = "/bank.MsgSend";

/// Amino type URL of [`MsgCall`].
pub const TYPE_URL_MSG_CALL: &str = "/vm.m_call";

/// Amino type URL of [`MsgRun`].
pub const TYPE_URL_MSG_RUN: &str = "/vm.m_run";

/// Amino type URL of [`MsgAddPackage`].
pub const TYPE_URL_MSG_ADD_PACKAGE: &str = "/vm.m_addpkg";

/// Amino type URL of [`MemPackageType`].
pub const TYPE_URL_MEM_PACKAGE_TYPE: &str = "/gno.MemPackageType";

/// Amino type URL of [`MsgCreateSession`].
pub const TYPE_URL_MSG_CREATE_SESSION: &str = "/auth.m_create_session";

/// Amino type URL of [`MsgRevokeSession`].
pub const TYPE_URL_MSG_REVOKE_SESSION: &str = "/auth.m_revoke_session";

/// Amino type URL of [`MsgRevokeAllSessions`].
pub const TYPE_URL_MSG_REVOKE_ALL_SESSIONS: &str = "/auth.m_revoke_all_sessions";

/// A transaction message.
///
/// In Amino-JSON a message is an `Any`: its type URL under `"@type"` with the
/// message's own fields inlined next to it, which is exactly serde's
/// internally tagged representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type")]
pub enum Msg {
    #[serde(rename = "/bank.MsgSend")]
    Send(MsgSend),
    #[serde(rename = "/vm.m_call")]
    Call(MsgCall),
    #[serde(rename = "/vm.m_run")]
    Run(MsgRun),
    #[serde(rename = "/vm.m_addpkg")]
    AddPackage(MsgAddPackage),
    #[serde(rename = "/auth.m_create_session")]
    CreateSession(MsgCreateSession),
    #[serde(rename = "/auth.m_revoke_session")]
    RevokeSession(MsgRevokeSession),
    #[serde(rename = "/auth.m_revoke_all_sessions")]
    RevokeAllSessions(MsgRevokeAllSessions),
}

impl Msg {
    /// The Amino type URL of the concrete message.
    pub fn type_url(&self) -> &'static str {
        match self {
            Msg::Send(_) => TYPE_URL_MSG_SEND,
            Msg::Call(_) => TYPE_URL_MSG_CALL,
            Msg::Run(_) => TYPE_URL_MSG_RUN,
            Msg::AddPackage(_) => TYPE_URL_MSG_ADD_PACKAGE,
            Msg::CreateSession(_) => TYPE_URL_MSG_CREATE_SESSION,
            Msg::RevokeSession(_) => TYPE_URL_MSG_REVOKE_SESSION,
            Msg::RevokeAllSessions(_) => TYPE_URL_MSG_REVOKE_ALL_SESSIONS,
        }
    }

    /// The accounts that must sign a transaction carrying this message.
    pub fn signers(&self) -> Vec<Address> {
        match self {
            Msg::Send(m) => vec![m.from_address],
            Msg::Call(m) => vec![m.caller],
            Msg::Run(m) => vec![m.caller],
            Msg::AddPackage(m) => vec![m.creator],
            Msg::CreateSession(m) => vec![m.creator],
            Msg::RevokeSession(m) => vec![m.creator],
            Msg::RevokeAllSessions(m) => vec![m.creator],
        }
    }

    /// The stateless checks that don't need a node (realm path rules are left
    /// to the node).
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            Msg::Send(m) => m.validate_basic(),
            Msg::Call(m) => m.validate_basic(),
            Msg::Run(m) => m.validate_basic(),
            Msg::AddPackage(m) => m.validate_basic(),
            Msg::CreateSession(m) => m.validate_basic(),
            Msg::RevokeSession(m) => m.validate_basic(),
            Msg::RevokeAllSessions(m) => m.validate_basic(),
        }
    }
}

/// Transfer coins between accounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgSend {
    pub from_address: Address,
    pub to_address: Address,
    pub amount: Coins,
}

impl MsgSend {
    pub fn validate_basic(&self) -> Result<()> {
        if self.from_address.is_zero() {
            return Err(Error::Tx("missing sender address".into()));
        }

        if self.to_address.is_zero() {
            return Err(Error::Tx("missing recipient address".into()));
        }

        if self.amount.is_empty() {
            return Err(Error::Tx("send amount must be positive".into()));
        }

        Ok(())
    }
}

/// Call an exported function of a realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgCall {
    pub caller: Address,
    pub send: Coins,
    pub max_deposit: Coins,
    pub pkg_path: String,
    pub func: String,
    /// Absent from JSON when there are no arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

impl MsgCall {
    pub fn validate_basic(&self) -> Result<()> {
        if self.caller.is_zero() {
            return Err(Error::Tx("missing caller address".into()));
        }

        if self.pkg_path.is_empty() {
            return Err(Error::Tx("missing package path".into()));
        }

        if self.func.is_empty() {
            return Err(Error::Tx("missing function to call".into()));
        }

        Ok(())
    }
}

/// Run a throwaway `main` package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgRun {
    pub caller: Address,
    pub send: Coins,
    pub max_deposit: Coins,
    pub package: MemPackage,
}

impl MsgRun {
    pub fn validate_basic(&self) -> Result<()> {
        if self.caller.is_zero() {
            return Err(Error::Tx("missing caller address".into()));
        }

        if !self.package.path.is_empty() {
            let expected = format!("gno.land/e/{}/run", self.caller);
            if self.package.path != expected {
                return Err(Error::Tx(format!(
                    "invalid pkgpath for MsgRun: {:?}",
                    self.package.path
                )));
            }
        }

        if self.package.files.is_empty() {
            return Err(Error::Tx("no files in MsgRun".into()));
        }

        Ok(())
    }
}

/// Publish a new package or realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgAddPackage {
    pub creator: Address,
    pub package: MemPackage,
    pub send: Coins,
    pub max_deposit: Coins,
}

impl MsgAddPackage {
    pub fn validate_basic(&self) -> Result<()> {
        if self.creator.is_zero() {
            return Err(Error::Tx("missing creator address".into()));
        }

        if self.package.path.is_empty() {
            return Err(Error::Tx("missing package path".into()));
        }

        if self.package.files.is_empty() {
            return Err(Error::Tx("no files in MsgAddPackage".into()));
        }

        Ok(())
    }
}

/// Authorize a key as a session account of the creator: it may then sign transactions
/// on the creator's behalf, within the limits given here. See [`crate::tx::session`]
/// for the allow-path grammar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgCreateSession {
    pub creator: Address,
    pub session_key: AnyPubKey,

    /// Unix timestamp after which the session is invalid; 0 means no expiry.
    #[serde(with = "quoted_i64")]
    pub expires_at: i64,

    /// Which messages the session may sign; the chain
    /// requires at least one entry, `"*"` for unrestricted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_paths: Vec<String>,

    /// Coins the session may spend per period; empty means no spending.
    #[serde(default, skip_serializing_if = "Coins::is_empty")]
    pub spend_limit: Coins,

    /// Spend period in seconds; 0 means the limit is a lifetime cap.
    #[serde(default, with = "quoted_i64", skip_serializing_if = "is_zero_i64")]
    pub spend_period: i64,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

impl MsgCreateSession {
    /// The stateless checks that don't need a node.
    pub fn validate_basic(&self) -> Result<()> {
        if self.creator.is_zero() {
            return Err(Error::Tx("missing creator address".into()));
        }
        if self.expires_at < 0 {
            return Err(Error::Tx(
                "expires_at must be non-negative (0 means no expiry)".into(),
            ));
        }
        if self.spend_period < 0 {
            return Err(Error::Tx("spend_period must be non-negative".into()));
        }
        if self.allow_paths.len() > crate::tx::session::MAX_ALLOW_PATHS {
            return Err(Error::Tx("too many allow_paths".into()));
        }
        Ok(())
    }
}

/// Revoke one session of the creator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgRevokeSession {
    pub creator: Address,
    pub session_key: AnyPubKey,
}

impl MsgRevokeSession {
    pub fn validate_basic(&self) -> Result<()> {
        if self.creator.is_zero() {
            return Err(Error::Tx("missing creator address".into()));
        }
        Ok(())
    }
}

/// Revoke every session of the creator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgRevokeAllSessions {
    pub creator: Address,
}

impl MsgRevokeAllSessions {
    pub fn validate_basic(&self) -> Result<()> {
        if self.creator.is_zero() {
            return Err(Error::Tx("missing creator address".into()));
        }
        Ok(())
    }
}

/// An in-memory Gno package. Its optional `info` field is not supported.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemPackage {
    pub name: String,
    pub path: String,
    #[serde(deserialize_with = "nullable_vec::deserialize")]
    pub files: Vec<MemFile>,
    /// Set when a package is read from a directory, absent for a single-file
    /// run. The node overwrites it on delivery, but it is part of what gets
    /// signed.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<MemPackageType>,
}

/// The kind of a [`MemPackage`]: `{"@type":"/gno.MemPackageType","value":"MPUserAll"}` in JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemPackageType(pub String);

impl MemPackageType {
    /// A user package with all its files, tests included.
    pub const USER_ALL: &str = "MPUserAll";

    /// A user package without its test files.
    pub const USER_PROD: &str = "MPUserProd";

    pub fn user_all() -> Self {
        Self(Self::USER_ALL.to_owned())
    }
}

impl Serialize for MemPackageType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_any_string(TYPE_URL_MEM_PACKAGE_TYPE, &self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for MemPackageType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserialize_any_string(TYPE_URL_MEM_PACKAGE_TYPE, deserializer)
            .map(Self)
            .map_err(|e| serde::de::Error::custom(format!("package type: {e}")))
    }
}

/// A file of a [`MemPackage`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemFile {
    pub name: String,
    pub body: String,
}

impl AminoBinary for Msg {
    fn encode_fields(&self, w: &mut Writer) {
        match self {
            Msg::Send(m) => m.encode_fields(w),
            Msg::Call(m) => m.encode_fields(w),
            Msg::Run(m) => m.encode_fields(w),
            Msg::AddPackage(m) => m.encode_fields(w),
            Msg::CreateSession(m) => m.encode_fields(w),
            Msg::RevokeSession(m) => m.encode_fields(w),
            Msg::RevokeAllSessions(m) => m.encode_fields(w),
        }
    }
}

impl AminoBinary for MsgCreateSession {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.creator.to_bech32());
        w.pub_key(2, &self.session_key);
        w.sint64(3, self.expires_at);
        w.repeated_string(4, self.allow_paths.iter().map(String::as_str));
        w.string(5, &self.spend_limit.to_string());
        w.sint64(6, self.spend_period);
    }
}

impl AminoBinary for MsgRevokeSession {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.creator.to_bech32());
        w.pub_key(2, &self.session_key);
    }
}

impl AminoBinary for MsgRevokeAllSessions {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.creator.to_bech32());
    }
}

impl AminoBinary for MsgSend {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.from_address.to_bech32());
        w.string(2, &self.to_address.to_bech32());
        w.string(3, &self.amount.to_string());
    }
}

impl AminoBinary for MsgCall {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.caller.to_bech32());
        w.string(2, &self.send.to_string());
        w.string(3, &self.max_deposit.to_string());
        w.string(4, &self.pkg_path);
        w.string(5, &self.func);
        w.repeated_string(6, self.args.iter().map(String::as_str));
    }
}

impl AminoBinary for MsgRun {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.caller.to_bech32());
        w.string(2, &self.send.to_string());
        w.string(3, &self.max_deposit.to_string());
        // Always written, even when empty
        w.message(4, true, &self.package);
    }
}

impl AminoBinary for MsgAddPackage {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.creator.to_bech32());
        w.message(2, true, &self.package);
        w.string(3, &self.send.to_string());
        w.string(4, &self.max_deposit.to_string());
    }
}

impl AminoBinary for MemPackage {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.name);
        w.string(2, &self.path);
        w.repeated_message(3, &self.files);
        if let Some(kind) = &self.r#type {
            w.any_string(4, TYPE_URL_MEM_PACKAGE_TYPE, &kind.0);
        }
    }
}

impl AminoBinary for MemFile {
    fn encode_fields(&self, w: &mut Writer) {
        w.string(1, &self.name);
        w.string(2, &self.body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amino::json;

    const ALICE: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";
    const BOB: &str = "g1vtad8680vhdfqvxx0f2yaxa6agdylelmtjqnfj";

    fn addr(s: &str) -> Address {
        Address::from_bech32(s).unwrap()
    }

    fn call() -> MsgCall {
        MsgCall {
            caller: addr(ALICE),
            send: Coins::empty(),
            max_deposit: Coins::empty(),
            pkg_path: "gno.land/r/demo/boards".into(),
            func: "CreateBoard".into(),
            args: vec![],
        }
    }

    #[test]
    fn send_serializes_with_inlined_type_url() {
        // Arrange
        let msg = Msg::Send(MsgSend {
            from_address: addr(ALICE),
            to_address: addr(BOB),
            amount: Coins::parse("5000atom,1000000ugnot").unwrap(),
        });

        // Act
        let json = json::to_string(&msg).unwrap();

        // Assert
        assert_eq!(
            json,
            format!(
                r#"{{"@type":"/bank.MsgSend","from_address":"{ALICE}","to_address":"{BOB}","amount":"5000atom,1000000ugnot"}}"#
            )
        );
    }

    #[test]
    fn call_omits_args_only_when_empty() {
        // Arrange
        let mut with_args = call();
        with_args.args = vec!["a".into(), "".into()];

        // Act
        let without = json::to_string(&Msg::Call(call())).unwrap();
        let with = json::to_string(&Msg::Call(with_args)).unwrap();

        // Assert
        assert!(without.ends_with(r#""func":"CreateBoard"}"#));
        assert!(with.ends_with(r#""func":"CreateBoard","args":["a",""]}"#));
    }

    #[test]
    fn deserializes_by_type_url_and_round_trips() {
        // Arrange
        let json_in = format!(
            r#"{{"@type":"/vm.m_run","caller":"{ALICE}","send":"","max_deposit":"1000ugnot","package":{{"name":"main","path":"","files":[{{"name":"main.gno","body":"package main"}}]}}}}"#
        );

        // Act
        let msg: Msg = json::from_str(&json_in).unwrap();
        let json_out = json::to_string(&msg).unwrap();

        // Assert
        assert!(matches!(&msg, Msg::Run(run) if run.package.files.len() == 1));
        assert_eq!(msg.type_url(), TYPE_URL_MSG_RUN);
        assert_eq!(json_out, json_in);
    }

    #[test]
    fn deserializes_null_files_as_empty() {
        // Act
        let pkg: MemPackage = json::from_str(r#"{"name":"x","path":"","files":null}"#).unwrap();

        // Assert
        assert!(pkg.files.is_empty());
    }

    #[test]
    #[should_panic(expected = "unknown variant `/bank.MsgMultiSend`")]
    fn rejects_unknown_type_url() {
        let _: Msg = json::from_str(r#"{"@type":"/bank.MsgMultiSend","inputs":[]}"#).unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown field `extra`")]
    fn rejects_unknown_fields() {
        //! A signer must never silently drop part of the document it signs

        let _: Msg = json::from_str(&format!(
            r#"{{"@type":"/bank.MsgSend","from_address":"{ALICE}","to_address":"{BOB}","amount":"1ugnot","extra":true}}"#
        ))
        .unwrap();
    }

    #[test]
    fn signers_is_the_sending_account() {
        // Assert
        assert_eq!(Msg::Call(call()).signers(), vec![addr(ALICE)]);
        assert_eq!(
            Msg::Send(MsgSend {
                from_address: addr(BOB),
                to_address: addr(ALICE),
                amount: Coins::parse("1ugnot").unwrap()
            })
            .signers(),
            vec![addr(BOB)]
        );
    }

    #[test]
    fn validate_basic_rejects_missing_fields() {
        // Arrange
        let mut no_func = call();
        no_func.func.clear();
        let mut zero_caller = call();
        zero_caller.caller = Address::from_bytes([0u8; 20]);
        let run = MsgRun {
            caller: addr(ALICE),
            send: Coins::empty(),
            max_deposit: Coins::empty(),
            package: MemPackage::default(),
        };

        // Assert
        assert!(call().validate_basic().is_ok());
        assert_eq!(
            no_func.validate_basic().unwrap_err().to_string(),
            "invalid transaction: missing function to call"
        );
        assert_eq!(
            zero_caller.validate_basic().unwrap_err().to_string(),
            "invalid transaction: missing caller address"
        );
        assert_eq!(
            run.validate_basic().unwrap_err().to_string(),
            "invalid transaction: no files in MsgRun"
        );
    }

    #[test]
    fn run_accepts_only_its_reserved_path() {
        // Arrange
        let file = MemFile {
            name: "main.gno".into(),
            body: "package main".into(),
        };
        let mut run = MsgRun {
            caller: addr(ALICE),
            send: Coins::empty(),
            max_deposit: Coins::empty(),
            package: MemPackage {
                name: "main".into(),
                path: format!("gno.land/e/{ALICE}/run"),
                files: vec![file],
                r#type: None,
            },
        };

        // Assert
        assert!(run.validate_basic().is_ok());
        run.package.path = "gno.land/r/demo/x".into();
        assert_eq!(
            run.validate_basic().unwrap_err().to_string(),
            "invalid transaction: invalid pkgpath for MsgRun: \"gno.land/r/demo/x\""
        );
    }
}

#[cfg(test)]
mod mem_package_type_tests {
    use super::*;
    use crate::amino::json;

    const TYPED: &str = r#"{"name":"hello","path":"gno.land/r/demo/hello","files":[],"type":{"@type":"/gno.MemPackageType","value":"MPUserAll"}}"#;

    #[test]
    fn type_round_trips_as_any_string() {
        // Act
        let pkg: MemPackage = json::from_str(TYPED).unwrap();
        let out = json::to_string(&pkg).unwrap();

        // Assert
        assert_eq!(pkg.r#type, Some(MemPackageType::user_all()));
        assert_eq!(out, TYPED);
    }

    #[test]
    fn type_is_omitted_when_absent() {
        // Act
        let out = json::to_string(&MemPackage::default()).unwrap();

        // Assert
        assert_eq!(out, r#"{"name":"","path":"","files":[]}"#);
    }

    #[test]
    #[should_panic(expected = "package type: unsupported type \\\"/gno.Other\\\"")]
    fn type_rejects_other_type_urls() {
        let _: MemPackage = json::from_str(
            r#"{"name":"","path":"","files":[],"type":{"@type":"/gno.Other","value":"x"}}"#,
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "unknown field `info`")]
    fn info_is_still_rejected() {
        let _: MemPackage =
            json::from_str(r#"{"name":"","path":"","files":[],"info":null}"#).unwrap();
    }
}

#[cfg(test)]
mod session_msg_tests {
    use super::*;
    use crate::PrivKey;
    use crate::amino::json;

    const ALICE: &str = "g1r5v5srda7xfth3hn2s26txvrcrntldjughmckm";

    fn key() -> AnyPubKey {
        PrivKey::from_bytes([3u8; 32]).unwrap().pub_key().into()
    }

    fn create() -> MsgCreateSession {
        MsgCreateSession {
            creator: Address::from_bech32(ALICE).unwrap(),
            session_key: key(),
            expires_at: 0,
            allow_paths: vec!["*".into()],
            spend_limit: Coins::empty(),
            spend_period: 0,
        }
    }

    #[test]
    fn create_session_omits_empty_optional_fields() {
        // Act
        let out = json::to_string(&Msg::CreateSession(create())).unwrap();
        let back: Msg = json::from_str(&out).unwrap();

        // Assert
        assert!(out.starts_with(r#"{"@type":"/auth.m_create_session","creator":"#));
        assert!(out.ends_with(r#""expires_at":"0","allow_paths":["*"]}"#));
        assert!(!out.contains("spend_limit") && !out.contains("spend_period"));
        assert_eq!(back, Msg::CreateSession(create()));
    }

    #[test]
    fn create_session_serializes_every_field_when_set() {
        // Arrange
        let mut msg = create();
        msg.expires_at = 1_800_000_000;
        msg.spend_limit = Coins::parse("1000000ugnot").unwrap();
        msg.spend_period = 86400;

        // Act
        let out = json::to_string(&msg).unwrap();

        // Assert
        assert!(out.ends_with(r#""expires_at":"1800000000","allow_paths":["*"],"spend_limit":"1000000ugnot","spend_period":"86400"}"#));
        let back: MsgCreateSession = json::from_str(&out).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn revoke_messages_round_trip() {
        // Arrange
        let revoke = Msg::RevokeSession(MsgRevokeSession {
            creator: Address::from_bech32(ALICE).unwrap(),
            session_key: key(),
        });
        let revoke_all = Msg::RevokeAllSessions(MsgRevokeAllSessions {
            creator: Address::from_bech32(ALICE).unwrap(),
        });

        // Assert
        for msg in [revoke, revoke_all] {
            let out = json::to_string(&msg).unwrap();
            let back: Msg = json::from_str(&out).unwrap();
            assert_eq!(back, msg);
            assert_eq!(msg.signers(), vec![Address::from_bech32(ALICE).unwrap()]);
            assert!(msg.validate_basic().is_ok());
        }
        assert_eq!(
            json::to_string(&Msg::RevokeAllSessions(MsgRevokeAllSessions {
                creator: Address::from_bech32(ALICE).unwrap()
            }))
            .unwrap(),
            format!(r#"{{"@type":"/auth.m_revoke_all_sessions","creator":"{ALICE}"}}"#)
        );
    }

    #[test]
    fn create_session_validate_basic_mirrors_gno() {
        // Arrange
        let mut negative_expiry = create();
        negative_expiry.expires_at = -1;
        let mut negative_period = create();
        negative_period.spend_period = -1;
        let mut too_many = create();
        too_many.allow_paths = vec!["bank/send".into(); 9];
        let mut no_creator = create();
        no_creator.creator = Address::default();

        // Assert
        assert!(create().validate_basic().is_ok());
        assert_eq!(
            negative_expiry.validate_basic().unwrap_err().to_string(),
            "invalid transaction: expires_at must be non-negative (0 means no expiry)"
        );
        assert_eq!(
            negative_period.validate_basic().unwrap_err().to_string(),
            "invalid transaction: spend_period must be non-negative"
        );
        assert_eq!(
            too_many.validate_basic().unwrap_err().to_string(),
            "invalid transaction: too many allow_paths"
        );
        assert_eq!(
            no_creator.validate_basic().unwrap_err().to_string(),
            "invalid transaction: missing creator address"
        );
    }

    #[test]
    fn create_session_binary_omits_defaults_and_writes_the_key_as_any() {
        // Act
        let bytes = Writer::encode(&create());

        // Assert: 1 creator, 2 key Any, (3 omitted), 4 "*"; no 5/6
        assert_eq!(bytes[0], 0x0a);
        assert!(bytes.ends_with(&[0x22, 0x01, b'*']));
        assert!(!bytes.windows(2).any(|w| w == [0x18, 0x00]));
    }
}
