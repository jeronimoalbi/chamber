use crate::error::{Error, Result};

/// Most allow-path entries a session may declare.
pub const MAX_ALLOW_PATHS: usize = 8;

/// Longest a non-zero expiry may lie in the future, in seconds.
pub const MAX_SESSION_DURATION: i64 = 4 * 365 * 24 * 60 * 60;

/// Longest spend period, in seconds.
pub const MAX_SPEND_PERIOD: i64 = 30 * 24 * 60 * 60;

/// The message kinds an allow-path entry may name.
pub const ROUTE_TYPES: [&str; 4] = ["vm/exec", "vm/run", "bank/send", "bank/multisend"];

/// The only route type that accepts a `:<path>` realm restriction.
const PATH_BEARING_ROUTE_TYPE: &str = "vm/exec";

/// Check allow-path entries against the grammar enforced when the
/// session is created: `"*"` or `<route>/<type>[:<path>]`, with the route
/// types in [`ROUTE_TYPES`], a path only after `vm/exec`, non-empty and
/// without a trailing slash. At least one entry is required.
pub fn validate_allow_paths(paths: &[String]) -> Result<()> {
    if paths.is_empty() {
        return Err(Error::Tx(
            "allow_paths is required (use \"*\" for unrestricted)".into(),
        ));
    }

    if paths.len() > MAX_ALLOW_PATHS {
        return Err(Error::Tx(format!(
            "too many allow_paths: {} > {MAX_ALLOW_PATHS}",
            paths.len()
        )));
    }

    for (i, entry) in paths.iter().enumerate() {
        validate_allow_path(entry).map_err(|e| Error::Tx(format!("allow_paths[{i}]: {e}")))?;
    }

    Ok(())
}

fn validate_allow_path(entry: &str) -> std::result::Result<(), String> {
    if entry.is_empty() {
        return Err("empty allow-paths entry".into());
    }

    if entry == "*" {
        return Ok(());
    }

    let (route_type, path) = match entry.split_once(':') {
        Some((route_type, path)) => (route_type, Some(path)),
        None => (entry, None),
    };
    if route_type == "*" {
        return Err("wildcard '*' must not have a path suffix".into());
    }

    if !ROUTE_TYPES.contains(&route_type) {
        return Err(format!(
            "unknown route_type {route_type:?} (want one of: *, vm/exec, vm/run, bank/send, bank/multisend)"
        ));
    }

    if let Some(path) = path {
        if route_type != PATH_BEARING_ROUTE_TYPE {
            return Err(format!(
                "only vm/exec accepts a path suffix; {route_type:?} does not"
            ));
        }

        if path.is_empty() {
            return Err("vm/exec entry requires a non-empty path after ':'".into());
        }

        if path.ends_with('/') {
            return Err(format!("path {path:?} has a trailing slash"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_the_documented_forms() {
        // Assert
        for ok in [
            vec!["*"],
            vec!["vm/exec:gno.land/r/jae/blog"],
            vec!["bank/send"],
            vec![
                "vm/exec:gno.land/r/jae/blog",
                "bank/send",
                "vm/run",
                "bank/multisend",
                "vm/exec",
            ],
        ] {
            assert!(validate_allow_paths(&paths(&ok)).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn rejects_what_the_chain_rejects() {
        // Assert
        for (bad, msg) in [
            (
                vec![],
                "allow_paths is required (use \"*\" for unrestricted)",
            ),
            (vec![""], "allow_paths[0]: empty allow-paths entry"),
            (
                vec!["*:gno.land/r/x"],
                "allow_paths[0]: wildcard '*' must not have a path suffix",
            ),
            (
                vec!["bank"],
                "allow_paths[0]: unknown route_type \"bank\" (want one of: *, vm/exec, vm/run, bank/send, bank/multisend)",
            ),
            (
                vec!["auth/create_session"],
                "allow_paths[0]: unknown route_type \"auth/create_session\" (want one of: *, vm/exec, vm/run, bank/send, bank/multisend)",
            ),
            (
                vec!["bank/send:foo"],
                "allow_paths[0]: only vm/exec accepts a path suffix; \"bank/send\" does not",
            ),
            (
                vec!["vm/exec:"],
                "allow_paths[0]: vm/exec entry requires a non-empty path after ':'",
            ),
            (
                vec!["bank/send", "vm/exec:gno.land/r/x/"],
                "allow_paths[1]: path \"gno.land/r/x/\" has a trailing slash",
            ),
        ] {
            let err = validate_allow_paths(&paths(&bad)).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("invalid transaction: {msg}"),
                "{bad:?}"
            );
        }
        let too_many = paths(&["bank/send"; 9]);
        assert_eq!(
            validate_allow_paths(&too_many).unwrap_err().to_string(),
            "invalid transaction: too many allow_paths: 9 > 8"
        );
    }
}
