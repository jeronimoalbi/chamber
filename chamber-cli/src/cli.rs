use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;

use crate::commands::add::AddArgs;
use crate::commands::delete::DeleteArgs;
use crate::commands::export::ExportArgs;
use crate::commands::import::ImportArgs;
use crate::commands::maketx::MakeTxArgs;
use crate::commands::multisign::MultisignArgs;
use crate::commands::sign::SignArgs;

/// A wallet for managing your Gno.land keys.
#[derive(Debug, Parser)]
#[command(
    name = "chamber",
    version,
    about = "A wallet for managing your Gno.land keys",
    long_about = None
)]
pub struct Cli {
    /// Location where keys are stored [default: this OS's data directory for chamber]
    #[arg(long, global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Where the keystore lives.
    pub fn home(&self) -> Result<PathBuf> {
        resolve_home(self.home.clone(), project_data_dir())
    }
}

/// This OS's conventional data directory for chamber, when there is one.
fn project_data_dir() -> Option<PathBuf> {
    ProjectDirs::from("", "", "chamber").map(|dirs| dirs.data_dir().to_path_buf())
}

/// Resolve home location for the keys or fail when no data dir is available.
/// Flag takes precedence over system.
fn resolve_home(flag: Option<PathBuf>, system: Option<PathBuf>) -> Result<PathBuf> {
    match flag.or(system) {
        Some(home) => Ok(home),
        None => {
            bail!("cannot determine where to store keys, specify it with the --home <PATH> option")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_flag_wins_over_the_system_directory() {
        // Act
        let home = resolve_home(
            Some(PathBuf::from("/explicit")),
            Some(PathBuf::from("/system")),
        )
        .unwrap();

        // Assert
        assert_eq!(home, PathBuf::from("/explicit"));
    }

    #[test]
    fn falls_back_to_the_system_directory() {
        // Act
        let home = resolve_home(None, Some(PathBuf::from("/system"))).unwrap();

        // Assert
        assert_eq!(home, PathBuf::from("/system"));
    }

    #[test]
    fn fails_with_a_hint_when_neither_is_available() {
        // Act
        let err = resolve_home(None, None).unwrap_err();

        // Assert
        let msg = err.to_string();
        assert!(msg.contains("cannot determine where to store keys"));
        assert!(msg.contains("--home"));
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new key or import one you already have
    Add(AddArgs),

    /// Delete a key from the store
    Delete(DeleteArgs),

    /// Export a key to a file
    Export(ExportArgs),

    /// Import a key previously exported with `chamber export`
    Import(ImportArgs),

    /// Show the keys you have stored
    List,

    /// Sign a transaction file with one of your keys
    Sign(SignArgs),

    /// Compose an unsigned transaction file
    #[command(name = "maketx")]
    MakeTx(MakeTxArgs),

    /// Combine members' signatures into a multisig transaction
    Multisign(MultisignArgs),
}
