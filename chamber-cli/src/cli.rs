use std::path::PathBuf;

use clap::{Parser, Subcommand};
use directories::ProjectDirs;

use crate::commands::add::AddArgs;
use crate::commands::delete::DeleteArgs;

/// A wallet for managing your Gno.land keys.
#[derive(Debug, Parser)]
#[command(
    name = "chamber",
    version,
    about = "A wallet for managing your Gno.land keys",
    long_about = None
)]
pub struct Cli {
    /// Location where keys are stored.
    #[arg(long, global = true, value_name = "PATH", default_value_os_t = default_home())]
    pub home: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

/// A sensible default folder for this OS. Falls back to a local ".chamber"
/// folder in the unusual case the OS's directories can't be determined at all.
fn default_home() -> PathBuf {
    ProjectDirs::from("", "", "chamber")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".chamber"))
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new key or import one you already have
    Add(AddArgs),

    /// Delete a key from the store
    Delete(DeleteArgs),

    /// Show the keys you have stored
    List,
}
