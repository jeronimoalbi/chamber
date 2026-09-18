use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

mod cli;
mod commands;
mod io;

use crate::cli::{Cli, Command};
use crate::io::TermIo;

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn run(cli: Cli) -> Result<()> {
    let mut store = chamber::Store::open(&cli.home)
        .with_context(|| format!("failed to open {}", cli.home.display()))?;
    let io = TermIo;

    match cli.command {
        Command::Add(args) => commands::add::run(&args, &mut store, &io),
        Command::Delete(args) => commands::delete::run(&args, &mut store, &io),
        Command::Export(args) => commands::export::run(&args, &store, &io),
        Command::Import(args) => commands::import::run(&args, &mut store, &io),
        Command::List => commands::list::run(&store, &io),
    }
}
