mod cli;
mod commands;
mod output;

use clap::Parser;
use cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen(args) => commands::keygen::run(args),
        Command::Derive(args) => commands::derive::run(args),
        Command::Encrypt(args) => commands::encrypt::run(args),
        Command::Decrypt(args) => commands::decrypt::run(args),
        Command::Sign(args) => commands::sign::run(args),
        Command::Verify(args) => commands::verify::run(args),
        Command::Grant(args) => commands::grant::run(args),
        Command::Revoke(args) => commands::revoke::run(args),
        Command::Inspect(args) => commands::inspect::run(args),
        Command::Keyring(args) => commands::keyring::run(args),
    }
}
