use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod cli;
mod config;
mod database;
mod proxy;
mod tls;
mod tokiort;

use cli::{Cli, Command};
use database::Database;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let cli = Cli::parse();
    let config = cli.read_config()?;

    // open database
    let path = config
        .firewall
        .database
        .clone()
        .unwrap_or_else(|| "httpf.db".to_owned());
    let database = Database::new(&path)?;

    // handle cli commands
    let command = cli.command.unwrap_or(Command::Run);
    let result = match command {
        Command::Run => {
            let proxy = proxy::ReverseProxy::new(config, database);
            proxy.run().await?;
            true
        }
        Command::Whitelist(command) => command.whitelist(&database)?,
        Command::Blacklist(command) => command.blacklist(&database)?,
    };

    // return result based on command
    let code = result.then(|| 0).unwrap_or(1);
    Ok(ExitCode::from(code))
}
