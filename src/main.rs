use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

mod config;
mod proxy;
mod tokiort;

use config::Config;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long, default_value = "config.toml")]
    config: PathBuf,
}

impl Cli {
    pub fn read_config(&self) -> Result<Config> {
        let content =
            std::fs::read_to_string(&self.config).context("failed to read config file")?;
        toml::from_str(&content).context("invalid configuration")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let cli = Cli::parse();

    let config = cli.read_config()?;
    let proxy = proxy::ReverseProxy::new(config);
    proxy.run().await?;

    Ok(())
}
