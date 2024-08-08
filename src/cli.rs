use std::net::IpAddr;
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use clap::{Args, Parser, Subcommand};
use colored::Colorize;

use crate::config::Config;
use crate::database::{Database, ListEntry};

#[derive(Debug, Clone)]
pub struct Expiration(pub DateTime<Utc>);

#[derive(Debug, Args)]
pub struct AddArgs {
    /// IpAddress to add to list
    ip: IpAddr,
    /// Expiration Configuration
    expr: Option<Expiration>,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// IpAddress to remove from list
    ip: IpAddr,
}

#[derive(Debug, Subcommand)]
pub enum ListCommand {
    /// Add IpAddress to list
    Add(AddArgs),
    /// Remove IpAddress from list
    Remove(RemoveArgs),
    /// Check if IpAddress in list
    Check(RemoveArgs),
    /// List rows in list
    List,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run HTTP Proxy & Firewall
    Run,
    /// Configure Firewall Blacklist
    #[clap(subcommand)]
    Blacklist(ListCommand),
    /// Configure Firewall Whitelist
    #[clap(subcommand)]
    Whitelist(ListCommand),
}

#[derive(Debug, Parser)]
pub struct Cli {
    /// Configuration filepath
    #[clap(short, long, default_value = "config.toml")]
    pub config: PathBuf,
    /// Httpf Command
    #[clap(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn read_config(&self) -> Result<Config> {
        let content =
            std::fs::read_to_string(&self.config).context("failed to read config file")?;
        toml::from_str(&content).context("invalid configuration")
    }
}

impl ListCommand {
    fn print_entries(&self, entries: Vec<ListEntry>) -> bool {
        if entries.is_empty() {
            println!("{}", "no entries available".italic().red());
            return false;
        }
        let space1 = entries.len().to_string().len() + 1;
        let space2 = entries
            .iter()
            .map(|e| e.ip.to_string().len())
            .max()
            .unwrap()
            + 1;
        let now = Utc::now();
        for (n, entry) in entries.into_iter().enumerate() {
            // calculate number to ip buffer
            let n = (n + 1).to_string();
            let blen1 = space1 - n.len();
            let buff1: String = (0..blen1).into_iter().map(|_| " ").collect();
            // calculate ip to expir buffer
            let ip = entry.ip.to_string();
            let blen2 = space2 - ip.len();
            let buff2: String = (0..blen2).into_iter().map(|_| " ").collect();
            let expr = entry
                .expires
                .map(|e| e.signed_duration_since(now).num_seconds() as u64)
                .map(|s| std::time::Duration::from_secs(s))
                .map(|d| humantime::Duration::from(d).to_string())
                .unwrap_or_else(|| "never".to_owned());
            println!("{n}.{buff1}{ip}{buff2}(expires: {expr})");
        }
        true
    }
    pub fn whitelist(&self, database: &Database) -> Result<bool> {
        let name = "whitelist".bold().italic().white();
        let s = format!("[{}]", "✓".bold().green());
        let f = format!("[{}]", "!".bold().red());
        match self {
            Self::Add(args) => {
                let expr = args.expr.clone().map(|e| e.0);
                let result = database.add_whitelist(&args.ip, expr)?;
                let ip = args.ip.to_string().italic();
                match result {
                    true => println!("{s} {ip} added to {name}."),
                    false => println!("{f} {ip} {} in {name}.", "expiration updated".italic()),
                }
                Ok(true)
            }
            Self::Remove(args) => {
                let result = database.remove_whitelist(&args.ip)?;
                let ip = args.ip.to_string().italic();
                match result {
                    true => println!("{s} {ip} removed from {name}."),
                    false => println!("{f} {ip} {} in {name}.", "not".italic().red()),
                }
                Ok(result)
            }
            Self::Check(args) => {
                let result = database.whitelist_contains(&args.ip)?;
                let ip = args.ip.to_string().italic();
                match result {
                    true => println!("{s} {ip} in {name}."),
                    false => println!("{s} {ip} {} from {name}.", "missing".italic().red()),
                }
                Ok(result)
            }
            Self::List => {
                let entries = database.list_whitelist()?;
                Ok(self.print_entries(entries))
            }
        }
    }
    pub fn blacklist(&self, database: &Database) -> Result<bool> {
        let name = "blacklist".bold().italic().black();
        let s = format!("[{}]", "✓".bold().green());
        let f = format!("[{}]", "!".bold().red());
        match self {
            Self::Add(args) => {
                let ip = args.ip.to_string().italic();
                if database.whitelist_contains(&args.ip)? {
                    let wl = "whitelist".bold().italic().white();
                    let cannot = "Cannot".italic().red();
                    println!("{f} {ip} in {wl}. {cannot} add to {name}.");
                    return Ok(false);
                }
                let expr = args.expr.clone().map(|e| e.0);
                let result = database.add_blacklist(&args.ip, expr)?;
                match result {
                    true => println!("{s} {ip} added to {name}"),
                    false => println!("{s} {ip} {} in {name}.", "expiration updated".italic()),
                }
                Ok(true)
            }
            Self::Remove(args) => {
                let result = database.remove_blacklist(&args.ip)?;
                let ip = args.ip.to_string().italic();
                match result {
                    true => println!("{s} {ip} removed from {name}."),
                    false => println!("{f} {ip} {} in {name}.", "not".italic().red()),
                }
                Ok(result)
            }
            Self::Check(args) => {
                let result = database.blacklist_contains(&args.ip)?;
                let ip = args.ip.to_string().italic();
                match result {
                    true => println!("{s} {ip} in {name}."),
                    false => println!("{f} {ip} {} from {name}.", "missing".italic().red()),
                }
                Ok(result)
            }
            Self::List => {
                let entries = database.list_blacklist()?;
                Ok(self.print_entries(entries))
            }
        }
    }
}

impl FromStr for Expiration {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(date) = DateTime::from_str(s) {
            return Ok(Self(date));
        }
        if let Ok(duration) = humantime::Duration::from_str(s) {
            let duration = TimeDelta::seconds(duration.as_secs() as i64);
            let date = Utc::now().add(duration);
            return Ok(Self(date));
        }
        Err(format!("invalid expiration: {s:?}"))
    }
}
