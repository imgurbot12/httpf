//! File Based Configuration for Proxy

use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListenConfig {
    pub host: IpAddr,
    pub port: u16,
}

pub type IpList = HashSet<IpAddr>;
pub type TrustedHeaders = Option<HashSet<String>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub trust_proxy_headers: bool,
    #[serde(default)]
    pub trusted_headers: TrustedHeaders,
    #[serde(default)]
    pub whitelist: IpList,
    #[serde(default)]
    pub blacklist: IpList,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub resolve: ResolveConfig,
    pub firewall: FirewallConfig,
}
