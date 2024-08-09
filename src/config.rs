//! File Based Configuration for Proxy

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{de::Error, Deserialize};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub resolve: ResolveConfig,
    pub firewall: FirewallConfig,
    pub controls: Vec<ControlConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub host: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveConfig {
    pub host: String,
    pub port: u16,
}

pub type IpList = HashSet<IpAddr>;
pub type TrustedHeaders = Option<HashSet<String>>;

#[derive(Debug, Deserialize)]
pub struct FirewallConfig {
    pub trust_proxy_headers: bool,
    #[serde(default)]
    pub trusted_headers: TrustedHeaders,
    #[serde(default)]
    pub whitelist: IpList,
    #[serde(default)]
    pub blacklist: IpList,
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ControlConfig {
    #[serde(alias = "match")]
    pub path: PathMatch,
    pub allow: Vec<ControlMatch>,
    pub deny: Vec<ControlMatch>,
}

impl ControlConfig {
    #[inline]
    pub fn matches_path(&self, path: &str) -> bool {
        self.path.0.is_match(path)
    }
    #[inline]
    pub fn match_allow(&self, ip: &IpAddr) -> bool {
        self.allow.iter().find(|rule| rule.contains(ip)).is_some()
    }
    #[inline]
    pub fn match_deny(&self, ip: &IpAddr) -> bool {
        self.deny.iter().find(|rule| rule.contains(ip)).is_some()
    }
    #[inline]
    pub fn match_deny_any(&self, ips: &Vec<IpAddr>) -> Option<IpAddr> {
        ips.iter()
            .find(|ip| self.match_deny(ip))
            .map(|ip| ip.clone())
    }
}

#[derive(Debug)]
pub struct PathMatch(pub regex::Regex);

impl FromStr for PathMatch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (pmod, pattern) = s.split_once(' ').unwrap_or(("", s));
        let (s, case) = match pmod {
            "" => (format!("^{pattern}.*$"), false),
            "^~" => (format!("^{pattern}.*$"), true),
            "=" => (format!("^{pattern}$"), false),
            "~" => (format!("{pattern}"), false),
            "~*" => (format!("{pattern}"), true),
            _ => return Err(format!("invalid pattern modifier: {pmod:?}")),
        };
        let r = regex::RegexBuilder::new(&s)
            .case_insensitive(case)
            .build()
            .expect("invalid regex");
        Ok(Self(r))
    }
}

#[derive(Debug)]
pub enum ControlMatch {
    All,
    IPNet(ipnet::IpNet),
    IpAddr(IpAddr),
}

impl ControlMatch {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::IpAddr(rip) => ip == rip,
            Self::IPNet(net) => net.contains(ip),
        }
    }
}

impl FromStr for ControlMatch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // accept all variant
        if s.to_lowercase().as_str() == "all" {
            return Ok(Self::All);
        }
        // attempt parsing as ipnet
        if let Ok(net) = s.parse() {
            return Ok(Self::IPNet(net));
        }
        // attempt parsing as plain ip-addres
        if let Ok(ip) = s.parse() {
            return Ok(Self::IpAddr(ip));
        }
        Err(format!("invalid control rule: {s:?}"))
    }
}

macro_rules! de_fromstr {
    ($s:ident) => {
        impl<'de> Deserialize<'de> for $s {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s: String = Deserialize::deserialize(deserializer)?;
                $s::from_str(&s).map_err(D::Error::custom)
            }
        }
    };
}

de_fromstr!(PathMatch);
de_fromstr!(ControlMatch);
