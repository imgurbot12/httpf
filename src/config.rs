//! File Based Configuration for Proxy

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{de::Error, Deserialize};

/// Complete Httpf Configuration
#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub resolve: ResolveConfig,
    pub proxy: ProxyConfig,
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub controls: Vec<ControlConfig>,
}

/// Proxy TLS Configuration Settings
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Server Listener Configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    pub host: IpAddr,
    pub port: u16,
    pub tls: Option<TlsConfig>,
}

/// Additional Proxy Configuration
#[derive(Debug, Deserialize)]
pub struct ProxyConfig {
    pub trust_headers: bool,
    #[serde(default)]
    pub trusted_headers: TrustedHeaders,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveConfig {
    pub default: Vec<url::Url>,
    #[serde(flatten)]
    pub domains: BTreeMap<DomainMatch, Vec<url::Url>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainMatch {
    pub pattern: String,
    pub glob: glob::Pattern,
}

impl FromStr for DomainMatch {
    type Err = glob::PatternError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let glob = glob::Pattern::new(s)?;
        Ok(Self {
            pattern: s.to_owned(),
            glob,
        })
    }
}

pub type IpList = HashSet<IpAddr>;
pub type TrustedHeaders = Option<HashSet<String>>;

/// Basic Firewall Configuration
#[derive(Debug, Deserialize)]
pub struct FirewallConfig {
    #[serde(default)]
    pub whitelist: IpList,
    #[serde(default)]
    pub blacklist: IpList,
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug)]
pub struct Duration(pub std::time::Duration);

impl FromStr for Duration {
    type Err = humantime::DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let duration = humantime::parse_duration(s)?;
        Ok(Self(duration))
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ChallengeConfig {
    pub cookie: String,
    pub timeout: Duration,
    pub threshold: usize,
    pub template: Option<PathBuf>,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            cookie: "HTTPF-Challenge".to_owned(),
            timeout: Duration(std::time::Duration::from_secs(60)),
            threshold: 20,
            template: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    #[default]
    Block,
    Challenge(ChallengeConfig),
    Ratelimit {
        limit: usize,
        #[serde(default)]
        global: bool,
    },
}

/// Firewall Action Control Configuration Component
#[derive(Debug, Deserialize)]
pub struct ControlConfig {
    pub path: PathMatch,
    #[serde(default)]
    pub skip: Vec<ControlMatch>,
    #[serde(default, alias = "match")]
    pub matches: Vec<ControlMatch>,
    #[serde(default)]
    pub action: Action,
}

impl ControlConfig {
    #[inline]
    pub fn matches_path(&self, path: &str) -> bool {
        self.path.0.is_match(path)
    }
    #[inline]
    pub fn match_skip(&self, ip: &IpAddr, path: &str) -> bool {
        self.skip
            .iter()
            .find(|rule| rule.contains(ip, path))
            .is_some()
    }
    #[inline]
    pub fn match_deny(&self, ip: &IpAddr, path: &str) -> bool {
        self.matches
            .iter()
            .find(|rule| rule.contains(ip, path))
            .is_some()
    }
    #[inline]
    pub fn match_deny_any(&self, ips: &Vec<IpAddr>, path: &str) -> Option<IpAddr> {
        ips.iter()
            .find(|ip| self.match_deny(ip, path))
            .map(|ip| ip.clone())
    }
}

/// Regex Based HTTP Path Matcher
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

/// Client IP Matcher Rule
#[derive(Debug)]
pub enum ControlMatch {
    All,
    Path(PathMatch),
    IPNet(ipnet::IpNet),
    IpAddr(IpAddr),
}

impl ControlMatch {
    pub fn contains(&self, ip: &IpAddr, path: &str) -> bool {
        match self {
            Self::All => true,
            Self::Path(rule) => rule.0.is_match(path),
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
        // attempt parsing path expression
        if let Ok(path) = PathMatch::from_str(s) {
            return Ok(Self::Path(path));
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

de_fromstr!(DomainMatch);
de_fromstr!(Duration);
de_fromstr!(PathMatch);
de_fromstr!(ControlMatch);
