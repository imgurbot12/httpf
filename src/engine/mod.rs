use std::net::IpAddr;

use anyhow::{Context, Result};

use crate::config::*;
use crate::database::Database;
use crate::proxy::{ProxyRequest, ProxyResponse};

mod challenge;
mod headers;
mod ratelimit;

#[derive(Debug)]
pub enum Ruling {
    Allow {
        ip: IpAddr,
        reason: String,
    },
    Challenge {
        ip: IpAddr,
        res: ProxyResponse,
    },
    Deny {
        ip: IpAddr,
        reason: String,
        code: u16,
    },
}

impl Ruling {
    #[inline]
    fn allow(ipaddr: IpAddr, reason: &str) -> Self {
        Self::Allow {
            ip: ipaddr,
            reason: reason.to_owned(),
        }
    }
    #[inline]
    fn block(ipaddr: IpAddr, reason: &str, code: u16) -> Self {
        Self::Deny {
            ip: ipaddr,
            code,
            reason: reason.to_owned(),
        }
    }
}

pub struct Engine {
    proxy: ProxyConfig,
    firewall: FirewallConfig,
    controls: Vec<ControlConfig>,
    database: Database,
    challenges: challenge::ChallengeGroup,
    ratelimit: ratelimit::RateLimiterGroup,
}

impl Engine {
    pub fn new(config: Config, database: Database) -> Result<Self> {
        let mut filters = challenge::ChallengeGroup::default();
        let mut ratelimit = ratelimit::RateLimiterGroup::default();
        for (rule_num, control) in config.controls.iter().enumerate() {
            match &control.action {
                Action::Challenge(cfg) => filters
                    .register(rule_num, &cfg)
                    .context("filter rule failed to register")?,
                Action::Ratelimit { limit, global } => {
                    ratelimit.register(rule_num, *limit, *global)
                }
                _ => {}
            }
        }
        Ok(Self {
            proxy: config.proxy,
            firewall: config.firewall,
            controls: config.controls,
            database,
            ratelimit,
            challenges: filters,
        })
    }

    /// Retrieve all IPs associated with request
    #[inline]
    fn get_ips(&self, addr: IpAddr, req: &ProxyRequest) -> Vec<IpAddr> {
        let mut ips = vec![addr];
        if !self.proxy.trust_headers {
            return ips;
        }
        let headers = req.headers();
        let proxy_ips = headers::get_forward_ip(headers, &self.proxy.trusted_headers);
        if !proxy_ips.is_empty() {
            ips.insert(0, proxy_ips[0]);
            ips.extend(proxy_ips.into_iter().skip(1));
        }
        ips
    }

    /// Check global whitelist/blacklist
    #[inline]
    fn check_global(&self, ip: &IpAddr) -> Option<Ruling> {
        if self.firewall.whitelist.contains(ip) {
            return Some(Ruling::allow(ip.clone(), "whitelist"));
        }
        if self.firewall.blacklist.contains(ip) {
            return Some(Ruling::block(ip.clone(), "blacklist", 403));
        }
        if self
            .database
            .whitelist_contains(ip)
            .expect("db whitelist access failed")
        {
            return Some(Ruling::allow(ip.clone(), "allowed"));
        }
        if self
            .database
            .blacklist_contains(ip)
            .expect("db blacklist access failed")
        {
            return Some(Ruling::block(ip.clone(), "blocked", 403));
        }
        None
    }

    pub fn is_blocked(&mut self, addr: IpAddr, req: &ProxyRequest) -> Ruling {
        // determine global ip allow/deny
        let ips = self.get_ips(addr, req);
        let addr = ips[0];
        if let Some(ruling) = ips.iter().find_map(|ip| self.check_global(ip)) {
            return ruling;
        }
        // determine if path is blocked
        let path = req.uri().path();
        log::trace!("evaluating {:?} controls", self.controls.len());
        for (rule_num, control) in self.controls.iter().enumerate() {
            if !control.matches_path(path) {
                log::trace!("evaluating control {control:?} (path: {path})");
                continue;
            }
            if control.match_skip(&addr, path) {
                log::trace!("{addr} allowed for {control:?} (path: {path})");
                continue;
            }
            let Some(ip) = control.match_deny_any(&ips, path) else {
                log::trace!("{addr} skipped {control:?} (path: {path})");
                continue;
            };
            match control.action {
                Action::Block => {
                    log::debug!("{ip} blocked due to {control:?} (path: {path})");
                    let reason = format!("rule_{rule_num}");
                    return Ruling::block(ip, &reason, 403);
                }
                Action::Challenge { .. } => {
                    log::trace!("{ip} being checked for challenge");
                    if let Some(res) = self.challenges.challenge(rule_num, &ip, req) {
                        log::debug!("{ip} challenged due to {control:?} (path: {path})");
                        return Ruling::Challenge { ip, res };
                    }
                }
                Action::Ratelimit { .. } => {
                    log::trace!("{ip} being checked for ratelimit");
                    if self.ratelimit.should_block(rule_num, &ip) {
                        log::debug!("{ip} rate limited due to {control:?} (path: {path})");
                        return Ruling::block(ip, "ratelimit", 429);
                    }
                }
            }
        }
        Ruling::allow(addr, "all_passed")
    }
}
