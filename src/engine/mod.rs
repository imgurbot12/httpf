use std::net::IpAddr;

use crate::config::{ControlConfig, FirewallConfig, ProxyConfig};
use crate::database::Database;
use crate::proxy::ProxyRequest;

mod headers;

pub type Determination = (bool, IpAddr);

pub struct Engine {
    pub proxy: ProxyConfig,
    pub firewall: FirewallConfig,
    pub controls: Vec<ControlConfig>,
    pub database: Database,
}

impl Engine {
    // check if globally allowed/rejected
    fn global_is_blocked(&self, ip: IpAddr) -> Option<IpAddr> {
        if self.firewall.whitelist.contains(&ip) {
            return None;
        }
        if self.firewall.blacklist.contains(&ip) {
            return Some(ip);
        }
        if self
            .database
            .whitelist_contains(&ip)
            .expect("db whitelist access failed")
        {
            return None;
        }
        if self
            .database
            .blacklist_contains(&ip)
            .expect("db blacklist access failed")
        {
            return Some(ip);
        }
        None
    }
    pub fn is_blocked(&self, mut addr: IpAddr, req: &ProxyRequest) -> Determination {
        // determine global ip allow/deny
        let mut ips = vec![addr];
        let mut blocked = self.global_is_blocked(addr);
        if self.proxy.trust_headers {
            let headers = req.headers();
            let proxy_ips = headers::get_forward_ip(headers, &self.proxy.trusted_headers);
            if !proxy_ips.is_empty() {
                addr = proxy_ips[0];
                if blocked.is_none() {
                    blocked = proxy_ips
                        .clone()
                        .into_iter()
                        .find(|ip| self.global_is_blocked(*ip).is_some());
                }
                ips.insert(0, addr);
                ips.extend(proxy_ips.into_iter().skip(1));
            }
        }
        log::trace!("global ip block? {blocked:?}");
        // determine if path is blocked
        if blocked.is_none() {
            let path = req.uri().path();
            for control in self.controls.iter() {
                if !control.matches_path(path) {
                    log::trace!("evaluating control {control:?} (path: {path})");
                    continue;
                }
                if control.match_allow(&addr) {
                    log::trace!("{addr} allowed for {control:?} (path: {path})");
                    continue;
                }
                if let Some(ip) = control.match_deny_any(&ips) {
                    log::debug!("{ip} blocked due to {control:?} (path: {path})");
                    blocked = Some(ip);
                    break;
                }
            }
        }
        match blocked {
            Some(addr) => (true, addr),
            None => (false, addr),
        }
    }
}
