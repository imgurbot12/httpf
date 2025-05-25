//! Simple RateLimit Handler

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

const DEFAULT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

struct Limiter {
    limit: usize,
    count: usize,
    expires: Instant,
}

impl Limiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            count: 0,
            expires: Instant::now(),
        }
    }

    fn should_block(&mut self) -> bool {
        if self.expires.elapsed().as_secs() >= 1 {
            self.expires = Instant::now();
            self.count = 0;
        }
        self.count += 1;
        return self.count > self.limit;
    }
}

struct RateLimiter {
    limit: usize,
    is_global: bool,
    limiters: HashMap<IpAddr, Limiter>,
}

impl RateLimiter {
    fn new(limit: usize, is_global: bool) -> Self {
        Self {
            limit,
            is_global,
            limiters: Default::default(),
        }
    }
    #[inline]
    fn should_block(&mut self, ip: &IpAddr) -> bool {
        let ip = match self.is_global {
            false => ip,
            true => &DEFAULT_IP,
        };
        if !self.limiters.contains_key(ip) {
            let limiter = Limiter::new(self.limit);
            self.limiters.insert(ip.clone(), limiter);
        }
        self.limiters
            .get_mut(ip)
            .expect("missing rate limiter")
            .should_block()
    }
}

#[derive(Default)]
pub struct RateLimiterGroup {
    limiters: HashMap<usize, RateLimiter>,
}

impl RateLimiterGroup {
    #[inline]
    pub fn register(&mut self, rule_num: usize, limit: usize, is_global: bool) {
        self.limiters
            .insert(rule_num, RateLimiter::new(limit, is_global));
    }
    #[inline]
    pub fn should_block(&mut self, rule_num: usize, ip: &IpAddr) -> bool {
        self.limiters
            .get_mut(&rule_num)
            .expect("invalid rule")
            .should_block(ip)
    }
}
