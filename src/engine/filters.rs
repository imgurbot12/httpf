//! Bot Filtering Utilities of Firewall

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use cookie::Cookie;
use http::header::{CONTENT_TYPE, COOKIE};
use hyper::Response;
use rand::{distr::Alphanumeric, Rng};

use crate::config::ChallengeConfig;
use crate::proxy::{full, ProxyResponse};
use crate::{engine::ratelimit::Limiter, proxy::ProxyRequest};

//TODO: new bot detection and challenge action
//TODO: configuration for new action type

const HTML_TEMPLATE: &'static str = include_str!("html/challenge.html");

fn random_cookie() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

struct Context {
    access: Instant,
    threshold: Limiter,
}

impl Context {
    fn new(limit: usize) -> Self {
        let access = Instant::now();
        let threshold = Limiter::new(limit);
        Self { access, threshold }
    }

    #[inline]
    fn is_expired(&self, now: Instant, timeout: Duration) -> bool {
        let expired = now.checked_sub(timeout).expect("timeout too large");
        expired >= self.access
    }
    #[inline]
    fn should_challenge(&mut self) -> bool {
        self.threshold.should_block()
    }
}

struct BotFilter {
    cookie: String,
    timeout: Duration,
    threshold: usize,
    contexts: HashMap<String, Context>,
    last_clean: Instant,
}

impl BotFilter {
    #[inline]
    fn get_cookies(&self, req: &ProxyRequest) -> HashMap<String, String> {
        let headers = req.headers();
        headers
            .get_all(COOKIE)
            .into_iter()
            .filter_map(|c| c.to_str().ok())
            .map(|s| Cookie::split_parse(s))
            .flatten()
            .filter_map(|c| c.ok())
            .map(|c| (c.name().to_owned(), c.value().to_owned()))
            .collect()
    }

    #[inline]
    fn clean(&mut self, now: Instant) {
        let expired = now.checked_sub(self.timeout).expect("timeout too large");
        if expired >= self.last_clean {
            self.last_clean = now;
            self.contexts
                .retain(|_, ctx| !ctx.is_expired(now, self.timeout));
        }
    }

    pub fn should_challenge(&mut self, addr: &IpAddr, req: &ProxyRequest) -> bool {
        let now = Instant::now();
        self.clean(now);
        let cookies = self.get_cookies(req);
        let value = match cookies.get(&self.cookie) {
            Some(cookie) => cookie,
            None => {
                log::trace!("{addr:?} is missing session cookie");
                return true;
            }
        };
        let ctx = match self.contexts.get_mut(value) {
            Some(ctx) => ctx,
            None => {
                log::trace!("{addr:?} cookie is invalid");
                return true;
            }
        };
        if ctx.is_expired(now, self.timeout) {
            log::trace!("{addr:?} cookie is expired");
            self.contexts.remove(value);
            return true;
        }
        ctx.should_challenge()
    }

    pub fn challenge(&mut self) -> ProxyResponse {
        // generate tracking context
        let cookie = random_cookie();
        self.contexts
            .insert(cookie.clone(), Context::new(self.threshold));
        // construct body and response
        let content = regex::Regex::new(r"\{\{(.*?)\}\}")
            .expect("invalid regex template")
            .replace_all(&HTML_TEMPLATE, |caps: &regex::Captures| {
                let key = caps.get(1).unwrap().as_str().trim();
                match key {
                    "cookie_name" => self.cookie.clone(),
                    "cookie_value" => cookie.clone(),
                    _ => panic!("invalid template key"),
                }
            })
            .to_string();
        Response::builder()
            .status(403)
            .header(CONTENT_TYPE, "text/html")
            .body(full(content))
            .expect("failed to construct challenge response")
    }
}

#[derive(Default)]
pub struct FilterGroup {
    filters: HashMap<usize, BotFilter>,
}

impl FilterGroup {
    #[inline]
    pub fn register(&mut self, rule_num: usize, config: &ChallengeConfig) {
        self.filters.insert(
            rule_num,
            BotFilter {
                cookie: config.cookie.clone(),
                timeout: config.timeout.0,
                threshold: config.threshold,
                contexts: Default::default(),
                last_clean: Instant::now(),
            },
        );
    }
    #[inline]
    pub fn challenge(
        &mut self,
        rule_num: usize,
        ip: &IpAddr,
        req: &ProxyRequest,
    ) -> Option<ProxyResponse> {
        let filter = self.filters.get_mut(&rule_num).expect("invalid rule");
        match filter.should_challenge(ip, req) {
            true => Some(filter.challenge()),
            false => None,
        }
    }
}
