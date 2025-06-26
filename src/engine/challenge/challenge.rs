//! Bot Filtering Utilities of Firewall

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use cookie::Cookie;
use http::header::{CONTENT_TYPE, COOKIE};
use hyper::Response;
use rand::distr::Alphanumeric;
use rand::Rng;

use crate::config::ChallengeConfig;
use crate::proxy::{full, ProxyResponse};
use crate::{engine::ratelimit::Limiter, proxy::ProxyRequest};

const HTML_TEMPLATE: &'static str = include_str!("static/challenge.html");
const SIMPLE_CHALLENGE: &'static str = include_str!("static/js/simple.js");

fn randstr(length: usize) -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

struct ChallengeCtx {
    access: Instant,
    threshold: Limiter,
}

impl ChallengeCtx {
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
    template: String,
    cookie: String,
    timeout: Duration,
    threshold: usize,
    contexts: HashMap<String, ChallengeCtx>,
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
        // compile javascript challenge
        let rgx = regex::Regex::new(r"\{\{(.*?)\}\}").expect("invalid regex template");
        let cookie = randstr(8);
        let challenge = rgx
            .replace_all(&SIMPLE_CHALLENGE, |c: &regex::Captures| {
                match c.get(1).unwrap().as_str().trim() {
                    "cookie_name" => self.cookie.clone(),
                    "cookie_value" => jsfuck::obfuscate(&cookie),
                    key => {
                        log::error!("invalid template key {key:?}");
                        String::new()
                    }
                }
            })
            .to_string();
        // generate tracking context
        self.contexts
            .insert(cookie, ChallengeCtx::new(self.threshold));
        // construct body and response
        let content = rgx
            .replace_all(&self.template, |c: &regex::Captures| {
                match c.get(1).unwrap().as_str().trim() {
                    "challenge" => challenge.clone(),
                    key => {
                        log::error!("invalid template key {key:?}");
                        String::new()
                    }
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
pub struct ChallengeGroup {
    filters: HashMap<usize, BotFilter>,
}

impl ChallengeGroup {
    #[inline]
    pub fn register(&mut self, rule_num: usize, config: &ChallengeConfig) -> Result<()> {
        let template = match config.template.as_ref().filter(|p| p.exists()) {
            Some(path) => std::fs::read_to_string(path).context("failed to read template")?,
            None => HTML_TEMPLATE.to_owned(),
        };
        self.filters.insert(
            rule_num,
            BotFilter {
                cookie: config.cookie.clone(),
                timeout: config.timeout.0,
                threshold: config.threshold,
                contexts: Default::default(),
                last_clean: Instant::now(),
                template,
            },
        );
        Ok(())
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
