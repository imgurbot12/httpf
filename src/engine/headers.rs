use std::{net::IpAddr, str::FromStr};

use http::{HeaderMap, HeaderValue};

use crate::config::{IpList, TrustedHeaders};

const PROXY_HEADERS: [&str; 6] = [
    "true-client-ip",
    "cf-connecting-ip",
    "cf-connecting-ipv4",
    "cf-connecting-ipv6",
    "x-real-ip",
    "x-forwarded-for",
];

fn header(headers: &HeaderMap<HeaderValue>, key: &str) -> Option<String> {
    match headers.get(key).map(|h| h.to_str()) {
        None => None,
        Some(header) => match header {
            Err(err) => {
                log::warn!("header {key:?} not valid utf-8: {err:?}");
                None
            }
            Ok(header) => Some(header.to_lowercase()),
        },
    }
}

#[inline]
fn is_trusted(trusted: &TrustedHeaders, header: &str) -> bool {
    trusted
        .as_ref()
        .map(|trusted| trusted.contains(&header.to_string()))
        .unwrap_or(true)
}

pub fn get_forward_ip(headers: &HeaderMap<HeaderValue>, trusted: &TrustedHeaders) -> Vec<IpAddr> {
    let mut ips = IpList::new();
    for name in PROXY_HEADERS.iter().filter(|key| is_trusted(trusted, key)) {
        if let Some(header) = header(headers, name) {
            ips.extend(
                header
                    .split(',')
                    .filter_map(|ip| IpAddr::from_str(ip.trim()).ok()),
            );
        }
    }
    // syntax: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
    if is_trusted(trusted, "forwarded") {
        if let Some(header) = header(headers, "forwarded") {
            ips.extend(
                header
                    .split(';')
                    .into_iter()
                    .map(|kv| kv.split(','))
                    .flatten()
                    .filter_map(|kv| kv.trim().split_once('='))
                    .filter(|(k, _)| *k == "for")
                    .map(|(_, v)| v.trim_matches(|c| c == '[' || c == '"' || c == '\''))
                    .map(|v| v.split_once(']').map(|(s, _)| s).unwrap_or(v))
                    .filter_map(|ip| IpAddr::from_str(ip).ok()),
            );
        }
    }
    ips.into_iter().collect()
}
