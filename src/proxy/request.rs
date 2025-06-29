use anyhow::{Context, Result};
use base64::prelude::*;

#[derive(Debug)]
pub struct UrlResult {
    pub uri: http::Uri,
    pub authorization: Option<String>,
}

/// Combine Requested URL with the Configured Resolution URL
#[inline]
pub fn combine_urls(base: &url::Url, resolv: &http::Uri) -> Result<UrlResult> {
    let mut host = base
        .host()
        .context("base resolution configuration url missing host")?
        .to_string();
    if let Some(port) = base.port_or_known_default() {
        host = format!("{host}:{port}")
    }

    let mut query = format!("?{}", resolv.query().unwrap_or_default());
    if let Some(base_query) = base.query() {
        let c = if query.len() > 1 { "&" } else { "" };
        query = format!("{query}{c}{base_query}");
    }

    // append requested path to base-path ignoring prefixed ..
    let mut path: Vec<&str> = base
        .path_segments()
        .map(|e| e.collect())
        .unwrap_or_default();
    path.extend(
        resolv
            .path()
            .split('/')
            .skip_while(|c| c.is_empty() || c == &".."),
    );
    if query.len() > 1 {
        path.push(&query);
    }

    let uri = http::Uri::builder()
        .scheme(base.scheme())
        .authority(host.clone())
        .path_and_query(path.join("/"))
        .build()
        .context("failed to construct url")?;

    let authorization = match base.has_authority() {
        false => None,
        true => match base.authority().split_once("@") {
            Some((auth, _)) => Some(format!("Basic {}", BASE64_STANDARD.encode(auth))),
            None => None,
        },
    };

    Ok(UrlResult { uri, authorization })
}
