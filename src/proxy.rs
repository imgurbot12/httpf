//! Implementation Stolen and Customized from https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
//! LICENSE: https://github.com/hyperium/hyper/blob/master/LICENSE (MIT)

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::{dns::GaiResolver, HttpConnector};
use hyper_util::client::legacy::Client;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::*;
use crate::database::Database;
use crate::tls::{setup_tls, UniversalTcpStream};
use crate::tokiort::TokioIo;

static PROXY_HEADERS: [&str; 6] = [
    "true-client-ip",
    "cf-connecting-ip",
    "cf-connecting-ipv4",
    "cf-connecting-ipv6",
    "x-real-ip",
    "x-forwarded-for",
];

type ProxyRequest = Request<Incoming>;
type ProxyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type ProxyResult = Result<ProxyResponse, anyhow::Error>;
type ProxyClient = Client<HttpConnector<GaiResolver>, Incoming>;

type Determination = (bool, IpAddr);

struct ProxyInner {
    proxy: ProxyConfig,
    firewall: FirewallConfig,
    controls: Vec<ControlConfig>,
    database: Database,
}

impl ProxyInner {
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
        if self.proxy.trust_proxy_headers {
            let headers = req.headers();
            let proxy_ips = get_forward_ip(headers, &self.proxy.trusted_headers);
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

type Inner = Arc<Mutex<ProxyInner>>;

pub struct ReverseProxy {
    listen: ListenConfig,
    resolve: ResolveConfig,
    inner: Inner,
}

impl ReverseProxy {
    pub fn new(config: Config, database: Database) -> Self {
        Self {
            listen: config.listen,
            resolve: config.resolve,
            inner: Arc::new(Mutex::new(ProxyInner {
                proxy: config.proxy,
                firewall: config.firewall,
                controls: config.controls,
                database,
            })),
        }
    }

    fn setup_tls(&self) -> Result<Option<TlsAcceptor>> {
        match self.listen.tls.as_ref() {
            Some(config) => Ok(Some(setup_tls(config)?)),
            None => Ok(None),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let tls = self.setup_tls()?;
        let addr = SocketAddr::from((self.listen.host, self.listen.port));

        let client: ProxyClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

        let listener = TcpListener::bind(addr)
            .await
            .context("failed to bind tcp listener")?;

        let scheme = if tls.is_some() { "https" } else { "http" };
        log::info!("Listening on {scheme}://{addr}");

        loop {
            // accept incoming connection
            let (stream, addr) = listener
                .accept()
                .await
                .context("failed to accept client socket")?;

            // unencrypt with tls if tls config is present
            let stream = match UniversalTcpStream::new(stream, tls.as_ref()).await {
                Ok(stream) => stream,
                Err(err) => {
                    log::error!("{addr} tls error: {err:?}");
                    continue;
                }
            };

            // wrap stream in hyper handler for io
            let io = TokioIo::new(stream);
            log::debug!("New Connection {addr:?}");

            // build proxy handler function
            let inner = Arc::clone(&self.inner);
            let config = self.resolve.clone();
            let client = client.clone();
            let proxy_fn = service_fn(move |req| {
                // check if native ip or forwarded ip should be accepted/rejected
                let src = addr.ip();
                let inner = inner.lock().expect("failed mutex lock");
                let (block, real) = inner.is_blocked(src.clone(), &req);
                // handle forwarding request
                let config = config.clone();
                let client = client.clone();
                async move {
                    let uri = req.uri();
                    let method = req.method();
                    if block {
                        log::warn!("[REJECT] {real} (from: {src}) {method} {uri}");
                        Ok(blocked_response())
                    } else {
                        log::info!("[ACCEPT] {real} (from: {src}) {method} {uri}");
                        proxy(config, client, req).await
                    }
                }
            });

            // run proxy handler function and process request
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, proxy_fn)
                    .with_upgrades()
                    .await
                {
                    log::error!("Failed to serve connection: {:?}", err);
                }
            });
        }
    }
}

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

fn get_forward_ip(headers: &HeaderMap<HeaderValue>, trusted: &TrustedHeaders) -> Vec<IpAddr> {
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

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn blocked_response() -> ProxyResponse {
    Response::builder()
        .status(403)
        .body(full("403 Request Denied"))
        .expect("invalid block response")
}

pub async fn proxy(
    config: ResolveConfig,
    client: ProxyClient,
    mut req: ProxyRequest,
) -> ProxyResult {
    // update request URI
    let host = format!("{}:{}", config.host, config.port);
    *req.uri_mut() = format!(
        "http://{host}{}",
        req.uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/")
    )
    .parse()
    .expect("invalid request uri");
    // modify HOST header
    let headers = req.headers_mut();
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(&host).expect("invalid host header"),
    );
    // make request
    let res = client
        .request(req)
        .await
        .context("forwarded http request failed")?;
    Ok(res.map(|b| b.boxed()))
}
