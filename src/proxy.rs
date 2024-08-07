//! Implementation Stolen and Customized from https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};

use tokio::net::{TcpListener, TcpStream};

use crate::config::{Config, IpList, ListenConfig, ResolveConfig};
use crate::tokiort::TokioIo;

static PROXY_HEADERS: [&str; 6] = [
    "true-client-ip",
    "cf-connecting-ip",
    "cf-connecting-ipv4",
    "cf-connecting-ipv6",
    "x-real-ip",
    "x-forwarded-for",
];

type ProxyRequest = Request<hyper::body::Incoming>;
type ProxyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type ProxyResult = Result<ProxyResponse, hyper::Error>;

struct ProxyInner {
    whitelist: IpList,
    blacklist: IpList,
}

impl ProxyInner {
    pub fn is_blocked(&self, ip: IpAddr) -> Option<IpAddr> {
        if self.whitelist.contains(&ip) {
            return None;
        }
        if self.blacklist.contains(&ip) {
            return Some(ip);
        }
        None
    }
}

type Inner = Arc<Mutex<ProxyInner>>;

pub struct ReverseProxy {
    listen: ListenConfig,
    resolve: ResolveConfig,
    inner: Inner,
}

impl ReverseProxy {
    pub fn new(config: Config) -> Self {
        Self {
            listen: config.listen,
            resolve: config.resolve,
            inner: Arc::new(Mutex::new(ProxyInner {
                whitelist: config.whitelist,
                blacklist: config.blacklist,
            })),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr = SocketAddr::from((self.listen.host, self.listen.port));

        let listener = TcpListener::bind(addr)
            .await
            .context("failed to bind tcp listener")?;
        log::info!("Listening on http://{addr}");

        loop {
            let (stream, addr) = listener
                .accept()
                .await
                .context("failed to accept client socket")?;
            let io = TokioIo::new(stream);

            // build proxy handler function
            let inner = Arc::clone(&self.inner);
            let config = self.resolve.clone();
            let proxy_fn = service_fn(move |req| {
                // check if native ip or forwarded ip should be accepted/rejected
                let ipaddr = addr.ip();
                let headers = req.headers();
                let inner = inner.lock().expect("failed mutex lock");
                let mut blocked = inner.is_blocked(ipaddr);
                if blocked.is_none() {
                    blocked = get_forward_ip(headers)
                        .into_iter()
                        .find(|ip| inner.is_blocked(*ip).is_some());
                }
                // handle forwarding request
                let config = config.clone();
                async move {
                    match blocked {
                        None => proxy(config, req).await,
                        Some(ip) => {
                            log::warn!("BLOCKED: {ip:?} ({} {})", req.method(), req.uri());
                            Ok(blocked_response())
                        }
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

fn get_forward_ip(headers: &HeaderMap<HeaderValue>) -> Vec<IpAddr> {
    let mut ips = IpList::new();
    for name in PROXY_HEADERS.iter() {
        if let Some(header) = header(headers, name) {
            ips.extend(
                header
                    .split(',')
                    .filter_map(|ip| IpAddr::from_str(ip.trim()).ok()),
            );
        }
    }
    // syntax: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded
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

pub async fn proxy(config: ResolveConfig, mut req: ProxyRequest) -> ProxyResult {
    // modify HOST header
    let host = format!("{}:{}", config.host, config.port);
    let headers = req.headers_mut();
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(&host).expect("invalid host header"),
    );

    // connec to socket with designated host/port
    let stream = TcpStream::connect((config.host, config.port))
        .await
        .unwrap();
    let io = TokioIo::new(stream);

    // build sender and check connection
    let (mut sender, conn) = Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            log::error!("Connection failed: {:?}", err);
        }
    });

    // send request and return response
    let resp = sender.send_request(req).await?;
    Ok(resp.map(|b| b.boxed()))
}
