//! Implementation Stolen and Customized from https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
//! LICENSE: https://github.com/hyperium/hyper/blob/master/LICENSE (MIT)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http::header::HOST;
use http::HeaderValue;
use http_body_util::Full;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::client::legacy::connect::{dns::GaiResolver, HttpConnector};
use hyper_util::client::legacy::Client;

use hyper_util::rt::TokioExecutor;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod request;
mod tls;
mod tokiort;

use crate::config::*;
use crate::database::Database;
use crate::engine::{Engine, Ruling};
use tls::{setup_tls, UniversalTcpStream};
use tokiort::TokioIo;

pub type ProxyRequest = Request<Incoming>;
pub type ProxyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type ProxyResult = Result<ProxyResponse, anyhow::Error>;
type ProxyClient = Client<HttpsConnector<HttpConnector<GaiResolver>>, Incoming>;

pub struct ProxyInner {
    rotation: HashMap<String, usize>,
    engine: Engine,
}

pub struct ReverseProxy {
    listen: ListenConfig,
    resolve: ResolveConfig,
    inner: Arc<Mutex<ProxyInner>>,
}

impl ReverseProxy {
    pub fn new(config: Config, database: Database) -> Result<Self> {
        if config.resolve.default.is_empty() && config.resolve.domains.is_empty() {
            return Err(anyhow!("no domain resolution present"));
        }
        let mut rotation: HashMap<String, usize> = config
            .resolve
            .domains
            .keys()
            .map(|d| (d.pattern.clone(), 0))
            .collect();
        rotation.insert("default".to_owned(), 0);
        Ok(Self {
            listen: config.listen.clone(),
            resolve: config.resolve.clone(),
            inner: Arc::new(Mutex::new(ProxyInner {
                rotation,
                engine: Engine::new(config, database)?,
            })),
        })
    }

    fn setup_tls(&self) -> Result<Option<TlsAcceptor>> {
        match self.listen.tls.as_ref() {
            Some(config) => Ok(Some(setup_tls(config)?)),
            None => Ok(None),
        }
    }

    pub async fn run(self) -> Result<()> {
        let server_tls = self.setup_tls()?;
        let addr = SocketAddr::from((self.listen.host, self.listen.port));

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client_tls = rustls::ClientConfig::builder()
            .with_native_roots()?
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(client_tls)
            .https_or_http()
            .enable_http1()
            .build();
        let client: Arc<ProxyClient> = Arc::new(Client::builder(TokioExecutor::new()).build(https));

        let listener = TcpListener::bind(addr)
            .await
            .context("failed to bind tcp listener")?;

        let scheme = match server_tls.is_some() {
            true => "https",
            false => "http",
        };
        log::info!("Listening on {scheme}://{addr}");

        loop {
            // accept incoming connection
            let (stream, addr) = listener
                .accept()
                .await
                .context("failed to accept client socket")?;

            // unencrypt with tls if tls config is present
            let stream = match UniversalTcpStream::new(stream, server_tls.as_ref()).await {
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
            let client = Arc::clone(&client);
            let resolve = self.resolve.clone();
            let proxy_fn = service_fn(move |req| {
                // check if native ip or forwarded ip should be accepted/rejected
                let src = addr.ip();
                let (base_url, rule) = {
                    // rotate through available urls to load-balance
                    let mut inner = inner.lock().expect("failed mutex lock");
                    let rule = inner.engine.is_blocked(src.clone(), &req);
                    match rule {
                        Ruling::Allow { .. } => {
                            // find list of urls to resolve to associated with request
                            let host = req.headers().get(HOST).and_then(|h| h.to_str().ok());
                            let (domain, urls) = host
                                .and_then(|host| {
                                    resolve
                                        .domains
                                        .iter()
                                        .find(|(matcher, _)| matcher.glob.matches(&host))
                                        .map(|(matcher, urls)| (matcher.pattern.clone(), urls))
                                })
                                .unwrap_or(("default".to_owned(), &resolve.default));
                            // rotate through available urls to load-balance
                            let rotation =
                                inner.rotation.remove(&domain).expect("missing rotation");
                            let base_url = urls[rotation].clone();
                            inner.rotation.insert(domain, (rotation + 1) % urls.len());
                            (base_url, rule)
                        }
                        rule => (url::Url::parse("http://example.com").unwrap(), rule),
                    }
                };
                // handle forwarding request
                let config = base_url.clone();
                let client = Arc::clone(&client);
                async move {
                    let uri = req.uri();
                    let method = req.method();
                    match rule {
                        Ruling::Allow { ip, reason } => {
                            log::info!(
                                "ACCEPT {ip} (from: {src}, reason: {reason}) {method} {uri}"
                            );
                            proxy(config, client, req).await
                        }
                        Ruling::Challenge { ip, res } => {
                            log::info!("CHALLENGE {ip} (from: {src}) {method} {uri}");
                            Ok(res)
                        }
                        Ruling::Deny { ip, reason, code } => {
                            log::warn!(
                                "REJECT {ip} (from: {src}, reason: {reason}) {method} {uri}"
                            );
                            Ok(blocked_response(code))
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

#[inline]
pub fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[inline]
fn blocked_response(code: u16) -> ProxyResponse {
    let status = http::StatusCode::from_u16(code).expect("invalid http code");
    let reason = status
        .canonical_reason()
        .map(|s| s.to_owned())
        .unwrap_or_else(|| format!("{code} Request Denied"));
    Response::builder()
        .status(status)
        .body(full(reason))
        .expect("invalid block response")
}

async fn proxy(config: url::Url, client: Arc<ProxyClient>, mut req: ProxyRequest) -> ProxyResult {
    let result = request::combine_urls(&config, &req.uri())?;
    *req.uri_mut() = result.uri;

    let headers = req.headers_mut();
    if !headers.contains_key(http::header::AUTHORIZATION) {
        if let Some(auth) = result.authorization {
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&auth).context("invalid auth header")?,
            );
        }
    }
    let res = client
        .request(req)
        .await
        .context("forwarded http request failed")?;
    Ok(res.map(|b| b.boxed()))
}
