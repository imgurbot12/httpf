//! Implementation Stolen and Customized from https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
//! LICENSE: https://github.com/hyperium/hyper/blob/master/LICENSE (MIT)

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
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
use crate::engine::Engine;
use tls::{setup_tls, UniversalTcpStream};
use tokiort::TokioIo;

pub type ProxyRequest = Request<Incoming>;
type ProxyResponse = Response<BoxBody<Bytes, hyper::Error>>;
type ProxyResult = Result<ProxyResponse, anyhow::Error>;
type ProxyClient = Client<HttpsConnector<HttpConnector<GaiResolver>>, Incoming>;

type Inner = Arc<Mutex<Engine>>;

pub struct ReverseProxy {
    listen: ListenConfig,
    resolve: Vec<url::Url>,
    rotation: usize,
    inner: Inner,
}

impl ReverseProxy {
    pub fn new(config: Config, database: Database) -> Self {
        if config.resolve.is_empty() {
            panic!("resolution list must not be empty");
        }
        Self {
            listen: config.listen,
            resolve: config.resolve,
            rotation: 0,
            inner: Arc::new(Mutex::new(Engine {
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

    pub async fn run(mut self) -> Result<()> {
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

        let scheme = if server_tls.is_some() {
            "https"
        } else {
            "http"
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

            // round robin rotate urls
            let base_url = self.resolve[self.rotation].clone();
            self.rotation = (self.rotation + 1) % self.resolve.len();

            // build proxy handler function
            let inner = Arc::clone(&self.inner);
            let client = Arc::clone(&client);
            let proxy_fn = service_fn(move |req| {
                // check if native ip or forwarded ip should be accepted/rejected
                let src = addr.ip();
                let inner = inner.lock().expect("failed mutex lock");
                let (block, real) = inner.is_blocked(src.clone(), &req);
                // handle forwarding request
                let config = base_url.clone();
                let client = Arc::clone(&client);
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

#[inline]
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[inline]
fn blocked_response() -> ProxyResponse {
    Response::builder()
        .status(403)
        .body(full("403 Request Denied"))
        .expect("invalid block response")
}

async fn proxy(url: url::Url, client: Arc<ProxyClient>, mut req: ProxyRequest) -> ProxyResult {
    let result = request::combine_urls(&url, &req.uri())?;
    *req.uri_mut() = result.uri;

    let headers = req.headers_mut();
    headers.insert(
        http::header::HOST,
        HeaderValue::from_str(&result.host).context("invalid host header")?,
    );
    if let Some(auth) = result.authorization {
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&auth).context("invalid auth header")?,
        );
    }

    let res = client
        .request(req)
        .await
        .context("forwarded http request failed")?;
    Ok(res.map(|b| b.boxed()))
}
