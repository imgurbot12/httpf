//! Stolen from https://github.com/NLnetLabs/routinator/blob/main/src/utils/tls.rs#L255
//! LICENSE: https://github.com/NLnetLabs/routinator/blob/main/LICENSE (BSD-3)

use std::fs::File;
use std::io::{self, BufReader};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use futures::future::Either;
use futures::pin_mut;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use tokio_rustls::rustls;

use crate::config::TlsConfig;

pub fn setup_tls(config: &TlsConfig) -> Result<TlsAcceptor> {
    use anyhow::Context;

    // read pem file
    let pem = File::open(&config.cert).context("failed to read tls cert")?;
    let mut pemr = BufReader::new(pem);
    let pems: Result<Vec<_>, _> = rustls_pemfile::certs(&mut pemr).collect::<Result<_, _>>();
    let pems: Vec<CertificateDer<'static>> = pems.context("failed to parse tls pemfile")?;

    // read key file
    let key = File::open(&config.key).context("failed to read tls key")?;
    let mut keyr = BufReader::new(key);
    let key =
        rustls_pemfile::private_key(&mut keyr)?.ok_or_else(|| anyhow!("no tls key present"))?;

    // build config and tls acceptor
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(pems, key)
        .context("failed to build tls config")?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    Ok(acceptor)
}

/// A TCP stream that may or may not use TLS.
pub struct UniversalTcpStream {
    sock: Either<TcpStream, TlsStream<TcpStream>>,
}

impl UniversalTcpStream {
    pub async fn new(sock: TcpStream, tls: Option<&TlsAcceptor>) -> Result<Self> {
        Ok(UniversalTcpStream {
            sock: match tls {
                Some(tls) => Either::Right(tls.accept(sock).await?),
                None => Either::Left(sock),
            },
        })
    }
}

impl AsyncRead for UniversalTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for UniversalTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        match self.sock {
            Either::Left(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
            Either::Right(ref mut sock) => {
                pin_mut!(sock);
                sock.poll_shutdown(cx)
            }
        }
    }
}
