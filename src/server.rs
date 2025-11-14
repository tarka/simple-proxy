
use std::{io::Read, net::SocketAddr, str::FromStr, sync::Arc};

use anyhow::Result;
use async_executor::Executor;
use async_lock::OnceCell;
use camino::Utf8PathBuf;
use cfg_if::cfg_if;
use futures_rustls::TlsAcceptor;
use http::{request::Builder, HeaderName, HeaderValue, Request};
use http_body_util::Full;
use hyper::{
    body::{Body, Buf, Bytes, Incoming},
    server::conn::http2,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST},
    service::service_fn,
    Method,
    Response,
    StatusCode,
    Uri
};
use rustls::{
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::ServerName,
    ClientConfig, ConfigBuilder,
    RootCertStore, ServerConfig, ServerConnection, Stream
};
use smol::net::{TcpListener, TcpStream};
use futures_rustls::TlsConnector;
use smol_hyper::rt::FuturesIo as HyperIo;
use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use tracing_log::log::{error, info, warn};

use crate::{certificates::{handler::CertHandler, store::CertStore, TlsFiles}, errors::Error};



static ROOT_STORE: OnceCell<RootCertStore> = OnceCell::new();

async fn load_system_certs() -> &'static RootCertStore {
    ROOT_STORE.get_or_init(|| async {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    }).await
}

#[derive(Clone)]
struct SmolExecutor;

impl<F> hyper::rt::Executor<F> for SmolExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        smol::spawn(fut).detach();
    }
}


async fn handler(request: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
    let host = request.headers().get(HOST)
        .ok_or(Error::HttpError("No host header in request"))?;
    let path = request.uri().path();

    let msg = format!("Request: {host:?} -> {path}").into_bytes();
    Ok(Response::new(Full::new(msg.into())))
}


pub async fn start_server() -> Result<()>{
    info!("Starting...");

    aws_lc_rs::default_provider().install_default();

    let files = TlsFiles {
        keyfile: Utf8PathBuf::from("tests/data/certs/external/dvalinn.haltcondition.net.key"),
        certfile: Utf8PathBuf::from("tests/data/certs/external/dvalinn.haltcondition.net.crt"),
    };
    let certstore = Arc::new(CertStore::new(&vec![files]).await?);

    let crypto = aws_lc_rs::default_provider();
    let resolver = Arc::new(CertHandler::new(certstore.clone()));
    let mut server_config = ServerConfig::builder_with_provider(crypto.into())
                                 .with_safe_default_protocol_versions()?
                                 .with_no_client_auth()
                                 .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    let server_config = Arc::new(server_config);
    let tls_acceptor = TlsAcceptor::from(server_config.clone());

    let addr = SocketAddr::from_str("0.0.0.0:0")?;
    let listener = TcpListener::bind(addr).await?;

    let service = service_fn(handler);

    loop {
        info!("Listening");
        let (tcp, remote) = listener.accept().await?;
        info!("Connected from {remote}");

        let tls = tls_acceptor.accept(tcp).await?;

        let io = HyperIo::new(tls);

        http2::Builder::new(SmolExecutor)
            .serve_connection(io, service_fn(handler)).await?;

    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    // FIXME
}
