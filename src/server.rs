
use std::{io::Read, net::SocketAddr, sync::Arc};

use anyhow::Result;
use async_lock::OnceCell;
use camino::Utf8PathBuf;
use cfg_if::cfg_if;
use http::{request::Builder, HeaderName, HeaderValue};
use hyper::{
    body::{Buf, Incoming},
    client::conn::http1,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST},
    Method,
    Response,
    StatusCode,
    Uri
};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::ServerName,
    ClientConfig, ConfigBuilder,
    RootCertStore, ServerConfig
};
use tracing_log::log::{error, info, warn};

use crate::{certificates::{handler::CertHandler, store::CertStore, TlsFiles}, errors::Error};

cfg_if! {
    if #[cfg(feature = "smol")] {
        use smol::net::{TcpListener, TcpStream};
        use futures_rustls::TlsConnector;
        use smol_hyper::rt::FuturesIo as HyperIo;

    } else if #[cfg(feature = "tokio")] {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use hyper_util::rt::tokio::TokioIo as HyperIo;

    } else {
        compile_error!("Either smol or tokio feature must be enabled");
    }
}

fn spawn<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) {
    cfg_if! {
        if #[cfg(feature = "smol")] {
            smol::spawn(future)
                .detach();

        } else if #[cfg(feature = "tokio")] {
            tokio::spawn(future);
        }
    }

    // NOTE: This also works, and could be a fallback for other runtimes?
    //
    // let _join = thread::spawn(|| {
    //     pollster::block_on(future);
    // });
}


static ROOT_STORE: OnceCell<RootCertStore> = OnceCell::new();

async fn load_system_certs() -> &'static RootCertStore {
    ROOT_STORE.get_or_init(|| async {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    }).await
}



pub async fn start_server() -> Result<()>{
    info!("Starting...");

    let files = TlsFiles {
        keyfile: Utf8PathBuf::from("tests/data/certs/external/dvalinn.haltcondition.net.key"),
        certfile: Utf8PathBuf::from("tests/data/certs/external/dvalinn.haltcondition.net.crt"),
    };
    let certstore = Arc::new(CertStore::new(&vec![files])?);

    let crypto = aws_lc_rs::default_provider();
    let resolver = Arc::new(CertHandler::new(certstore.clone()));
    let server_config = ServerConfig::builder_with_provider(crypto.into())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // let addr = SocketAddr::from_str("0.0.0.0:8443")?;
    // let listener = TcpListener::bind(addr).await?;

    // TcpStream::connect();

    Ok(())
}




async fn request<In>(method: Method, uri: &Uri, obj: Option<In>, headers: Vec<(HeaderName, HeaderValue)>)
//-> Result<Response<Incoming>>
    -> Result<()>
{
    let host = uri.host()
        .ok_or(Error::UrlError(format!("URL: {:?}", uri)))?
        .to_owned();

    // let mut rb = Builder::new()
    //     .method(method)
    //     .uri(uri)
    //     .header(HOST, &host)
    //     .header(ACCEPT, "application/json");
    // let rheaders = rb.headers_mut()
    //     .ok_or(Error::ApiError("Failed to retrieve HTTP builder headers".to_string()))?;
    // for (k, v) in headers {
    //     rheaders.insert(k, v);
    // }
    // let req = if obj.is_some() {
    //     rb = rb.header(CONTENT_TYPE, "application/json");
    //     let body = serde_json::to_string(&obj)?;
    //     rb.body(body)?
    // } else {
    //     rb.body("".to_string())?
    // };


    // let stream = TcpStream::connect((host.clone(), 443)).await?;

    // let cert_store = load_system_certs();
    // let tlsdomain = ServerName::try_from(host)?;
    // let crypto = aws_lc_rs::default_provider();
    // let tlsconf = ClientConfig::builder_with_provider(crypto.into())
    //     .with_safe_default_protocol_versions()?
    //     .with_root_certificates(cert_store.await)
    //     .with_no_client_auth();
    // let tlsconn = TlsConnector::from(Arc::new(tlsconf));
    // let tlsstream = tlsconn.connect(tlsdomain, stream).await?;
    // println!("tlsstream: {tlsstream:#?}");

    // let (mut sender, conn) = http1::handshake(HyperIo::new(tlsstream)).await?;

    // spawn(async move {
    //     if let Err(e) = conn.await {
    //         error!("Connection failed: {:?}", e);
    //     }
    // });

//    let res = sender.send_request(req).await?;

    Ok(())
}


// async fn from_error(res: Response<Incoming>) -> Result<Error> {
//     let code = res.status();
//     let mut err = String::new();
//     let _nr = res.collect().await?
//         .to_bytes()
//         .reader()
//         .read_to_string(&mut err)?;
//     error!("REST op failed: {code} {err:?}");
//     Ok(Error::HttpError(format!("REST op failed: {code} {err:?}")))
// }


#[cfg(test)]
mod tests {
    use super::*;

    // FIXME
}
