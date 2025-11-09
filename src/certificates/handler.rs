use std::sync::Arc;

use anyhow::Context;
use rustls::{crypto::CryptoProvider, server::{ClientHello, ResolvesServerCert}, sign::{self, CertifiedKey}};
use tracing_log::log::info;

use crate::certificates::store::CertStore;


#[derive(Debug)]
pub struct CertHandler {
    certstore: Arc<CertStore>,
}

impl CertHandler {
    pub fn new(certstore: Arc<CertStore>) -> Self {
        Self {
            certstore
        }
    }
}

impl ResolvesServerCert for CertHandler {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?;

        info!("TLS Host is {host}; loading certs");

        // FIXME: This should be a `get()` in CertStore, but papaya
        // guard lifetimes make it pointless (we'd have to generate a
        // guard here anyway). There may be another way to do it
        // cleanly?
        let pmap = self.certstore.by_host.pin();
        let host_cert = pmap.get(&host.to_string())
            .expect("Certificate for host not found");

        let provider = CryptoProvider::get_default()?;
        let cert = CertifiedKey::from_der(host_cert.certs.clone(),
                                          host_cert.key.clone_key(),
                                          &provider).ok()?;

        Some(Arc::new(cert))
    }

}
