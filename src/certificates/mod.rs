
pub mod handler;
pub mod store;
//pub mod watcher;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rustls::{crypto::CryptoProvider, sign::CertifiedKey};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::errors::Error;



pub struct TlsFiles {
    pub keyfile: Utf8PathBuf,
    pub certfile: Utf8PathBuf,
}

pub type PrivateKey = PrivateKeyDer<'static>;
pub type Certificate = CertificateDer<'static>;

#[derive(Debug)]
pub struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    certfile: Utf8PathBuf,
    cert: Arc<CertifiedKey>,
}

impl HostCertificate {
    async fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile).await?;

        let (_, x509) = X509Certificate::from_der(&certs[0])?;
        let host = x509.subject()
            .iter_common_name()
            .next()
            .context("No host/CN in certificate")?
            .as_str()?
            .to_string();

        let crypto = CryptoProvider::get_default()
            .ok_or(Error::CertificateError("Failed to find default crypto provider in rustls"))?;
        let cert = Arc::new(CertifiedKey::from_der(certs, key, &crypto)?);

        Ok(HostCertificate {
            host,
            keyfile,
            certfile,
            cert,
        })
    }

}

async fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PrivateKey, Vec<Certificate>)> {
    let key = {
        let keyfile = keyfile.to_path_buf();
        blocking::unblock(move || PrivateKeyDer::from_pem_file(keyfile)).await?
    };

    let certs = {
        let certfile = certfile.to_path_buf();
        blocking::unblock(move || CertificateDer::pem_file_iter(certfile)).await?
            .collect::<Result<Vec<_>, _>>()?
    };

    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }
    Ok((key, certs))
}


#[cfg(test)]
mod tests {
    use super::*;
    use macro_rules_attribute::apply;
    use smol_macros::test;
    use x509_parser::prelude::{FromDer, X509Certificate};


    #[apply(test!)]
    #[test_log::test]
    async fn test_load_snakeoil() -> Result<()> {
        let keyfile = Utf8PathBuf::from("tests/data/certs/snakeoil.key");
        let certfile = Utf8PathBuf::from("tests/data/certs/snakeoil.crt");
        let (key, certs) = load_certs(&keyfile, &certfile).await?;

        assert_eq!(1, certs.len());
        let (_, x509) = X509Certificate::from_der(&certs[0])?;
        let cn = x509.subject().iter_common_name().next().unwrap().as_str()?;

        assert_eq!("proxeny.example.com", cn);

        Ok(())
    }


    #[apply(test!)]
    #[test_log::test]
    async fn test_hostcert() -> Result<()> {
        rustls::crypto::aws_lc_rs::default_provider().install_default();

        let keyfile = Utf8PathBuf::from("tests/data/certs/snakeoil.key");
        let certfile = Utf8PathBuf::from("tests/data/certs/snakeoil.crt");
        let hc = HostCertificate::new(keyfile, certfile).await?;

        assert_eq!("proxeny.example.com", hc.host);

        Ok(())
    }
}
