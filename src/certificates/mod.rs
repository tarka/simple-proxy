
pub mod handler;
pub mod store;
//pub mod watcher;

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};



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
    key: PrivateKey,
    certfile: Utf8PathBuf,
    certs: Vec<Certificate>,
}

impl HostCertificate {
    async fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile).await?;

        let (_, x509) = X509Certificate::from_der(&certs[0])?;
        let cn = x509.subject()
            .iter_common_name()
            .next()
            .context("No host/CN in certificate")?
            .as_str()?
            .to_string();

        Ok(HostCertificate {
            host: cn,
            keyfile,
            key,
            certfile,
            certs,
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
        let keyfile = Utf8PathBuf::from("tests/data/certs/snakeoil.key");
        let certfile = Utf8PathBuf::from("tests/data/certs/snakeoil.crt");
        let hc = HostCertificate::new(keyfile, certfile).await?;

        assert_eq!(1, hc.certs.len());
        assert_eq!("proxeny.example.com", hc.host);

        Ok(())
    }
}
