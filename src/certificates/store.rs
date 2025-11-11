use std::sync::Arc;

use anyhow::Result;
use camino::Utf8PathBuf;
use futures::{stream, StreamExt};
use tracing::{debug, info, warn};

use crate::certificates::{HostCertificate, TlsFiles};


#[derive(Debug)]
pub struct CertStore {
    pub by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    pub by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
    // Watched files; this may be a subset of all files as some are
    // unwatched, either by configuration or policy
    // (i.e. acme-generated).
    pub watchlist: Vec<Utf8PathBuf>,
}

impl CertStore {
    pub async fn new(cert_files: &Vec<TlsFiles>) -> Result<Self> {
        info!("Loading host certificates");

        let certs = stream::iter(cert_files)
            .then(|cf| async move {
                info!("Loading certs from {}, {}", cf.keyfile, cf.certfile);
                let hc = HostCertificate::new(cf.keyfile.clone(), cf.certfile.clone()).await?;
                Ok(Arc::new(hc))
            })
            .collect::<Vec<Result<Arc<HostCertificate>>>>().await
            .into_iter().collect::<Result<Vec<Arc<HostCertificate>>>>()?;

        let by_host = certs.iter()
            .map(|cert| (cert.host.clone(),
                         cert.clone()))
            .collect();

        let by_file = certs.iter()
            .flat_map(|cert| {
                vec!((cert.keyfile.clone(), cert.clone()),
                     (cert.certfile.clone(), cert.clone()))
            })
            .collect();

        let watchlist = certs.iter()
            .flat_map(|cert| vec![cert.keyfile.clone(),
                               cert.certfile.clone()])
            .collect();

        let certstore = Self {
            by_host,
            by_file,
            watchlist,
        };

        info!("Loaded {} certificates", certs.len());

        Ok(certstore)
    }

    pub fn replace(&self, newcert: Arc<HostCertificate>) -> Result<()> {
        let host = newcert.host.clone();
        info!("Replacing certificate for {host}");

        self.by_host.pin().update(host, |_old| newcert.clone());

        let by_file = self.by_file.pin();
        let keyfile = newcert.keyfile.clone();
        by_file.update(keyfile, |_old| newcert.clone());
        let certfile = newcert.keyfile.clone();
        by_file.update(certfile, |_old| newcert.clone());

        Ok(())
    }

    pub fn file_list(&self) -> Vec<Utf8PathBuf> {
        self.by_file.pin()
            .keys()
            .cloned()
            .collect()
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use macro_rules_attribute::apply;
    use smol_macros::test;


    #[apply(test!)]
    #[test_log::test]
    async fn test_snakeoil_certstore() -> Result<()> {
        let files = TlsFiles {
            keyfile: Utf8PathBuf::from("tests/data/certs/snakeoil.key"),
            certfile: Utf8PathBuf::from("tests/data/certs/snakeoil.crt"),
        };
        let certstore = CertStore::new(&vec![files]).await?;

        let pinned = certstore.by_host.pin();
        let cert = pinned.get("proxeny.example.com").unwrap();
        assert_eq!("proxeny.example.com", cert.host);

        Ok(())
    }
}
