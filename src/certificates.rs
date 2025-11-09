
use std::{fs, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use crossbeam_channel::{
    self as cbc,
    select,
    Receiver,
    Sender
};
use http::Uri;
use itertools::Itertools;
use notify::{
    EventKind,
    RecursiveMode,
};
use notify_debouncer_full::{
    self as debouncer,
    DebounceEventResult,
    DebouncedEvent,
};
use rustls::server::CertificateType;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
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
struct HostCertificate {
    host: String,
    keyfile: Utf8PathBuf,
    key: PrivateKey,
    certfile: Utf8PathBuf,
    certs: Vec<Certificate>,
}

impl HostCertificate {
    fn new(keyfile: Utf8PathBuf, certfile: Utf8PathBuf) -> Result<Self> {
        let (key, certs) = load_certs(&keyfile, &certfile)?;

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

fn load_certs(keyfile: &Utf8Path, certfile: &Utf8Path) -> Result<(PrivateKey, Vec<Certificate>)> {
    let key = PrivateKeyDer::from_pem_file(keyfile)?
        .clone_key();

    let certs = CertificateDer::pem_file_iter(certfile)?
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        bail!("No certificates found in TLS .crt file");
    }
    Ok((key, certs))
}


pub struct CertStore {
    by_host: papaya::HashMap<String, Arc<HostCertificate>>,
    by_file: papaya::HashMap<Utf8PathBuf, Arc<HostCertificate>>,
    // Watched files; this may be a subset of all files as some are
    // unwatched, either by configuration or policy
    // (i.e. acme-generated).
    watchlist: Vec<Utf8PathBuf>,
}

impl CertStore {
    pub fn new(cert_files: &Vec<TlsFiles>) -> Result<Self> {
        info!("Loading host certificates");

        let certs = cert_files.iter()
            .map(|cf| {
                debug!("Loading certs from {}, {}", cf.keyfile, cf.certfile);
                Ok(Arc::new(HostCertificate::new(cf.keyfile.clone(), cf.certfile.clone())?))
            })
            .collect::<Result<Vec<Arc<HostCertificate>>>>()?;

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

    fn replace(&self, newcert: Arc<HostCertificate>) -> Result<()> {
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


// const RELOAD_GRACE: Duration = Duration::from_millis(1500);

// pub struct CertWatcher {
//     certstore: Arc<CertStore>,
//     tx: Sender<DebounceEventResult>,
//     rx: Receiver<DebounceEventResult>,
//     q_tx: Sender<()>,
//     q_rx: Receiver<()>,
// }

// impl CertWatcher {
//     pub fn new(certstore: Arc<CertStore>) -> Self {
//         let (tx, rx) = cbc::unbounded();
//         let (q_tx, q_rx) = cbc::bounded(1);
//         Self {certstore, tx, rx, q_tx, q_rx}
//     }

//     pub fn watch(&self) -> Result<()> {

//         let mut watcher = debouncer::new_debouncer(RELOAD_GRACE, None, self.tx.clone())?;
//         for f in &self.certstore.watchlist {
//             info!("Starting watch of {f}");
//             watcher.watch(f, RecursiveMode::NonRecursive)?;
//         }

//         loop {
//             select! {
//                 recv(&self.q_rx) -> _r => {
//                     info!("Quitting certificate watcher loop.");
//                     break;
//                 },
//                 recv(&self.rx) -> events => {
//                     match events? {
//                         Err(errs) => warn!("Received errors from cert watcher: {errs:#?}"),
//                         Ok(evs) => self.process_events(evs)?,
//                     }
//                 }
//             };
//         }

//         Ok(())
//     }

//     fn process_events(&self, events: Vec<DebouncedEvent>) -> Result<()> {
//         let certs = events.into_iter()
//             .filter(|dev| matches!(dev.event.kind,
//                                    EventKind::Create(_)
//                                    | EventKind::Modify(_)
//                                    | EventKind::Remove(_)))
//             .flat_map(|dev| dev.paths.clone())
//             .unique()
//             .map(|path| {
//                 let up = Utf8PathBuf::from_path_buf(path)
//                     .expect("Invalid path encoding: {path}")
//                     .canonicalize_utf8()
//                     .expect("Invalid UTF8 path: {path}");
//                 self.certstore.by_file.pin().get(&up)
//                     .expect("Unexpected cert path: {up}")
//                     .clone()
//             })
//             .collect::<Vec<Arc<HostCertificate>>>();

//         for cert in certs {
//             let newcert = Arc::new(HostCertificate::new(cert.host.clone(),
//                                                         cert.keyfile.clone(),
//                                                         cert.certfile.clone())?);
//             self.certstore.replace(newcert)?;
//         }

//         Ok(())
//     }

//     pub fn quit(&self) -> Result<()> {
//         info!("Sending watcher quit signal");
//         self.q_tx.send(())?;
//         Ok(())
//     }

// }


// pub struct CertHandler {
//     certstore: Arc<CertStore>,
// }

// impl CertHandler {
//     pub fn new(certstore: Arc<CertStore>) -> Self {
//         Self {
//             certstore
//         }
//     }
// }

// #[async_trait]
// impl TlsAccept for CertHandler {

//     // NOTE:This is all boringssl specific as pingora doesn't
//     // currently support dynamic certs with rustls.
//     async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
//         let host = ssl.servername(NameType::HOST_NAME)
//             .expect("No servername in TLS handshake");

//         info!("TLS Host is {host}; loading certs");

//         // FIXME: This should be a `get()` in CertStore, but papaya
//         // guard lifetimes make it pointless (we'd have to generate a
//         // guard here anyway). There may be another way to do it
//         // cleanly?
//         let pmap = self.certstore.by_host.pin();
//         let cert = pmap.get(&host.to_string())
//             .expect("Certificate for host not found");

//         ssl.set_private_key(&cert.key)
//             .expect("Failed to set private key");
//         info!("Certificate found: {:?}, expires {}", cert.certs[0].subject_name(), cert.certs[0].not_after());
//         ssl.set_certificate(&cert.certs[0])
//             .expect("Failed to set certificate");

//         if cert.certs.len() > 1 {
//             for c in cert.certs[1..].iter() {
//                 ssl.add_chain_cert(&c)
//                     .expect("Failed to add chain certificate");
//             }
//         }
//     }

// }



#[cfg(test)]
mod tests {
    use std::io::Read;

    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;

    #[test]
    fn test_load_snakeoil() -> Result<()> {
        let keyfile = Utf8PathBuf::from("tests/data/certs/snakeoil.key");
        let certfile = Utf8PathBuf::from("tests/data/certs/snakeoil.crt");
        let (key, certs) = load_certs(&keyfile, &certfile)?;

        assert_eq!(1, certs.len());
        let (_, x509) = X509Certificate::from_der(&certs[0])?;
        let cn = x509.subject().iter_common_name().next().unwrap().as_str()?;

        assert_eq!("proxeny.example.com", cn);

        Ok(())
    }

    #[test]
    fn test_snakeoil_certstore() -> Result<()> {
        let files = TlsFiles {
            keyfile: Utf8PathBuf::from("tests/data/certs/snakeoil.key"),
            certfile: Utf8PathBuf::from("tests/data/certs/snakeoil.crt"),
        };
        let certstore = CertStore::new(&vec![files])?;

        let pinned = certstore.by_host.pin();
        let cert = pinned.get("proxeny.example.com").unwrap();
        assert_eq!("proxeny.example.com", cert.host);

        Ok(())
    }

    // #[test]
    // fn test_watchlist_exclusion() -> Result<()> {
    //     let config = Config {
    //         servers: vec![
    //             Server {
    //                 hostname: "host1".to_owned(),
    //                 tls: TlsConfig {
    //                     port: 443,
    //                     config: TlsConfigType::Files(TlsFilesConfig {
    //                         keyfile: Utf8PathBuf::from("keyfile1.key"),
    //                         certfile: Utf8PathBuf::from("certfile1.crt"),
    //                         reload: true,
    //                     })
    //                 },
    //                 backends: vec![
    //                     Backend {
    //                         context: None,
    //                         url: Uri::from_static("http://localhost")
    //                     }
    //                 ]
    //             },
    //             Server {
    //                 hostname: "host2".to_owned(),
    //                 tls: TlsConfig {
    //                     port: 443,
    //                     config: TlsConfigType::Files(TlsFilesConfig {
    //                         keyfile: Utf8PathBuf::from("keyfile2.key"),
    //                         certfile: Utf8PathBuf::from("certfile2.crt"),
    //                         reload: false,
    //                     })
    //                 },
    //                 backends: vec![
    //                     Backend {
    //                         context: None,
    //                         url: Uri::from_static("http://localhost")
    //                     }
    //                 ]
    //             },
    //             Server {
    //                 hostname: "host3".to_owned(),
    //                 tls: TlsConfig {
    //                     port: 443,
    //                     config: TlsConfigType::Acme(TlsAcmeConfig {
    //                         provider: AcmeProvider::LetsEncrypt,
    //                         challenge_type: AcmeChallenge::Dns01,
    //                         contact: "myname@example.com".to_string(),
    //                         dns_provider: DnsProvider::Gandi(Auth::ApiKey("test".to_string())),
    //                     })}
    //                 ,
    //                 backends: vec![
    //                     Backend {
    //                         context: None,
    //                         url: Uri::from_static("http://localhost")
    //                     }
    //                 ]
    //             },
    //         ]
    //     };

    //     let watchlist = gen_watchlist(&config);

    //     assert_eq!(2, watchlist.len());
    //     assert_eq!(Utf8PathBuf::from("keyfile1.key"), watchlist[0]);
    //     assert_eq!(Utf8PathBuf::from("certfile1.crt"), watchlist[1]);

    //     Ok(())
    // }
}
