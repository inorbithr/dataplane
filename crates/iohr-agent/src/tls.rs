//! TLS for every outbound connection: one root store (the system's plus an optional
//! company CA bundle), the `ring` provider, safe protocol versions only.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};

/// Installs `ring` as the process's rustls provider. Safe to call more than once.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Trusted roots and the client configurations built from them.
#[derive(Debug, Clone)]
pub struct TlsContext {
    roots: Arc<RootCertStore>,
}

impl TlsContext {
    /// The system's roots plus every certificate in `extra_ca` (PEM), if given.
    ///
    /// # Errors
    /// When `extra_ca` cannot be read, or no root at all is available.
    pub fn new(extra_ca: Option<&Path>) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        if let Some(path) = extra_ca {
            add_pem_file(&mut roots, path)?;
        }
        if roots.is_empty() {
            return Err(Error::Tls(
                "no trusted root certificates: install the system CA bundle or set tls.ca_file"
                    .into(),
            ));
        }
        Ok(Self {
            roots: Arc::new(roots),
        })
    }

    /// Only the certificates in `ca_file` (used for the Kubernetes API).
    ///
    /// # Errors
    /// When the file cannot be read or holds no certificate.
    pub fn only(ca_file: &Path) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        add_pem_file(&mut roots, ca_file)?;
        if roots.is_empty() {
            return Err(Error::Tls(format!(
                "{} holds no certificate",
                ca_file.display()
            )));
        }
        Ok(Self {
            roots: Arc::new(roots),
        })
    }

    /// A client configuration offering the given ALPN protocols.
    #[must_use]
    pub fn client_config(&self, alpn: &[&[u8]]) -> ClientConfig {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_or_else(
                    // The ring provider supports the default versions; this branch is unreachable
                    // in practice and falls back to the process default.
                    |_| ClientConfig::builder().with_root_certificates(self.roots.clone()),
                    |b| b.with_root_certificates(self.roots.clone()),
                )
                .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    /// A reqwest client builder that trusts these roots, HTTP/1.1 only.
    pub fn reqwest_builder(&self) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .tls_backend_preconfigured(self.client_config(&[b"http/1.1"]))
            .user_agent(concat!("iohr-agent/", env!("CARGO_PKG_VERSION")))
    }
}

fn add_pem_file(roots: &mut RootCertStore, path: &Path) -> Result<()> {
    let iter = CertificateDer::pem_file_iter(path)
        .map_err(|e| Error::Tls(format!("{}: {e}", path.display())))?;
    for cert in iter {
        let cert = cert.map_err(|e| Error::Tls(format!("{}: {e}", path.display())))?;
        roots
            .add(cert)
            .map_err(|e| Error::Tls(format!("{}: {e}", path.display())))?;
    }
    Ok(())
}
