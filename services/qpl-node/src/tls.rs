// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS / mTLS scaffolding (D-1 CRITICAL remediation).
//!
//! Builds a [`rustls::ServerConfig`] from the operator's PEM-encoded
//! certificate + key, optionally configuring a [`WebPkiClientVerifier`]
//! when mTLS is requested via `tls.client_ca_path`.

use crate::config::TlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

/// Outcome of TLS construction. The error variant deliberately
/// **never** carries a reference to file paths or PEM contents — those
/// are logged via `tracing` server-side only.
#[derive(Debug, thiserror::Error)]
pub enum TlsBuildError {
    #[error("TLS I/O failure")]
    Io,
    #[error("TLS PEM parse failure")]
    Pem,
    #[error("TLS config build failure")]
    Build,
}

/// Build a [`rustls::ServerConfig`] from the supplied [`TlsConfig`].
///
/// On any failure this returns [`TlsBuildError`] (a generic typed
/// error) and writes a detailed `tracing::error!` log line server-side
/// containing the offending path so operators can debug — but the
/// detailed reason is **never** propagated to the client.
pub fn build_server_config(cfg: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, TlsBuildError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_chain = load_certs(&cfg.cert_path)?;
    let key = load_private_key(&cfg.key_path)?;

    let builder = rustls::ServerConfig::builder();

    let server_cfg = if let Some(ca_path) = cfg.client_ca_path.as_ref() {
        // mTLS — require client cert signed by `ca_path`.
        let mut roots = RootCertStore::empty();
        for c in load_certs(ca_path)? {
            roots.add(c).map_err(|e| {
                tracing::error!(error = ?e, "failed to add client CA certificate");
                TlsBuildError::Build
            })?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| {
                tracing::error!(error = ?e, "failed to build client cert verifier");
                TlsBuildError::Build
            })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                tracing::error!(error = ?e, "rustls server config build failed");
                TlsBuildError::Build
            })?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| {
                tracing::error!(error = ?e, "rustls server config build failed");
                TlsBuildError::Build
            })?
    };

    Ok(Arc::new(server_cfg))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsBuildError> {
    let file = File::open(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = ?e, "TLS: cert file open failed");
        TlsBuildError::Io
    })?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            tracing::error!(path = %path.display(), error = ?e, "TLS: cert PEM parse failed");
            TlsBuildError::Pem
        })?;
    if certs.is_empty() {
        tracing::error!(path = %path.display(), "TLS: cert file contained no certificates");
        return Err(TlsBuildError::Pem);
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsBuildError> {
    let file = File::open(path).map_err(|e| {
        tracing::error!(path = %path.display(), error = ?e, "TLS: key file open failed");
        TlsBuildError::Io
    })?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| {
            tracing::error!(path = %path.display(), error = ?e, "TLS: key PEM parse failed");
            TlsBuildError::Pem
        })?
        .ok_or_else(|| {
            tracing::error!(path = %path.display(), "TLS: key file contained no private key");
            TlsBuildError::Pem
        })?;
    Ok(key)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Generates ephemeral self-signed certs for the in-memory TLS test.

    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Write a fresh self-signed cert + key to `dir` and return a
    /// [`TlsConfig`] pointing at them.
    pub fn ephemeral_tls_config() -> (TempDir, TlsConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let mut cf = File::create(&cert_path).unwrap();
        cf.write_all(cert.cert.pem().as_bytes()).unwrap();
        let mut kf = File::create(&key_path).unwrap();
        kf.write_all(cert.key_pair.serialize_pem().as_bytes()).unwrap();
        (
            dir,
            TlsConfig {
                enabled: true,
                cert_path,
                key_path,
                client_ca_path: None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_server_config_with_ephemeral_cert() {
        let (_dir, cfg) = test_support::ephemeral_tls_config();
        let sc = build_server_config(&cfg);
        assert!(sc.is_ok(), "build_server_config should succeed: {:?}", sc.err());
    }

    #[test]
    fn missing_cert_returns_typed_error_without_path_leak() {
        let cfg = TlsConfig {
            enabled: true,
            cert_path: "/nonexistent/qpl/cert.pem".into(),
            key_path: "/nonexistent/qpl/key.pem".into(),
            client_ca_path: None,
        };
        let err = build_server_config(&cfg).unwrap_err();
        let msg = format!("{}", err);
        assert!(!msg.contains("/nonexistent"), "error message must not leak paths");
    }
}
