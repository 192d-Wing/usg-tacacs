// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::sync::Arc;

/// Build a RustlsConfig that *requires* client certs (mTLS).
/// Env:
///  - TLS_CERT: server cert PEM (may include chain)
///  - TLS_KEY: server key PEM (PKCS#8)
///  - CLIENT_CA: CA PEM used to verify *client* certs (publishers)
///  - CLIENT_ALLOWED_CN: optional comma-separated CN allowlist
///  - CLIENT_ALLOWED_SAN: optional comma-separated DNS SAN allowlist
pub async fn make_rustls_config_from_env() -> Result<RustlsConfig> {
    let cert_path = std::env::var("TLS_CERT").context("TLS_CERT required")?;
    let key_path = std::env::var("TLS_KEY").context("TLS_KEY required")?;
    let client_ca_path = std::env::var("CLIENT_CA").context("CLIENT_CA required")?;
    let allowed_cn = std::env::var("CLIENT_ALLOWED_CN").unwrap_or_default();
    let allowed_san = std::env::var("CLIENT_ALLOWED_SAN").unwrap_or_default();

    let server_certs = load_certs(&cert_path)?;
    let server_key = load_key(&key_path)?;
    let client_roots = load_ca_roots(&client_ca_path)?;

    let base = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .context("failed building client verifier")?;

    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        if allowed_cn.is_empty() && allowed_san.is_empty() {
            base
        } else {
            Arc::new(crate::tls_allowlist::AllowlistVerifier::new(
                base,
                allowed_cn,
                allowed_san,
            ))
        };

    let cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .context("failed building rustls ServerConfig")?;

    Ok(RustlsConfig::from_config(Arc::new(cfg)))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open cert: {path}"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls::pki_types::PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading private key from {path}"))
}

fn load_ca_roots(path: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open client ca: {path}"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for c in ca {
        roots.add(c)?;
    }
    Ok(roots)
}
