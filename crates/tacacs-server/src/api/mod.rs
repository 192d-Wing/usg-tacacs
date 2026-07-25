// SPDX-License-Identifier: Apache-2.0
//! Management API server with RBAC.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../../docs/NIST-CONTROLS-MAPPING.md](../../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-12 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AU-12 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | CM-3 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | SC-8 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-31",
//!   "control_families": [
//!     "AC",
//!     "AU",
//!     "CM",
//!     "SC"
//!   ],
//!   "total_controls": 7,
//!   "file_path": "crates/tacacs-server/src/api/mod.rs"
//! }
//! ```
//!
//! </details>
//!
//! Provides REST API endpoints for runtime management of the TACACS+ server,
//! including session management, policy reload, and monitoring.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-3 (Access Enforcement)**: All API endpoints require RBAC authentication.
//!   Unauthenticated requests are denied with HTTP 403 Forbidden.
//!
//! - **SC-8 (Transmission Confidentiality)**: API supports TLS 1.3 with mTLS
//!   for client authentication (when TLS acceptor is provided).
//!
//! - **AU-2/AU-12 (Audit Events)**: All API access attempts are logged.

mod handlers;
mod middleware;
mod models;
mod rbac;

pub use handlers::{RuntimeConfig, build_api_router};
pub use rbac::{RbacConfig, TlsPeerIdentity};

use crate::jit_lease_store::JitLeaseStore;
use crate::nad_reconciler::RuntimeNadRegistry;
use crate::nad_store::NadStore;
use crate::server::PolicyReloadRequest;
use crate::session_registry::SessionRegistry;
use axum::body::Body;
use hyper_util::rt::TokioIo;
use openssl::nid::Nid;
use openssl::x509::X509;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info, warn};
use usg_tacacs_policy::PolicyEngine;

/// Extract typed identity candidates from a TLS peer certificate.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification | Extracts CN from validated mTLS client certificate |
fn extract_client_identities(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<TlsPeerIdentity> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    let x509 = X509::from_der(leaf.as_ref()).ok()?;
    let candidates = x509_identity_candidates(&x509);
    (!candidates.is_empty()).then_some(TlsPeerIdentity { candidates })
}

fn x509_identity_candidates(x509: &X509) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(names) = x509.subject_alt_names() {
        for name in names {
            if let Some(value) = name.dnsname() {
                candidates.push(format!("dns:{}", value.to_ascii_lowercase()));
            } else if let Some(value) = name.uri() {
                candidates.push(format!("uri:{value}"));
            } else if let Some(value) = name.email() {
                candidates.push(format!("email:{}", value.to_ascii_lowercase()));
            }
        }
    }
    for entry in x509.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(value) = entry.data().to_string() {
            candidates.push(format!("cn:{value}"));
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Handle single TLS connection for management API.
///
/// # NIST SP 800-53 Controls
/// - SC-8: TLS handshake with mTLS client validation
/// - IA-3: Client certificate CN extracted and attached to requests
/// - AU-12: Log TLS handshake failures
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    app: axum::Router,
) {
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            // NIST IA-3: Extract client identity from TLS certificate
            let peer_identity = extract_client_identities(&tls_stream);
            serve_tls_api_connection(tls_stream, peer_addr, app, peer_identity).await;
        }
        Err(e) => {
            warn!(peer = %peer_addr, error = %e, "TLS handshake failed for API connection");
        }
    }
}

/// Serve an established TLS API connection, injecting client identity into requests.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Injects TlsClientIdentity for RBAC middleware |
async fn serve_tls_api_connection(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    app: axum::Router,
    peer_identity: Option<TlsPeerIdentity>,
) {
    let io = TokioIo::new(tls_stream);
    let tower_service = app.clone();
    let hyper_service =
        hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let tower_service = tower_service.clone();
            let identity = peer_identity.clone();
            async move {
                let (mut parts, body) = req.into_parts();
                let body = Body::new(body);
                // NIST IA-3/AC-3: Inject TLS client identity as request extension
                if let Some(id) = identity {
                    parts.extensions.insert(id);
                }
                let axum_req = axum::http::Request::from_parts(parts, body);

                tower_service
                    .oneshot(axum_req)
                    .await
                    .map_err(|err| match err {})
            }
        });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, hyper_service)
        .await
        && !e.is_incomplete_message()
    {
        error!(peer = %peer_addr, error = %e, "API connection error");
    }
}

/// Start the management API server.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | RBAC enforced on all endpoints |
/// | AC-10/AC-12 | Session Control | Session listing and termination via API |
/// | CM-3 | Configuration Change Control | Policy reload channel for controlled updates |
/// | SC-8 | Transmission Confidentiality | TLS 1.3 with mTLS when acceptor is provided |
///
/// The network listener is always TLS 1.3 with mandatory client
/// authentication. Router tests do not use this network entry point.
#[allow(clippy::too_many_arguments)]
pub async fn serve_api(
    addr: SocketAddr,
    acceptor: Option<TlsAcceptor>,
    rbac: RbacConfig,
    policy: Arc<RwLock<PolicyEngine>>,
    policy_path: String,
    schema_path: Option<PathBuf>,
    reload_tx: mpsc::Sender<PolicyReloadRequest>,
    registry: Arc<SessionRegistry>,
    config: RuntimeConfig,
    jit_lease_store: Option<Arc<JitLeaseStore>>,
    nad_store: Option<Arc<NadStore>>,
    runtime_nads: Option<Arc<RuntimeNadRegistry>>,
) -> anyhow::Result<()> {
    let tls_acceptor = require_mtls_acceptor(acceptor)?;
    let app = build_api_router(
        rbac,
        policy,
        policy_path,
        schema_path,
        reload_tx,
        registry,
        config,
        jit_lease_store,
        nad_store,
        runtime_nads,
    );
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, tls = true, "Management API server listening");
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "failed to accept API connection");
                continue;
            }
        };
        let acceptor = tls_acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            handle_tls_connection(stream, peer_addr, acceptor, app).await;
        });
    }
}

fn require_mtls_acceptor(acceptor: Option<TlsAcceptor>) -> anyhow::Result<TlsAcceptor> {
    acceptor.ok_or_else(|| anyhow::anyhow!("management API requires TLS 1.3 client authentication"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    struct TestPki {
        ca: CertificateDer<'static>,
        server: CertificateDer<'static>,
        server_key: Vec<u8>,
        client: CertificateDer<'static>,
        client_key: Vec<u8>,
    }

    fn signed_leaf(
        name: &str,
        usage: ExtendedKeyUsagePurpose,
        issuer: &Issuer<'_, KeyPair>,
    ) -> (CertificateDer<'static>, Vec<u8>) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(usage);
        let cert = params.signed_by(&key, issuer).unwrap();
        (cert.der().clone(), key.serialize_der())
    }

    fn test_pki() -> TestPki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages.extend([
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ]);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let (server, server_key) =
            signed_leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth, &issuer);
        let (client, client_key) = signed_leaf(
            "admin.example.mil",
            ExtendedKeyUsagePurpose::ClientAuth,
            &issuer,
        );
        TestPki {
            ca: ca.der().clone(),
            server,
            server_key,
            client,
            client_key,
        }
    }

    fn server_acceptor(pki: &TestPki) -> TlsAcceptor {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
            .build()
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key.clone()));
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![pki.server.clone()], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    fn client_connector(pki: &TestPki, authenticate: bool, tls13: bool) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone()).unwrap();
        let versions = if tls13 {
            &[&rustls::version::TLS13][..]
        } else {
            &[&rustls::version::TLS12][..]
        };
        let builder =
            ClientConfig::builder_with_protocol_versions(versions).with_root_certificates(roots);
        let config = if authenticate {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_key.clone()));
            builder
                .with_client_auth_cert(vec![pki.client.clone()], key)
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        TlsConnector::from(Arc::new(config))
    }

    async fn run_one_connection(acceptor: TlsAcceptor) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let app = Router::new().route("/probe", get(|| async { "ok" }));
            handle_tls_connection(stream, peer, acceptor, app).await;
        });
        address
    }

    async fn connect(
        address: SocketAddr,
        connector: TlsConnector,
    ) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(address).await?;
        let name = ServerName::try_from("localhost")?;
        Ok(connector.connect(name, stream).await?)
    }

    async fn assert_connection_rejected(address: SocketAddr, connector: TlsConnector) {
        let Ok(mut stream) = connect(address, connector).await else {
            return;
        };
        let request = b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if stream.write_all(request).await.is_err() {
            return;
        }
        let mut response = Vec::new();
        let read_result = stream.read_to_end(&mut response).await;
        assert!(read_result.is_err() || response.is_empty());
    }

    #[test]
    fn certificate_candidates_are_typed_and_dns_is_canonical() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["Admin.Example.Mil".to_owned()]).unwrap();
        let certificate = X509::from_der(certified.cert.der()).unwrap();
        let candidates = x509_identity_candidates(&certificate);
        assert!(candidates.contains(&"dns:admin.example.mil".to_owned()));
        assert!(candidates.iter().all(|identity| {
            ["cn:", "dns:", "email:", "uri:"]
                .iter()
                .any(|prefix| identity.starts_with(prefix))
        }));
    }

    #[test]
    fn plaintext_management_listener_is_rejected() {
        let result = require_mtls_acceptor(None);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn management_socket_requires_mtls_and_tls13() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = test_pki();

        let address = run_one_connection(server_acceptor(&pki)).await;
        let mut stream = connect(address, client_connector(&pki, true, true))
            .await
            .unwrap();
        stream
            .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));

        let address = run_one_connection(server_acceptor(&pki)).await;
        assert_connection_rejected(address, client_connector(&pki, false, true)).await;

        let address = run_one_connection(server_acceptor(&pki)).await;
        assert_connection_rejected(address, client_connector(&pki, true, false)).await;
    }
}
