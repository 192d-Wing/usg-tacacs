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
mod models;
mod rbac;

pub use handlers::{RuntimeConfig, build_api_router};
pub use rbac::{RbacConfig, TlsClientIdentity};

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

/// Extract the Common Name from a TLS peer certificate.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification | Extracts CN from validated mTLS client certificate |
fn extract_client_cn(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    let x509 = X509::from_der(leaf.as_ref()).ok()?;
    for entry in x509.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(val) = entry.data().as_utf8() {
            return Some(val.to_string());
        }
    }
    None
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
            let client_identity = extract_client_cn(&tls_stream).map(|cn| TlsClientIdentity { cn });
            serve_tls_api_connection(tls_stream, peer_addr, app, client_identity).await;
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
    client_identity: Option<TlsClientIdentity>,
) {
    let io = TokioIo::new(tls_stream);
    let tower_service = app.clone();
    let hyper_service =
        hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let tower_service = tower_service.clone();
            let identity = client_identity.clone();
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
    {
        if !e.is_incomplete_message() {
            error!(peer = %peer_addr, error = %e, "API connection error");
        }
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
/// # Security Warning
/// When `acceptor` is `None`, the API runs in plaintext mode which should only
/// be used for development/testing. Production deployments must use TLS.
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
) -> anyhow::Result<()> {
    let app = build_api_router(
        rbac,
        policy,
        policy_path,
        schema_path,
        reload_tx,
        registry,
        config,
    );
    let listener = TcpListener::bind(addr).await?;

    if let Some(tls_acceptor) = acceptor {
        info!(addr = %addr, tls = true, "Management API server listening (TLS enabled)");

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
    } else {
        warn!(
            addr = %addr,
            "Management API server listening in PLAINTEXT mode - NOT RECOMMENDED FOR PRODUCTION"
        );
        if let Err(e) = axum::serve(listener, app).await {
            error!(error = %e, "API server error");
            return Err(e.into());
        }
    }

    Ok(())
}
