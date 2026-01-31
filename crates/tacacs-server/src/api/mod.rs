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
pub use rbac::RbacConfig;

use crate::server::PolicyReloadRequest;
use crate::session_registry::SessionRegistry;
use axum::body::Body;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info, warn};
use usg_tacacs_policy::PolicyEngine;

/// Handle single TLS connection for management API.
///
/// # NIST SP 800-53 Controls
/// - SC-8: TLS handshake with mTLS client validation
/// - AU-12: Log TLS handshake failures
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    app: axum::Router,
) {
    match acceptor.accept(stream).await {
        Ok(tls_stream) => {
            let io = TokioIo::new(tls_stream);
            let tower_service = app.clone();
            let hyper_service = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let tower_service = tower_service.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = Body::new(body);
                        let axum_req = axum::http::Request::from_parts(parts, body);

                        tower_service
                            .oneshot(axum_req)
                            .await
                            .map_err(|err| match err {})
                    }
                },
            );

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_service)
                .await
            {
                if !e.is_incomplete_message() {
                    error!(peer = %peer_addr, error = %e, "API connection error");
                }
            }
        }
        Err(e) => {
            warn!(peer = %peer_addr, error = %e, "TLS handshake failed for API connection");
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
