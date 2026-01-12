// SPDX-License-Identifier: Apache-2.0
//! Prometheus metrics for TACACS+ server observability.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AU-6 (Audit Review, Analysis, and Reporting)**: Provides Prometheus
//!   metrics for operational visibility, trend analysis, and alerting.
//!
//! - **SI-4 (Information System Monitoring)**: Exposes metrics for:
//!   - Connection counts (active, total, rejected)
//!   - Authentication requests by method and result
//!   - Authorization decisions by result
//!   - Accounting records by type and status
//!   - Rate limiting rejections
//!   - Policy reload status
//!
//! - **AU-2 (Audit Events)**: Metrics serve as aggregate audit data for
//!   detecting anomalies and security incidents.

use prometheus::{
    CounterVec, Gauge, Histogram, HistogramOpts, HistogramVec, Opts, Registry, TextEncoder,
    core::Collector,
};
use std::sync::OnceLock;

/// Global metrics registry singleton.
static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Get the global metrics instance.
pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// Prometheus metrics for the TACACS+ server.
/// Note: Some fields are not yet used but will be instrumented in server.rs.
#[allow(dead_code)]
pub struct Metrics {
    registry: Registry,

    // Connection metrics
    pub connections_active: Gauge,
    pub connections_total: CounterVec,
    pub connections_rejected: CounterVec,

    // Authentication metrics
    pub authn_requests_total: CounterVec,
    pub authn_duration_seconds: HistogramVec,

    // Authorization metrics
    pub authz_requests_total: CounterVec,
    pub authz_duration_seconds: Histogram,

    // Accounting metrics
    pub acct_records_total: CounterVec,

    // Session metrics
    pub sessions_active: Gauge,

    // Policy metrics
    pub policy_reload_total: CounterVec,
    pub policy_rules_count: Gauge,

    // Rate limiting metrics
    pub ratelimit_rejections_total: CounterVec,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();

        // Connection metrics
        let connections_active = Gauge::with_opts(Opts::new(
            "tacacs_connections_active",
            "Number of active connections",
        ))
        .expect("metric can be created");

        let connections_total = CounterVec::new(
            Opts::new("tacacs_connections_total", "Total connections by status"),
            &["status", "listener"],
        )
        .expect("metric can be created");

        let connections_rejected = CounterVec::new(
            Opts::new(
                "tacacs_connections_rejected_total",
                "Connections rejected by reason",
            ),
            &["reason"],
        )
        .expect("metric can be created");

        // Authentication metrics
        let authn_requests_total = CounterVec::new(
            Opts::new(
                "tacacs_authn_requests_total",
                "Authentication requests by method and result",
            ),
            &["method", "result"],
        )
        .expect("metric can be created");

        let authn_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "tacacs_authn_duration_seconds",
                "Authentication request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &["method"],
        )
        .expect("metric can be created");

        // Authorization metrics
        let authz_requests_total = CounterVec::new(
            Opts::new(
                "tacacs_authz_requests_total",
                "Authorization requests by result",
            ),
            &["result"],
        )
        .expect("metric can be created");

        let authz_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "tacacs_authz_duration_seconds",
                "Authorization request duration in seconds",
            )
            .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1]),
        )
        .expect("metric can be created");

        // Accounting metrics
        let acct_records_total = CounterVec::new(
            Opts::new("tacacs_acct_records_total", "Accounting records by type"),
            &["type", "status"],
        )
        .expect("metric can be created");

        // Session metrics
        let sessions_active = Gauge::with_opts(Opts::new(
            "tacacs_sessions_active",
            "Number of active sessions",
        ))
        .expect("metric can be created");

        // Policy metrics
        let policy_reload_total = CounterVec::new(
            Opts::new(
                "tacacs_policy_reload_total",
                "Policy reload attempts by result",
            ),
            &["result"],
        )
        .expect("metric can be created");

        let policy_rules_count = Gauge::with_opts(Opts::new(
            "tacacs_policy_rules_count",
            "Number of rules in the active policy",
        ))
        .expect("metric can be created");

        // Rate limiting metrics
        let ratelimit_rejections_total = CounterVec::new(
            Opts::new(
                "tacacs_ratelimit_rejections_total",
                "Rate limit rejections by reason",
            ),
            &["reason"],
        )
        .expect("metric can be created");

        // Register all metrics
        registry
            .register(Box::new(connections_active.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(connections_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(connections_rejected.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(authn_requests_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(authn_duration_seconds.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(authz_requests_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(authz_duration_seconds.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(acct_records_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(sessions_active.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(policy_reload_total.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(policy_rules_count.clone()))
            .expect("metric can be registered");
        registry
            .register(Box::new(ratelimit_rejections_total.clone()))
            .expect("metric can be registered");

        Self {
            registry,
            connections_active,
            connections_total,
            connections_rejected,
            authn_requests_total,
            authn_duration_seconds,
            authz_requests_total,
            authz_duration_seconds,
            acct_records_total,
            sessions_active,
            policy_reload_total,
            policy_rules_count,
            ratelimit_rejections_total,
        }
    }

    /// Encode all metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode_to_string(&metric_families)
            .unwrap_or_default()
    }

    /// Aggregate total connections across all labels.
    pub fn total_connections(&self) -> u64 {
        self.connections_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Aggregate total authentication requests across all labels.
    pub fn total_authn_requests(&self) -> u64 {
        self.authn_requests_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Count successful authentication requests.
    pub fn authn_success_count(&self) -> u64 {
        self.authn_requests_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .filter(|m| {
                        m.get_label()
                            .iter()
                            .any(|l| l.get_name() == "result" && l.get_value() == "pass")
                    })
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Aggregate total authorization requests across all labels.
    pub fn total_authz_requests(&self) -> u64 {
        self.authz_requests_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Count successful authorization requests (allow/pass_add/pass_repl).
    pub fn authz_success_count(&self) -> u64 {
        self.authz_requests_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .filter(|m| {
                        m.get_label().iter().any(|l| {
                            l.get_name() == "result"
                                && (l.get_value() == "allow"
                                    || l.get_value() == "pass_add"
                                    || l.get_value() == "pass_repl")
                        })
                    })
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Aggregate total accounting records across all labels.
    pub fn total_acct_requests(&self) -> u64 {
        self.acct_records_total
            .collect()
            .first()
            .map(|mf| {
                mf.get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }
}

/// Helper to record authentication duration.
/// Used when instrumenting authentication flows in server.rs.
#[allow(dead_code)]
pub struct AuthnTimer {
    method: &'static str,
    start: std::time::Instant,
}

impl AuthnTimer {
    pub fn new(method: &'static str) -> Self {
        Self {
            method,
            start: std::time::Instant::now(),
        }
    }

    pub fn finish(self, result: &str) {
        let duration = self.start.elapsed().as_secs_f64();
        metrics()
            .authn_duration_seconds
            .with_label_values(&[self.method])
            .observe(duration);
        metrics()
            .authn_requests_total
            .with_label_values(&[self.method, result])
            .inc();
    }
}

/// Helper to record authorization duration.
/// Used when instrumenting authorization flows in server.rs.
#[allow(dead_code)]
pub struct AuthzTimer {
    start: std::time::Instant,
}

impl AuthzTimer {
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    pub fn finish(self, result: &str) {
        let duration = self.start.elapsed().as_secs_f64();
        metrics().authz_duration_seconds.observe(duration);
        metrics()
            .authz_requests_total
            .with_label_values(&[result])
            .inc();
    }
}

impl Default for AuthzTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_initialization() {
        let m = metrics();
        // Should be able to increment counters
        m.connections_active.inc();
        m.connections_total
            .with_label_values(&["success", "tls"])
            .inc();
        m.authn_requests_total
            .with_label_values(&["pap", "pass"])
            .inc();

        // Should be able to encode
        let output = m.encode();
        assert!(output.contains("tacacs_connections_active"));
        assert!(output.contains("tacacs_connections_total"));
        assert!(output.contains("tacacs_authn_requests_total"));
    }

    #[test]
    fn test_authn_timer() {
        let timer = AuthnTimer::new("pap");
        std::thread::sleep(std::time::Duration::from_millis(1));
        timer.finish("pass");

        let output = metrics().encode();
        assert!(output.contains("tacacs_authn_duration_seconds"));
    }

    #[test]
    fn test_authz_timer() {
        let timer = AuthzTimer::new();
        timer.finish("allow");

        let output = metrics().encode();
        assert!(output.contains("tacacs_authz_duration_seconds"));
    }
}
