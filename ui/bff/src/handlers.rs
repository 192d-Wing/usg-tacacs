// SPDX-License-Identifier: Apache-2.0
//! HTTP handlers: audit, flows, metrics, resources, alerts, me.

use crate::clients::{loki_query_range, prom_query_range, prom_scalar, AuditEntry};
use crate::AppState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

type Params = HashMap<String, String>;

fn now_ns() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64
}
fn now_s() -> i64 {
    now_ns() / 1_000_000_000
}
fn p_u32(q: &Params, k: &str, d: u32) -> u32 {
    q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn p_i64(q: &Params, k: &str, d: i64) -> i64 {
    q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
}
/// Escape a value for use inside a LogQL double-quoted regex/string.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn err(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_GATEWAY, Json(json!({ "error": e.to_string() })))
}

// ---------------------------------------------------------------------------
// Policy dry-run types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DryRunRule {
    id: String,
    priority: i64,
    effect: String, // "allow" | "deny"
    pattern: String,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize)]
struct DryRunPolicy {
    rules: Vec<DryRunRule>,
    #[serde(default = "default_allow")]
    default_allow: bool,
}

fn default_allow() -> bool { false }

#[derive(Deserialize)]
pub struct DryRunRequest {
    policy: DryRunPolicy,
    #[serde(default = "default_minutes")]
    minutes: i64,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_minutes() -> i64 { 60 }
fn default_limit() -> u32 { 500 }

// ---------------------------------------------------------------------------

/// POST /api/policy/dry-run — evaluate a candidate policy against recent authz events.
///
/// Body: `{ "policy": { "rules": [...], "default_allow": false }, "minutes": 60 }`
///
/// Returns a list of events whose authz decision would change under the new policy,
/// plus summary counts.  Only command-level authz events are evaluated; shell-start
/// events (no `cmd`) are skipped.
pub async fn policy_dry_run(
    State(st): State<AppState>,
    Json(req): Json<DryRunRequest>,
) -> impl IntoResponse {
    let minutes = req.minutes.clamp(1, 60 * 24);
    let limit   = req.limit.clamp(1, 5000);
    let end   = now_ns();
    let start = end - minutes * 60 * 1_000_000_000;

    // Fetch recent authz events (both allow and deny).
    let logql = format!(
        "{{logtarget=\"{}\"}} | json | event=~\"authz_policy_allow|authz_policy_deny\"",
        esc(&st.audit_target)
    );
    let events = match loki_query_range(&st, &logql, start, end, limit, true).await {
        Ok(e) => e,
        Err(e) => return err(e).into_response(),
    };

    // Compile candidate policy rules once.
    let mut compiled: Vec<(i64, &DryRunRule, Regex)> = Vec::new();
    for rule in &req.policy.rules {
        let anchored = format!("^(?:{})$", rule.pattern);
        match Regex::new(&anchored) {
            Ok(re) => compiled.push((rule.priority, rule, re)),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid pattern in rule {}: {}", rule.id, rule.pattern)})),
                ).into_response();
            }
        }
    }
    compiled.sort_by_key(|(p, _, _)| *p);

    let mut changes: Vec<Value> = Vec::new();
    let mut evaluated = 0u32;

    for ev in &events {
        let current_decision = ev.fields.get("event")
            .and_then(|v| v.as_str())
            .map(|e| if e == "authz_policy_allow" { "allow" } else { "deny" })
            .unwrap_or("unknown");
        let user = ev.fields.get("user").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let data = ev.fields.get("data").and_then(|v| v.as_str()).unwrap_or("");

        // Extract command from data field: "...;cmd=show version;..."
        let cmd = data.split(';')
            .find_map(|p| p.strip_prefix("cmd="))
            .unwrap_or("")
            .to_string();

        if cmd.is_empty() || cmd == "service=shell" {
            continue; // skip shell-start events
        }

        evaluated += 1;
        let new_decision = eval_policy(&compiled, &user, &cmd, req.policy.default_allow);

        if new_decision != current_decision {
            changes.push(json!({
                "ts": ev.ts / 1_000_000,
                "user": user,
                "cmd": cmd,
                "current": current_decision,
                "new": new_decision,
            }));
        }
    }

    Json(json!({
        "evaluated": evaluated,
        "changed": changes.len(),
        "changes": changes,
    })).into_response()
}

/// Evaluate a single command against the compiled candidate rules.
fn eval_policy(rules: &[(i64, &DryRunRule, Regex)], user: &str, cmd: &str, default: bool) -> &'static str {
    for (_, rule, re) in rules {
        if !rule.users.is_empty() && !rule.users.iter().any(|u| u.eq_ignore_ascii_case(user)) {
            continue;
        }
        if re.is_match(cmd) {
            return if rule.effect == "allow" { "allow" } else { "deny" };
        }
    }
    if default { "allow" } else { "deny" }
}

/// GET /api/sessions — live snapshot of active TACACS+ sessions.
///
/// Proxies the `/sessions` endpoint on the TACACS+ server health port.
/// Requires `TACACS_HTTP_URL` env var pointing at the internal HTTP service
/// (e.g. `http://tacacs-metrics.tacacs.svc:8080`).
pub async fn sessions(State(st): State<AppState>) -> impl IntoResponse {
    let Some(ref base) = st.tacacs_http_url else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "TACACS_HTTP_URL not configured"})),
        )
            .into_response();
    };
    let url = format!("{base}/sessions");
    match st.http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>().await {
                Ok(body) => Json(body).into_response(),
                Err(e) => err(anyhow::anyhow!(e)).into_response(),
            }
        }
        Ok(resp) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": format!("upstream {}", resp.status())})),
        )
            .into_response(),
        Err(e) => err(anyhow::anyhow!(e)).into_response(),
    }
}

/// GET /api/config — active authentication source and (for ICAM) endpoint metadata.
///
/// The `auth_source` field is one of `"icam"`, `"ldap"`, or `"local"`.
/// When ICAM is configured the handler probes the OIDC discovery endpoint and
/// reports reachability so the UI can display a live health indicator.
pub async fn config(State(st): State<AppState>) -> impl IntoResponse {
    let source = st.auth_source.as_deref().unwrap_or("local");
    let mut resp = json!({ "auth_source": source });

    if source == "icam" {
        if let Some(ep) = &st.icam_endpoint {
            // Reachability check uses the internal HTTP base URL (BFF has no TLS client).
            // e.g. ICAM_INTERNAL_BASE=http://keycloak.icam.svc.cluster.local
            let reachable: Option<bool> = if let Some(base) = &st.icam_internal_base {
                let realm_path = ep
                    .split("/protocol/openid-connect/token")
                    .next()
                    .and_then(|s| s.split("/realms/").nth(1))
                    .map(|r| format!("{base}/realms/{r}/.well-known/openid-configuration"));
                if let Some(url) = realm_path {
                    Some(
                        st.http
                            .get(&url)
                            .timeout(std::time::Duration::from_secs(3))
                            .send()
                            .await
                            .map(|r| r.status().is_success())
                            .unwrap_or(false),
                    )
                } else {
                    None
                }
            } else {
                None
            };
            resp["icam"] = json!({
                "endpoint": ep,
                "client_id": st.icam_client_id.as_deref().unwrap_or(""),
                "groups_claim": st.icam_groups_claim.as_deref().unwrap_or("groups"),
                "reachable": reachable,
                "device_flow": st.icam_device_flow,
            });
        }
    }

    if source == "ldap" {
        if let Some(url) = &st.ldap_url {
            resp["ldap"] = json!({ "url": url });
        }
    }

    Json(resp)
}

/// Identity injected by oauth2-proxy (Keycloak OIDC).
pub async fn me(headers: HeaderMap) -> Json<Value> {
    let h = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(String::from);
    let user = h("x-auth-request-user").or_else(|| h("x-forwarded-user"));
    let email = h("x-auth-request-email").or_else(|| h("x-forwarded-email"));
    let groups = h("x-auth-request-groups");
    Json(json!({ "user": user, "email": email, "groups": groups }))
}

/// Build the base LogQL selector with optional event/status label matchers.
fn audit_selector(st: &AppState, q: &Params) -> String {
    let mut sel = format!("logtarget=\"{}\"", esc(&st.audit_target));
    if let Some(ev) = q.get("event").filter(|s| !s.is_empty()) {
        sel.push_str(&format!(", event=\"{}\"", esc(ev)));
    }
    if let Some(stt) = q.get("status").filter(|s| !s.is_empty()) {
        sel.push_str(&format!(", status=\"{}\"", esc(stt)));
    }
    let mut logql = format!("{{{sel}}}");
    // peer/user live in the JSON line, so post-filter with | json.
    let mut pipe = String::new();
    if let Some(peer) = q.get("peer").filter(|s| !s.is_empty()) {
        pipe.push_str(&format!(" | json | peer=~\".*{}.*\"", esc(peer)));
    }
    if let Some(user) = q.get("user").filter(|s| !s.is_empty()) {
        if pipe.is_empty() {
            pipe.push_str(" | json");
        }
        pipe.push_str(&format!(" | user=\"{}\"", esc(user)));
    }
    logql.push_str(&pipe);
    logql
}

/// GET /api/audit — recent audit events with optional filters.
pub async fn audit(
    State(st): State<AppState>,
    Query(q): Query<Params>,
) -> impl IntoResponse {
    let minutes = p_i64(&q, "minutes", 60).clamp(1, 60 * 24 * 14);
    let limit = p_u32(&q, "limit", 200).clamp(1, 5000);
    let end = now_ns();
    let start = end - minutes * 60 * 1_000_000_000;
    let logql = audit_selector(&st, &q);
    match loki_query_range(&st, &logql, start, end, limit, false).await {
        Ok(mut e) => {
            e.reverse(); // newest first
            Json(json!({ "query": logql, "count": e.len(), "events": e })).into_response()
        }
        Err(e) => err(e).into_response(),
    }
}

/// GET /api/flows?peer=<ip> — reconstruct a NAD's sessions from audit events.
pub async fn flows(
    State(st): State<AppState>,
    Query(q): Query<Params>,
) -> impl IntoResponse {
    let peer = match q.get("peer").filter(|s| !s.is_empty()) {
        Some(p) => p.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error":"peer is required"})))
                .into_response()
        }
    };
    let minutes = p_i64(&q, "minutes", 180).clamp(1, 60 * 24 * 14);
    let end = now_ns();
    let start = end - minutes * 60 * 1_000_000_000;
    let logql = format!(
        "{{logtarget=\"{}\"}} | json | peer=~\".*{}.*\"",
        esc(&st.audit_target),
        esc(&peer)
    );
    let events = match loki_query_range(&st, &logql, start, end, 5000, true).await {
        Ok(e) => e,
        Err(e) => return err(e).into_response(),
    };
    // Group by session_id (string-or-number), preserving chronological order.
    let mut sessions: BTreeMap<String, Vec<AuditEntry>> = BTreeMap::new();
    for ev in events {
        let sid = ev.fields.get("session").map(sid_str).unwrap_or_else(|| "0".into());
        sessions.entry(sid).or_default().push(ev);
    }
    let mut out: Vec<Value> = sessions
        .into_iter()
        .map(|(sid, evs)| {
            let started = evs.first().map(|e| e.ts).unwrap_or(0);
            json!({ "session": sid, "started": started, "count": evs.len(), "events": evs })
        })
        .collect();
    out.sort_by_key(|s| s["started"].as_i64().unwrap_or(0));
    Json(json!({ "peer": peer, "sessions": out })).into_response()
}

fn sid_str(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => "0".into(),
    }
}

/// GET /api/metrics — instant summary + a short connections sparkline.
pub async fn metrics(State(st): State<AppState>) -> impl IntoResponse {
    let q = |p: &'static str| {
        let s = st.clone();
        async move { prom_scalar(&s, p).await }
    };
    let conns = q("sum(tacacs_connections_active)").await;
    let sessions = q("sum(tacacs_sessions_active)").await;
    let cert_days = q("min(tacacs_certificate_validity_days)").await;
    let rules = q("max(tacacs_policy_rules_count)").await;
    let authn_rate = q("sum(rate(tacacs_authn_requests_total[5m]))").await;
    let authn_fail_rate = q("sum(rate(tacacs_authn_requests_total{result=\"fail\"}[5m]))").await;
    let authz_p99 = q("histogram_quantile(0.99, sum(rate(tacacs_authz_duration_seconds_bucket[5m])) by (le))").await;

    let end = now_s();
    let start = end - 60 * 60;
    let conns_series = prom_query_range(&st, "sum(tacacs_connections_active)", start, end, 60)
        .await
        .unwrap_or_else(|_| json!([]));

    Json(json!({
        "connections_active": conns,
        "sessions_active": sessions,
        "certificate_validity_days": cert_days,
        "policy_rules": rules,
        "authn_rate_per_s": authn_rate,
        "authn_fail_rate_per_s": authn_fail_rate,
        "authz_p99_seconds": authz_p99,
        "connections_series": conns_series,
    }))
}

/// GET /api/resources?minutes= — per-pod container CPU & memory vs limits.
pub async fn resources(
    State(st): State<AppState>,
    Query(q): Query<Params>,
) -> impl IntoResponse {
    let minutes = p_i64(&q, "minutes", 60).clamp(5, 60 * 24);
    let end = now_s();
    let start = end - minutes * 60;
    let ns = esc(&st.namespace);
    let step = (minutes * 60 / 120).max(15); // ~120 points

    let cpu = prom_query_range(
        &st,
        &format!("sum by (pod) (rate(container_cpu_usage_seconds_total{{namespace=\"{ns}\",container=\"tacacs\"}}[2m]))"),
        start, end, step,
    ).await.unwrap_or_else(|_| json!([]));
    let mem = prom_query_range(
        &st,
        &format!("sum by (pod) (container_memory_working_set_bytes{{namespace=\"{ns}\",container=\"tacacs\"}})"),
        start, end, step,
    ).await.unwrap_or_else(|_| json!([]));
    // Limits from cAdvisor spec metrics (no kube-state-metrics required).
    let mem_limit = prom_scalar(&st, &format!("max(container_spec_memory_limit_bytes{{namespace=\"{ns}\",container=\"tacacs\"}})")).await;
    let cpu_limit = prom_scalar(&st, &format!("max(container_spec_cpu_quota{{namespace=\"{ns}\",container=\"tacacs\"}} / container_spec_cpu_period{{namespace=\"{ns}\",container=\"tacacs\"}})")).await;

    Json(json!({
        "cpu_cores": cpu,
        "memory_bytes": mem,
        "cpu_limit_cores": cpu_limit,
        "memory_limit_bytes": mem_limit,
        "step_seconds": step,
    }))
}

/// GET /api/alerts — evaluate a small rule set against Prometheus + Loki.
pub async fn alerts(State(st): State<AppState>) -> impl IntoResponse {
    let mut alerts: Vec<Value> = Vec::new();
    let mk = |sev: &str, title: &str, detail: String| {
        json!({ "severity": sev, "title": title, "detail": detail, "at": now_s() })
    };
    let ns = esc(&st.namespace);

    // 1) Certificate expiry. A 0/absent value means the gauge isn't populated
    // (no EST/cert-watch), so treat it as "unknown" rather than expired.
    if let Some(days) = prom_scalar(&st, "min(tacacs_certificate_validity_days)").await {
        if days > 0.0 && days < 7.0 {
            alerts.push(mk("critical", "TLS certificate expiring", format!("server cert valid for {days:.1} days")));
        } else if days >= 7.0 && days < 30.0 {
            alerts.push(mk("warning", "TLS certificate expiring soon", format!("server cert valid for {days:.1} days")));
        }
    }
    // 2) Memory pressure vs limit.
    let mem_used = prom_scalar(&st, &format!("max(container_memory_working_set_bytes{{namespace=\"{ns}\",container=\"tacacs\"}})")).await;
    let mem_lim = prom_scalar(&st, &format!("max(container_spec_memory_limit_bytes{{namespace=\"{ns}\",container=\"tacacs\"}})")).await;
    if let (Some(u), Some(l)) = (mem_used, mem_lim) {
        if l > 0.0 && u / l > 0.85 {
            alerts.push(mk("warning", "Container memory pressure", format!("{:.0}% of memory limit", u / l * 100.0)));
        }
    }
    // 3) CPU pressure vs limit.
    let cpu_used = prom_scalar(&st, &format!("max(sum by (pod) (rate(container_cpu_usage_seconds_total{{namespace=\"{ns}\",container=\"tacacs\"}}[2m])))")).await;
    let cpu_lim = prom_scalar(&st, &format!("max(container_spec_cpu_quota{{namespace=\"{ns}\",container=\"tacacs\"}} / container_spec_cpu_period{{namespace=\"{ns}\",container=\"tacacs\"}})")).await;
    if let (Some(u), Some(l)) = (cpu_used, cpu_lim) {
        if l > 0.0 && u / l > 0.8 {
            alerts.push(mk("warning", "Container CPU pressure", format!("{:.0}% of CPU limit", u / l * 100.0)));
        }
    }
    // 4) Authentication failure burst (from Loki, last 15m).
    let end = now_ns();
    let start = end - 15 * 60 * 1_000_000_000;
    let fail_q = format!("{{logtarget=\"{}\", event=\"authn_terminal\", status=\"fail\"}}", esc(&st.audit_target));
    if let Ok(fails) = loki_query_range(&st, &fail_q, start, end, 1000, false).await {
        if fails.len() >= 20 {
            alerts.push(mk("warning", "Authentication failure burst", format!("{} failed auths in 15m", fails.len())));
        }
    }
    // 5) Command frequency anomaly — alert when a single user runs an unusually
    //    high volume of commands in 15 minutes (potential scripted compromise or
    //    runaway automation).  Threshold: >100 authz events from one user.
    let cmd_q = format!(
        "{{logtarget=\"{}\", event=\"authz_policy_allow\"}} | json",
        esc(&st.audit_target)
    );
    if let Ok(cmds) = loki_query_range(&st, &cmd_q, start, end, 5000, false).await {
        let mut per_user: HashMap<String, usize> = HashMap::new();
        for ev in &cmds {
            let user = ev.fields.get("user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !user.is_empty() {
                *per_user.entry(user).or_insert(0) += 1;
            }
        }
        for (user, count) in per_user {
            if count > 100 {
                alerts.push(mk(
                    "warning",
                    "Command frequency anomaly",
                    format!("{user} ran {count} commands in 15m — possible scripted activity"),
                ));
            }
        }
    }

    Json(json!({ "count": alerts.len(), "alerts": alerts }))
}
