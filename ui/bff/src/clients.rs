// SPDX-License-Identifier: Apache-2.0
//! Thin HTTP clients for Loki (LogQL) and Prometheus (PromQL).

use crate::AppState;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

/// One flattened audit log entry: parsed JSON fields + ns timestamp.
#[derive(serde::Serialize, Clone)]
pub struct AuditEntry {
    pub ts: i64, // unix nanoseconds
    #[serde(flatten)]
    pub fields: Value,
}

/// Run a Loki `query_range` and flatten streams into time-ordered audit entries.
pub async fn loki_query_range(
    st: &AppState,
    logql: &str,
    start_ns: i64,
    end_ns: i64,
    limit: u32,
    forward: bool,
) -> Result<Vec<AuditEntry>> {
    let url = format!("{}/loki/api/v1/query_range", st.loki_url);
    let direction = if forward { "forward" } else { "backward" };
    let resp = st
        .http
        .get(&url)
        .query(&[
            ("query", logql),
            ("start", &start_ns.to_string()),
            ("end", &end_ns.to_string()),
            ("limit", &limit.to_string()),
            ("direction", direction),
        ])
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("loki {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
    }
    let body: Value = resp.json().await?;
    let mut out = Vec::new();
    if let Some(streams) = body["data"]["result"].as_array() {
        for s in streams {
            let labels = &s["stream"];
            for v in s["values"].as_array().into_iter().flatten() {
                let ts: i64 = v[0].as_str().and_then(|x| x.parse().ok()).unwrap_or(0);
                let line = v[1].as_str().unwrap_or("");
                // The line is the server's JSON log object.
                let mut fields: Value = serde_json::from_str(line).unwrap_or_else(|_| json!({"raw": line}));
                // Merge stream labels (event/status/etc.) as a fallback.
                if let (Some(f), Some(l)) = (fields.as_object_mut(), labels.as_object()) {
                    for (k, val) in l {
                        f.entry(k.clone()).or_insert(val.clone());
                    }
                }
                out.push(AuditEntry { ts, fields });
            }
        }
    }
    out.sort_by_key(|e| e.ts);
    Ok(out)
}

/// Prometheus instant query → `data.result` array.
pub async fn prom_query(st: &AppState, promql: &str) -> Result<Value> {
    let url = format!("{}/api/v1/query", st.prom_url);
    let body: Value = st
        .http
        .get(&url)
        .query(&[("query", promql)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(body["data"]["result"].clone())
}

/// First scalar value of an instant query, or `None`.
pub async fn prom_scalar(st: &AppState, promql: &str) -> Option<f64> {
    let r = prom_query(st, promql).await.ok()?;
    r.get(0)?["value"][1].as_str()?.parse().ok()
}

/// Prometheus range query → `data.result` (matrix).
pub async fn prom_query_range(
    st: &AppState,
    promql: &str,
    start_s: i64,
    end_s: i64,
    step_s: i64,
) -> Result<Value> {
    let url = format!("{}/api/v1/query_range", st.prom_url);
    let body: Value = st
        .http
        .get(&url)
        .query(&[
            ("query", promql),
            ("start", &start_s.to_string()),
            ("end", &end_s.to_string()),
            ("step", &format!("{step_s}s")),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(body["data"]["result"].clone())
}
