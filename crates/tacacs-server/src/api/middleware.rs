// SPDX-License-Identifier: Apache-2.0
//! Common security and request-context middleware for HTTP APIs.

use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::metrics::metrics;

const MAX_CONCURRENT_REQUESTS: usize = 128;
const MAX_REQUESTS_PER_SECOND: u32 = 500;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

static CONCURRENCY: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_REQUESTS));
static RATE_WINDOW: LazyLock<Mutex<RateWindow>> = LazyLock::new(|| Mutex::new(RateWindow::new()));

struct RateWindow {
    started: Instant,
    requests: u32,
}

impl RateWindow {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
        }
    }

    fn admit(&mut self) -> bool {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.requests = 0;
        }
        if self.requests >= MAX_REQUESTS_PER_SECOND {
            return false;
        }
        self.requests += 1;
        true
    }
}

#[derive(Serialize)]
struct MiddlewareProblem {
    #[serde(rename = "type")]
    problem_type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    correlation_id: String,
}

/// Establish correlation context and enforce process-local API safety limits.
pub async fn request_context(mut request: Request<Body>, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let started = Instant::now();
    let correlation_id = match establish_correlation(request.headers_mut()) {
        Ok(value) => value,
        Err(value) => {
            let response =
                secured_problem(StatusCode::BAD_REQUEST, "invalid_correlation_id", value);
            return record_metrics(response, &method, started);
        }
    };

    if !RATE_WINDOW.lock().await.admit() {
        return record_metrics(
            secured_problem(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                correlation_id,
            ),
            &method,
            started,
        );
    }

    let permit = match CONCURRENCY.try_acquire() {
        Ok(value) => value,
        Err(_) => {
            return record_metrics(
                secured_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "concurrency_limit_exceeded",
                    correlation_id,
                ),
                &method,
                started,
            );
        }
    };

    let response = tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await;
    drop(permit);

    let response = match response {
        Ok(response) => secure_response(response, correlation_id),
        Err(_) => secured_problem(
            StatusCode::GATEWAY_TIMEOUT,
            "request_timeout",
            correlation_id,
        ),
    };
    record_metrics(response, &method, started)
}

fn establish_correlation(headers: &mut HeaderMap) -> Result<Uuid, Uuid> {
    let id = match headers.get("x-correlation-id") {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|raw| Uuid::parse_str(raw).ok())
            .ok_or_else(Uuid::now_v7)?,
        None => Uuid::now_v7(),
    };
    headers.insert(
        "x-correlation-id",
        HeaderValue::from_str(&id.to_string()).expect("UUID is a valid header value"),
    );
    Ok(id)
}

fn record_metrics(response: Response, method: &str, started: Instant) -> Response {
    metrics()
        .api_requests_total
        .with_label_values(&[method, response.status().as_str()])
        .inc();
    metrics()
        .api_request_duration_seconds
        .with_label_values(&[method])
        .observe(started.elapsed().as_secs_f64());
    response
}

fn secured_problem(status: StatusCode, code: &'static str, correlation_id: Uuid) -> Response {
    let body = MiddlewareProblem {
        problem_type: "about:blank",
        title: status.canonical_reason().unwrap_or("Request failed"),
        status: status.as_u16(),
        code,
        correlation_id: correlation_id.to_string(),
    };
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if status == StatusCode::TOO_MANY_REQUESTS {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    secure_response(response, correlation_id)
}

fn secure_response(mut response: Response, correlation_id: Uuid) -> Response {
    response.headers_mut().insert(
        "x-correlation-id",
        HeaderValue::from_str(&correlation_id.to_string())
            .expect("UUID is always a valid HTTP header value"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn supplies_uuidv7_and_security_headers() {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(request_context));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let correlation = response.headers()["x-correlation-id"].to_str().unwrap();
        assert_eq!(Uuid::parse_str(correlation).unwrap().get_version_num(), 7);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }

    #[tokio::test]
    async fn rejects_malformed_correlation_id() {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(request_context));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-correlation-id", "not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
    }

    #[tokio::test]
    async fn preserves_valid_correlation_id() {
        let supplied = Uuid::new_v4();
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(axum::middleware::from_fn(request_context));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-correlation-id", supplied.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.headers()["x-correlation-id"], supplied.to_string());
    }
}
