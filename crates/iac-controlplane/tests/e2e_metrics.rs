// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7ad: `GET /v1/metrics` admin-only endpoint exposing the
//! webhook dispatcher's snapshot. Tests cover the auth gate, the
//! shape when the dispatcher is plumbed through AppState, and the
//! `webhook: null` shape when it's not.

use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_controlplane::webhook::WebhookDispatcher;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{LoginRequest, LoginResponse};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "metrics-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    store: Store,
    _tempdir: TempDir,
}

async fn spawn(with_dispatcher: bool) -> TestServer {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("server.db");
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}?mode=rwc", db.display()),
        state_dir: dir.path().to_path_buf(),
        max_body_bytes: 1 << 20,
        admin_token: Some(ADMIN_TOKEN.to_string()),
        policies: vec![],
        retention: iac_controlplane::retention::RetentionConfig::default(),
        rate_limit: iac_controlplane::rate_limit::RateLimitConfig::default(),
        maintenance_windows: vec![],
        recurring_maintenance_windows: vec![],
        webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
    tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
    };
    let store = Store::connect(&cfg.database_url).await.unwrap();
    let signer = std::sync::Arc::new(
        iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
    );
    let webhook_dispatcher = if with_dispatcher {
        Some(Arc::new(WebhookDispatcher::new(cfg.webhooks.clone())))
    } else {
        None
    };
    let state = AppState {
        store: store.clone(),
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
        signer,
        rate_limiter: Arc::new(
            iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
        ),
        webhook_dispatcher,
        maintenance_metrics: Arc::new(
            iac_controlplane::maintenance::MaintenanceMetrics::default(),
        ),
            secret_registry: None,
    };
    let app = iac_controlplane::server::router(state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
    });
    TestServer { addr, shutdown, handle, store, _tempdir: dir }
}

impl TestServer {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

#[tokio::test]
async fn admin_can_read_metrics_with_dispatcher_attached() {
    let server = spawn(true).await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    // `webhook` is non-null and carries every counter, all zero on a
    // freshly-constructed dispatcher.
    let w = body["webhook"].as_object().expect("webhook block present");
    assert_eq!(w["dispatched_ok"], 0);
    assert_eq!(w["dispatched_non_success"], 0);
    assert_eq!(w["dispatched_ratelimited"], 0);
    assert_eq!(w["delivery_errors"], 0);
    assert_eq!(w["semaphore_wait_micros"], 0);
    assert_eq!(w["in_flight"], 0);
    assert_eq!(w["in_flight_peak"], 0);
    // Phase 7ae: rate_limit block present with all zeros.
    let rl = body["rate_limit"]
        .as_object()
        .expect("rate_limit block present");
    assert_eq!(rl["checks_total"], 0);
    assert_eq!(rl["rejected_total"], 0);
    assert_eq!(rl["admitted_total"], 0);
    // Phase 7ag: maintenance block present with all zeros.
    let m = body["maintenance"]
        .as_object()
        .expect("maintenance block present");
    assert_eq!(m["checks_total"], 0);
    assert_eq!(m["blocked_total"], 0);
    // Phase 7ah: per-window-type splits.
    assert_eq!(m["blocked_by_absolute_total"], 0);
    assert_eq!(m["blocked_by_recurring_total"], 0);
    assert_eq!(m["bypassed_total"], 0);
    // Phase 7ai: misconfigured-windows gauge.
    assert_eq!(m["misconfigured_windows"], 0);
    server.shutdown().await;
}

#[tokio::test]
async fn prom_format_returns_text_exposition() {
    // Phase 7af: ?format=prom emits OpenMetrics text format with the
    // proper Content-Type and the `# HELP / # TYPE / metric value`
    // triplet per counter.
    let server = spawn(true).await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics?format=prom", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/plain"),
        "Prom must use text/plain, got {ct:?}"
    );
    let body = r.text().await.unwrap();
    // Webhook + rate-limit blocks both present, with the OpenMetrics
    // shape.
    assert!(body.contains("# HELP iac_webhook_dispatched_ok_total "));
    assert!(body.contains("# TYPE iac_webhook_dispatched_ok_total counter\n"));
    assert!(body.contains("\niac_webhook_dispatched_ok_total 0\n"));
    assert!(body.contains("# TYPE iac_webhook_in_flight gauge\n"));
    assert!(body.contains("\niac_rate_limit_checks_total 0\n"));
    server.shutdown().await;
}

#[tokio::test]
async fn json_format_remains_default_without_query() {
    // Backwards-compat: existing scrapers that hit /v1/metrics with
    // no query still get JSON.
    let server = spawn(true).await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("application/json"), "got {ct:?}");
    server.shutdown().await;
}

#[tokio::test]
async fn metrics_returns_null_webhook_when_dispatcher_not_attached() {
    // Tests that don't run the webhook loop still get a valid 200
    // — useful for fixtures that just want auth + rate limiting.
    let server = spawn(false).await;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body["webhook"].is_null(), "got: {body}");
    server.shutdown().await;
}

#[tokio::test]
async fn metrics_requires_at_least_viewer() {
    let server = spawn(true).await;

    // Unauthenticated → 401.
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn metrics_readable_by_viewer_role() {
    // Phase 7ae: dashboards / read-only ops automation can scrape
    // without holding admin keys. Viewer is the floor.
    let server = spawn(true).await;
    server
        .store
        .create_user(CreateUser {
            username: "dash",
            password: "p",
            roles: vec![Role::Viewer],
        })
        .await
        .unwrap();
    let token = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest { username: "dash".into(), password: "p".into() })
        .send()
        .await
        .unwrap()
        .json::<LoginResponse>()
        .await
        .unwrap()
        .token;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/metrics", server.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn maintenance_counters_track_admit_block_bypass() {
    // Phase 7ag: each submission past auth bumps `checks_total`.
    // Active window without bypass → `blocked_total`. Admin with the
    // bypass header → `bypassed_total`.
    use iac_controlplane::maintenance::MaintenanceWindow;
    use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
    use serde_json::json;

    let dir = TempDir::new().unwrap();
    let db = dir.path().join("server.db");
    // Window covering "now" so submits land inside.
    let now_ts = jiff::Timestamp::now();
    let start = now_ts
        .checked_sub(jiff::Span::new().try_minutes(30).unwrap())
        .unwrap();
    let end = now_ts
        .checked_add(jiff::Span::new().try_minutes(30).unwrap())
        .unwrap();
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}?mode=rwc", db.display()),
        state_dir: dir.path().to_path_buf(),
        max_body_bytes: 1 << 20,
        admin_token: Some(ADMIN_TOKEN.to_string()),
        policies: vec![],
        retention: iac_controlplane::retention::RetentionConfig::default(),
        rate_limit: iac_controlplane::rate_limit::RateLimitConfig::default(),
        maintenance_windows: vec![MaintenanceWindow {
            name: "active".into(),
            environment: "ops".into(),
            start: start.to_string(),
            end: end.to_string(),
        }],
        recurring_maintenance_windows: vec![],
        webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
    tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
    };
    let store = Store::connect(&cfg.database_url).await.unwrap();
    let signer = std::sync::Arc::new(
        iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
    );
    let state = AppState {
        store: store.clone(),
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
        signer,
        rate_limiter: Arc::new(
            iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
        ),
        webhook_dispatcher: None,
        maintenance_metrics: Arc::new(
            iac_controlplane::maintenance::MaintenanceMetrics::default(),
        ),
            secret_registry: None,
    };
    let app = iac_controlplane::server::router(state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");

    reqwest::Client::new()
        .post(format!("{url}/v1/agents/register"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm".into(),
            environment: "ops".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap();

    let submit = |i: u32, bypass: bool| {
        let url = url.clone();
        async move {
            let mut req = reqwest::Client::new()
                .post(format!("{url}/v1/operations"))
                .bearer_auth(ADMIN_TOKEN)
                .json(&SubmitOperationRequest {
                    environment: "ops".into(),
                    requested_by: "alice".into(),
                    source_commit: None,
                    summary: None,
                    resources: vec![json!({
                        "apiVersion": "iac.example/v1",
                        "kind": "file",
                        "metadata": { "name": format!("r{i}"), "environment": "ops" },
                        "spec": {
                            "path": format!("/tmp/{i}.txt"),
                            "mode": "0644",
                            "content": "x\n",
                        }
                    })], canary: None,
                });
            if bypass {
                req = req.header("x-iac-maintenance-bypass", "yes");
            }
            req.send().await.unwrap().status()
        }
    };

    // 1: blocked (no bypass, window active).
    assert_eq!(submit(0, false).await, StatusCode::SERVICE_UNAVAILABLE);
    // 2: bypassed (admin bypass header).
    assert_eq!(submit(1, true).await, StatusCode::OK);

    let r = reqwest::Client::new()
        .get(format!("{url}/v1/metrics"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let m = body["maintenance"].as_object().unwrap();
    assert_eq!(m["checks_total"], 2);
    assert_eq!(m["blocked_total"], 1);
    // Phase 7ah: the block was due to the absolute window in this fixture.
    assert_eq!(m["blocked_by_absolute_total"], 1);
    assert_eq!(m["blocked_by_recurring_total"], 0);
    assert_eq!(m["bypassed_total"], 1);

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn maintenance_recurring_block_increments_per_type_counter() {
    // Phase 7ah: a recurring window match increments
    // `blocked_by_recurring_total`, not `blocked_by_absolute_total`.
    use iac_controlplane::maintenance::RecurringMaintenanceWindow;
    use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
    use serde_json::json;

    let dir = TempDir::new().unwrap();
    let db = dir.path().join("server.db");
    // Recurring window covering "now" (every weekday, current ±30min).
    let now_ts = jiff::Timestamp::now();
    let now_zoned = now_ts.to_zoned(jiff::tz::TimeZone::UTC);
    let now_minute = now_zoned.hour() as u32 * 60 + now_zoned.minute() as u32;
    // 30-min window ending "shortly", started 30 minutes ago. Clamp
    // to a single same-day window so we don't span midnight.
    let start_min = now_minute.saturating_sub(30).min(23 * 60);
    let end_min = (now_minute + 30).min(23 * 60 + 59);
    let fmt = |m: u32| format!("{:02}:{:02}", m / 60, m % 60);
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}?mode=rwc", db.display()),
        state_dir: dir.path().to_path_buf(),
        max_body_bytes: 1 << 20,
        admin_token: Some(ADMIN_TOKEN.to_string()),
        policies: vec![],
        retention: iac_controlplane::retention::RetentionConfig::default(),
        rate_limit: iac_controlplane::rate_limit::RateLimitConfig::default(),
        maintenance_windows: vec![],
        recurring_maintenance_windows: vec![RecurringMaintenanceWindow {
            name: "every-day".into(),
            environment: "ops".into(),
            weekdays: vec![], // empty = every day
            start_hhmm: fmt(start_min),
            end_hhmm: fmt(end_min),
            timezone: None,
        }],
        webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
    tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
    };
    let store = Store::connect(&cfg.database_url).await.unwrap();
    let signer = std::sync::Arc::new(
        iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
    );
    let state = AppState {
        store: store.clone(),
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
        signer,
        rate_limiter: Arc::new(
            iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
        ),
        webhook_dispatcher: None,
        maintenance_metrics: Arc::new(
            iac_controlplane::maintenance::MaintenanceMetrics::default(),
        ),
            secret_registry: None,
    };
    let app = iac_controlplane::server::router(state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");

    reqwest::Client::new()
        .post(format!("{url}/v1/agents/register"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm".into(),
            environment: "ops".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap();

    let r = reqwest::Client::new()
        .post(format!("{url}/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "ops".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "x", "environment": "ops" },
                "spec": {
                    "path": "/tmp/x.txt",
                    "mode": "0644",
                    "content": "x\n",
                }
            })], canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("{url}/v1/metrics"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let m = body["maintenance"].as_object().unwrap();
    assert_eq!(m["checks_total"], 1);
    assert_eq!(m["blocked_total"], 1);
    assert_eq!(m["blocked_by_absolute_total"], 0);
    assert_eq!(m["blocked_by_recurring_total"], 1);

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn rate_limit_counters_increment_after_submissions() {
    // Phase 7ae: each rate-limited submission ticks `checks_total`;
    // each rejection bumps `rejected_total` too. Verify by submitting
    // against a tight cap and reading the snapshot.
    use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
    use serde_json::json;

    let dir = TempDir::new().unwrap();
    let db = dir.path().join("server.db");
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}?mode=rwc", db.display()),
        state_dir: dir.path().to_path_buf(),
        max_body_bytes: 1 << 20,
        admin_token: Some(ADMIN_TOKEN.to_string()),
        policies: vec![],
        retention: iac_controlplane::retention::RetentionConfig::default(),
        rate_limit: iac_controlplane::rate_limit::RateLimitConfig {
            operations_per_minute: Some(2),
            agent_requests_per_minute: None, ..Default::default()
        },
        maintenance_windows: vec![],
        recurring_maintenance_windows: vec![],
        webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
    tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
    };
    let store = Store::connect(&cfg.database_url).await.unwrap();
    let signer = std::sync::Arc::new(
        iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
    );
    let state = AppState {
        store: store.clone(),
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
        signer,
        rate_limiter: Arc::new(
            iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit),
        ),
        webhook_dispatcher: None,
    maintenance_metrics: Arc::new(iac_controlplane::maintenance::MaintenanceMetrics::default()),
            secret_registry: None,
    };
    let app = iac_controlplane::server::router(state);
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(Notify::new());
    let signal = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
    });
    let url = format!("http://{addr}");

    // Register an agent so submits aren't unrouted.
    reqwest::Client::new()
        .post(format!("{url}/v1/agents/register"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm".into(),
            environment: "ops".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap();

    let submit = |i: u32| {
        let url = url.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{url}/v1/operations"))
                .bearer_auth(ADMIN_TOKEN)
                .json(&SubmitOperationRequest {
                    environment: "ops".into(),
                    requested_by: "alice".into(),
                    source_commit: None,
                    summary: None,
                    resources: vec![json!({
                        "apiVersion": "iac.example/v1",
                        "kind": "file",
                        "metadata": { "name": format!("r{i}"), "environment": "ops" },
                        "spec": {
                            "path": format!("/tmp/{i}.txt"),
                            "mode": "0644",
                            "content": "x\n",
                        }
                    })], canary: None,
                })
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // 2 admit + 1 reject.
    assert_eq!(submit(0).await, StatusCode::OK);
    assert_eq!(submit(1).await, StatusCode::OK);
    assert_eq!(submit(2).await, StatusCode::TOO_MANY_REQUESTS);

    let r = reqwest::Client::new()
        .get(format!("{url}/v1/metrics"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    let rl = body["rate_limit"].as_object().unwrap();
    assert_eq!(rl["checks_total"], 3);
    assert_eq!(rl["rejected_total"], 1);
    assert_eq!(rl["admitted_total"], 2);

    shutdown.notify_waiters();
    let _ = handle.await;
}
