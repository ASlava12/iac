// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7i: maintenance windows. Submissions during an active window
//! return 503 + Retry-After. Outside the window submissions proceed
//! normally; environment-specific windows don't fence other envs.

use iac_controlplane::identity::Role;
use iac_controlplane::maintenance::MaintenanceWindow;
use iac_controlplane::store::CreateUser;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    AuditEvent, LoginRequest, LoginResponse, RegisterRequest, SubmitOperationRequest,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "maint-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    store: Store,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(windows: Vec<MaintenanceWindow>) -> Self {
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
            maintenance_windows: windows,
            recurring_maintenance_windows: vec![],
            webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
        tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: iac_controlplane::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
            trusted_proxies: vec![],
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
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async move { signal.notified().await })
                .await
                .unwrap();
        });
        Self { addr, shutdown, handle, store, _tempdir: dir }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn make_user(&self, name: &str, password: &str, roles: Vec<Role>) {
        self.store
            .create_user(CreateUser { username: name, password, roles })
            .await
            .unwrap();
    }

    async fn login(&self, name: &str, password: &str) -> LoginResponse {
        reqwest::Client::new()
            .post(format!("{}/v1/auth/login", self.url()))
            .json(&LoginRequest { username: name.into(), password: password.into() })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }

    async fn register_agent(&self, name: &str, env: &str) {
        reqwest::Client::new()
            .post(format!("{}/v1/agents/register", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&RegisterRequest {
                name: name.into(),
                environment: env.into(),
                metadata: serde_json::Value::Null,
            })
            .send()
            .await
            .unwrap();
    }

    async fn submit(&self, env: &str) -> reqwest::Response {
        self.submit_as(env, ADMIN_TOKEN, false).await
    }

    async fn submit_as(&self, env: &str, bearer: &str, bypass: bool) -> reqwest::Response {
        let mut req = reqwest::Client::new()
            .post(format!("{}/v1/operations", self.url()))
            .bearer_auth(bearer)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources: vec![json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "file",
                    "metadata": { "name": "x", "environment": env },
                    "spec": {
                        "path": "/tmp/x.txt",
                        "mode": "0644",
                        "content": "x\n",
                    }
                })], canary: None,
            });
        if bypass {
            req = req.header("x-iac-maintenance-bypass", "yes");
        }
        req.send().await.unwrap()
    }
}

fn window_now(name: &str, env: &str) -> MaintenanceWindow {
    // 1-hour window centered on "now" so a test submit definitely lands inside.
    let now = jiff::Timestamp::now();
    let start = now
        .checked_sub(jiff::Span::new().try_minutes(30).unwrap())
        .unwrap();
    let end = now
        .checked_add(jiff::Span::new().try_minutes(30).unwrap())
        .unwrap();
    MaintenanceWindow {
        name: name.into(),
        environment: env.into(),
        start: start.to_string(),
        end: end.to_string(),
    }
}

fn window_past(name: &str, env: &str) -> MaintenanceWindow {
    // 1-hour window that ended an hour ago.
    let now = jiff::Timestamp::now();
    let end = now
        .checked_sub(jiff::Span::new().try_hours(1).unwrap())
        .unwrap();
    let start = end
        .checked_sub(jiff::Span::new().try_hours(1).unwrap())
        .unwrap();
    MaintenanceWindow {
        name: name.into(),
        environment: env.into(),
        start: start.to_string(),
        end: end.to_string(),
    }
}

#[tokio::test]
async fn no_windows_allows_submit() {
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm", "prod").await;
    assert_eq!(server.submit("prod").await.status(), StatusCode::OK);
    server.shutdown().await;
}

#[tokio::test]
async fn active_window_blocks_with_503_and_retry_after() {
    let server = TestServer::spawn(vec![window_now("tuesday", "prod")]).await;
    server.register_agent("vm", "prod").await;

    let r = server.submit("prod").await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let retry = r
        .headers()
        .get("retry-after")
        .expect("Retry-After set")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    // ~30 minutes left in the window.
    assert!(retry > 0 && retry <= 35 * 60, "retry: {retry}");

    let body = r.text().await.unwrap();
    assert!(body.contains("tuesday"), "body: {body}");

    server.shutdown().await;
}

#[tokio::test]
async fn past_window_does_not_block() {
    let server = TestServer::spawn(vec![window_past("yesterday", "prod")]).await;
    server.register_agent("vm", "prod").await;
    assert_eq!(server.submit("prod").await.status(), StatusCode::OK);
    server.shutdown().await;
}

#[tokio::test]
async fn env_specific_window_doesnt_fence_other_envs() {
    let server = TestServer::spawn(vec![window_now("prod-only", "prod")]).await;
    server.register_agent("vm-prod", "prod").await;
    server.register_agent("vm-stage", "stage").await;

    // prod blocked.
    assert_eq!(
        server.submit("prod").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // stage allowed.
    assert_eq!(server.submit("stage").await.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn wildcard_window_blocks_all_envs() {
    let server = TestServer::spawn(vec![window_now("global", "*")]).await;
    server.register_agent("vm-prod", "prod").await;
    server.register_agent("vm-stage", "stage").await;

    assert_eq!(
        server.submit("prod").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        server.submit("stage").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    server.shutdown().await;
}

#[tokio::test]
async fn admin_bypass_header_overrides_active_window() {
    // Admin sets X-Iac-Maintenance-Bypass: yes → submit goes through
    // even though a window is active. The bypass is audited.
    let server = TestServer::spawn(vec![window_now("incident-fix", "prod")]).await;
    server.register_agent("vm", "prod").await;

    let r = server.submit_as("prod", ADMIN_TOKEN, true).await;
    assert_eq!(r.status(), StatusCode::OK);

    // Audit log captures the bypass.
    let audit: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!(
            "{}/v1/audit?kind=operation.maintenance_bypass",
            server.url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].severity, "warning");
    assert_eq!(audit[0].payload["environment"], "prod");

    server.shutdown().await;
}

#[tokio::test]
async fn non_admin_bypass_header_is_forbidden() {
    // Operator role isn't enough — bypass is admin-only.
    let server = TestServer::spawn(vec![window_now("active", "prod")]).await;
    server.register_agent("vm", "prod").await;
    server.make_user("op", "p", vec![Role::Operator]).await;
    let op_token = server.login("op", "p").await.token;

    let r = server.submit_as("prod", &op_token, true).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    server.shutdown().await;
}

#[tokio::test]
async fn bypass_audited_even_outside_window() {
    // Capture intent: admin sets the bypass header even with no
    // window active. The submit succeeds normally, but the bypass
    // intent is logged. Useful for "who's been wearing a parachute
    // when they didn't need to" reviews.
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm", "prod").await;

    let r = server.submit_as("prod", ADMIN_TOKEN, true).await;
    assert_eq!(r.status(), StatusCode::OK);

    let audit: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!(
            "{}/v1/audit?kind=operation.maintenance_bypass",
            server.url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn empty_bypass_header_is_treated_as_not_set() {
    // An empty header value shouldn't trigger bypass. This protects
    // against pipelines that template the value but produce empty
    // strings — they should hit the same 503 as everyone else.
    let server = TestServer::spawn(vec![window_now("active", "prod")]).await;
    server.register_agent("vm", "prod").await;

    let r = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .header("x-iac-maintenance-bypass", "")
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": { "path": "/tmp/x.txt", "mode": "0644", "content": "x\n" }
            })], canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);

    server.shutdown().await;
}

#[tokio::test]
async fn maintenance_runs_after_auth() {
    // Unauthenticated submit must return 401, not 503 — auth is the
    // first gate so a maintenance window doesn't accidentally let
    // anonymous probes succeed (or silently mask the auth failure).
    let server = TestServer::spawn(vec![window_now("active", "prod")]).await;
    server.register_agent("vm", "prod").await;

    let r = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "anon".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": { "path": "/tmp/x.txt", "mode": "0644", "content": "x" }
            })], canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}
