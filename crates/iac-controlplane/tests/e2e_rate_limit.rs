// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7h: per-environment rate limit on operation submissions.
//! When configured, exceeding the cap returns 429 with a `Retry-After`
//! header; separate environments have separate buckets; default config
//! (no limit) leaves behavior unchanged.

use iac_controlplane::rate_limit::{RateLimitConfig, RateLimiter};
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "rate-limit-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(rate_limit: RateLimitConfig) -> Self {
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
            rate_limit,
            maintenance_windows: vec![],
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
            agent_enrollment_token: None,
        };
        let store = Store::connect(&cfg.database_url).await.unwrap();
        let signer = std::sync::Arc::new(
            iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap(),
        );
        let state = AppState {
            store,
            live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
            )),
            config_path: None,
            signer,
            rate_limiter: Arc::new(RateLimiter::from_config(&cfg.rate_limit)),
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
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move { signal.notified().await })
            .await
            .unwrap();
        });
        Self {
            addr,
            shutdown,
            handle,
            _tempdir: dir,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
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

    async fn submit(&self, env: &str, name: &str) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/operations", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources: vec![json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "file",
                    "metadata": { "name": name, "environment": env },
                    "spec": {
                        "path": format!("/tmp/{name}.txt"),
                        "mode": "0644",
                        "content": format!("{name}\n"),
                    }
                })],
                canary: None,
            })
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn unlimited_default_allows_all_submissions() {
    let server = TestServer::spawn(RateLimitConfig::default()).await;
    server.register_agent("vm-noop", "ops").await;

    for i in 0..5 {
        let r = server.submit("ops", &format!("r{i}")).await;
        assert_eq!(r.status(), StatusCode::OK, "iteration {i}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn cap_exceeded_returns_429_with_retry_after() {
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: Some(2),
        agent_requests_per_minute: None,
        ..Default::default()
    })
    .await;
    server.register_agent("vm-cap", "ops").await;

    // First two go through.
    for i in 0..2 {
        let r = server.submit("ops", &format!("ok{i}")).await;
        assert_eq!(r.status(), StatusCode::OK, "iteration {i}");
    }

    // Third trips the limit.
    let r = server.submit("ops", "blocked").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry = r
        .headers()
        .get("retry-after")
        .expect("Retry-After header set")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(
        (1..=60).contains(&retry),
        "Retry-After {retry} out of range"
    );
    // Phase 7q + 7av: structured bucket field carries `(type, name)`;
    // detail is a plain human-readable retry hint, no legacy
    // `bucket=<type>:<name>` prefix.
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["bucket"]["type"], "env");
    assert_eq!(body["bucket"]["name"], "ops");
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.starts_with("retry after "), "detail: {detail}");
    assert!(
        !detail.contains("bucket="),
        "legacy prefix should be gone: {detail}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn separate_environments_have_separate_buckets() {
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: Some(1),
        agent_requests_per_minute: None,
        ..Default::default()
    })
    .await;
    server.register_agent("vm-prod", "prod").await;
    server.register_agent("vm-stage", "stage").await;

    // prod's quota: one ok, one rejected.
    assert_eq!(server.submit("prod", "p1").await.status(), StatusCode::OK);
    assert_eq!(
        server.submit("prod", "p2").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // stage is independent — its quota wasn't consumed.
    assert_eq!(server.submit("stage", "s1").await.status(), StatusCode::OK);
    assert_eq!(
        server.submit("stage", "s2").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    server.shutdown().await;
}

#[tokio::test]
async fn rate_limit_runs_after_basic_validation() {
    // Empty environment → 400 (bad request), not 429. Means we don't
    // burn budget on requests that the server would have rejected
    // anyway — keeps the bucket reflecting *real* submissions.
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: Some(1),
        agent_requests_per_minute: None,
        ..Default::default()
    })
    .await;
    server.register_agent("vm-x", "ops").await;

    // Send one bad request — should be 400, not 429.
    let r = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: "".into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources: vec![],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Bucket should still allow one valid submit.
    assert_eq!(server.submit("ops", "ok").await.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn rate_limit_runs_after_auth() {
    // Unauthenticated submit returns 401, NOT 429 — auth is the first
    // gate. This prevents an unauthenticated attacker from burning
    // legitimate operators' budgets.
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: Some(1),
        agent_requests_per_minute: None,
        ..Default::default()
    })
    .await;
    server.register_agent("vm-y", "ops").await;

    for _ in 0..5 {
        let r = reqwest::Client::new()
            .post(format!("{}/v1/operations", server.url()))
            .json(&SubmitOperationRequest {
                environment: "ops".into(),
                requested_by: "anonymous".into(),
                source_commit: None,
                summary: None,
                resources: vec![json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "file",
                    "metadata": { "name": "spam", "environment": "ops" },
                    "spec": { "path": "/tmp/spam.txt", "mode": "0644", "content": "x" }
                })],
                canary: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    // Legitimate operator's budget is intact.
    assert_eq!(server.submit("ops", "real").await.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn agent_rate_limit_caps_heartbeats_per_agent_id() {
    // Phase 7bh: per-agent cap kicks in across the agent endpoints.
    // Two heartbeats fit; the third returns 429 with `bucket.type = "agent"`.
    use iac_core::protocol::v1::{AgentHealth, HeartbeatRequest, RegisterResponse};
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: None,
        agent_requests_per_minute: Some(2),
        ..Default::default()
    })
    .await;

    // Register and capture the bearer token (we need the agent's own
    // token, not ADMIN_TOKEN, because the agent endpoints authenticate
    // via the agent's bearer).
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm-rl".into(),
            environment: "ops".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let creds: RegisterResponse = resp.json().await.unwrap();

    let hb = HeartbeatRequest {
        status: AgentHealth::Healthy,
        managed: 0,
        open_drifts: 0,
        last_observe_at: None,
    };
    let url = format!("{}/v1/agents/{}/heartbeat", server.url(), creds.agent_id);

    // Two heartbeats inside the window go through.
    for i in 0..2 {
        let r = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&creds.token)
            .json(&hb)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "heartbeat {i}");
    }

    // Third heartbeat is rate-limited.
    let r = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&creds.token)
        .json(&hb)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["bucket"]["type"], "agent");
    assert_eq!(body["bucket"]["name"], creds.agent_id);

    server.shutdown().await;
}

#[tokio::test]
async fn agent_rate_limit_isolates_per_agent_id_in_e2e() {
    // Two agents with the same per-agent cap don't share buckets —
    // a chatty agent must not impact a quiet one.
    use iac_core::protocol::v1::{AgentHealth, HeartbeatRequest, RegisterResponse};
    let server = TestServer::spawn(RateLimitConfig {
        operations_per_minute: None,
        agent_requests_per_minute: Some(1),
        ..Default::default()
    })
    .await;

    let mut creds_pair: Vec<RegisterResponse> = Vec::new();
    for name in ["agent-a", "agent-b"] {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/agents/register", server.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&RegisterRequest {
                name: name.into(),
                environment: "ops".into(),
                metadata: serde_json::Value::Null,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        creds_pair.push(resp.json().await.unwrap());
    }
    let hb = HeartbeatRequest {
        status: AgentHealth::Healthy,
        managed: 0,
        open_drifts: 0,
        last_observe_at: None,
    };

    // Burn agent-a's quota.
    let a_url = format!(
        "{}/v1/agents/{}/heartbeat",
        server.url(),
        creds_pair[0].agent_id
    );
    assert_eq!(
        reqwest::Client::new()
            .post(&a_url)
            .bearer_auth(&creds_pair[0].token)
            .json(&hb)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        reqwest::Client::new()
            .post(&a_url)
            .bearer_auth(&creds_pair[0].token)
            .json(&hb)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // agent-b's quota is still 1, untouched.
    let b_url = format!(
        "{}/v1/agents/{}/heartbeat",
        server.url(),
        creds_pair[1].agent_id
    );
    assert_eq!(
        reqwest::Client::new()
            .post(&b_url)
            .bearer_auth(&creds_pair[1].token)
            .json(&hb)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    server.shutdown().await;
}
