// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7n: per-policy rate limit. Each `[[policies]]` block can carry a
//! `rate_limit_per_minute` that applies on top of the global env-level
//! limit. Lets operators say "prod-deploy policy gets 3/min; everyone
//! else unrestricted" without slowing down stage/test envs.

use iac_controlplane::policy::{Policy, PolicyMatch};
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "policy-rate-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(policies: Vec<Policy>) -> Self {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("server.db");
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: format!("sqlite://{}?mode=rwc", db.display()),
            state_dir: dir.path().to_path_buf(),
            max_body_bytes: 1 << 20,
            admin_token: Some(ADMIN_TOKEN.to_string()),
            policies,
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
        let state = AppState {
            store,
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
        Self { addr, shutdown, handle, _tempdir: dir }
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
                })], canary: None,
            })
            .send()
            .await
            .unwrap()
    }
}

fn prod_policy_with_cap(cap: u32) -> Policy {
    Policy {
        name: "prod-cap".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: false,
        approvers: vec![],
        rate_limit_per_minute: Some(cap),
    }
}

#[tokio::test]
async fn matched_policy_cap_rejects_excess() {
    let server = TestServer::spawn(vec![prod_policy_with_cap(2)]).await;
    server.register_agent("vm", "prod").await;

    // First two are within budget.
    for i in 0..2 {
        let r = server.submit("prod", &format!("p{i}")).await;
        assert_eq!(r.status(), StatusCode::OK, "iteration {i}");
    }

    // Third trips the per-policy cap.
    let r = server.submit("prod", "blocked").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry = r
        .headers()
        .get("retry-after")
        .expect("Retry-After set")
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!((1..=60).contains(&retry));
    // Phase 7q: structured bucket field carries the machine-readable
    // `(type, name)`. Phase 7av: detail is now a plain human-readable
    // string with the retry hint, no legacy `bucket=<type>:<name>`
    // prefix. Programmatic clients use `body.bucket` directly.
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["bucket"]["type"], "policy");
    assert_eq!(body["bucket"]["name"], "prod-cap");
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.starts_with("retry after "), "detail: {detail}");
    assert!(!detail.contains("bucket="), "legacy prefix should be gone: {detail}");

    server.shutdown().await;
}

#[tokio::test]
async fn unmatched_policy_does_not_consume_cap() {
    // Policy targets prod; submitting to stage shouldn't tick the
    // prod-cap bucket at all.
    let server = TestServer::spawn(vec![prod_policy_with_cap(1)]).await;
    server.register_agent("vm-prod", "prod").await;
    server.register_agent("vm-stage", "stage").await;

    // Five stage submissions go through unimpeded.
    for i in 0..5 {
        let r = server.submit("stage", &format!("s{i}")).await;
        assert_eq!(r.status(), StatusCode::OK, "stage iter {i}");
    }
    // Prod's cap of 1 is still intact.
    assert_eq!(server.submit("prod", "p1").await.status(), StatusCode::OK);
    assert_eq!(
        server.submit("prod", "p2").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    server.shutdown().await;
}

#[tokio::test]
async fn no_cap_field_treats_policy_as_unrestricted() {
    // Policy with rate_limit_per_minute = None doesn't impose a limit.
    let policy = Policy {
        name: "informational".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: false,
        approvers: vec![],
        rate_limit_per_minute: None,
    };
    let server = TestServer::spawn(vec![policy]).await;
    server.register_agent("vm", "prod").await;

    for i in 0..5 {
        let r = server.submit("prod", &format!("p{i}")).await;
        assert_eq!(r.status(), StatusCode::OK, "iteration {i}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn stricter_of_two_policies_wins() {
    // Two matching policies — caps 5 and 1. The stricter (1) rejects
    // earlier; that's the operator-visible behavior.
    let p1 = Policy {
        name: "loose".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: false,
        approvers: vec![],
        rate_limit_per_minute: Some(5),
    };
    let p2 = Policy {
        name: "tight".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: false,
        approvers: vec![],
        rate_limit_per_minute: Some(1),
    };
    let server = TestServer::spawn(vec![p1, p2]).await;
    server.register_agent("vm", "prod").await;

    assert_eq!(server.submit("prod", "p1").await.status(), StatusCode::OK);
    let r = server.submit("prod", "p2").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    // Phase 7q + 7av: stricter policy ("tight", cap=1) is the one that
    // rejects; surfaced via the structured `bucket` field. Detail is a
    // plain retry hint after the 7av cleanup.
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["bucket"]["type"], "policy");
    assert_eq!(body["bucket"]["name"], "tight");
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.starts_with("retry after "), "detail: {detail}");
    assert!(!detail.contains("bucket="), "legacy prefix should be gone: {detail}");

    server.shutdown().await;
}
