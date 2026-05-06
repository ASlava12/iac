// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7b: `GET /v1/operations/{id}/desired-state` lets approvers preview
//! exactly which primitives an operation will write before greenlighting.
//! The endpoint reads `desired_states` directly so it works for ops in
//! `pending_approval` (no assignments exist yet) and for clean ops.

use iac_controlplane::identity::Role;
use iac_controlplane::policy::{Policy, PolicyMatch};
use iac_controlplane::store::CreateUser;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    LoginRequest, LoginResponse, OperationDesiredState, RegisterRequest, RegisterResponse,
    SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "plan-remote-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    store: Store,
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
            wal_checkpoint_interval_secs: 0,
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
            rate_limiter: std::sync::Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(&cfg.rate_limit)),
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

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }

    async fn register_agent(&self, name: &str, env: &str) -> RegisterResponse {
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
            .unwrap()
            .json()
            .await
            .unwrap()
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
}

fn prod_policy() -> Policy {
    Policy {
        name: "prod-needs-approval".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: true,
        approvers: vec![],
        rate_limit_per_minute: None,
    }
}

async fn submit_two_files(server: &TestServer, env: &str) -> SubmitOperationResponse {
    let req = SubmitOperationRequest {
        environment: env.into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![
            json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "alpha", "environment": env },
                "spec": {
                    "path": "/tmp/alpha.txt",
                    "mode": "0644",
                    "content": "alpha\n",
                }
            }),
            json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "beta", "environment": env },
                "spec": {
                    "path": "/tmp/beta.txt",
                    "mode": "0644",
                    "content": "beta\n",
                }
            }),
        ], canary: None,
    };
    reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn pending_approval_op_exposes_desired_state() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    server.register_agent("vm-1", "prod").await;

    let resp = submit_two_files(&server, "prod").await;
    // Sanity: it really did land in pending_approval.
    assert_eq!(resp.assignment_count, 0);

    let body: OperationDesiredState = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.operation_id, resp.operation_id);
    assert_eq!(body.items.len(), 2);

    let kinds: Vec<&str> = body.items.iter().map(|i| i.kind.as_str()).collect();
    assert!(kinds.iter().all(|k| *k == "file"));

    // Routing assigned both to vm-1 (single agent in env).
    for item in &body.items {
        assert!(!item.agent_id.is_empty(), "expected routed agent_id");
        // Resource shape preserved (apiVersion/kind/metadata/spec) and
        // routing hints stripped.
        assert_eq!(item.resource["kind"], "file");
        assert!(item.resource["spec"].get("hostSelector").is_none());
    }

    let names: Vec<&str> = body
        .items
        .iter()
        .map(|i| i.resource["metadata"]["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"alpha"));
    assert!(names.contains(&"beta"));

    server.shutdown().await;
}

#[tokio::test]
async fn clean_op_also_exposes_desired_state() {
    // No policy → op proceeds without approval. desired_states still
    // populated at submit time, so the endpoint works for running/closed
    // ops too — useful for post-hoc review.
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm-2", "stage").await;

    let resp = submit_two_files(&server, "stage").await;
    assert_eq!(resp.assignment_count, 1);

    let body: OperationDesiredState = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.items.len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn viewer_can_read_desired_state() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    server.register_agent("vm-3", "prod").await;
    server.make_user("eve", "p", vec![Role::Viewer]).await;

    let resp = submit_two_files(&server, "prod").await;
    let viewer_token = server.login("eve", "p").await.token;

    let r = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: OperationDesiredState = r.json().await.unwrap();
    assert_eq!(body.items.len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn unauthenticated_request_is_rejected() {
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm-4", "stage").await;

    let resp = submit_two_files(&server, "stage").await;
    let r = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            resp.operation_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn unknown_operation_returns_404() {
    let server = TestServer::spawn(vec![]).await;

    let r = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/01ARZ3NDEKTSV4RRFFQ69G5FAV/desired-state",
            server.url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    server.shutdown().await;
}

#[tokio::test]
async fn unrouted_resources_are_returned_with_empty_agent_id() {
    // Two agents in the env without hostSelector → routing is ambiguous.
    // The operation still surfaces the desired-state items with
    // agent_id="" so the approver sees the gap explicitly.
    let server = TestServer::spawn(vec![]).await;
    server.register_agent("vm-a", "stage").await;
    server.register_agent("vm-b", "stage").await;

    let resp = submit_two_files(&server, "stage").await;

    let body: OperationDesiredState = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.items.len(), 2);
    for item in &body.items {
        assert!(
            item.agent_id.is_empty(),
            "ambiguous routing should leave agent_id empty"
        );
    }

    server.shutdown().await;
}
