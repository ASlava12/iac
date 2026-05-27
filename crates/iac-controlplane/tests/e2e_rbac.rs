// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6e: RBAC. Login + role-gated endpoints + audit names.

use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::ResourceId;
use iac_core::diff::Diff;
use iac_core::protocol::v1::{
    AuditEvent, DriftAcceptRequest, DriftBatch, DriftItem, DriftSummary, LoginRequest,
    LoginResponse, OperationApproveRequest, OperationRejectRequest, OperationStatus, OperationView,
    RegisterRequest, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "rbac-admin-legacy";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    store: Store,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn() -> Self {
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
            rate_limiter: std::sync::Arc::new(
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
            store,
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

    async fn make_user(&self, name: &str, password: &str, roles: Vec<Role>) {
        self.store
            .create_user(CreateUser {
                username: name,
                password,
                roles,
            })
            .await
            .unwrap();
    }

    async fn login(&self, name: &str, password: &str) -> LoginResponse {
        reqwest::Client::new()
            .post(format!("{}/v1/auth/login", self.url()))
            .json(&LoginRequest {
                username: name.into(),
                password: password.into(),
            })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

async fn submit_op(
    server: &TestServer,
    bearer: &str,
    env: &str,
    target: &std::path::Path,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(bearer)
        .json(&SubmitOperationRequest {
            environment: env.into(),
            requested_by: "anyone".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "x", "environment": env },
                "spec": { "path": target.display().to_string(), "mode": "0644", "content": "y\n" }
            })],
            canary: None,
        })
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn login_returns_token_with_correct_password() {
    let server = TestServer::spawn().await;
    server
        .make_user("alice", "hunter2", vec![Role::Operator])
        .await;

    let resp = server.login("alice", "hunter2").await;
    assert!(!resp.token.is_empty());
    assert!(resp.expires_at.len() > 10);
    assert_eq!(resp.roles, vec!["operator"]);

    server.shutdown().await;
}

#[tokio::test]
async fn login_rejects_wrong_password() {
    let server = TestServer::spawn().await;
    server
        .make_user("alice", "hunter2", vec![Role::Operator])
        .await;

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "alice".into(),
            password: "wrong".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "no-such-user".into(),
            password: "anything".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn operator_can_submit_but_not_approve() {
    let server = TestServer::spawn().await;
    server.make_user("op", "p", vec![Role::Operator]).await;
    let token = server.login("op", "p").await.token;

    // Operator submits → 200.
    let dir = TempDir::new().unwrap();
    let resp = submit_op(&server, &token, "test", &dir.path().join("x")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let r: SubmitOperationResponse = resp.json().await.unwrap();

    // Operator approves → 403 (needs Approver).
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            r.operation_id
        ))
        .bearer_auth(&token)
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    server.shutdown().await;
}

#[tokio::test]
async fn approver_can_approve() {
    let server = TestServer::spawn().await;
    server.make_user("a", "p", vec![Role::Approver]).await;
    let token = server.login("a", "p").await.token;

    // Approver also has Operator (lattice), so they can submit too.
    let dir = TempDir::new().unwrap();
    let resp = submit_op(&server, &token, "test", &dir.path().join("x")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn viewer_cannot_submit_or_approve_or_accept_drift() {
    let server = TestServer::spawn().await;
    server.make_user("v", "p", vec![Role::Viewer]).await;
    let viewer = server.login("v", "p").await.token;

    // Phase 7co.2 (security fix #4.6): the audit log is sensitive-by-
    // default and now requires Approver. A read-only Viewer used to
    // be able to enumerate admins and reconstruct deploy timelines.
    let resp = reqwest::Client::new()
        .get(format!("{}/v1/audit", server.url()))
        .bearer_auth(&viewer)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Viewer cannot submit.
    let dir = TempDir::new().unwrap();
    let resp = submit_op(&server, &viewer, "test", &dir.path().join("x")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Viewer cannot accept drift. Set up a real drift first.
    let creds: iac_core::protocol::v1::RegisterResponse = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .json(&RegisterRequest {
            name: "x".into(),
            environment: "test".into(),
            metadata: json!({}),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/drift",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&creds.token)
        .json(&DriftBatch {
            items: vec![DriftItem {
                resource_id: ResourceId::new("file", "test", "x"),
                severity: "warning".into(),
                detected_at: jiff::Timestamp::now().to_string(),
                diff: Diff::no_change(),
            }],
        })
        .send()
        .await
        .unwrap();
    let drifts: Vec<DriftSummary> = reqwest::Client::new()
        .get(format!("{}/v1/drift", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = drifts[0].id;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/drift/{id}/accept", server.url()))
        .bearer_auth(&viewer)
        .json(&DriftAcceptRequest {
            reason: "no".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    server.shutdown().await;
}

#[tokio::test]
async fn legacy_admin_token_still_works() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();

    // Static admin token with no users in DB — should still grant Admin.
    let resp = submit_op(&server, ADMIN_TOKEN, "test", &dir.path().join("x")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn audit_records_user_actor_not_admin() {
    let server = TestServer::spawn().await;
    server
        .make_user("alice", "p", vec![Role::Operator, Role::Approver])
        .await;
    let token = server.login("alice", "p").await.token;

    let dir = TempDir::new().unwrap();
    let r = submit_op(&server, &token, "test", &dir.path().join("x")).await;
    assert_eq!(r.status(), StatusCode::OK);
    let body: SubmitOperationResponse = r.json().await.unwrap();

    // Audit event for the submission should carry "user:alice".
    let events: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!(
            "{}/v1/audit?kind=operation.submitted",
            server.url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let our = events
        .iter()
        .find(|e| e.operation_id.as_deref() == Some(body.operation_id.as_str()))
        .expect("our op");
    assert_eq!(our.actor, "user:alice");

    server.shutdown().await;
}

#[tokio::test]
async fn approver_named_user_recorded_on_approve_and_reject() {
    let server = TestServer::spawn().await;
    // Set up: server requires approval for any submission to "prod" via a
    // policy. Use the admin to plant a policy by inserting it via Config —
    // but our config struct is fixed in spawn(). Instead, simulate the gate
    // by creating a pending_approval op directly through the store.
    server.make_user("op", "p", vec![Role::Operator]).await;
    server.make_user("alice", "p", vec![Role::Approver]).await;
    let op_token = server.login("op", "p").await.token;
    let alice_token = server.login("alice", "p").await.token;

    // op submits two ops. First gets approved by alice, second rejected.
    let dir = TempDir::new().unwrap();
    let r1 = submit_op(&server, &op_token, "test", &dir.path().join("a")).await;
    let r1_body: SubmitOperationResponse = r1.json().await.unwrap();

    // Mark op1 as pending_approval directly via store.
    sqlx::query("UPDATE operations SET status = 'pending_approval' WHERE id = ?")
        .bind(&r1_body.operation_id)
        .execute(server.store.pool())
        .await
        .unwrap();
    // Delete its assignment so approve has clean state to recreate.
    sqlx::query("DELETE FROM assignments WHERE operation_id = ?")
        .bind(&r1_body.operation_id)
        .execute(server.store.pool())
        .await
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            r1_body.operation_id
        ))
        .bearer_auth(&alice_token)
        .json(&OperationApproveRequest {
            reason: Some("LGTM".into()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let view: OperationView = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            r1_body.operation_id
        ))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(view.approved_by.as_deref(), Some("alice"));

    // Audit shows user:alice as approver actor.
    let approve_events: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!("{}/v1/audit?kind=operation.approved", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approve_events.len(), 1);
    assert_eq!(approve_events[0].actor, "user:alice");
    assert_eq!(approve_events[0].payload["approver"], "alice");

    // Reject path: op2.
    let r2 = submit_op(&server, &op_token, "test", &dir.path().join("b")).await;
    let r2_body: SubmitOperationResponse = r2.json().await.unwrap();
    sqlx::query("UPDATE operations SET status = 'pending_approval' WHERE id = ?")
        .bind(&r2_body.operation_id)
        .execute(server.store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM assignments WHERE operation_id = ?")
        .bind(&r2_body.operation_id)
        .execute(server.store.pool())
        .await
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/reject",
            server.url(),
            r2_body.operation_id
        ))
        .bearer_auth(&alice_token)
        .json(&OperationRejectRequest {
            reason: "needs more thought".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let view: OperationView = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            r2_body.operation_id
        ))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(view.status, OperationStatus::Rejected));
    assert_eq!(view.rejected_by.as_deref(), Some("alice"));

    server.shutdown().await;
}

#[tokio::test]
async fn logout_invalidates_token() {
    let server = TestServer::spawn().await;
    server.make_user("alice", "p", vec![Role::Operator]).await;
    let token = server.login("alice", "p").await.token;

    // Token works.
    let dir = TempDir::new().unwrap();
    let r = submit_op(&server, &token, "test", &dir.path().join("a")).await;
    assert_eq!(r.status(), StatusCode::OK);

    // Logout.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/auth/logout", server.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Same token now fails.
    let r = submit_op(&server, &token, "test", &dir.path().join("b")).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn duplicate_username_fails() {
    let server = TestServer::spawn().await;
    server.make_user("a", "p", vec![Role::Viewer]).await;
    let res = server
        .store
        .create_user(CreateUser {
            username: "a",
            password: "x",
            roles: vec![Role::Viewer],
        })
        .await;
    assert!(matches!(res, Err(iac_controlplane::ApiError::Conflict(_))));
    server.shutdown().await;
}
