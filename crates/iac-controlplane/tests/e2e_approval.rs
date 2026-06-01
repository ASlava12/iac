// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6d: approval gate. Operations matching a `requires_approval` policy
//! land in `pending_approval` until an admin token holder calls `.../approve`.
//! Until then no assignments exist, so agents see nothing — even if they
//! poll the assignments endpoint, the operation is invisible.

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_controlplane::policy::{Policy, PolicyMatch};
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{
    AssignmentList, AuditEvent, OperationApproveRequest, OperationRejectRequest, OperationStatus,
    OperationView, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "approval-admin";

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

fn build_agent(workdir: &Path, server_url: &str, name: &str, env: &str) -> Agent {
    let manifests = workdir.join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let cfg = AgentConfig::load(
        None,
        ConfigOverrides {
            state_dir: Some(workdir.join("state")),
            manifests_dir: Some(manifests),
            observe_interval_secs: Some(1),
            environment: Some(env.into()),
            actor: Some("test".into()),
            server_url: Some(server_url.into()),
            agent_name: Some(name.into()),
            capabilities_file: None,
        },
    )
    .unwrap();
    Agent::new(cfg).unwrap()
}

async fn submit_prod(server: &TestServer, target: &Path) -> SubmitOperationResponse {
    let req = SubmitOperationRequest {
        environment: "prod".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "watched", "environment": "prod" },
            "spec": {
                "path": target.display().to_string(),
                "mode": "0644",
                "content": "approved-content\n",
            }
        })],
        canary: None,
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

async fn fetch_op(server: &TestServer, op_id: &str) -> OperationView {
    reqwest::Client::new()
        .get(format!("{}/v1/operations/{}", server.url(), op_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn submission_against_policy_lands_in_pending_approval() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-1", "prod");
    assert!(agent.connect_remote().await);

    let target = dir.path().join("file.txt");
    let resp = submit_prod(&server, &target).await;
    // No assignments dispatched yet — the gate held.
    assert_eq!(resp.assignment_count, 0);

    let view = fetch_op(&server, &resp.operation_id).await;
    assert!(matches!(view.status, OperationStatus::PendingApproval));
    assert_eq!(view.matched_policies, vec!["prod-needs-approval"]);
    assert!(view.approved_by.is_none());

    // Agent's own assignments endpoint returns nothing — the operation is
    // gated server-side and no rows were ever inserted into `assignments`.
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("state/identity.json")).unwrap())
            .unwrap();
    let resp = reqwest::Client::new()
        .get(format!(
            "{}/v1/agents/{}/assignments",
            server.url(),
            identity["agent_id"].as_str().unwrap()
        ))
        .bearer_auth(identity["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: AssignmentList = resp.json().await.unwrap();
    assert!(list.items.is_empty());

    // Even forcing an observe doesn't apply anything.
    agent.observe_once().await.unwrap();
    assert!(!target.exists());

    server.shutdown().await;
}

#[tokio::test]
async fn approve_promotes_pending_to_running_and_lets_agent_apply() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-2", "prod");
    assert!(agent.connect_remote().await);

    let target = dir.path().join("file.txt");
    let resp = submit_prod(&server, &target).await;
    let op_id = resp.operation_id;
    assert!(matches!(
        fetch_op(&server, &op_id).await.status,
        OperationStatus::PendingApproval
    ));

    // Approve.
    let approve = reqwest::Client::new()
        .post(format!("{}/v1/operations/{}/approve", server.url(), op_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationApproveRequest {
            reason: Some("LGTM after eyeballing the diff".into()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::OK);

    // Op now has assignments and is no longer pending_approval.
    let view = fetch_op(&server, &op_id).await;
    assert!(view.approved_at.is_some());
    assert_eq!(view.approved_by.as_deref(), Some("admin"));
    assert!(matches!(
        view.status,
        OperationStatus::Pending | OperationStatus::Running
    ));
    assert_eq!(view.assignments.len(), 1);

    // Agent observes → applies.
    agent.observe_once().await.unwrap();
    assert!(target.exists());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "approved-content\n"
    );

    let view = fetch_op(&server, &op_id).await;
    assert!(matches!(view.status, OperationStatus::Succeeded));

    server.shutdown().await;
}

#[tokio::test]
async fn reject_terminates_operation() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-3", "prod");
    assert!(agent.connect_remote().await);

    let target = dir.path().join("file.txt");
    let resp = submit_prod(&server, &target).await;
    let op_id = resp.operation_id;

    let reject = reqwest::Client::new()
        .post(format!("{}/v1/operations/{}/reject", server.url(), op_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationRejectRequest {
            reason: "needs more review".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(reject.status(), StatusCode::OK);

    let view = fetch_op(&server, &op_id).await;
    assert!(matches!(view.status, OperationStatus::Rejected));
    assert_eq!(view.rejected_by.as_deref(), Some("admin"));
    assert_eq!(view.rejection_reason.as_deref(), Some("needs more review"));

    // Approving a rejected op fails.
    let approve = reqwest::Client::new()
        .post(format!("{}/v1/operations/{}/approve", server.url(), op_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::CONFLICT);

    // Agent observes → does NOT apply.
    agent.observe_once().await.unwrap();
    assert!(!target.exists());

    server.shutdown().await;
}

#[tokio::test]
async fn clean_submission_skips_gate() {
    // No prod policy → submit goes through normally.
    let server = TestServer::spawn(vec![]).await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-4", "prod");
    assert!(agent.connect_remote().await);

    let target = dir.path().join("clean.txt");
    let resp = submit_prod(&server, &target).await;
    assert_eq!(resp.assignment_count, 1);
    let view = fetch_op(&server, &resp.operation_id).await;
    assert!(matches!(
        view.status,
        OperationStatus::Pending | OperationStatus::Running
    ));
    assert!(view.matched_policies.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn approve_and_reject_audit_events_are_recorded() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let _agent = build_agent(dir.path(), &server.url(), "vm-5", "prod");

    let target = dir.path().join("a.txt");
    let r1 = submit_prod(&server, &target).await;
    let target = dir.path().join("b.txt");
    let r2 = submit_prod(&server, &target).await;

    reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            r1.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationApproveRequest {
            reason: Some("ship it".into()),
        })
        .send()
        .await
        .unwrap();
    reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/reject",
            server.url(),
            r2.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationRejectRequest {
            reason: "wrong env".into(),
        })
        .send()
        .await
        .unwrap();

    let approved: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!("{}/v1/audit?kind=operation.approved", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(approved.len(), 1);
    assert_eq!(
        approved[0].operation_id.as_deref(),
        Some(r1.operation_id.as_str())
    );
    assert_eq!(approved[0].payload["reason"], "ship it");

    let rejected: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!("{}/v1/audit?kind=operation.rejected", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].severity, "warning");
    assert_eq!(rejected[0].payload["reason"], "wrong env");

    // Original `operation.submitted` is replaced by `operation.pending_approval`
    // for gated submits — confirm it's recorded too.
    let pending: Vec<AuditEvent> = reqwest::Client::new()
        .get(format!(
            "{}/v1/audit?kind=operation.pending_approval",
            server.url()
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(pending.len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn approve_and_reject_require_admin() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let _agent = build_agent(dir.path(), &server.url(), "vm-6", "prod");

    let target = dir.path().join("a.txt");
    let resp = submit_prod(&server, &target).await;

    let bad_approve = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth("wrong")
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(bad_approve.status(), StatusCode::UNAUTHORIZED);

    let bad_reject = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/reject",
            server.url(),
            resp.operation_id
        ))
        .json(&OperationRejectRequest { reason: "x".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(bad_reject.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn empty_reject_reason_returns_400() {
    let server = TestServer::spawn(vec![prod_policy()]).await;
    let dir = TempDir::new().unwrap();
    let _agent = build_agent(dir.path(), &server.url(), "vm-7", "prod");

    let target = dir.path().join("a.txt");
    let resp = submit_prod(&server, &target).await;

    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/reject",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationRejectRequest {
            reason: "  ".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    server.shutdown().await;
}
