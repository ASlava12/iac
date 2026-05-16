// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7ci: end-to-end tests for server-side rollback.
//!
//! Coverage:
//! 1. Happy path: deploy v1, deploy v2, rollback latest → produces a
//!    new op with v1's spec.
//! 2. Two-deploy chain: only the most recent prior is restored
//!    (history walks back exactly one step).
//! 3. First-time apply: no prior state → resource lands in
//!    `resources_orphaned` and the rollback rejects when EVERY
//!    resource is orphaned.
//! 4. Cannot rollback an in-flight (non-terminal) operation.
//! 5. Rollback inherits canary spec from the request.
//! 6. Audit log records `operation.rollback_initiated` with the
//!    target_operation_id linkage.
//! 7. Rollback with `--reason` propagates the reason into the
//!    summary + audit payload.

use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    AssignmentResultRequest, AssignmentResultStatus, CanarySpec, RegisterRequest,
    RollbackOperationRequest, RollbackOperationResponse, SubmitOperationRequest,
    SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "rollback-admin";

struct TestServer {
    addr: SocketAddr,
    store: Store,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
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
            rate_limiter: Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(
                &cfg.rate_limit,
            )),
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
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async move { signal.notified().await })
                .await
                .unwrap();
        });
        Self { addr, store, shutdown, handle, _tempdir: dir }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }

    async fn register_agent(&self, name: &str, env: &str) -> String {
        let resp = reqwest::Client::new()
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
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        body["agent_id"].as_str().unwrap().to_string()
    }

    async fn submit(&self, env: &str, resources: Vec<serde_json::Value>) -> SubmitOperationResponse {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/operations", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources,
                canary: None,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "submit failed: {}", resp.text().await.unwrap());
        resp.json().await.unwrap()
    }

    async fn rollback(
        &self,
        op_id: &str,
        reason: Option<&str>,
        canary: Option<CanarySpec>,
    ) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/operations/{op_id}/rollback", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&RollbackOperationRequest {
                requested_by: "alice".into(),
                reason: reason.map(str::to_string),
                canary,
            })
            .send()
            .await
            .unwrap()
    }
}

fn file_resource(name: &str, env: &str, host: &str, content: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": format!("/tmp/{name}"),
            "mode": "0644",
            "content": format!("{content}\n"),
            "hostSelector": { "name": host },
        }
    })
}

async fn drive_to_success(store: &Store, op_id: &str) {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, agent_id FROM assignments
         WHERE operation_id = ? AND status IN ('pending', 'fetched')",
    )
    .bind(op_id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    for row in rows {
        let id: String = row.try_get("id").unwrap();
        let agent_id: String = row.try_get("agent_id").unwrap();
        let result = AssignmentResultRequest {
            status: AssignmentResultStatus::Succeeded,
            items: vec![],
            summary: None,
        };
        store.complete_assignment(&agent_id, &id, &result).await.unwrap();
    }
}

#[tokio::test]
async fn rollback_reverts_to_prior_spec() {
    // Deploy v1 → succeed → deploy v2 → succeed → rollback v2.
    // The new operation must contain v1's spec.
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;

    let v1 = server
        .submit("prod", vec![file_resource("greet", "prod", "vm-a", "hello-v1")])
        .await;
    drive_to_success(&server.store, &v1.operation_id).await;

    let v2 = server
        .submit("prod", vec![file_resource("greet", "prod", "vm-a", "hello-v2")])
        .await;
    drive_to_success(&server.store, &v2.operation_id).await;

    let resp = server.rollback(&v2.operation_id, Some("regression"), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: RollbackOperationResponse = resp.json().await.unwrap();
    assert_eq!(body.resources_reverted, 1);
    assert!(body.resources_orphaned.is_empty());
    assert_eq!(body.assignment_count, 1);

    // Inspect what got persisted as desired_state for the rollback op.
    let new_spec: String = sqlx::query_scalar(
        "SELECT spec_json FROM desired_states WHERE operation_id = ?",
    )
    .bind(&body.new_operation_id)
    .fetch_one(server.store.pool())
    .await
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&new_spec).unwrap();
    let content = parsed["spec"]["content"].as_str().unwrap();
    assert_eq!(content, "hello-v1\n", "rollback must restore v1's content");

    server.shutdown().await;
}

#[tokio::test]
async fn rollback_chain_walks_back_one_step() {
    // v1 → v2 → v3 → rollback v3 → result is v2 (NOT v1).
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;

    for i in 1..=3 {
        let op = server
            .submit(
                "prod",
                vec![file_resource("greet", "prod", "vm-a", &format!("v{i}"))],
            )
            .await;
        drive_to_success(&server.store, &op.operation_id).await;
        // Tiny sleep so created_at timestamps don't collide.
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    }
    // Find the v3 op id.
    let v3_id: String = sqlx::query_scalar(
        "SELECT id FROM operations ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(server.store.pool())
    .await
    .unwrap();

    let resp = server.rollback(&v3_id, None, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: RollbackOperationResponse = resp.json().await.unwrap();

    let new_spec: String = sqlx::query_scalar(
        "SELECT spec_json FROM desired_states WHERE operation_id = ?",
    )
    .bind(&body.new_operation_id)
    .fetch_one(server.store.pool())
    .await
    .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&new_spec).unwrap();
    let content = parsed["spec"]["content"].as_str().unwrap();
    assert_eq!(content, "v2\n", "rollback walks back exactly one step");

    server.shutdown().await;
}

#[tokio::test]
async fn rollback_first_time_apply_returns_orphan() {
    // First-ever deploy of resource → no prior state → entire
    // rollback fails (Conflict 409, "no resources to revert").
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;

    let v1 = server
        .submit("prod", vec![file_resource("only", "prod", "vm-a", "v1")])
        .await;
    drive_to_success(&server.store, &v1.operation_id).await;

    let resp = server.rollback(&v1.operation_id, None, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("no resources") && body.contains("orphan"),
        "unexpected error: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn rollback_in_flight_op_rejected() {
    // v1 deploy is created but agents haven't completed yet → rollback
    // refuses (would race with assignment dispatch).
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;

    let v1 = server
        .submit("prod", vec![file_resource("greet", "prod", "vm-a", "v1")])
        .await;
    // Don't drive to success — op stays pending.

    let resp = server.rollback(&v1.operation_id, None, None).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn rollback_inherits_canary_spec() {
    // Rollback request with canary 50% across 2 agents must split
    // batches per Phase 7cg.
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;
    server.register_agent("vm-b", "prod").await;

    let v1 = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a", "v1"),
                file_resource("b", "prod", "vm-b", "v1"),
            ],
        )
        .await;
    drive_to_success(&server.store, &v1.operation_id).await;

    let v2 = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a", "v2"),
                file_resource("b", "prod", "vm-b", "v2"),
            ],
        )
        .await;
    drive_to_success(&server.store, &v2.operation_id).await;

    let resp = server
        .rollback(&v2.operation_id, None, Some(CanarySpec { pct: 50, min_count: None }))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: RollbackOperationResponse = resp.json().await.unwrap();

    let rows: Vec<(Option<i64>, String)> = sqlx::query_as(
        "SELECT batch, status FROM assignments WHERE operation_id = ?",
    )
    .bind(&body.new_operation_id)
    .fetch_all(server.store.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    let canary_count = rows.iter().filter(|(b, _)| *b == Some(0)).count();
    let baseline_count = rows.iter().filter(|(b, _)| *b == Some(1)).count();
    assert_eq!(canary_count, 1);
    assert_eq!(baseline_count, 1);
    let canary_status = rows.iter().find(|(b, _)| *b == Some(0)).unwrap();
    let baseline_status = rows.iter().find(|(b, _)| *b == Some(1)).unwrap();
    assert_eq!(canary_status.1, "pending");
    assert_eq!(baseline_status.1, "pending_canary");

    server.shutdown().await;
}

#[tokio::test]
async fn rollback_emits_audit_event_with_linkage() {
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;

    let v1 = server
        .submit("prod", vec![file_resource("greet", "prod", "vm-a", "v1")])
        .await;
    drive_to_success(&server.store, &v1.operation_id).await;
    let v2 = server
        .submit("prod", vec![file_resource("greet", "prod", "vm-a", "v2")])
        .await;
    drive_to_success(&server.store, &v2.operation_id).await;

    let resp = server.rollback(&v2.operation_id, Some("incident-1234"), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: RollbackOperationResponse = resp.json().await.unwrap();

    use sqlx::Row;
    let row = sqlx::query(
        "SELECT actor, payload_json FROM audit_events
         WHERE kind = 'operation.rollback_initiated' AND operation_id = ?",
    )
    .bind(&body.new_operation_id)
    .fetch_one(server.store.pool())
    .await
    .unwrap();
    let payload: String = row.try_get("payload_json").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed["target_operation_id"], v2.operation_id);
    assert_eq!(parsed["reason"], "incident-1234");
    assert_eq!(parsed["resources_reverted"], 1);

    server.shutdown().await;
}
