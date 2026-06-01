// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7by: end-to-end tests for phased apply (cross-agent dependency
//! gating). When `metadata.dependsOn` produces multiple layers, the
//! server holds layer-N+1 assignments in `pending_layer` until ALL
//! layer-N assignments succeed across every agent. Failure in any
//! layer cancels all subsequent layers — the rollout stops at the
//! boundary instead of cascading damage.

use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{
    AssignmentResultRequest, AssignmentResultStatus, RegisterRequest, SubmitOperationRequest,
    SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "phased-apply-admin";

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
            trusted_proxies: vec![],
            agent_enrollment_token: None,
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
            store,
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

    /// Register an agent via the public API. We don't go through a
    /// real Agent struct here — for these tests we drive assignment
    /// completions through the Store API directly to control timing.
    async fn register_agent(&self, name: &str, env: &str) -> (String, String) {
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
        (
            body["agent_id"].as_str().unwrap().to_string(),
            body["token"].as_str().unwrap().to_string(),
        )
    }

    async fn submit(
        &self,
        env: &str,
        resources: Vec<serde_json::Value>,
    ) -> SubmitOperationResponse {
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
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }
}

fn file_resource(
    name: &str,
    env: &str,
    host_selector: Option<&str>,
    depends_on: &[&str],
) -> serde_json::Value {
    let mut metadata = json!({ "name": name, "environment": env });
    if !depends_on.is_empty() {
        metadata["dependsOn"] = json!(depends_on);
    }
    let mut spec = json!({
        "path": format!("/tmp/{name}"),
        "mode": "0644",
        "content": format!("{name}\n"),
    });
    if let Some(h) = host_selector {
        spec["hostSelector"] = json!({ "name": h });
    }
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": metadata,
        "spec": spec,
    })
}

/// Read all (id, agent_id, status, layer) for an op directly from the DB.
async fn assignments_of(store: &Store, op_id: &str) -> Vec<(String, String, String, i64)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, agent_id, status, layer FROM assignments
         WHERE operation_id = ? ORDER BY layer, id",
    )
    .bind(op_id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    rows.iter()
        .map(|r| {
            (
                r.try_get::<String, _>("id").unwrap(),
                r.try_get::<String, _>("agent_id").unwrap(),
                r.try_get::<String, _>("status").unwrap(),
                r.try_get::<i64, _>("layer").unwrap(),
            )
        })
        .collect()
}

/// Mark an assignment as terminal via the Store API. The phased-apply
/// state machine runs as a side-effect of complete_assignment.
async fn complete(store: &Store, agent_id: &str, assignment_id: &str, ok: bool) {
    let result = AssignmentResultRequest {
        status: if ok {
            AssignmentResultStatus::Succeeded
        } else {
            AssignmentResultStatus::Failed
        },
        items: vec![],
        summary: None,
    };
    store
        .complete_assignment(agent_id, assignment_id, &result)
        .await
        .unwrap();
}

#[tokio::test]
async fn layer_zero_pending_and_layer_one_pending_layer_at_submit() {
    // Two agents, two-layer dependsOn: a (layer 0, agent A), b (layer 1,
    // agent B, depends on a). Submit must produce two assignments —
    // A's pending, B's pending_layer.
    let server = TestServer::spawn().await;
    let (_a_id, _a_tok) = server.register_agent("vm-a", "prod").await;
    let (_b_id, _b_tok) = server.register_agent("vm-b", "prod").await;

    let resp = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", Some("vm-a"), &[]),
                file_resource("b", "prod", Some("vm-b"), &["file/prod/a"]),
            ],
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(assignments.len(), 2);
    let (_, _, status_a, layer_a) = &assignments[0];
    let (_, _, status_b, layer_b) = &assignments[1];
    assert_eq!(*layer_a, 0);
    assert_eq!(status_a, "pending");
    assert_eq!(*layer_b, 1);
    assert_eq!(
        status_b, "pending_layer",
        "layer-1 must hold in pending_layer until layer-0 succeeds"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn layer_one_promoted_to_pending_after_layer_zero_succeeds() {
    let server = TestServer::spawn().await;
    let (a_id, _a_tok) = server.register_agent("vm-a", "prod").await;
    let (_b_id, _b_tok) = server.register_agent("vm-b", "prod").await;

    let resp = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", Some("vm-a"), &[]),
                file_resource("b", "prod", Some("vm-b"), &["file/prod/a"]),
            ],
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let layer_zero_id = assignments
        .iter()
        .find(|(_, _, _, l)| *l == 0)
        .unwrap()
        .0
        .clone();

    // Agent A reports layer-0 as succeeded.
    complete(&server.store, &a_id, &layer_zero_id, true).await;

    // Layer 1 should now be pending (was pending_layer).
    let after = assignments_of(&server.store, &resp.operation_id).await;
    let (_, _, status_b, layer_b) = after
        .iter()
        .find(|(_, _, _, l)| *l == 1)
        .expect("layer-1 row exists");
    assert_eq!(*layer_b, 1);
    assert_eq!(status_b, "pending", "layer-1 must be promoted to pending");

    server.shutdown().await;
}

#[tokio::test]
async fn layer_one_cancelled_when_layer_zero_fails() {
    let server = TestServer::spawn().await;
    let (a_id, _a_tok) = server.register_agent("vm-a", "prod").await;
    let (_b_id, _b_tok) = server.register_agent("vm-b", "prod").await;

    let resp = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", Some("vm-a"), &[]),
                file_resource("b", "prod", Some("vm-b"), &["file/prod/a"]),
            ],
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let layer_zero_id = assignments
        .iter()
        .find(|(_, _, _, l)| *l == 0)
        .unwrap()
        .0
        .clone();

    // Agent A reports layer-0 as FAILED.
    complete(&server.store, &a_id, &layer_zero_id, false).await;

    // Layer 1 should be cancelled — phased apply stops the rollout.
    let after = assignments_of(&server.store, &resp.operation_id).await;
    let (_, _, status_b, _) = after
        .iter()
        .find(|(_, _, _, l)| *l == 1)
        .expect("layer-1 row exists");
    assert_eq!(
        status_b, "cancelled",
        "layer-1 must be cancelled when layer-0 fails"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn three_layer_chain_advances_one_step_at_a_time() {
    // a (l0, vm-a) → b (l1, vm-b) → c (l2, vm-c). Each completion
    // promotes exactly one layer. Mid-progress states are observable
    // — at no point are layer-(N+1) assignments dispatchable while
    // layer-N is still in flight.
    let server = TestServer::spawn().await;
    let (a_id, _) = server.register_agent("vm-a", "prod").await;
    let (b_id, _) = server.register_agent("vm-b", "prod").await;
    let (_c_id, _) = server.register_agent("vm-c", "prod").await;

    let resp = server
        .submit(
            "prod",
            vec![
                file_resource("a", "prod", Some("vm-a"), &[]),
                file_resource("b", "prod", Some("vm-b"), &["file/prod/a"]),
                file_resource("c", "prod", Some("vm-c"), &["file/prod/b"]),
            ],
        )
        .await;
    let initial = assignments_of(&server.store, &resp.operation_id).await;
    // Initial: l0=pending, l1=pending_layer, l2=pending_layer.
    assert_eq!(initial.len(), 3);
    assert_eq!(initial[0].2, "pending"); // layer 0
    assert_eq!(initial[1].2, "pending_layer"); // layer 1
    assert_eq!(initial[2].2, "pending_layer"); // layer 2

    // Complete layer 0 → layer 1 promotes; layer 2 still pending_layer.
    complete(&server.store, &a_id, &initial[0].0, true).await;
    let after_l0 = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(after_l0[1].2, "pending");
    assert_eq!(after_l0[2].2, "pending_layer");

    // Complete layer 1 → layer 2 promotes.
    complete(&server.store, &b_id, &after_l0[1].0, true).await;
    let after_l1 = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(after_l1[2].2, "pending");

    server.shutdown().await;
}

#[tokio::test]
async fn no_depends_on_keeps_flat_dispatch() {
    // Backwards-compat guard. Operations with no dependsOn declared
    // stay at layer 0 across all resources, so per-agent assignments
    // are still single-bucket. Pre-7by behavior preserved.
    let server = TestServer::spawn().await;
    let (_a_id, _) = server.register_agent("vm-a", "prod").await;
    let (_b_id, _) = server.register_agent("vm-b", "prod").await;

    let resp = server
        .submit(
            "prod",
            vec![
                file_resource("x", "prod", Some("vm-a"), &[]),
                file_resource("y", "prod", Some("vm-b"), &[]),
            ],
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(assignments.len(), 2);
    for (_, _, status, layer) in &assignments {
        assert_eq!(*layer, 0, "no deps → all layer 0");
        assert_eq!(status, "pending", "no deps → all dispatchable immediately");
    }

    server.shutdown().await;
}
