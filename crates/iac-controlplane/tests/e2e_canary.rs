// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7cg: end-to-end tests for canary rollouts.
//!
//! Canary builds on the phased-apply infrastructure (7by). Within each
//! layer, agents are split into a canary batch (0) and a baseline
//! batch (1). Canary dispatches first; baseline holds in
//! `pending_canary` until the canary batch fully succeeds. Any
//! failure in canary cancels the rest of the rollout — same blast-
//! radius containment as a layer failure.
//!
//! Coverage:
//! - Submit without canary: pre-7cg behavior (every agent gets work
//!   immediately).
//! - Submit with canary 50% across 4 agents: 2 dispatch, 2 wait.
//! - All canary succeed → baseline promoted.
//! - One canary fails → baseline cancelled, op ends as failed.
//! - Canary on a single-agent layer: degenerate → that agent gets
//!   the work immediately (no batch split).
//! - Canary composes with phased apply: layer-N canary runs only
//!   after layer-(N-1) baseline succeeds.

use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    AssignmentResultRequest, AssignmentResultStatus, CanarySpec, RegisterRequest,
    SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "canary-admin";

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

    async fn submit_with_canary(
        &self,
        env: &str,
        resources: Vec<serde_json::Value>,
        canary: Option<CanarySpec>,
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
                canary,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.json().await.unwrap()
    }
}

fn file_resource(name: &str, env: &str, host_selector: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": format!("/tmp/{name}"),
            "mode": "0644",
            "content": format!("{name}\n"),
            "hostSelector": { "name": host_selector },
        }
    })
}

/// Read all (id, agent_id, status, layer, batch) for an op directly from the DB.
async fn assignments_of(
    store: &Store,
    op_id: &str,
) -> Vec<(String, String, String, i64, Option<i64>)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, agent_id, status, layer, batch FROM assignments
         WHERE operation_id = ? ORDER BY layer, batch, id",
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
                r.try_get::<Option<i64>, _>("batch").unwrap(),
            )
        })
        .collect()
}

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
async fn no_canary_keeps_legacy_behavior() {
    // Without `canary`, every agent in a layer gets `pending`
    // immediately and `batch` is NULL. Pre-7cg behavior preserved.
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;
    server.register_agent("vm-b", "prod").await;

    let resp = server
        .submit_with_canary(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a"),
                file_resource("b", "prod", "vm-b"),
            ],
            None,
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(assignments.len(), 2);
    for (_, _, status, _, batch) in &assignments {
        assert_eq!(status, "pending");
        assert!(batch.is_none(), "no canary spec → batch is NULL");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn canary_50_pct_across_4_agents_splits_2_2() {
    let server = TestServer::spawn().await;
    let _ = server.register_agent("vm-a", "prod").await;
    let _ = server.register_agent("vm-b", "prod").await;
    let _ = server.register_agent("vm-c", "prod").await;
    let _ = server.register_agent("vm-d", "prod").await;

    let resp = server
        .submit_with_canary(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a"),
                file_resource("b", "prod", "vm-b"),
                file_resource("c", "prod", "vm-c"),
                file_resource("d", "prod", "vm-d"),
            ],
            Some(CanarySpec { pct: 50, min_count: None }),
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(assignments.len(), 4);
    let canary: Vec<_> = assignments.iter().filter(|a| a.4 == Some(0)).collect();
    let baseline: Vec<_> = assignments.iter().filter(|a| a.4 == Some(1)).collect();
    assert_eq!(canary.len(), 2, "50% of 4 = 2 canary");
    assert_eq!(baseline.len(), 2);
    for c in &canary {
        assert_eq!(c.2, "pending", "canary dispatches immediately");
    }
    for b in &baseline {
        assert_eq!(b.2, "pending_canary", "baseline waits");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn canary_succeeds_promotes_baseline() {
    let server = TestServer::spawn().await;
    let a_id = server.register_agent("vm-a", "prod").await;
    let b_id = server.register_agent("vm-b", "prod").await;
    let c_id = server.register_agent("vm-c", "prod").await;
    let d_id = server.register_agent("vm-d", "prod").await;
    let agent_ids = std::collections::HashMap::from([
        ("vm-a".to_string(), a_id),
        ("vm-b".to_string(), b_id),
        ("vm-c".to_string(), c_id),
        ("vm-d".to_string(), d_id),
    ]);

    let _ = agent_ids;
    let resp = server
        .submit_with_canary(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a"),
                file_resource("b", "prod", "vm-b"),
                file_resource("c", "prod", "vm-c"),
                file_resource("d", "prod", "vm-d"),
            ],
            Some(CanarySpec { pct: 50, min_count: None }),
        )
        .await;

    // Complete all canary assignments.
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let canary: Vec<_> = assignments
        .iter()
        .filter(|a| a.4 == Some(0))
        .cloned()
        .collect();
    for (asg_id, agent_id, _, _, _) in &canary {
        complete(&server.store, agent_id, asg_id, true).await;
    }

    // Baseline must now be promoted to `pending`.
    let after = assignments_of(&server.store, &resp.operation_id).await;
    let baseline: Vec<_> = after.iter().filter(|a| a.4 == Some(1)).collect();
    assert!(!baseline.is_empty(), "expected baseline rows");
    for b in &baseline {
        assert_eq!(b.2, "pending", "baseline promoted after canary success");
    }

    // Drive baseline to success → operation completes.
    for (asg_id, agent_id, _, _, _) in baseline.iter().map(|x| (*x).clone()).collect::<Vec<_>>() {
        complete(&server.store, &agent_id, &asg_id, true).await;
    }

    let op: String = sqlx::query_scalar("SELECT status FROM operations WHERE id = ?")
        .bind(&resp.operation_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    assert_eq!(op, "succeeded");

    server.shutdown().await;
}

#[tokio::test]
async fn canary_failure_cancels_baseline_and_fails_op() {
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "prod").await;
    server.register_agent("vm-b", "prod").await;
    server.register_agent("vm-c", "prod").await;
    server.register_agent("vm-d", "prod").await;

    let resp = server
        .submit_with_canary(
            "prod",
            vec![
                file_resource("a", "prod", "vm-a"),
                file_resource("b", "prod", "vm-b"),
                file_resource("c", "prod", "vm-c"),
                file_resource("d", "prod", "vm-d"),
            ],
            Some(CanarySpec { pct: 25, min_count: None }),
        )
        .await;

    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let canary: Vec<_> = assignments
        .iter()
        .filter(|a| a.4 == Some(0))
        .cloned()
        .collect();
    assert_eq!(canary.len(), 1, "25% of 4 ≈ 1 canary");
    let (asg_id, agent_id, _, _, _) = &canary[0];
    complete(&server.store, agent_id, asg_id, false).await;

    let after = assignments_of(&server.store, &resp.operation_id).await;
    for (_, _, status, _, batch) in &after {
        if *batch == Some(0) && status == "failed" {
            continue;
        }
        assert_eq!(
            status, "cancelled",
            "non-failed-canary rows should be cancelled after canary failure"
        );
    }

    let op: String = sqlx::query_scalar("SELECT status FROM operations WHERE id = ?")
        .bind(&resp.operation_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    // failed canary + cancelled baseline → no successes → "failed".
    assert_eq!(op, "failed");

    server.shutdown().await;
}

#[tokio::test]
async fn canary_on_single_agent_layer_skips_split() {
    // One agent → splitting makes no sense. The single agent goes
    // straight to `pending` with NULL batch (no canary gating
    // possible).
    let server = TestServer::spawn().await;
    server.register_agent("only", "solo").await;

    let resp = server
        .submit_with_canary(
            "solo",
            vec![file_resource("solo-r", "solo", "only")],
            Some(CanarySpec { pct: 50, min_count: None }),
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].2, "pending");
    assert!(
        assignments[0].4.is_none(),
        "single-agent layer skips canary split"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn canary_min_count_floor_overrides_pct() {
    // 5 agents, pct=10 → ceil(0.5) = 1 canary by pct, but min_count=3
    // floors to 3.
    let server = TestServer::spawn().await;
    for n in ["vm-1", "vm-2", "vm-3", "vm-4", "vm-5"] {
        server.register_agent(n, "prod").await;
    }
    let resources: Vec<_> = ["vm-1", "vm-2", "vm-3", "vm-4", "vm-5"]
        .iter()
        .map(|n| file_resource(&format!("r-{n}"), "prod", n))
        .collect();
    let resp = server
        .submit_with_canary(
            "prod",
            resources,
            Some(CanarySpec { pct: 10, min_count: Some(3) }),
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let canary: Vec<_> = assignments.iter().filter(|a| a.4 == Some(0)).collect();
    assert_eq!(canary.len(), 3, "min_count floor applied");
    server.shutdown().await;
}

#[tokio::test]
async fn canary_count_capped_to_n_minus_one() {
    // 3 agents, pct=99 → would be 3 canary, but we always leave at
    // least 1 baseline → clamped to 2.
    let server = TestServer::spawn().await;
    server.register_agent("vm-1", "prod").await;
    server.register_agent("vm-2", "prod").await;
    server.register_agent("vm-3", "prod").await;

    let resp = server
        .submit_with_canary(
            "prod",
            vec![
                file_resource("r1", "prod", "vm-1"),
                file_resource("r2", "prod", "vm-2"),
                file_resource("r3", "prod", "vm-3"),
            ],
            Some(CanarySpec { pct: 99, min_count: None }),
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;
    let canary: Vec<_> = assignments.iter().filter(|a| a.4 == Some(0)).collect();
    let baseline: Vec<_> = assignments.iter().filter(|a| a.4 == Some(1)).collect();
    assert_eq!(canary.len(), 2);
    assert_eq!(baseline.len(), 1);
    server.shutdown().await;
}

#[tokio::test]
async fn canary_composes_with_phased_apply() {
    // Two-layer rollout: layer-0 has agents A,B; layer-1 has agents
    // C,D depending on layer-0. Canary 50% should split:
    //   layer-0: A canary, B baseline (A goes pending immediately;
    //            B in pending_canary)
    //   layer-1: C canary, D baseline (both in pending_layer)
    let server = TestServer::spawn().await;
    server.register_agent("vm-a", "phase").await;
    server.register_agent("vm-b", "phase").await;
    server.register_agent("vm-c", "phase").await;
    server.register_agent("vm-d", "phase").await;

    let make = |name: &str, host: &str, deps: &[&str]| {
        let mut metadata = json!({ "name": name, "environment": "phase" });
        if !deps.is_empty() {
            metadata["dependsOn"] = json!(deps);
        }
        json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": metadata,
            "spec": {
                "path": format!("/tmp/{name}"),
                "mode": "0644",
                "content": format!("{name}\n"),
                "hostSelector": { "name": host },
            }
        })
    };

    let resp = server
        .submit_with_canary(
            "phase",
            vec![
                make("a", "vm-a", &[]),
                make("b", "vm-b", &[]),
                make("c", "vm-c", &["file/phase/a"]),
                make("d", "vm-d", &["file/phase/b"]),
            ],
            Some(CanarySpec { pct: 50, min_count: None }),
        )
        .await;
    let assignments = assignments_of(&server.store, &resp.operation_id).await;

    // Layer-0: one pending (canary), one pending_canary (baseline).
    let layer0: Vec<_> = assignments.iter().filter(|a| a.3 == 0).collect();
    assert_eq!(layer0.len(), 2);
    assert_eq!(
        layer0
            .iter()
            .filter(|a| a.2 == "pending" && a.4 == Some(0))
            .count(),
        1
    );
    assert_eq!(
        layer0
            .iter()
            .filter(|a| a.2 == "pending_canary" && a.4 == Some(1))
            .count(),
        1
    );

    // Layer-1: every assignment is pending_layer regardless of batch.
    let layer1: Vec<_> = assignments.iter().filter(|a| a.3 == 1).collect();
    assert_eq!(layer1.len(), 2);
    for a in &layer1 {
        assert_eq!(a.2, "pending_layer");
        assert!(a.4.is_some(), "canary spec applies per layer");
    }

    server.shutdown().await;
}
