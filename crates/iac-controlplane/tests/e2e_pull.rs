// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 2b end-to-end: operator submits a desired-state via `POST /v1/operations`,
//! the agent drains the resulting assignment, applies it locally, and reports
//! back. Server's view of the operation reaches `succeeded`.

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{
    OperationStatus, OperationView, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "test-admin-token";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn_with_admin() -> Self {
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

fn file_resource_json(name: &str, env: &str, target: &Path, content: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": target.display().to_string(),
            "mode": "0644",
            "content": format!("{content}\n"),
        }
    })
}

#[tokio::test]
async fn operator_submits_then_agent_applies_and_reports() {
    let server = TestServer::spawn_with_admin().await;
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("hello-pull.txt");

    let agent = build_agent(dir.path(), &server.url(), "vm-test", "smoke");
    assert!(agent.connect_remote().await);

    // Operator submits the desired state.
    let req = SubmitOperationRequest {
        environment: "smoke".into(),
        requested_by: "op".into(),
        source_commit: Some("abc123".into()),
        summary: Some("smoke test".into()),
        resources: vec![file_resource_json("greet", "smoke", &target, "hi")],
        canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "submit failed: {}",
        resp.text().await.unwrap()
    );
    let submit: SubmitOperationResponse = resp.json().await.unwrap();
    assert_eq!(submit.assignment_count, 1);
    assert!(submit.unrouted.is_empty());

    // Initial server status: pending or running.
    let resp = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let view: OperationView = resp.json().await.unwrap();
    assert!(matches!(
        view.status,
        OperationStatus::Pending | OperationStatus::Running
    ));
    assert_eq!(view.assignments.len(), 1);

    // Agent observes (which also drains assignments).
    agent.observe_once().await.unwrap();

    // File should now exist.
    assert!(target.exists(), "agent did not apply the assignment");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hi\n");

    // Server view should now be succeeded with a result.
    let resp = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let view: OperationView = resp.json().await.unwrap();
    assert!(
        matches!(view.status, OperationStatus::Succeeded),
        "expected succeeded, got {:?}",
        view.status
    );
    assert_eq!(view.assignments.len(), 1);
    let a = &view.assignments[0];
    assert_eq!(a.status, "succeeded");
    assert!(a.completed_at.is_some());
    assert!(a.result.is_some());

    server.shutdown().await;
}

#[tokio::test]
async fn submit_without_admin_token_unauthorized() {
    let server = TestServer::spawn_with_admin().await;
    let req = SubmitOperationRequest {
        environment: "smoke".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![
            json!({"apiVersion":"iac.example/v1","kind":"file","metadata":{"name":"x"},"spec":{}}),
        ],
        canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth("wrong")
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    server.shutdown().await;
}

#[tokio::test]
async fn submit_with_no_admin_configured_returns_400() {
    // Server has no admin_token configured.
    let dir = TempDir::new().unwrap();
    let cfg = ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: format!("sqlite://{}/test.db?mode=rwc", dir.path().display()),
        state_dir: dir.path().to_path_buf(),
        max_body_bytes: 1 << 20,
        admin_token: None,
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
        store,
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
            iac_controlplane::server::ReloadableState::new(std::sync::Arc::new(cfg.clone())),
        )),
        config_path: None,
        signer,
        rate_limiter: std::sync::Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(
            &cfg.rate_limit,
        )),
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
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { signal.notified().await })
        .await
        .unwrap();
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/v1/operations"))
        .bearer_auth("anything")
        .json(&SubmitOperationRequest {
            environment: "x".into(),
            requested_by: "y".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({"x": 1})],
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    shutdown.notify_waiters();
    let _ = handle.await;
}

#[tokio::test]
async fn submit_with_unrouted_resources_lists_them() {
    let server = TestServer::spawn_with_admin().await;
    let dir = TempDir::new().unwrap();

    // Two agents in different envs; operator targets env with no agents.
    let agent_a = build_agent(&dir.path().join("a"), &server.url(), "vm-a", "envA");
    assert!(agent_a.connect_remote().await);

    let req = SubmitOperationRequest {
        environment: "ghost-env".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![file_resource_json(
            "x",
            "ghost-env",
            &dir.path().join("nonexistent.txt"),
            "hi",
        )],
        canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();
    assert_eq!(submit.assignment_count, 0);
    assert_eq!(submit.unrouted.len(), 1);
    assert!(submit.unrouted[0].reason.contains("no agents"));

    // The op should be marked succeeded immediately (no work to do).
    let resp = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let view: OperationView = resp.json().await.unwrap();
    assert!(matches!(view.status, OperationStatus::Succeeded));
    assert!(view.assignments.is_empty());

    server.shutdown().await;
}

#[tokio::test]
async fn host_selector_routes_to_named_agent() {
    let server = TestServer::spawn_with_admin().await;
    let dir = TempDir::new().unwrap();

    // Two agents in the same env.
    let a_dir = dir.path().join("a");
    let b_dir = dir.path().join("b");
    let agent_a = build_agent(&a_dir, &server.url(), "host-A", "prod");
    assert!(agent_a.connect_remote().await);
    let agent_b = build_agent(&b_dir, &server.url(), "host-B", "prod");
    assert!(agent_b.connect_remote().await);

    let target = dir.path().join("on-A.txt");
    let mut resource = file_resource_json("x", "prod", &target, "hello-A");
    resource["spec"]["hostSelector"] = json!({ "name": "host-A" });

    let req = SubmitOperationRequest {
        environment: "prod".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![resource],
        canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();
    assert_eq!(submit.assignment_count, 1);

    // Only agent A should pick up the assignment.
    let drained_a = agent_a.drain_assignments().await.unwrap();
    let drained_b = agent_b.drain_assignments().await.unwrap();
    assert_eq!(drained_a, 1, "agent A should have drained 1 assignment");
    assert_eq!(drained_b, 0, "agent B should have drained 0 assignments");

    assert!(target.exists());

    let resp = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let view: OperationView = resp.json().await.unwrap();
    assert_eq!(view.assignments.len(), 1);
    let a = &view.assignments[0];
    // Verify the assignment was given to agent A by name.
    // Phase 7dh.1: list_agents now requires Viewer; admin token has it.
    let agents = client
        .get(format!("{}/v1/agents", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json::<Vec<iac_core::protocol::v1::AgentSummary>>()
        .await
        .unwrap();
    let agent_a_id = agents
        .iter()
        .find(|x| x.name == "host-A")
        .unwrap()
        .agent_id
        .clone();
    assert_eq!(a.agent_id, agent_a_id);

    server.shutdown().await;
}

/// Phase 7dh.1: regression — `GET /v1/agents` without auth must
/// 401, and a wrong token must also 401. Pre-7dh this was a CRIT
/// gap (any reachable client could enumerate the fleet).
#[tokio::test]
async fn list_agents_requires_auth() {
    let server = TestServer::spawn_with_admin().await;
    let cli = reqwest::Client::new();

    let resp = cli
        .get(format!("{}/v1/agents", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = cli
        .get(format!("{}/v1/agents", server.url()))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Admin token (which carries Viewer) → 200.
    let resp = cli
        .get(format!("{}/v1/agents", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}
