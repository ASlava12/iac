// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7cd: agent auto-rotation. The agent's `Client` exposes
//! `token_seconds_until_expiry`, `rotate_token`, and `rotate_if_needed`.
//! These tests validate them against a live server.

use iac_agent::remote::Client;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{AgentHealth, HeartbeatRequest, RegisterRequest};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "auto-rotation-admin";

struct TestServer {
    addr: SocketAddr,
    store: Store,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(token_ttl_secs: Option<u64>) -> Self {
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
            agent_token_ttl_secs: token_ttl_secs,
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
}

#[tokio::test]
async fn identity_persists_expires_at_when_ttl_configured() {
    // TTL configured → register response carries expires_at →
    // identity file persists it.
    let server = TestServer::spawn(Some(3600)).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();

    assert!(
        client.identity().token_expires_at.is_some(),
        "identity must carry expires_at when TTL configured"
    );
    let secs_left = client.token_seconds_until_expiry().unwrap();
    assert!(secs_left > 3500 && secs_left <= 3600, "got: {secs_left}");

    // identity.json on disk also has it.
    let on_disk: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&identity_file).unwrap(),
    )
    .unwrap();
    assert!(on_disk["token_expires_at"].is_string());

    server.shutdown().await;
}

#[tokio::test]
async fn identity_skips_expires_at_when_grandfathered() {
    // No TTL → server returns null in expires_at; identity file stores
    // None. Agent's seconds-until-expiry returns None.
    let server = TestServer::spawn(None).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();

    assert!(client.identity().token_expires_at.is_none());
    assert_eq!(client.token_seconds_until_expiry(), None);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_token_swaps_identity_in_memory_and_on_disk() {
    let server = TestServer::spawn(Some(3600)).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();
    let original_token = client.identity().token.clone();

    // Wait a moment so the new expiry is observably different.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    client.rotate_token(&identity_file).await.unwrap();

    // In-memory identity changed.
    assert_ne!(client.identity().token, original_token);
    // Heartbeat with the NEW token works.
    let resp = client
        .heartbeat(AgentHealth::Healthy, 0, 0, None)
        .await;
    assert!(resp.is_ok(), "heartbeat after rotate: {resp:?}");

    // On-disk identity also has the new token.
    let on_disk: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&identity_file).unwrap(),
    )
    .unwrap();
    assert_eq!(on_disk["token"], client.identity().token);
    // Old token now rejected by the server.
    let bogus_resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/heartbeat",
            server.url(),
            client.identity().agent_id
        ))
        .bearer_auth(&original_token)
        .json(&HeartbeatRequest {
            status: AgentHealth::Healthy,
            managed: 0,
            open_drifts: 0,
            last_observe_at: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(bogus_resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_if_needed_no_op_when_far_from_expiry() {
    // 1 hour TTL, safety margin 60s → fresh token has ~3600s left,
    // nowhere near rotation. Returns Ok(None).
    let server = TestServer::spawn(Some(3600)).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();
    let token_before = client.identity().token.clone();

    let result = client.rotate_if_needed(&identity_file, 60).await.unwrap();
    assert!(result.is_none(), "no rotation when far from expiry");
    // Token unchanged.
    assert_eq!(client.identity().token, token_before);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_if_needed_rotates_when_near_expiry() {
    // 1 hour TTL but safety margin is 4000s (> remaining ~3600s) →
    // immediate rotation triggered.
    let server = TestServer::spawn(Some(3600)).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();
    let token_before = client.identity().token.clone();

    let result = client.rotate_if_needed(&identity_file, 4000).await.unwrap();
    assert!(result.is_some(), "rotation must trigger");
    assert_ne!(client.identity().token, token_before);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_if_needed_no_op_for_grandfathered_token() {
    // Grandfathered (no TTL) → seconds_until_expiry None → never
    // rotate, no matter the safety margin.
    let server = TestServer::spawn(None).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();
    let token_before = client.identity().token.clone();

    // Even with absurd safety margin, no rotation for grandfathered.
    let result = client.rotate_if_needed(&identity_file, 999_999).await.unwrap();
    assert!(result.is_none());
    assert_eq!(client.identity().token, token_before);

    server.shutdown().await;
}

#[tokio::test]
async fn server_audit_log_records_rotation_with_actor() {
    // Verify the rotation goes through the audit log as
    // `agent.token_rotated` with the agent's id as actor — operators
    // need this for compliance traceability.
    let server = TestServer::spawn(Some(3600)).await;
    let dir = TempDir::new().unwrap();
    let identity_file = dir.path().join("identity.json");

    let mut client = Client::connect(
        &server.url(),
        &identity_file,
        RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        },
    )
    .await
    .unwrap();
    client.rotate_token(&identity_file).await.unwrap();

    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT actor, kind FROM audit_events
         WHERE kind = 'agent.token_rotated' AND agent_id = ?",
    )
    .bind(&client.identity().agent_id)
    .fetch_all(server.store.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "expected one rotation event");
    let actor: String = rows[0].try_get("actor").unwrap();
    assert!(actor.starts_with("agent:"), "actor: {actor}");

    server.shutdown().await;
}
