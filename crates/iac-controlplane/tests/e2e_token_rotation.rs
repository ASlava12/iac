// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7cc: agent token TTL + explicit rotation.
//!
//! Pre-7cc agent tokens were long-lived bearer secrets — once issued,
//! valid forever. This phase adds optional TTL via
//! `[server].agent_token_ttl_secs` and an explicit rotate endpoint
//! `POST /v1/agents/{id}/rotate-token`. Backwards compat is preserved
//! through grandfathered NULL `token_expires_at` for existing agents
//! and a None default for the config field.

use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{HeartbeatRequest, RegisterRequest, RegisterResponse, AgentHealth};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "token-rotation-admin";

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
}

async fn register_via_api(server: &TestServer) -> RegisterResponse {
    reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm-1".into(),
            environment: "prod".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn heartbeat(server: &TestServer, agent_id: &str, token: &str) -> StatusCode {
    reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{agent_id}/heartbeat",
            server.url()
        ))
        .bearer_auth(token)
        .json(&HeartbeatRequest {
            status: AgentHealth::Healthy,
            managed: 0,
            open_drifts: 0,
            last_observe_at: None,
        })
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn token_with_no_ttl_is_grandfathered() {
    // Default config (no TTL set). Tokens issued with no expiry —
    // pre-7cc behavior. Heartbeat works perpetually.
    let server = TestServer::spawn(None).await;
    let creds = register_via_api(&server).await;
    let status = heartbeat(&server, &creds.agent_id, &creds.token).await;
    assert_eq!(status, StatusCode::OK);

    // Verify DB column is NULL.
    use sqlx::Row;
    let row = sqlx::query("SELECT token_expires_at FROM agents WHERE id = ?")
        .bind(&creds.agent_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    let expires: Option<String> = row.try_get("token_expires_at").unwrap();
    assert!(expires.is_none(), "expected NULL, got {expires:?}");
    server.shutdown().await;
}

#[tokio::test]
async fn token_with_ttl_works_when_fresh() {
    // TTL set to 1 hour. Fresh token works.
    let server = TestServer::spawn(Some(3600)).await;
    let creds = register_via_api(&server).await;
    let status = heartbeat(&server, &creds.agent_id, &creds.token).await;
    assert_eq!(status, StatusCode::OK);

    // Verify DB has expires_at populated.
    use sqlx::Row;
    let row = sqlx::query("SELECT token_expires_at FROM agents WHERE id = ?")
        .bind(&creds.agent_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    let expires: Option<String> = row.try_get("token_expires_at").unwrap();
    assert!(expires.is_some(), "expected expires_at populated");
    server.shutdown().await;
}

#[tokio::test]
async fn token_rejected_after_expiry() {
    // TTL of 60 seconds (the minimum). We don't actually wait —
    // we manually backdate the expires_at via direct DB write.
    let server = TestServer::spawn(Some(60)).await;
    let creds = register_via_api(&server).await;

    // Backdate expires_at to 1 hour ago.
    let past = (jiff::Timestamp::now() - jiff::SignedDuration::from_secs(3600))
        .to_string();
    sqlx::query("UPDATE agents SET token_expires_at = ? WHERE id = ?")
        .bind(&past)
        .bind(&creds.agent_id)
        .execute(server.store.pool())
        .await
        .unwrap();

    let status = heartbeat(&server, &creds.agent_id, &creds.token).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expired token must be rejected"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn rotate_endpoint_issues_new_valid_token() {
    let server = TestServer::spawn(Some(3600)).await;
    let creds = register_via_api(&server).await;
    let original_token = creds.token.clone();

    // Rotate.
    let resp: RegisterResponse = reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/rotate-token",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&original_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.agent_id, creds.agent_id);
    assert_ne!(resp.token, original_token, "rotate must issue a new token");

    // New token works.
    let status = heartbeat(&server, &creds.agent_id, &resp.token).await;
    assert_eq!(status, StatusCode::OK);

    // Old token now rejected — hash was overwritten.
    let status_old = heartbeat(&server, &creds.agent_id, &original_token).await;
    assert_eq!(
        status_old,
        StatusCode::UNAUTHORIZED,
        "old token must be invalid after rotation"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_requires_valid_current_token() {
    let server = TestServer::spawn(Some(3600)).await;
    let creds = register_via_api(&server).await;

    // Rotate with bogus token → 401.
    let status = reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/rotate-token",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth("not-the-token")
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_with_expired_token_rejected() {
    // Operators wanting to rotate must do it before expiry. Once
    // expired, they have to re-register.
    let server = TestServer::spawn(Some(3600)).await;
    let creds = register_via_api(&server).await;

    // Backdate expires_at.
    let past = (jiff::Timestamp::now() - jiff::SignedDuration::from_secs(3600))
        .to_string();
    sqlx::query("UPDATE agents SET token_expires_at = ? WHERE id = ?")
        .bind(&past)
        .bind(&creds.agent_id)
        .execute(server.store.pool())
        .await
        .unwrap();

    let status = reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/rotate-token",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&creds.token)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expired token can't self-renew"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn rotation_extends_expiry_to_new_ttl() {
    // After rotation, the new token's expiry should be roughly now+TTL,
    // not just inherited from the original token.
    let server = TestServer::spawn(Some(3600)).await;
    let creds = register_via_api(&server).await;

    // Read original expiry.
    use sqlx::Row;
    let row = sqlx::query("SELECT token_expires_at FROM agents WHERE id = ?")
        .bind(&creds.agent_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    let original_exp: String = row.try_get::<Option<String>, _>("token_expires_at").unwrap().unwrap();
    let original_ts: jiff::Timestamp = original_exp.parse().unwrap();

    // Wait a tick (test only verifies "extended", not exact delta).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let _new: RegisterResponse = reqwest::Client::new()
        .post(format!(
            "{}/v1/agents/{}/rotate-token",
            server.url(),
            creds.agent_id
        ))
        .bearer_auth(&creds.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let row = sqlx::query("SELECT token_expires_at FROM agents WHERE id = ?")
        .bind(&creds.agent_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    let new_exp: String = row.try_get::<Option<String>, _>("token_expires_at").unwrap().unwrap();
    let new_ts: jiff::Timestamp = new_exp.parse().unwrap();
    assert!(
        new_ts > original_ts,
        "new expiry {new_ts} must be after original {original_ts}"
    );
    server.shutdown().await;
}
