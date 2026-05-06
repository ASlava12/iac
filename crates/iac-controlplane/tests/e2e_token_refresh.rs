// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7e: token refresh. `POST /v1/auth/refresh` with a valid bearer
//! issues a fresh token and revokes the old one. The new token reflects
//! the user's *current* roles, so admin role changes propagate without
//! requiring the user to re-enter their password.

use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{
    LoginRequest, LoginResponse, UpdateUserRequest,
};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "refresh-admin";

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

    async fn make_user(&self, name: &str, password: &str, roles: Vec<Role>) -> String {
        self.store
            .create_user(CreateUser { username: name, password, roles })
            .await
            .unwrap()
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

    async fn refresh(&self, token: &str) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/auth/refresh", self.url()))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
    }

    async fn whoami_via_audit(&self, token: &str) -> StatusCode {
        // GET /v1/metrics requires Viewer or higher; we use it as a probe to
        // tell whether a token is still valid (200) or revoked (401).
        // (Was /v1/audit before Phase 7co — audit now requires Approver,
        // and the tests still want to exercise Operator-level callers.)
        reqwest::Client::new()
            .get(format!("{}/v1/metrics", self.url()))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
    }
}

#[tokio::test]
async fn refresh_issues_new_token_and_revokes_old() {
    let server = TestServer::spawn().await;
    server.make_user("alice", "p", vec![Role::Operator]).await;
    let old = server.login("alice", "p").await.token;

    // Old token currently works.
    assert_eq!(server.whoami_via_audit(&old).await, StatusCode::OK);

    let resp = server.refresh(&old).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: LoginResponse = resp.json().await.unwrap();
    assert_ne!(body.token, old, "expected a fresh token");
    assert_eq!(body.roles, vec!["operator"]);

    // New token works.
    assert_eq!(server.whoami_via_audit(&body.token).await, StatusCode::OK);
    // Old token is revoked.
    assert_eq!(
        server.whoami_via_audit(&old).await,
        StatusCode::UNAUTHORIZED
    );

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_picks_up_role_changes() {
    let server = TestServer::spawn().await;
    let bob_id = server.make_user("bob", "p", vec![Role::Viewer]).await;
    let bob_token = server.login("bob", "p").await.token;

    // Admin promotes bob to approver.
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["approver".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Bob refreshes — the new token reflects approver, no password needed.
    let resp = server.refresh(&bob_token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: LoginResponse = resp.json().await.unwrap();
    assert_eq!(body.roles, vec!["approver"]);

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_rejects_disabled_user() {
    let server = TestServer::spawn().await;
    let id = server.make_user("eve", "p", vec![Role::Operator]).await;
    let eve_token = server.login("eve", "p").await.token;

    // Admin disables eve. This also revokes eve's tokens, but even if
    // we somehow had a token in hand the refresh path checks
    // disabled_at.
    let _ = reqwest::Client::new()
        .delete(format!("{}/v1/users/{}", server.url(), id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();

    let resp = server.refresh(&eve_token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_rejects_unknown_token() {
    let server = TestServer::spawn().await;

    let resp = server.refresh("totally-not-a-real-token").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_rejects_legacy_admin_token() {
    // The legacy admin_token is a static config value, not a row in
    // user_tokens. Refreshing it has no semantic meaning — refuse it.
    let server = TestServer::spawn().await;

    let resp = server.refresh(ADMIN_TOKEN).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn refresh_rejects_revoked_token() {
    let server = TestServer::spawn().await;
    server.make_user("carol", "p", vec![Role::Operator]).await;
    let token = server.login("carol", "p").await.token;

    // First refresh: succeeds, returns new token.
    let body: LoginResponse = server.refresh(&token).await.json().await.unwrap();
    assert_ne!(body.token, token);

    // Second refresh with the *original* token: should fail. The first
    // refresh revoked it.
    let resp = server.refresh(&token).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}
