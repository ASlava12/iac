// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7d: must-keep-admin guard. Operators can no longer disable or
//! demote the last active admin via the user CRUD endpoints. The legacy
//! `admin_token` is intentionally NOT counted toward "active admins" —
//! relying on it for break-glass is fine, but the user-side guarantee
//! has to hold without it.

use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{LoginRequest, LoginResponse, UpdateUserRequest, UserView};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "guard-admin";

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

    async fn list_users(&self, bearer: &str) -> Vec<UserView> {
        reqwest::Client::new()
            .get(format!("{}/v1/users", self.url()))
            .bearer_auth(bearer)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn cannot_disable_last_active_admin_via_delete() {
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;
    let alice_token = server.login("alice", "p").await.token;

    // Alice is the only active admin (legacy token doesn't count).
    let r = reqwest::Client::new()
        .delete(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(&alice_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // Alice still listed as active.
    let users = server.list_users(ADMIN_TOKEN).await;
    let alice = users.iter().find(|u| u.id == alice_id).unwrap();
    assert!(alice.disabled_at.is_none());

    server.shutdown().await;
}

#[tokio::test]
async fn cannot_disable_last_active_admin_via_patch() {
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;

    // Same outcome through PATCH disabled=true.
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            disabled: Some(true),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn cannot_demote_last_active_admin() {
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;

    // Drop Admin → only Viewer left → would leave zero active admins.
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["viewer".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn can_demote_one_admin_when_another_remains() {
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;
    let _bob_id = server.make_user("bob", "p", vec![Role::Admin]).await;

    // Two admins active → demoting Alice is fine.
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["operator".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Now demoting Bob fails — he's the only one left.
    let users = server.list_users(ADMIN_TOKEN).await;
    let bob = users.iter().find(|u| u.username == "bob").unwrap();
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob.id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["viewer".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn disabled_admins_dont_count_toward_quorum() {
    // Alice is active admin. Bob is a disabled admin (his Admin role
    // still in roles_json, but disabled_at set). Bob shouldn't keep
    // Alice from being demoted… wait, NO — disabling Alice would still
    // leave zero active admins because Bob is disabled. The guard MUST
    // hold.
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;
    let bob_id = server.make_user("bob", "p", vec![Role::Admin]).await;

    // Disable bob first (still 2 admins → 1 admin transition is OK).
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            disabled: Some(true),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Now Alice is the only active admin. Trying to disable her must
    // fail even though Bob still has Admin in his roles_json.
    let r = reqwest::Client::new()
        .delete(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn re_enable_disabled_admin_restores_quorum() {
    // Two admins, disable one. Try to disable the other (rejected).
    // Re-enable the first and the second can now be demoted.
    let server = TestServer::spawn().await;
    let alice_id = server.make_user("alice", "p", vec![Role::Admin]).await;
    let bob_id = server.make_user("bob", "p", vec![Role::Admin]).await;

    // Disable bob.
    reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            disabled: Some(true),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();

    // Disabling alice now should fail — alice is the only active admin.
    let r = reqwest::Client::new()
        .delete(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // Re-enable bob → quorum is back.
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            disabled: Some(false),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Now alice can be demoted (bob is the remaining admin).
    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), alice_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["viewer".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn promoting_a_user_to_admin_works_normally() {
    // Ensure the guard isn't blocking *promotions*.
    let server = TestServer::spawn().await;
    let _alice = server.make_user("alice", "p", vec![Role::Admin]).await;
    let bob_id = server.make_user("bob", "p", vec![Role::Operator]).await;

    let r = reqwest::Client::new()
        .patch(format!("{}/v1/users/{}", server.url(), bob_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["admin".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}
