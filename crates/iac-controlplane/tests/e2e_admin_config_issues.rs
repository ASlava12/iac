// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7aj: `GET /v1/admin/config-issues`. Admin-only structured
//! list of misconfigured maintenance windows. Pairs with the
//! `iac_maintenance_misconfigured_windows` gauge from Phase 7ai —
//! gauge tells operators "you have N typos", endpoint tells them
//! "here are the names + parser errors so you can fix them."

use iac_controlplane::identity::Role;
use iac_controlplane::maintenance::{
    MaintenanceMetrics, MaintenanceWindow, RecurringMaintenanceWindow,
};
use iac_controlplane::store::CreateUser;
use iac_controlplane::{Config as ServerConfig, Store, server::AppState};
use iac_core::protocol::v1::{LoginRequest, LoginResponse};
use reqwest::StatusCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "admin-issues-token";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    store: Store,
    _tempdir: TempDir,
}

async fn spawn(
    absolute: Vec<MaintenanceWindow>,
    recurring: Vec<RecurringMaintenanceWindow>,
) -> TestServer {
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
        maintenance_windows: absolute,
        recurring_maintenance_windows: recurring,
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
    // Phase 7aq: precompute the issues snapshot the same way main.rs does
    // so the endpoint serves real data through the cache path.
    let config_issues = Arc::new(iac_controlplane::maintenance::collect_config_issues(
        &cfg.maintenance_windows,
        &cfg.recurring_maintenance_windows,
    ));
    // Phase 7bx: build the live state explicitly so the test can
    // inject a non-empty config_issues vec (the production path goes
    // through `ReloadableState::new` which recomputes from config).
    let reloadable = iac_controlplane::server::ReloadableState {
        config: std::sync::Arc::new(cfg.clone()),
        config_issues,
    };
    let state = AppState {
        store: store.clone(),
        live: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(reloadable)),
        config_path: None,
        signer,
        rate_limiter: Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(
            &cfg.rate_limit,
        )),
        webhook_dispatcher: None,
        maintenance_metrics: Arc::new(MaintenanceMetrics::default()),
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
    TestServer {
        addr,
        shutdown,
        handle,
        store,
        _tempdir: dir,
    }
}

impl TestServer {
    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

fn abs_window(name: &str, start: &str, end: &str) -> MaintenanceWindow {
    MaintenanceWindow {
        name: name.into(),
        environment: "*".into(),
        start: start.into(),
        end: end.into(),
    }
}

fn rec_window(name: &str, weekdays: &[&str], start: &str, end: &str) -> RecurringMaintenanceWindow {
    RecurringMaintenanceWindow {
        name: name.into(),
        environment: "*".into(),
        weekdays: weekdays.iter().map(|s| s.to_string()).collect(),
        start_hhmm: start.into(),
        end_hhmm: end.into(),
        timezone: None,
    }
}

#[tokio::test]
async fn returns_empty_list_when_config_is_clean() {
    let server = spawn(
        vec![abs_window(
            "good",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )],
        vec![rec_window("good", &["mon"], "02:00", "04:00")],
    )
    .await;

    let r = reqwest::Client::new()
        .get(format!("{}/v1/admin/config-issues", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    let issues = body["maintenance"].as_array().unwrap();
    assert!(issues.is_empty(), "got: {body}");

    server.shutdown().await;
}

#[tokio::test]
async fn lists_misconfigured_entries_with_kind_name_error() {
    let server = spawn(
        vec![
            abs_window("good", "2026-05-01T02:00:00Z", "2026-05-01T04:00:00Z"),
            abs_window("bad-start", "not-a-time", "2026-05-01T04:00:00Z"),
            abs_window("inverted", "2026-05-01T04:00:00Z", "2026-05-01T02:00:00Z"),
        ],
        vec![
            rec_window("good", &["mon"], "02:00", "04:00"),
            rec_window("bad-day", &["munday"], "02:00", "04:00"),
        ],
    )
    .await;

    let r = reqwest::Client::new()
        .get(format!("{}/v1/admin/config-issues", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    let issues = body["maintenance"].as_array().unwrap();
    assert_eq!(issues.len(), 3, "got: {body}");

    // Order: absolute first (in config order), then recurring.
    assert_eq!(issues[0]["kind"], "maintenance_window");
    assert_eq!(issues[0]["name"], "bad-start");
    assert!(
        issues[0]["error"].as_str().unwrap().contains("bad start"),
        "got: {body}"
    );
    assert_eq!(issues[1]["kind"], "maintenance_window");
    assert_eq!(issues[1]["name"], "inverted");
    assert!(
        issues[1]["error"]
            .as_str()
            .unwrap()
            .contains("end must be > start"),
        "got: {body}"
    );
    assert_eq!(issues[2]["kind"], "recurring_maintenance_window");
    assert_eq!(issues[2]["name"], "bad-day");
    assert!(
        issues[2]["error"]
            .as_str()
            .unwrap()
            .contains("unknown weekday"),
        "got: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn admin_only() {
    let server = spawn(vec![], vec![]).await;

    // Unauthenticated → 401.
    let r = reqwest::Client::new()
        .get(format!("{}/v1/admin/config-issues", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // Operator role → 403.
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    let token = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "op".into(),
            password: "p".into(),
        })
        .send()
        .await
        .unwrap()
        .json::<LoginResponse>()
        .await
        .unwrap()
        .token;
    let r = reqwest::Client::new()
        .get(format!("{}/v1/admin/config-issues", server.url()))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    server.shutdown().await;
}
