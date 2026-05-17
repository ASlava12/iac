// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7br: outbound `Retry-After` header format. Default is
//! `delta-seconds` (numeric); operators can opt into RFC 7231
//! `HTTP-date` (IMF-fixdate) via `[server].retry_after_format =
//! "http-date"`. The middleware translates at response-emit time so
//! handlers stay format-agnostic.

use iac_controlplane::config::RetryAfterFormat;
use iac_controlplane::rate_limit::{RateLimitConfig, RateLimiter};
use iac_controlplane::{server::AppState, Config as ServerConfig, Store};
use iac_core::protocol::v1::{RegisterRequest, SubmitOperationRequest};
use reqwest::StatusCode;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

const ADMIN_TOKEN: &str = "retry-after-admin";

struct TestServer {
    addr: SocketAddr,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
    _tempdir: TempDir,
}

impl TestServer {
    async fn spawn(format: RetryAfterFormat) -> Self {
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
            // 1 op per minute → second submit blocks with 429.
            rate_limit: RateLimitConfig {
                operations_per_minute: Some(1),
                agent_requests_per_minute: None, ..Default::default()
            },
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            webhooks: iac_controlplane::webhook::WebhooksConfig::default(),
            tls: iac_controlplane::tls::TlsConfig::default(),
            secrets: iac_controlplane::config::SecretsConfig::default(),
            retry_after_format: format,
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
            rate_limiter: Arc::new(RateLimiter::from_config(&cfg.rate_limit)),
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
        Self { addr, shutdown, handle, _tempdir: dir }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }

    async fn register_agent(&self, name: &str, env: &str) {
        reqwest::Client::new()
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
    }

    async fn submit(&self, env: &str, name: &str) -> reqwest::Response {
        reqwest::Client::new()
            .post(format!("{}/v1/operations", self.url()))
            .bearer_auth(ADMIN_TOKEN)
            .json(&SubmitOperationRequest {
                environment: env.into(),
                requested_by: "alice".into(),
                source_commit: None,
                summary: None,
                resources: vec![json!({
                    "apiVersion": "iac.example/v1",
                    "kind": "file",
                    "metadata": { "name": name, "environment": env },
                    "spec": {
                        "path": format!("/tmp/{name}.txt"),
                        "state": "present",
                        "content": "x"
                    }
                })], canary: None,
            })
            .send()
            .await
            .unwrap()
    }
}

async fn trip_rate_limit_and_capture_header(format: RetryAfterFormat) -> String {
    let server = TestServer::spawn(format).await;
    server.register_agent("vm", "ops").await;
    // First op consumes the quota.
    let r = server.submit("ops", "first").await;
    assert_eq!(r.status(), StatusCode::OK);
    // Second op trips the limit → 429 with Retry-After.
    let r = server.submit("ops", "second").await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let header = r
        .headers()
        .get("retry-after")
        .expect("Retry-After header set")
        .to_str()
        .expect("Retry-After is ASCII")
        .to_string();
    server.shutdown().await;
    header
}

#[tokio::test]
async fn default_format_emits_delta_seconds() {
    // Pre-7br behavior: numeric delta-seconds. Test guards against
    // accidental flip in default behavior.
    let header = trip_rate_limit_and_capture_header(RetryAfterFormat::default()).await;
    let secs: i64 = header
        .parse()
        .unwrap_or_else(|_| panic!("default format must be numeric, got {header:?}"));
    assert!(secs > 0 && secs <= 60, "delta-seconds out of range: {secs}");
}

#[tokio::test]
async fn http_date_format_emits_imf_fixdate() {
    // HttpDate mode: header value is the IMF-fixdate form per RFC
    // 7231 §7.1.3. Format: "Sun, 06 Nov 1994 08:49:37 GMT".
    let header = trip_rate_limit_and_capture_header(RetryAfterFormat::HttpDate).await;
    // Numeric form must be absent — the middleware should have
    // rewritten it.
    assert!(
        header.parse::<i64>().is_err(),
        "HttpDate mode must NOT emit numeric form, got {header:?}"
    );
    // Trailing GMT marker per IMF-fixdate.
    assert!(
        header.ends_with(" GMT"),
        "IMF-fixdate must end with ' GMT', got {header:?}"
    );
    // Parse it back through the same parser the dispatcher uses for
    // inbound `Retry-After` (Phase 7au) — proves the format is one we
    // can round-trip.
    let now = jiff::Timestamp::now();
    let parsed = iac_controlplane::webhook::parse_retry_after(&header, now)
        .expect("emitted IMF-fixdate must parse via Phase 7au inbound parser");
    // Should be roughly the original delta (within 5s for clock
    // jitter / network latency).
    assert!(
        parsed <= 65,
        "round-trip seconds outside expected range: {parsed} (header was {header:?})"
    );
}
