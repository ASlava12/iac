// Phase 7di.4: shared test harness for the 40+ integration tests in
// `crates/iac-controlplane/tests/`. Each test file used to carry a
// near-identical 50–80-line `TestServer::spawn()` block; this module
// folds the common path into one builder and exposes the bits each
// test needs (addr, store, signer, AppState, config_path) as public
// fields. Tests with truly bespoke harness (e.g. mTLS, SSH push) keep
// their own setup — that's signal, not duplication.
//
// Usage in a test file:
//
//     mod common;
//     use common::{TestServer, ADMIN_TOKEN, client};
//
//     #[tokio::test]
//     async fn my_test() {
//         let server = TestServer::spawn().await;
//         let resp = client().get(server.url("/v1/health")).send().await.unwrap();
//         assert!(resp.status().is_success());
//         server.shutdown().await;
//     }
//
// To override config (modules, rate-limit, TLS, …) use the builder:
//
//     let server = TestServer::builder()
//         .modules(vec![my_module])
//         .agent_token_ttl_secs(60)
//         .build()
//         .await;
//
// Phase 7cz.16: integration tests are compiled as their own crates,
// so the crate-root `#[cfg_attr(test, allow(...))]` doesn't reach
// here — apply it locally.
#![allow(dead_code)] // each integration crate uses a different subset
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_controlplane::config::{RetryAfterFormat, SecretsConfig, SshTargetConfig};
use iac_controlplane::maintenance::{MaintenanceMetrics, MaintenanceWindow, RecurringMaintenanceWindow};
use iac_controlplane::modules::Module;
use iac_controlplane::policy::Policy;
use iac_controlplane::rate_limit::{RateLimitConfig, RateLimiter};
use iac_controlplane::retention::RetentionConfig;
use iac_controlplane::secrets::SecretRegistry;
use iac_controlplane::server::{router, AppState, ReloadableState};
use iac_controlplane::signing::ServerSigner;
use iac_controlplane::tls::TlsConfig;
use iac_controlplane::webhook::{WebhookDispatcher, WebhooksConfig};
use iac_controlplane::{Config, Store};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Notify;

/// Default admin token every test uses unless explicitly overridden.
/// Matches the legacy literal that ~30 of the 40 integration tests
/// already used (`"test-admin"`); the rest used a `const ADMIN_TOKEN`
/// pointing at the same string. One name now.
pub const ADMIN_TOKEN: &str = "test-admin";

/// Spawned test server bundle. Public fields so tests that need to
/// poke the DB (`store`), rotate signing keys (`signer`), or hot-
/// reload config (`state` + `config_path`) can do so without going
/// through the HTTP surface.
pub struct TestServer {
    pub addr: SocketAddr,
    pub store: Store,
    pub signer: Arc<ServerSigner>,
    pub state: AppState,
    /// Set when the test built its `Config` from disk via
    /// [`TestServerBuilder::config_path`]; otherwise `None`.
    pub config_path: Option<PathBuf>,
    pub shutdown: Arc<Notify>,
    pub handle: tokio::task::JoinHandle<()>,
    pub _tempdir: TempDir,
}

impl TestServer {
    /// Spawn a server with default config and the canonical
    /// `ADMIN_TOKEN`. For overrides, use [`TestServer::builder`].
    pub async fn spawn() -> Self {
        TestServerBuilder::default().build().await
    }

    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::default()
    }

    /// Base URL `http://127.0.0.1:<port>` (no trailing slash).
    /// Matches the dominant convention across the existing test
    /// corpus where callers build paths with `format!()`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Alias for `url()`. A handful of legacy tests use `url_base()`;
    /// keeping the name avoids mass-rename churn.
    pub fn url_base(&self) -> String {
        self.url()
    }

    /// Joined-endpoint URL. Equivalent to `format!("{}{path}", self.url())`,
    /// but reads cleanly when the path is constant.
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url())
    }

    pub async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
    }
}

/// Builder for [`TestServer`]. Every override is fluent and optional;
/// `build()` defaults match the legacy `TestServer::spawn()` shape
/// that ~30 integration test files used.
pub struct TestServerBuilder {
    admin_token: Option<String>,
    modules: Vec<Module>,
    policies: Vec<Policy>,
    rate_limit: RateLimitConfig,
    webhooks: WebhooksConfig,
    webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    maintenance_windows: Vec<MaintenanceWindow>,
    recurring_maintenance_windows: Vec<RecurringMaintenanceWindow>,
    tls: TlsConfig,
    secrets: SecretsConfig,
    secret_registry: Option<Arc<SecretRegistry>>,
    retry_after_format: RetryAfterFormat,
    agent_token_ttl_secs: Option<u64>,
    ssh_targets: Vec<SshTargetConfig>,
    /// When `Some(path)`, the builder writes the resolved Config out
    /// as TOML at `path` and the resulting `TestServer` carries the
    /// path for hot-reload tests to mutate. When `None`, no file is
    /// written and `config_path` ends up `None`.
    config_path: Option<PathBuf>,
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self {
            admin_token: Some(ADMIN_TOKEN.into()),
            modules: vec![],
            policies: vec![],
            rate_limit: RateLimitConfig::default(),
            webhooks: WebhooksConfig::default(),
            webhook_dispatcher: None,
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            tls: TlsConfig::default(),
            secrets: SecretsConfig::default(),
            secret_registry: None,
            retry_after_format: RetryAfterFormat::default(),
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
            config_path: None,
        }
    }
}

impl TestServerBuilder {
    pub fn admin_token(mut self, t: impl Into<String>) -> Self {
        self.admin_token = Some(t.into());
        self
    }

    /// Disable bearer auth entirely (rare; used by older tests that
    /// predate the admin-token gate).
    pub fn no_admin_token(mut self) -> Self {
        self.admin_token = None;
        self
    }

    pub fn modules(mut self, m: Vec<Module>) -> Self {
        self.modules = m;
        self
    }

    pub fn policies(mut self, p: Vec<Policy>) -> Self {
        self.policies = p;
        self
    }

    pub fn rate_limit(mut self, r: RateLimitConfig) -> Self {
        self.rate_limit = r;
        self
    }

    pub fn webhooks(mut self, w: WebhooksConfig) -> Self {
        self.webhooks = w;
        self
    }

    pub fn webhook_dispatcher(mut self, d: Arc<WebhookDispatcher>) -> Self {
        self.webhook_dispatcher = Some(d);
        self
    }

    pub fn maintenance_windows(mut self, w: Vec<MaintenanceWindow>) -> Self {
        self.maintenance_windows = w;
        self
    }

    pub fn recurring_maintenance_windows(
        mut self,
        w: Vec<RecurringMaintenanceWindow>,
    ) -> Self {
        self.recurring_maintenance_windows = w;
        self
    }

    pub fn tls(mut self, t: TlsConfig) -> Self {
        self.tls = t;
        self
    }

    pub fn secrets(mut self, s: SecretsConfig) -> Self {
        self.secrets = s;
        self
    }

    pub fn secret_registry(mut self, r: Arc<SecretRegistry>) -> Self {
        self.secret_registry = Some(r);
        self
    }

    pub fn retry_after_format(mut self, f: RetryAfterFormat) -> Self {
        self.retry_after_format = f;
        self
    }

    pub fn agent_token_ttl_secs(mut self, t: u64) -> Self {
        self.agent_token_ttl_secs = Some(t);
        self
    }

    pub fn ssh_targets(mut self, t: Vec<SshTargetConfig>) -> Self {
        self.ssh_targets = t;
        self
    }

    /// Write the resolved Config out as TOML at `<tempdir>/server.toml`
    /// and remember the path on the resulting `TestServer`. Used by
    /// hot-reload tests that mutate the file and SIGHUP the server.
    pub fn with_config_path(mut self) -> Self {
        // The actual path is computed in `build()` once we know the
        // tempdir; this flag just opts in. Sentinel: empty path =
        // "yes, but resolve later".
        self.config_path = Some(PathBuf::new());
        self
    }

    pub async fn build(self) -> TestServer {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("test.db");
        let cfg = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: format!("sqlite://{}?mode=rwc", db.display()),
            state_dir: dir.path().to_path_buf(),
            max_body_bytes: 1 << 20,
            admin_token: self.admin_token,
            policies: self.policies,
            retention: RetentionConfig::default(),
            rate_limit: self.rate_limit,
            maintenance_windows: self.maintenance_windows,
            recurring_maintenance_windows: self.recurring_maintenance_windows,
            webhooks: self.webhooks,
            tls: self.tls,
            secrets: self.secrets,
            retry_after_format: self.retry_after_format,
            modules: self.modules,
            agent_token_ttl_secs: self.agent_token_ttl_secs,
            ssh_targets: self.ssh_targets,
        };

        let resolved_config_path = if self.config_path.is_some() {
            let p = dir.path().join("server.toml");
            // Tests that opt in are the ones writing/reloading the
            // file; we just create it once with a stub so the path
            // exists. Real content is whatever the test writes next.
            std::fs::write(&p, b"# placeholder, hot-reload tests overwrite\n").unwrap();
            Some(p)
        } else {
            None
        };

        let store = Store::connect(&cfg.database_url).await.unwrap();
        let signer = Arc::new(ServerSigner::load_or_create(dir.path()).unwrap());
        let state = AppState {
            store: store.clone(),
            live: Arc::new(arc_swap::ArcSwap::from_pointee(ReloadableState::new(
                Arc::new(cfg.clone()),
            ))),
            config_path: resolved_config_path.clone(),
            signer: signer.clone(),
            rate_limiter: Arc::new(RateLimiter::from_config(&cfg.rate_limit)),
            webhook_dispatcher: self.webhook_dispatcher,
            maintenance_metrics: Arc::new(MaintenanceMetrics::default()),
            secret_registry: self.secret_registry,
        };
        let app = router(state.clone());

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

        TestServer {
            addr,
            store,
            signer,
            state,
            config_path: resolved_config_path,
            shutdown,
            handle,
            _tempdir: dir,
        }
    }
}

/// Plain reqwest client without any default auth. Tests that hit
/// authed endpoints add `.bearer_auth(ADMIN_TOKEN)` per request — keeps
/// the auth surface visible at the call site rather than buried in
/// helper plumbing.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}
