use crate::api;
use crate::config::{Config, RetryAfterFormat};
use crate::maintenance::{ConfigIssue, MaintenanceMetrics, compute_config_issues};
use crate::rate_limit::RateLimiter;
use crate::secrets::SecretRegistry;
use crate::signing::ServerSigner;
use crate::store::Store;
use crate::webhook::WebhookDispatcher;
use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

/// Phase 7bx: live state that gets atomically swapped on SIGHUP. Holds
/// fields that are derived from config and need to stay coherent —
/// readers grab a single `Arc<ReloadableState>` snapshot via
/// `state.live.load_full()` and use it for the duration of one
/// request. SIGHUP rebuilds a new `ReloadableState` and atomically
/// replaces the inner pointer; in-flight requests keep their
/// pre-swap snapshot.
///
/// Fields that DON'T live here (and need a server restart to change):
///   - `bind`, `database_url`, `state_dir`, `max_body_bytes` — wire
///     into the listener / store / body limit at startup.
///   - `webhooks` — drives the background dispatcher's in-memory
///     cursors, which can't be rebuilt without losing position.
///   - `tls`, `admin_token`, `secrets` — change with care, restart.
///
/// Note: `rate_limit` IS hot-reloaded despite owning background state.
/// `reload_config` calls `RateLimiter::apply_config` so the caps
/// (held in `AtomicU32`s) swap in place while per-bucket history
/// survives — see `reload_config` below.
///
/// Soft-reloadable:
///   - `policies`, `maintenance_windows`, `recurring_maintenance_windows`,
///     `retention`, `modules`, `retry_after_format` — read on each
///     request, swapping is safe.
#[derive(Debug)]
pub struct ReloadableState {
    pub config: Arc<Config>,
    pub config_issues: Arc<Vec<ConfigIssue>>,
}

impl ReloadableState {
    pub fn new(config: Arc<Config>) -> Self {
        let config_issues = Arc::new(compute_config_issues(&config));
        Self {
            config,
            config_issues,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub store: Store,
    /// Phase 7bx: hot-swappable live state. Readers do
    /// `state.live.load_full()` to grab a snapshot. SIGHUP swaps in
    /// a fresh `ReloadableState` built from re-read TOML.
    pub live: Arc<ArcSwap<ReloadableState>>,
    /// Path the live config was loaded from. SIGHUP re-reads this same
    /// path to pick up edits. `None` when running from a programmatic
    /// config (most tests) — those tests drive reload via
    /// `live.store(Arc::new(...))` directly.
    pub config_path: Option<PathBuf>,
    pub signer: Arc<ServerSigner>,
    /// Phase 7h: in-memory token-bucket rate limiter. `None` config →
    /// limiter disabled (default in tests + dev). Hot-reloadable
    /// (Phase 9 follow-up): the caps live in `AtomicU32`s so SIGHUP
    /// can swap them via [`RateLimiter::apply_config`] without
    /// touching per-bucket `Instant` history — operators tuning
    /// thresholds get no spurious rejection-bursts and no slate-wipe
    /// freebies for over-budget buckets.
    pub rate_limiter: Arc<RateLimiter>,
    /// Phase 7ad: shared with the webhook loop so the metrics
    /// endpoint can snapshot live counters. `None` when the server
    /// runs without the dispatcher (e.g. tests that don't need it).
    /// Not hot-reloadable — the dispatcher holds in-memory cursors.
    pub webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    /// Phase 7ag: counters for the maintenance-window submission gate.
    /// Surfaced in `/v1/metrics`. The metrics object survives reloads
    /// (per-window-name map is built from config but counts are
    /// process-lifetime cumulative).
    pub maintenance_metrics: Arc<MaintenanceMetrics>,
    /// Phase 7am: secret-resolver registry. The submit handler walks the
    /// desired-state JSON through this and substitutes every
    /// `${secret://...}` token before routing. `None` when the server runs
    /// with no resolvers configured — `${secret://...}` tokens then surface
    /// to the operator as `BadRequest`, which is the right failure mode.
    pub secret_registry: Option<Arc<SecretRegistry>>,
}

impl AppState {
    /// Phase 7bx: convenience accessor — grab a config snapshot. Each
    /// call returns the latest pointer; for handlers that read multiple
    /// fields, store the snapshot in a local var so they're consistent.
    pub fn config(&self) -> Arc<Config> {
        self.live.load_full().config.clone()
    }

    /// Phase 7bx: convenience accessor — grab a snapshot of the
    /// config-issues vec. Same caveat as `config()`.
    pub fn config_issues(&self) -> Arc<Vec<ConfigIssue>> {
        self.live.load_full().config_issues.clone()
    }

    /// Phase 7bx: re-read config from `config_path`, validate, and
    /// atomically swap the live state. Returns the path used and the
    /// number of config-issues found in the new config (for logging /
    /// SIGHUP feedback). Only soft-reloadable fields take effect —
    /// hard-reload fields require a restart.
    pub fn reload_config(&self) -> anyhow::Result<ReloadOutcome> {
        let path = self.config_path.as_deref().ok_or_else(|| {
            anyhow::anyhow!("reload_config: no config_path set; running from programmatic config")
        })?;
        let new_config = Config::load(Some(path), crate::config::Overrides::default())?;
        // Phase 9 follow-up: hot-swap rate-limit caps too. Caps live
        // in AtomicU32s now (0 = disabled); per-bucket state survives.
        self.rate_limiter.apply_config(&new_config.rate_limit);
        let new_state = Arc::new(ReloadableState::new(Arc::new(new_config)));
        let issues_count = new_state.config_issues.len();
        self.live.store(new_state);
        Ok(ReloadOutcome {
            path: path.to_path_buf(),
            config_issues: issues_count,
        })
    }
}

/// Phase 7bx: result of a successful reload. Surfaces what was
/// reloaded so SIGHUP / admin endpoints can log it.
#[derive(Debug, Clone)]
pub struct ReloadOutcome {
    pub path: PathBuf,
    pub config_issues: usize,
}

pub fn router(state: AppState) -> Router {
    // max_body_bytes is wired into the layer at startup — not hot-reloadable
    // by design (changing it mid-flight could leave queued requests stranded).
    let max = state.config().max_body_bytes;
    Router::new()
        .merge(api::health::router())
        .merge(api::agents::router())
        .merge(api::drift::router())
        .merge(api::operations::router())
        .merge(api::signing::router())
        .merge(api::audit::router())
        .merge(api::auth::router())
        .merge(api::users::router())
        .merge(api::expanders::router())
        .merge(api::metrics::router())
        .merge(api::admin::router())
        .layer(from_fn_with_state(
            state.clone(),
            retry_after_format_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(max))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Phase 7br: rewrite outbound `Retry-After` headers from delta-seconds
/// form into RFC 7231 IMF-fixdate when the operator configured
/// `retry_after_format = "http-date"`. Handlers always emit the
/// numeric form (rate_limit.rs / maintenance.rs / error.rs); this
/// middleware translates at response-emit time so handlers stay
/// format-agnostic.
///
/// The transformation is one-way: delta-seconds in → IMF-fixdate out.
/// Handlers never emit IMF-fixdate themselves, so a header that's
/// already non-numeric is passed through unchanged (defensive: future
/// code paths might emit something else).
async fn retry_after_format_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    // Phase 7bx: pull a snapshot — retry_after_format is hot-reloadable.
    let cfg = state.config();
    if cfg.retry_after_format != RetryAfterFormat::HttpDate {
        return response;
    }
    let secs = match response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
    {
        Some(s) if s >= 0 => s,
        _ => return response, // already non-numeric or negative — pass through
    };
    let now = jiff::Timestamp::now();
    let deadline = match now.checked_add(jiff::Span::new().seconds(secs)) {
        Ok(t) => t,
        Err(_) => return response, // overflow on giant secs; leave as-is
    };
    let date = format_imf_fixdate(deadline);
    if let Ok(hv) = HeaderValue::from_str(&date) {
        response.headers_mut().insert(header::RETRY_AFTER, hv);
    }
    response
}

/// Phase 7br: format a `jiff::Timestamp` as RFC 7231 IMF-fixdate
/// (`Sun, 06 Nov 1994 08:49:37 GMT`). Always GMT — IMF-fixdate is
/// fixed-zone per the RFC.
pub(crate) fn format_imf_fixdate(t: jiff::Timestamp) -> String {
    let zoned = t.to_zoned(jiff::tz::TimeZone::UTC);
    zoned.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
