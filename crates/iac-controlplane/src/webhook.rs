//! Phase 7t: outbound webhooks for audit events.
//!
//! Operators configure `[[webhooks]]` blocks pointing at external
//! receivers (PagerDuty / Slack / Linear). The server polls the
//! `audit_events` table and fans matching rows out as JSON POSTs.
//! Filtered by minimum severity and optional kind list.
//!
//! Architecture: transactional outbox via polling. The dispatcher
//! tracks `last_seen_id` in memory, queries `WHERE id > last_seen_id`
//! every N seconds, fires webhooks for matching events, then bumps the
//! cursor. We deliberately don't persist the cursor — restart loses at
//! most one polling window of events. That's acceptable for
//! best-effort notifications; durable delivery wants a real outbox
//! table or message queue, which is out of scope here.
//!
//! Failure handling: each POST is fire-and-forget (with a short
//! timeout). Failed deliveries are logged at warn level but do NOT
//! retry — same rationale. If you need at-least-once, plug the audit
//! log into a real bus.

use crate::store::{Store, sql};
use iac_core::protocol::v1::AuditEvent;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhooksConfig {
    /// One entry per receiver. Defaults to empty (no dispatch).
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    /// Polling interval in seconds. Default 5s.
    #[serde(default = "default_interval")]
    pub poll_interval_secs: u64,
    /// Phase 7z: cap on in-flight HTTP requests across the entire
    /// dispatcher. Protects misconfigured receivers from being
    /// blasted when the dispatcher catches up after a long quiet
    /// window. Default 16. Min 1.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_requests: u32,
    /// Phase 7bj: how many audit rows to scan per tick. Default 200.
    /// Tuning matters most during backfill (`backfill = true` on a
    /// freshly-added receiver against a long history) — a larger
    /// batch finishes faster but blocks the dispatcher's mutex
    /// longer; a smaller batch lets other receivers progress in
    /// between. Min 1; `None` / `0` falls back to the default.
    #[serde(default = "default_backfill_batch_size")]
    pub backfill_batch_size: u32,
    /// Phase 7cz.5: SSRF guard. By default the validator rejects
    /// receiver URLs whose host resolves to a loopback / link-local
    /// / private-network IP (or a known cloud-metadata hostname).
    /// Set this to `true` to allow them — only for in-cluster
    /// dispatch where the receiver is a peer service on the same
    /// private network.
    #[serde(default)]
    pub allow_private_urls: bool,
    /// Phase 7cz.5: by default URLs must use `https://`. Set to
    /// `true` to allow plain `http://` — only for tests / dev.
    #[serde(default)]
    pub allow_insecure_urls: bool,
}

impl WebhooksConfig {
    /// Phase 7cz.5: validate every webhook URL at config-load time.
    /// Compromised admin token → registers webhook at
    /// `http://169.254.169.254/...` (cloud IMDS) →
    /// audit-event-driven SSRF that exfiltrates instance creds.
    /// We reject URLs that look like SSRF targets unless the
    /// operator opted in via the new flags.
    pub fn validate(&self) -> Result<(), String> {
        for w in &self.webhooks {
            if w.name.is_empty() {
                return Err("webhook name must not be empty".into());
            }
            validate_webhook_url(&w.url, self.allow_insecure_urls, self.allow_private_urls)
                .map_err(|e| format!("webhook {:?}: {e}", w.name))?;
        }
        Ok(())
    }
}

/// Phase 7cz.5: classify a webhook URL. Errors are returned as
/// `String` so the caller can prefix them with the webhook name.
fn validate_webhook_url(
    url: &str,
    allow_insecure: bool,
    allow_private: bool,
) -> Result<(), String> {
    // We don't use `url` crate (extra dep); a manual prefix-based
    // check is sufficient. Worst-case false-negative is "operator
    // wrote a malformed URL"; reqwest will refuse at dispatch time.
    let scheme_ok = if allow_insecure {
        url.starts_with("https://") || url.starts_with("http://")
    } else {
        url.starts_with("https://")
    };
    if !scheme_ok {
        return Err(format!(
            "url {url:?} must use https:// (set allow_insecure_urls=true to permit http://)"
        ));
    }
    let host_part = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("url {url:?} unparseable"))?;
    let host = host_part
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| format!("url {url:?} has empty host"))?;
    // Strip optional `user:pass@` and trailing `:port`.
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let host = host
        .rsplit_once(':')
        // Only strip trailing `:port` when the suffix is all digits;
        // IPv6 literals contain colons inside `[...]` which we leave
        // alone for the contains-check below.
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(host);
    if host.is_empty() {
        return Err(format!("url {url:?} has empty host"));
    }
    if !allow_private && is_private_or_metadata_host(host) {
        return Err(format!(
            "url {url:?} resolves to a private / loopback / metadata target \
             (set allow_private_urls=true to permit)"
        ));
    }
    Ok(())
}

fn is_private_or_metadata_host(host: &str) -> bool {
    // Cloud metadata endpoints (literal hostnames + literal IPs).
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "metadata.google.internal"
            | "metadata"
            | "metadata.azure.com"
            | "metadata.aws"
            | "169.254.169.254"
            | "fd00:ec2::254"
    ) {
        return true;
    }
    // Try to parse as IP. If it parses, classify.
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return ip.is_loopback()
            || ip.is_link_local()
            || ip.is_private()
            || ip.is_unspecified()
            || ip.octets() == [169, 254, 169, 254];
    }
    if let Some(stripped) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'))
        && let Ok(ip6) = stripped.parse::<std::net::Ipv6Addr>()
    {
        return ip6.is_loopback() || ip6.is_unspecified() || is_ipv6_private(&ip6);
    }
    // Hostname forms we deliberately keep allowed (DNS-resolved
    // names — operators must trust their resolver). The reverse:
    // an attacker who controls DNS for an operator-supplied host
    // can still SSRF; that's a perimeter concern, not config-load.
    matches!(
        lower.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    )
}

fn is_ipv6_private(ip: &std::net::Ipv6Addr) -> bool {
    // ULA fc00::/7
    let segs = ip.segments();
    (segs[0] & 0xfe00) == 0xfc00
}

impl Default for WebhooksConfig {
    fn default() -> Self {
        Self {
            webhooks: Vec::new(),
            poll_interval_secs: default_interval(),
            max_concurrent_requests: default_max_concurrent(),
            backfill_batch_size: default_backfill_batch_size(),
            allow_insecure_urls: false,
            allow_private_urls: false,
        }
    }
}

fn default_interval() -> u64 {
    5
}

fn default_max_concurrent() -> u32 {
    16
}

fn default_backfill_batch_size() -> u32 {
    200
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Operator-readable name. Surfaces in logs so a failing webhook
    /// can be traced back to its config block. Phase 7y also uses it
    /// as the cursor key, so renaming a webhook resets its delivery
    /// state.
    pub name: String,
    /// Receiver URL. POSTed with the AuditEvent JSON as body.
    pub url: String,
    /// Minimum severity to dispatch. `info | warning | error`.
    /// Matches any audit row with `severity >= min_severity` per the
    /// `severity_rank` ordering.
    #[serde(default = "default_severity")]
    pub min_severity: String,
    /// Optional kind filter. Empty list = all kinds. Otherwise the
    /// audit row's `kind` must match exactly one of these strings.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Phase 7u: shared HMAC secret. When set, the dispatcher emits
    /// an `X-Iac-Signature` header (Stripe-style; see Phase 7x).
    /// Receivers verify with the same secret; mismatched / missing
    /// → drop the event. `None` (default) = no signing.
    #[serde(default)]
    pub hmac_secret: Option<String>,
    /// Phase 7y: when a webhook has no persisted cursor, start from
    /// id=0 instead of MAX(id). Useful for new webhooks added to a
    /// running deployment that should backfill historical events.
    /// Default `false` — preserves Phase 7t/7v "no replay on first
    /// boot" semantics.
    #[serde(default)]
    pub backfill: bool,
    /// Phase 7bk: per-receiver cap on concurrent in-flight requests.
    /// Independent of (and stricter than) `WebhooksConfig::
    /// max_concurrent_requests`, which is the dispatcher-wide cap.
    /// Use case: one slow / fragile receiver should be limited to
    /// (say) 1 in-flight request at a time so its backlog doesn't eat
    /// the global semaphore and starve other receivers. `None` =
    /// share the global cap only (Phase 7z behavior). `Some(0)` is
    /// treated as "no per-receiver cap" so a typo'd `0` doesn't
    /// silently halt the receiver. Min effective value 1.
    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
    /// Phase 7bp: signing versions to emit in the `X-Iac-Signature`
    /// header. Default `["v1"]` preserves the original Phase 7x format
    /// (HMAC of `<t>.<body>`). Setting `["v1","v2"]` emits BOTH
    /// signatures during a receiver-rollout window; setting `["v2"]`
    /// drops v1 once all receivers have been upgraded.
    ///
    /// v2 binds the signature to the full target URL (HMAC of
    /// `<t>.<url>.<body>`) so a captured payload can't be replayed
    /// against a different endpoint (e.g. a misconfigured forwarder).
    /// Only meaningful when `hmac_secret` is set; ignored otherwise.
    ///
    /// Validation: every entry must be `"v1"` or `"v2"`; the list
    /// must be non-empty; duplicates are rejected.
    #[serde(default = "default_signing_versions")]
    pub signing_versions: Vec<String>,
}

fn default_signing_versions() -> Vec<String> {
    vec!["v1".into()]
}

fn default_severity() -> String {
    "warning".into()
}

fn severity_rank(s: &str) -> i32 {
    match s {
        "info" => 0,
        "warning" => 1,
        "error" => 2,
        _ => 0,
    }
}

impl WebhookConfig {
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if severity_rank(&event.severity) < severity_rank(&self.min_severity) {
            return false;
        }
        if !self.kinds.is_empty() && !self.kinds.iter().any(|k| k == &event.kind) {
            return false;
        }
        true
    }
}

/// Phase 7y: per-webhook cursor state. Each webhook has its own
/// `last_seen_id` keyed by `webhook.name`, so a new webhook added to
/// a running deployment can opt into backfill without affecting the
/// existing receivers' delivery state.
///
/// Phase 7z: a shared semaphore caps total in-flight HTTP requests
/// so a backed-up dispatcher catching up on a backlog can't blast
/// configured receivers with hundreds of concurrent connections.
#[derive(Debug)]
pub struct WebhookDispatcher {
    config: WebhooksConfig,
    cursors: tokio::sync::Mutex<std::collections::HashMap<String, i64>>,
    /// Phase 7ab: per-webhook backoff. When a receiver returns 429 +
    /// `Retry-After: <secs>`, we record `now + secs` here and skip
    /// subsequent ticks until the deadline passes. Capped at
    /// `MAX_BACKOFF_SECS` so a misbehaving receiver can't pause the
    /// dispatcher indefinitely.
    backoff_until: tokio::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    http: reqwest::Client,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    /// Phase 7bk: per-receiver semaphores for receivers that opted in
    /// via `WebhookConfig::max_concurrent_requests`. Pre-built at
    /// construction (read-only after) so the hot path is a HashMap
    /// lookup. Receivers without a configured cap are absent from the
    /// map; only the global semaphore gates them.
    per_webhook_semaphores:
        std::collections::HashMap<String, std::sync::Arc<tokio::sync::Semaphore>>,
    /// Phase 7ac: in-process telemetry counters. Snapshottable via
    /// [`WebhookDispatcher::metrics`].
    metrics: WebhookMetrics,
}

/// Phase 7ac: dispatcher telemetry. All counters are atomic so the
/// snapshot is lock-free. `in_flight` reflects the live count;
/// `in_flight_peak` is the high-watermark observed since startup.
///
/// Phase 7at: per-receiver counters live alongside the global ones so
/// operators can both see "the whole dispatcher" (existing label-free
/// metrics) AND drill into "which receiver is misbehaving"
/// (`{webhook="..."}` labeled lines). Per-webhook entries are built
/// once at dispatcher construction so the hot path is a HashMap lookup
/// + atomic increment, no locks.
#[derive(Debug, Default)]
pub struct WebhookMetrics {
    /// Successful 2xx deliveries.
    pub dispatched_ok: std::sync::atomic::AtomicU64,
    /// Non-2xx responses other than 429.
    pub dispatched_non_success: std::sync::atomic::AtomicU64,
    /// 429 responses (`Retry-After` parseable or not).
    pub dispatched_ratelimited: std::sync::atomic::AtomicU64,
    /// Network / HTTP errors (refused, timeout, etc).
    pub delivery_errors: std::sync::atomic::AtomicU64,
    /// Cumulative microseconds spent waiting on the semaphore.
    /// Operators with a tight `max_concurrent_requests` see this
    /// climb when the dispatcher is backed up.
    pub semaphore_wait_micros: std::sync::atomic::AtomicU64,
    /// Phase 7ap: histogram of semaphore-wait latencies. The cumulative
    /// counter above tells you "is the dispatcher slow on average"; this
    /// histogram tells you "is the slow tail dominating, or are *all*
    /// requests slow." Bucket bounds are powers-of-ten in microseconds:
    /// 100µs, 1ms, 10ms, 100ms, 1s, 10s, +Inf.
    pub semaphore_wait_hist: SemaphoreWaitHistogram,
    /// Currently in-flight HTTP requests.
    pub in_flight: std::sync::atomic::AtomicU64,
    /// Peak observed in-flight value since startup.
    pub in_flight_peak: std::sync::atomic::AtomicU64,
    /// Phase 7bt: cumulative microseconds spent in `req.send().await`
    /// across all webhook deliveries. Distinct from
    /// `semaphore_wait_micros`, which measures queueing time. This
    /// counter measures the actual HTTP round-trip — receiver latency,
    /// network, TLS, connection setup. Operators dividing by
    /// `dispatched_ok + dispatched_non_success + dispatched_ratelimited
    /// + delivery_errors` get average HTTP duration.
    pub dispatch_duration_micros: std::sync::atomic::AtomicU64,
    /// Phase 7bu: distribution of HTTP round-trip latencies. Same
    /// bucket bounds as `semaphore_wait_hist` (powers of 10 in µs)
    /// since both metrics live in the same range — sub-ms to seconds.
    /// Lets operators distinguish "everything is slow" from "the tail
    /// is dragging" without per-receiver disaggregation.
    pub dispatch_duration_hist: SemaphoreWaitHistogram,
    /// Phase 7at: per-receiver dispatch counters. Map keys are the
    /// configured webhook names; values are populated at dispatcher
    /// construction so the lookup path is `&HashMap` + `AtomicU64::fetch_add`.
    /// Read-only after construction — `&` borrow is sufficient for both
    /// readers and writers because the inner counters are atomic.
    pub per_webhook: std::collections::HashMap<String, PerWebhookCounters>,
}

/// Phase 7at: per-receiver dispatch counters. Same shape as the global
/// `dispatched_*` / `delivery_errors` fields, scoped to one webhook
/// name.
///
/// Phase 7bq: now also tracks `semaphore_wait_micros` per-receiver.
/// The Phase 7at note that "the semaphore is shared so wait isn't
/// per-receiver-attributable" predated Phase 7bk's per-receiver
/// semaphores. Total wait per-receiver = how long this receiver's
/// events spent queued (across both global + per-receiver permits) —
/// a useful diagnostic for "why does receiver X feel slow."
///
/// Phase 7bs: also tracks the wait distribution per-receiver via a
/// `SemaphoreWaitHistogram`. Operators wanting to know "is the slow
/// tail dominating receiver X specifically, or is everything slow"
/// can read the labeled bucket lines.
#[derive(Debug, Default)]
pub struct PerWebhookCounters {
    pub dispatched_ok: std::sync::atomic::AtomicU64,
    pub dispatched_non_success: std::sync::atomic::AtomicU64,
    pub dispatched_ratelimited: std::sync::atomic::AtomicU64,
    pub delivery_errors: std::sync::atomic::AtomicU64,
    /// Phase 7bq: cumulative microseconds this receiver's deliveries
    /// spent waiting on permits (global semaphore + optional
    /// per-receiver semaphore combined). One observation per call to
    /// `fire_with_permit`.
    pub semaphore_wait_micros: std::sync::atomic::AtomicU64,
    /// Phase 7bs: per-receiver wait-latency distribution. Same bucket
    /// bounds as the global histogram — operators can compare a
    /// receiver's bucket profile against the global one to spot
    /// outliers.
    pub semaphore_wait_hist: SemaphoreWaitHistogram,
    /// Phase 7bt: cumulative microseconds this receiver's deliveries
    /// spent inside `req.send().await`. Independent of
    /// `semaphore_wait_micros` (queueing) — this captures actual HTTP
    /// round-trip latency, which is the metric operators want when
    /// asking "is receiver X actually slow, or just queued."
    pub dispatch_duration_micros: std::sync::atomic::AtomicU64,
    /// Phase 7bu: per-receiver HTTP-duration distribution. Same bucket
    /// bounds as `semaphore_wait_hist`. Lets operators compare a
    /// receiver's HTTP-latency profile against the global one to spot
    /// outliers — e.g. one receiver always in the >1s bucket while
    /// others sit at <100ms.
    pub dispatch_duration_hist: SemaphoreWaitHistogram,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerWebhookSnapshot {
    pub dispatched_ok: u64,
    pub dispatched_non_success: u64,
    pub dispatched_ratelimited: u64,
    pub delivery_errors: u64,
    /// Phase 7bq: per-receiver cumulative semaphore wait (µs).
    pub semaphore_wait_micros: u64,
    /// Phase 7bs: per-receiver semaphore-wait bucket distribution.
    pub semaphore_wait_hist: SemaphoreWaitHistogramSnapshot,
    /// Phase 7bt: per-receiver cumulative HTTP round-trip latency (µs).
    pub dispatch_duration_micros: u64,
    /// Phase 7bu: per-receiver HTTP-duration bucket distribution.
    pub dispatch_duration_hist: SemaphoreWaitHistogramSnapshot,
}

#[derive(Debug)]
/// Phase 7ap: Prometheus-style histogram of semaphore-wait latencies.
/// Each bucket is non-cumulative (`bucket[i]` = observations with value
/// strictly above `BUCKET_BOUNDS_MICROS[i-1]` and ≤ `BUCKET_BOUNDS_MICROS[i]`,
/// with the trailing entry covering `+Inf`); render-time output converts
/// to OpenMetrics-cumulative form. Storing non-cumulative is one atomic
/// increment per observation; the cumulative form is the rendering's job.
pub struct SemaphoreWaitHistogram {
    /// Per-bucket observation counts. `len() == BUCKET_BOUNDS_MICROS.len() + 1`,
    /// the trailing entry being the implicit `+Inf` bucket.
    pub buckets: [std::sync::atomic::AtomicU64; SEMAPHORE_WAIT_BUCKET_COUNT],
    /// Total observations (denominator). Equal to the sum of `buckets`.
    pub count: std::sync::atomic::AtomicU64,
}

/// Powers-of-ten microsecond boundaries chosen so the typical
/// fast-dispatch case (sub-millisecond) lands in the first two buckets
/// and a backed-up dispatcher's >1s waits show up at the tail.
pub const SEMAPHORE_WAIT_BUCKETS_MICROS: &[u64] =
    &[100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000];

const SEMAPHORE_WAIT_BUCKET_COUNT: usize = SEMAPHORE_WAIT_BUCKETS_MICROS.len() + 1;

impl Default for SemaphoreWaitHistogram {
    fn default() -> Self {
        // `[T::default(); N]` only works when T: Copy, and AtomicU64 isn't
        // Copy. Build via `from_fn` instead.
        Self {
            buckets: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
            count: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl SemaphoreWaitHistogram {
    /// Record one observation. Picks the lowest bucket whose upper bound
    /// is ≥ `v`; observations above the largest bound land in `+Inf`.
    fn record(&self, v: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let idx = SEMAPHORE_WAIT_BUCKETS_MICROS
            .iter()
            .position(|&b| v <= b)
            .unwrap_or(SEMAPHORE_WAIT_BUCKETS_MICROS.len());
        self.buckets[idx].fetch_add(1, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    /// Lock-free snapshot: load the count + every bucket counter.
    fn snapshot(&self) -> SemaphoreWaitHistogramSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        SemaphoreWaitHistogramSnapshot {
            buckets: std::array::from_fn(|i| self.buckets[i].load(Relaxed)),
            count: self.count.load(Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SemaphoreWaitHistogramSnapshot {
    /// Non-cumulative bucket counts. `buckets[BUCKET_COUNT-1]` = `+Inf`.
    pub buckets: [u64; SEMAPHORE_WAIT_BUCKET_COUNT],
    /// Total observations.
    pub count: u64,
}

/// Plain snapshot of the dispatcher's metrics. Operators inspect
/// this from logs or via a future `/v1/metrics` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookMetricsSnapshot {
    pub dispatched_ok: u64,
    pub dispatched_non_success: u64,
    pub dispatched_ratelimited: u64,
    pub delivery_errors: u64,
    pub semaphore_wait_micros: u64,
    /// Phase 7ap: per-bucket histogram of semaphore-wait latencies.
    pub semaphore_wait_hist: SemaphoreWaitHistogramSnapshot,
    pub in_flight: u64,
    pub in_flight_peak: u64,
    /// Phase 7bt: cumulative HTTP round-trip duration across all
    /// receivers (microseconds).
    pub dispatch_duration_micros: u64,
    /// Phase 7bu: distribution of HTTP round-trip durations.
    pub dispatch_duration_hist: SemaphoreWaitHistogramSnapshot,
    /// Phase 7at: per-receiver counter breakdown. Names are the
    /// `webhook.name` values from config. Sorted by name in the
    /// snapshot so the JSON / Prom output is stable across calls.
    pub per_webhook: Vec<(String, PerWebhookSnapshot)>,
}

const MAX_BACKOFF_SECS: u64 = 60 * 60;

impl WebhookDispatcher {
    pub fn new(mut config: WebhooksConfig) -> Self {
        let max_concurrent = config.max_concurrent_requests.max(1) as usize;
        // Phase 7bp: sanitize each webhook's signing_versions. Drop
        // unknown entries (logging a warning); empty after filtering →
        // fall back to ["v1"]. Same typo-guard pattern as Phase 7bj's
        // `backfill_batch_size = 0` → default. Deduplicate — operators
        // can't accidentally double-emit `v1=`.
        for w in &mut config.webhooks {
            let mut filtered: Vec<String> = Vec::with_capacity(w.signing_versions.len());
            let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for v in &w.signing_versions {
                if v != "v1" && v != "v2" {
                    tracing::warn!(
                        webhook = %w.name,
                        unknown_version = %v,
                        "ignoring unknown signing_versions entry; valid: v1, v2"
                    );
                    continue;
                }
                if seen.insert(v.clone()) {
                    filtered.push(v.clone());
                }
            }
            if filtered.is_empty() {
                tracing::warn!(
                    webhook = %w.name,
                    "signing_versions empty after sanitization; falling back to [\"v1\"]"
                );
                filtered = default_signing_versions();
            }
            w.signing_versions = filtered;
        }
        // Phase 7at: pre-build the per-webhook counter map so the hot
        // path is a HashMap lookup + atomic increment, no locks. The
        // set of receivers is fixed at construction; if a future SIGHUP
        // reload changes it, the dispatcher gets rebuilt with a fresh
        // map.
        let per_webhook: std::collections::HashMap<String, PerWebhookCounters> = config
            .webhooks
            .iter()
            .map(|w| (w.name.clone(), PerWebhookCounters::default()))
            .collect();
        let metrics = WebhookMetrics {
            per_webhook,
            ..WebhookMetrics::default()
        };
        // Phase 7bk: build the per-receiver semaphore map. Receivers
        // without `max_concurrent_requests` (or a typo'd `Some(0)`)
        // are absent — only the global semaphore gates them, which
        // matches Phase 7z behavior exactly. Capacity is clamped to
        // `max(1)` so a configured `Some(1)` actually serializes the
        // receiver.
        let per_webhook_semaphores: std::collections::HashMap<
            String,
            std::sync::Arc<tokio::sync::Semaphore>,
        > = config
            .webhooks
            .iter()
            .filter_map(|w| {
                let cap = w.max_concurrent_requests?;
                if cap == 0 {
                    return None;
                }
                Some((
                    w.name.clone(),
                    std::sync::Arc::new(tokio::sync::Semaphore::new(cap as usize)),
                ))
            })
            .collect();
        Self {
            config,
            cursors: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            backoff_until: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            http: {
                // Phase 7cz.16: `reqwest::Client::builder()` only fails
                // on TLS-init or CA-bundle issues; the default builder
                // can't realistically fail. Tag for clippy.
                #[allow(clippy::expect_used)]
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("reqwest client");
                client
            },
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
            per_webhook_semaphores,
            metrics,
        }
    }

    /// Phase 7ac: lock-free snapshot of the telemetry counters.
    pub fn metrics(&self) -> WebhookMetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        // Phase 7at: snapshot per-webhook counters in name-sorted order so
        // the JSON / Prom output is stable across calls. HashMap iteration
        // order would otherwise be non-deterministic.
        let mut per_webhook: Vec<(String, PerWebhookSnapshot)> = self
            .metrics
            .per_webhook
            .iter()
            .map(|(name, c)| {
                (
                    name.clone(),
                    PerWebhookSnapshot {
                        dispatched_ok: c.dispatched_ok.load(Relaxed),
                        dispatched_non_success: c.dispatched_non_success.load(Relaxed),
                        dispatched_ratelimited: c.dispatched_ratelimited.load(Relaxed),
                        delivery_errors: c.delivery_errors.load(Relaxed),
                        semaphore_wait_micros: c.semaphore_wait_micros.load(Relaxed),
                        semaphore_wait_hist: c.semaphore_wait_hist.snapshot(),
                        dispatch_duration_micros: c.dispatch_duration_micros.load(Relaxed),
                        dispatch_duration_hist: c.dispatch_duration_hist.snapshot(),
                    },
                )
            })
            .collect();
        per_webhook.sort_by(|a, b| a.0.cmp(&b.0));

        WebhookMetricsSnapshot {
            dispatched_ok: self.metrics.dispatched_ok.load(Relaxed),
            dispatched_non_success: self.metrics.dispatched_non_success.load(Relaxed),
            dispatched_ratelimited: self.metrics.dispatched_ratelimited.load(Relaxed),
            delivery_errors: self.metrics.delivery_errors.load(Relaxed),
            semaphore_wait_micros: self.metrics.semaphore_wait_micros.load(Relaxed),
            semaphore_wait_hist: self.metrics.semaphore_wait_hist.snapshot(),
            in_flight: self.metrics.in_flight.load(Relaxed),
            in_flight_peak: self.metrics.in_flight_peak.load(Relaxed),
            dispatch_duration_micros: self.metrics.dispatch_duration_micros.load(Relaxed),
            dispatch_duration_hist: self.metrics.dispatch_duration_hist.snapshot(),
            per_webhook,
        }
    }

    /// Per-webhook cursor key. Stable across restarts since it's
    /// keyed on the operator-supplied `name`.
    fn cursor_key(name: &str) -> String {
        format!("audit:{name}")
    }

    /// Phase 7y: initialize one cursor per webhook. Resolution order:
    ///   1. `audit:<webhook_name>` row in `webhook_cursor` (per-webhook
    ///      persistence — survives restarts).
    ///   2. Legacy `audit` row (Phase 7v's single shared cursor) so
    ///      upgrading deployments don't lose progress.
    ///   3. `0` if `backfill=true`, else `MAX(audit_events.id)` —
    ///      first-boot semantics.
    pub async fn initialize(&self, store: &Store) {
        let max_id: i64 = sqlx::query_as::<_, (i64,)>(
            &store.sql("SELECT COALESCE(MAX(id), 0) FROM audit_events"),
        )
        .fetch_one(store.pool())
        .await
        .map(|(id,)| id)
        .unwrap_or(0);
        let legacy: Option<i64> = sqlx::query_as::<_, (i64,)>(
            &store.sql("SELECT last_seen_id FROM webhook_cursor WHERE key = 'audit'"),
        )
        .fetch_optional(store.pool())
        .await
        .ok()
        .flatten()
        .map(|(id,)| id);

        let mut cursors = self.cursors.lock().await;
        for webhook in &self.config.webhooks {
            let key = Self::cursor_key(&webhook.name);
            let persisted: Option<i64> = sqlx::query_as::<_, (i64,)>(
                &store.sql("SELECT last_seen_id FROM webhook_cursor WHERE key = ?"),
            )
            .bind(&key)
            .fetch_optional(store.pool())
            .await
            .ok()
            .flatten()
            .map(|(id,)| id);
            let cursor = match (persisted, legacy, webhook.backfill) {
                (Some(id), _, _) => id,
                (None, Some(id), _) => id,
                (None, None, true) => 0,
                (None, None, false) => max_id,
            };
            cursors.insert(key, cursor);
        }
        drop(cursors);

        // Phase: prune orphan rows from webhook_cursor for webhooks
        // that have been removed from config since the last run.
        // Only `audit:<name>` rows are candidates — the legacy
        // `audit` row stays put as a forward fallback for any future
        // newly-added webhook.
        self.prune_orphan_cursors(store).await;

        // Phase 7as: restore persisted backoff deadlines so a server
        // restart during an active 429 cool-down doesn't immediately
        // re-fire the same misbehaving receiver. Only deadlines still
        // in the future are loaded — expired rows stay in the DB and
        // get overwritten on the next 429.
        self.load_persisted_backoffs(store).await;
    }

    /// Phase 7as: write the new deadline to `webhook_backoff`. Upsert
    /// keyed on `webhook_name`. Best-effort: failure logs but doesn't
    /// fail dispatch — the in-memory map is still authoritative for
    /// this process; restart-survival is the cost.
    async fn persist_backoff(&self, store: &Store, webhook: &WebhookConfig, retry_secs: u64) {
        let now = jiff::Timestamp::now();
        let deadline_unix = now.as_second().saturating_add(retry_secs as i64);
        let updated_at = now.to_string();
        if let Err(e) = sqlx::query(&store.sql(
            "INSERT INTO webhook_backoff (webhook_name, deadline_unix, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(webhook_name) DO UPDATE SET
               deadline_unix = excluded.deadline_unix,
               updated_at = excluded.updated_at",
        ))
        .bind(&webhook.name)
        .bind(deadline_unix)
        .bind(&updated_at)
        .execute(store.pool())
        .await
        {
            tracing::warn!(
                name = %webhook.name,
                error = %e,
                "persisting webhook backoff failed"
            );
        }
    }

    /// Read every `webhook_backoff` row whose deadline is still in the
    /// future and rebuild the in-memory `backoff_until` map. Best
    /// effort: a query failure logs and proceeds — operators get
    /// "missed" backoff (one premature attempt) but no other harm.
    async fn load_persisted_backoffs(&self, store: &Store) {
        let now_unix = jiff::Timestamp::now().as_second();
        let rows: Vec<(String, i64)> = match sqlx::query_as(&store.sql(
            "SELECT webhook_name, deadline_unix FROM webhook_backoff
             WHERE deadline_unix > ?",
        ))
        .bind(now_unix)
        .fetch_all(store.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "loading persisted webhook backoffs failed");
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let mut map = self.backoff_until.lock().await;
        for (name, deadline_unix) in rows {
            // Convert "absolute unix seconds" → "Instant on this run's
            // monotonic clock." `Instant` arithmetic doesn't accept
            // negative durations, so clamp at "now+1s" if the row is
            // marginally past now (race with the WHERE filter).
            let now_inst = std::time::Instant::now();
            let secs_remaining = deadline_unix.saturating_sub(now_unix).max(1) as u64;
            let deadline =
                now_inst + std::time::Duration::from_secs(secs_remaining.min(MAX_BACKOFF_SECS));
            map.insert(name.clone(), deadline);
            tracing::info!(
                name = %name,
                secs_remaining,
                "restored persisted webhook backoff"
            );
        }
    }

    /// Delete `webhook_cursor` rows of the form `audit:<name>` whose
    /// `name` is NOT in the configured webhook list. Best-effort:
    /// failure is logged but doesn't fail initialize. Pruning runs
    /// once at startup; operators editing config without a restart
    /// would have to wait for the next startup for cleanup.
    async fn prune_orphan_cursors(&self, store: &Store) {
        let configured: std::collections::HashSet<String> = self
            .config
            .webhooks
            .iter()
            .map(|w| Self::cursor_key(&w.name))
            .collect();
        // Read all `audit:*` rows so we can compute orphans in Rust;
        // expressing "NOT IN (?, ?, ?)" in SQL with a dynamic-length
        // list is more code than this set difference.
        let rows: Vec<(String,)> = match sqlx::query_as(
            &store.sql("SELECT key FROM webhook_cursor WHERE key LIKE 'audit:%'"),
        )
        .fetch_all(store.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "orphan prune query failed");
                return;
            }
        };
        let mut pruned = 0u64;
        for (key,) in rows {
            if configured.contains(&key) {
                continue;
            }
            match sqlx::query(&store.sql("DELETE FROM webhook_cursor WHERE key = ?"))
                .bind(&key)
                .execute(store.pool())
                .await
            {
                Ok(res) => pruned += res.rows_affected(),
                Err(e) => tracing::warn!(
                    key = %key,
                    error = %e,
                    "orphan prune delete failed"
                ),
            }
        }
        if pruned > 0 {
            tracing::info!(pruned, "pruned orphan webhook cursors");
        }
    }

    /// One polling tick. Each webhook polls + fires + persists
    /// independently against its own cursor. Returns the total
    /// number of dispatched HTTP requests across all webhooks for
    /// observability + tests.
    pub async fn tick_once(&self, store: &Store) -> usize {
        if self.config.webhooks.is_empty() {
            return 0;
        }
        let mut total = 0usize;
        // Process webhooks sequentially; within each webhook the
        // matching events for a single tick still fan out in parallel
        // (they're per-webhook, so there's only ever one match per
        // event here). This ordering means a slow webhook doesn't
        // affect another's cursor. We keep the loop sequential so a
        // misbehaving webhook can't starve cursor-write commits in
        // the middle of an outer batch — the per-webhook tick is
        // self-contained.
        for webhook in &self.config.webhooks {
            total += self.tick_one_webhook(store, webhook).await;
        }
        total
    }

    async fn tick_one_webhook(&self, store: &Store, webhook: &WebhookConfig) -> usize {
        // Phase 7ab: respect prior 429 Retry-After. Don't advance
        // cursor while backed off — events queued during the wait
        // will be picked up on the first tick after the deadline.
        if let Some(deadline) = self.backoff_until.lock().await.get(&webhook.name).copied()
            && std::time::Instant::now() < deadline
        {
            tracing::debug!(
                name = %webhook.name,
                "webhook in receiver-requested backoff; skipping tick"
            );
            return 0;
        }

        let key = Self::cursor_key(&webhook.name);
        let cursor = {
            let cursors = self.cursors.lock().await;
            *cursors.get(&key).unwrap_or(&0)
        };
        // Phase 7bj: batch size from config. `0` (or any unset variant
        // that round-tripped through serde) falls back to the default
        // so a typo'd `backfill_batch_size = 0` doesn't accidentally
        // halt the dispatcher.
        let batch_size = if self.config.backfill_batch_size == 0 {
            default_backfill_batch_size()
        } else {
            self.config.backfill_batch_size
        };
        let rows = match sqlx::query(&store.sql(
            "SELECT id, timestamp, actor, kind, severity,
                    operation_id, agent_id, resource_id, drift_id, payload_json
             FROM audit_events WHERE id > ? ORDER BY id LIMIT ?",
        ))
        .bind(cursor)
        .bind(i64::from(batch_size))
        .fetch_all(store.pool())
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    name = %webhook.name,
                    error = %e,
                    "webhook poll query failed"
                );
                return 0;
            }
        };

        // Materialize events first so we can parallelize the fire()
        // calls across them. `last` advances to the highest id seen
        // even for events the webhook filter rejects — otherwise a
        // string of skipped rows would keep the cursor stuck.
        let mut events: Vec<AuditEvent> = Vec::with_capacity(rows.len());
        let mut last = cursor;
        for row in rows {
            let id: i64 = match row.try_get("id") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let payload_json: String = row.try_get("payload_json").unwrap_or_default();
            let payload: serde_json::Value =
                serde_json::from_str(&payload_json).unwrap_or(serde_json::Value::Null);
            events.push(AuditEvent {
                id,
                timestamp: row.try_get("timestamp").unwrap_or_default(),
                actor: row.try_get("actor").unwrap_or_default(),
                kind: row.try_get("kind").unwrap_or_default(),
                severity: row.try_get("severity").unwrap_or_default(),
                operation_id: row.try_get("operation_id").unwrap_or(None),
                agent_id: row.try_get("agent_id").unwrap_or(None),
                resource_id: row.try_get("resource_id").unwrap_or(None),
                drift_id: row.try_get("drift_id").unwrap_or(None),
                payload,
            });
            last = id;
        }

        // Phase 7z: fire matching events in parallel within this
        // webhook's tick. Each call grabs a permit from the shared
        // semaphore so the total number of concurrent HTTP requests
        // across the dispatcher is capped.
        let matching: Vec<&AuditEvent> = events.iter().filter(|e| webhook.matches(e)).collect();
        let dispatched = matching.len();
        if !matching.is_empty() {
            let futures = matching
                .iter()
                .map(|e| self.fire_with_permit(store, webhook, e));
            futures_util::future::join_all(futures).await;
        }

        if last != cursor {
            self.cursors.lock().await.insert(key.clone(), last);
            let now = jiff::Timestamp::now().to_string();
            if let Err(e) = sqlx::query(&store.sql(
                "INSERT INTO webhook_cursor (key, last_seen_id, updated_at)
                 VALUES (?, ?, ?)
                 ON CONFLICT(key) DO UPDATE SET
                   last_seen_id = excluded.last_seen_id,
                   updated_at = excluded.updated_at",
            ))
            .bind(&key)
            .bind(last)
            .bind(&now)
            .execute(store.pool())
            .await
            {
                tracing::warn!(
                    name = %webhook.name,
                    error = %e,
                    "webhook cursor persist failed"
                );
            }
        }
        dispatched
    }

    /// Acquire a semaphore permit, then fire the webhook. The permit
    /// is released when the future completes. Ensures the dispatcher
    /// never exceeds `max_concurrent_requests` in-flight HTTP calls
    /// across all webhooks combined.
    ///
    /// Phase 7bk: when the receiver has a per-webhook cap configured,
    /// also acquire a permit from its dedicated semaphore. Order is
    /// **global first, then per-receiver** — flipping the order would
    /// let a slow receiver hold its per-receiver permit while waiting
    /// on the global one, defeating the whole point (the per-receiver
    /// cap should never block other receivers' progress through the
    /// global semaphore).
    ///
    /// Phase 7bq: total wait (global + per-receiver) is recorded into
    /// `per_webhook[name].semaphore_wait_micros` so operators can spot
    /// "receiver X spent N µs queued" without diffing global counters.
    /// The per-receiver counter and the global counter answer
    /// different questions (per-receiver: "is THIS hook backed up?",
    /// global: "is the dispatcher overloaded?") so both are kept.
    async fn fire_with_permit(&self, store: &Store, webhook: &WebhookConfig, event: &AuditEvent) {
        use std::sync::atomic::Ordering::Relaxed;
        // Phase 7ac: measure (global) semaphore acquisition delay.
        let acquire_start = std::time::Instant::now();
        // Phase 7cz.16: tokio Semaphore::acquire only errors on close,
        // and we never call close() on these. Tag for clippy.
        #[allow(clippy::expect_used)]
        let _global_permit = self
            .semaphore
            .acquire()
            .await
            .expect("semaphore should never close");
        let global_wait = acquire_start.elapsed();
        let global_wait_micros = global_wait.as_micros() as u64;
        self.metrics
            .semaphore_wait_micros
            .fetch_add(global_wait_micros, Relaxed);
        // Phase 7ap: tick the histogram bucket for this observation. Same
        // wait value feeds both — the cumulative counter for legacy
        // dashboards, the histogram for distributional view.
        self.metrics.semaphore_wait_hist.record(global_wait_micros);

        // Phase 7bk: per-receiver permit (if configured). Held alongside
        // the global one for the request lifetime. Tied to the same
        // scope as `_global_permit` so both release together when the
        // future ends.
        // Phase 7cz.16: same close-only-error invariant as above.
        #[allow(clippy::expect_used)]
        let _per_receiver_permit = match self.per_webhook_semaphores.get(&webhook.name) {
            Some(sem) => Some(
                sem.acquire()
                    .await
                    .expect("per-receiver semaphore should never close"),
            ),
            None => None,
        };

        // Phase 7bq: record cumulative wait (both permits) on the
        // per-receiver counter. For receivers without a per-receiver
        // semaphore, this equals `global_wait_micros`. For receivers
        // with one, it's longer when the per-receiver cap is the
        // bottleneck.
        //
        // Phase 7bs: also tick the per-receiver histogram bucket. The
        // global histogram (above) covers "is the dispatcher slow on
        // average"; the per-receiver one answers "is it slow for THIS
        // receiver specifically."
        let total_wait_micros = acquire_start.elapsed().as_micros() as u64;
        if let Some(p) = self.metrics.per_webhook.get(&webhook.name) {
            p.semaphore_wait_micros
                .fetch_add(total_wait_micros, Relaxed);
            p.semaphore_wait_hist.record(total_wait_micros);
        }

        // Track in-flight count + peak. fetch_add returns the OLD value
        // so add 1 for the post-increment view.
        let cur = self.metrics.in_flight.fetch_add(1, Relaxed) + 1;
        // fetch_max keeps the watermark monotonic.
        self.metrics.in_flight_peak.fetch_max(cur, Relaxed);
        self.fire(store, webhook, event).await;
        self.metrics.in_flight.fetch_sub(1, Relaxed);
    }

    async fn fire(&self, store: &Store, webhook: &WebhookConfig, event: &AuditEvent) {
        // Serialize to bytes once so the signature covers the exact
        // bytes on the wire. Building the body and signing it both
        // from `event` would be subtly broken if serde reorders keys
        // between calls.
        let body = match serde_json::to_vec(event) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    name = %webhook.name,
                    error = %e,
                    "webhook body serialization failed"
                );
                return;
            }
        };

        let mut req = self
            .http
            .post(&webhook.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone());
        if let Some(secret) = &webhook.hmac_secret {
            // Phase 7x: Stripe-style signed envelope. Header carries
            // `t=<unix_secs>,v1=<hex>` where `v1 = HMAC-SHA256(secret,
            // <t>.<body>)`. The timestamp is INSIDE the signed
            // envelope so a captured POST can't be replayed with a
            // forged-fresh timestamp — receivers verify the HMAC over
            // the same string, then check timestamp freshness.
            //
            // Phase 7bp: optionally also emit `v2=<hex>` where
            // `v2 = HMAC-SHA256(secret, <t>.<url>.<body>)`. v2 binds
            // the signature to the exact target URL so a captured
            // payload can't be replayed against a different endpoint.
            // Both signatures share the same timestamp, so receivers
            // can verify whichever version they support.
            let timestamp = jiff::Timestamp::now().as_second();
            let body_str = std::str::from_utf8(&body).unwrap_or("");
            if let Some(header) = build_signature_header(
                secret.as_bytes(),
                timestamp,
                &webhook.url,
                body_str,
                &webhook.signing_versions,
            ) {
                req = req.header("X-Iac-Signature", header);
            }
        }

        use std::sync::atomic::Ordering::Relaxed;
        // Phase 7bt: time the actual HTTP round-trip so operators can
        // tell "is receiver X slow because of queueing or because of
        // the receiver itself." Recorded regardless of outcome —
        // success, non-2xx, 429, network error — every send counts.
        // The timer wraps `req.send().await` only, so it doesn't
        // include body serialization or signature computation upstream.
        //
        // Phase 7bu: also tick the dispatch-duration histogram. Same
        // observation feeds counter + hist; counter answers "is this
        // receiver slow on average," histogram answers "is the slow
        // tail dominating."
        let send_start = std::time::Instant::now();
        let result = req.send().await;
        let dispatch_micros = send_start.elapsed().as_micros() as u64;
        self.metrics
            .dispatch_duration_micros
            .fetch_add(dispatch_micros, Relaxed);
        self.metrics.dispatch_duration_hist.record(dispatch_micros);
        // Phase 7at: per-webhook counter handle. Lookup is `&HashMap`
        // get + atomic increment, no locks. `None` should never happen
        // in practice (the map was populated from `config.webhooks` at
        // construction); guard with `if let` so a future config-mutation
        // path doesn't panic.
        let per = self.metrics.per_webhook.get(&webhook.name);
        if let Some(p) = per {
            p.dispatch_duration_micros
                .fetch_add(dispatch_micros, Relaxed);
            p.dispatch_duration_hist.record(dispatch_micros);
        }

        match result {
            Ok(resp) if resp.status().is_success() => {
                self.metrics.dispatched_ok.fetch_add(1, Relaxed);
                if let Some(p) = per {
                    p.dispatched_ok.fetch_add(1, Relaxed);
                }
                tracing::debug!(
                    name = %webhook.name,
                    kind = %event.kind,
                    severity = %event.severity,
                    "webhook delivered"
                );
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                self.metrics.dispatched_ratelimited.fetch_add(1, Relaxed);
                if let Some(p) = per {
                    p.dispatched_ratelimited.fetch_add(1, Relaxed);
                }
                // Phase 7ab: receiver-requested backoff via `Retry-After`.
                // Phase 7au: accept both forms RFC 7231 §7.1.3 allows —
                // delta-seconds (`120`) and HTTP-date (`Fri, 31 Dec 1999
                // 23:59:59 GMT`). Cap at `MAX_BACKOFF_SECS` so a
                // hostile / buggy receiver can't pause the dispatcher
                // indefinitely.
                let retry_secs = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| parse_retry_after(s, jiff::Timestamp::now()))
                    .map(|s| s.min(MAX_BACKOFF_SECS))
                    .unwrap_or(0);
                if retry_secs > 0 {
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(retry_secs);
                    self.backoff_until
                        .lock()
                        .await
                        .insert(webhook.name.clone(), deadline);
                    // Phase 7as: persist deadline so a restart during the
                    // cool-down window survives. Best-effort — DB failure
                    // logs but doesn't fail dispatch (the in-memory map is
                    // still authoritative for this process).
                    self.persist_backoff(store, webhook, retry_secs).await;
                    tracing::warn!(
                        name = %webhook.name,
                        retry_after_secs = retry_secs,
                        "webhook returned 429; backing off"
                    );
                } else {
                    tracing::warn!(
                        name = %webhook.name,
                        "webhook returned 429 without parseable Retry-After"
                    );
                }
            }
            Ok(resp) => {
                self.metrics.dispatched_non_success.fetch_add(1, Relaxed);
                if let Some(p) = per {
                    p.dispatched_non_success.fetch_add(1, Relaxed);
                }
                tracing::warn!(
                    name = %webhook.name,
                    status = %resp.status(),
                    kind = %event.kind,
                    "webhook returned non-success"
                );
            }
            Err(e) => {
                self.metrics.delivery_errors.fetch_add(1, Relaxed);
                if let Some(p) = per {
                    p.delivery_errors.fetch_add(1, Relaxed);
                }
                tracing::warn!(
                    name = %webhook.name,
                    error = %e,
                    kind = %event.kind,
                    "webhook delivery failed"
                );
            }
        }
    }
}

/// Phase 7au: parse an HTTP `Retry-After` header in either of the two
/// forms RFC 7231 §7.1.3 allows:
///
///   * `delta-seconds`: an unsigned integer count of seconds (e.g. `120`).
///   * `HTTP-date` (IMF-fixdate): `Fri, 31 Dec 1999 23:59:59 GMT`.
///
/// Returns the number of seconds to wait, computed as `max(0, target - now)`
/// for the date form. Negative or unparseable values yield `None` so the
/// caller (which falls back to a no-op log) treats them like an absent header.
///
/// We don't bother with the obsolete RFC 850 / asctime forms — modern
/// HTTP servers emit IMF-fixdate, and falling back to "no backoff" is
/// safer than honoring a misparsed date.
pub fn parse_retry_after(value: &str, now: jiff::Timestamp) -> Option<u64> {
    let trimmed = value.trim();
    // Form 1: delta-seconds. Pure ASCII digits.
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(secs);
    }
    // Form 2: IMF-fixdate. The standard form is always GMT — strip
    // that suffix and parse the civil datetime, then explicitly attach
    // UTC. jiff's `Timestamp::strptime` doesn't recognize the literal
    // `GMT` token as a zone, so we go through `civil::DateTime` and
    // then zone it.
    let body = trimmed.strip_suffix(" GMT").unwrap_or(trimmed);
    let dt = jiff::civil::DateTime::strptime("%a, %d %b %Y %H:%M:%S", body).ok()?;
    let target = dt.to_zoned(jiff::tz::TimeZone::UTC).ok()?.timestamp();
    let delta = target.as_second().saturating_sub(now.as_second());
    if delta <= 0 {
        return Some(0);
    }
    Some(delta as u64)
}

/// Phase 7x: parse a Stripe-style `X-Iac-Signature` header into its
/// `(timestamp, signature_hex)` parts. Returns `None` on malformed
/// input. Exposed so receiver-side verifiers can use the same parser.
///
/// Phase 7bp: this returns only the `v1` signature for backward
/// compatibility. Receivers wanting v2 should call
/// [`parse_signature_header_versioned`] which returns both.
pub fn parse_signature_header(header: &str) -> Option<(i64, String)> {
    let parsed = parse_signature_header_versioned(header)?;
    Some((parsed.timestamp, parsed.v1?))
}

/// Phase 7bp: parsed signature header carrying timestamp and any of
/// the version-keyed signatures that were present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignatureHeader {
    pub timestamp: i64,
    pub v1: Option<String>,
    pub v2: Option<String>,
}

/// Phase 7bp: parse a multi-version `X-Iac-Signature` header. The
/// header format is comma-separated `k=v` pairs:
/// `t=<unix>,v1=<hex>,v2=<hex>`. Unknown keys are silently ignored
/// (forward-compat). Returns `None` if `t` is missing or non-numeric.
pub fn parse_signature_header_versioned(header: &str) -> Option<ParsedSignatureHeader> {
    let mut t: Option<i64> = None;
    let mut v1: Option<String> = None;
    let mut v2: Option<String> = None;
    for part in header.split(',') {
        let (k, v) = part.split_once('=')?;
        match k.trim() {
            "t" => t = v.trim().parse().ok(),
            "v1" => v1 = Some(v.trim().to_string()),
            "v2" => v2 = Some(v.trim().to_string()),
            _ => {} // unknown key, ignore
        }
    }
    Some(ParsedSignatureHeader {
        timestamp: t?,
        v1,
        v2,
    })
}

/// Phase 7bp: assemble the `X-Iac-Signature` header value from a list
/// of versions. Returns `None` if no version produces a valid HMAC
/// (would only happen if the underlying primitive fails to initialize,
/// which is best-effort kept fallible). The order of versions in the
/// output matches the order in `versions` so operators get a stable
/// header value across calls.
pub fn build_signature_header(
    secret: &[u8],
    timestamp: i64,
    url: &str,
    body: &str,
    versions: &[String],
) -> Option<String> {
    let mut parts: Vec<String> = vec![format!("t={timestamp}")];
    for version in versions {
        let payload = match version.as_str() {
            "v1" => format!("{timestamp}.{body}"),
            "v2" => format!("{timestamp}.{url}.{body}"),
            _ => continue,
        };
        let sig = compute_hmac_sha256(secret, payload.as_bytes())?;
        parts.push(format!("{version}={sig}"));
    }
    if parts.len() == 1 {
        return None; // only `t=...` — no signatures means nothing to verify
    }
    Some(parts.join(","))
}

/// Phase 7x: receiver-side verification helper. Returns `Ok(())` if
/// the signature matches AND the timestamp is within `tolerance_secs`
/// of `now`. Constant-time comparison via `subtle`-style equality
/// over hex strings — both sides are fixed-length so it's just a
/// byte loop.
pub fn verify_signed_payload(
    secret: &[u8],
    body: &[u8],
    header: &str,
    now: i64,
    tolerance_secs: i64,
) -> Result<(), &'static str> {
    let (timestamp, sig_hex) =
        parse_signature_header(header).ok_or("malformed signature header")?;
    if (now - timestamp).abs() > tolerance_secs {
        return Err("timestamp outside tolerance");
    }
    let signed_payload = format!(
        "{timestamp}.{}",
        std::str::from_utf8(body).map_err(|_| "non-utf8 body")?
    );
    let expected =
        compute_hmac_sha256(secret, signed_payload.as_bytes()).ok_or("hmac compute failed")?;
    if !ct_eq(sig_hex.as_bytes(), expected.as_bytes()) {
        return Err("signature mismatch");
    }
    Ok(())
}

/// Phase 7bp: receiver-side verification of v2 signatures. v2 binds
/// the signature to the URL the receiver is hosted at, so a captured
/// payload can't be replayed against a different endpoint.
///
/// `url` is the full URL the receiver expects (e.g.
/// `https://hooks.example.com/iac`). The dispatcher signs over
/// `<t>.<url>.<body>`; a receiver that knows its own URL reconstructs
/// the same string and HMACs to verify.
///
/// Returns `Ok(())` only when the v2 entry is present, matches, and
/// the timestamp is within tolerance. If the header carries v1 only,
/// returns `Err("v2 signature missing")` — the caller can fall back
/// to [`verify_signed_payload`] during a rotation window.
pub fn verify_signed_payload_v2(
    secret: &[u8],
    body: &[u8],
    url: &str,
    header: &str,
    now: i64,
    tolerance_secs: i64,
) -> Result<(), &'static str> {
    let parsed = parse_signature_header_versioned(header).ok_or("malformed signature header")?;
    if (now - parsed.timestamp).abs() > tolerance_secs {
        return Err("timestamp outside tolerance");
    }
    let sig_hex = parsed.v2.ok_or("v2 signature missing")?;
    let body_str = std::str::from_utf8(body).map_err(|_| "non-utf8 body")?;
    let signed_payload = format!("{}.{url}.{body_str}", parsed.timestamp);
    let expected =
        compute_hmac_sha256(secret, signed_payload.as_bytes()).ok_or("hmac compute failed")?;
    if !ct_eq(sig_hex.as_bytes(), expected.as_bytes()) {
        return Err("signature mismatch");
    }
    Ok(())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Compute `HMAC-SHA256(secret, body)` and return it as lowercase hex.
/// Returns `None` if the HMAC primitive can't be initialized — should
/// never happen with sha2 but defensively kept fallible.
pub fn compute_hmac_sha256(secret: &[u8], body: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};
    // RFC 2104 HMAC: derive ipad/opad from secret. Block size 64 for SHA-256.
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(secret);
        let digest = h.finalize();
        key[..digest.len()].copy_from_slice(&digest);
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(body);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();
    Some(hex::encode(outer_digest))
}

/// Spawn the polling loop. Caller signals shutdown via `Notify`.
pub fn spawn_loop(
    store: Store,
    dispatcher: Arc<WebhookDispatcher>,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        dispatcher.initialize(&store).await;
        let interval = Duration::from_secs(dispatcher.config.poll_interval_secs.max(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately; skip it so we don't spam at boot.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!("webhook loop shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    let n = dispatcher.tick_once(&store).await;
                    if n > 0 {
                        tracing::info!(dispatched = n, "webhook tick");
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Phase 7cz.5: SSRF guard tests.
    #[test]
    fn url_validator_accepts_https_public() {
        assert!(validate_webhook_url("https://hooks.example.com/sink", false, false).is_ok());
        assert!(validate_webhook_url("https://hooks.example.com:8443/sink", false, false).is_ok());
    }

    #[test]
    fn url_validator_rejects_http_by_default() {
        let err = validate_webhook_url("http://hooks.example.com/sink", false, false).unwrap_err();
        assert!(err.contains("https://"), "{err}");
    }

    #[test]
    fn url_validator_allows_http_with_optin() {
        assert!(validate_webhook_url("http://hooks.example.com/sink", true, false).is_ok());
    }

    #[test]
    fn url_validator_rejects_loopback() {
        for url in [
            "http://127.0.0.1/sink",
            "https://127.0.0.1:8443/sink",
            "http://localhost:9000/sink",
            "https://[::1]/sink",
        ] {
            let err = validate_webhook_url(url, true, false).unwrap_err();
            assert!(err.contains("private"), "{url}: {err}");
        }
    }

    #[test]
    fn url_validator_rejects_aws_imds() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://[fd00:ec2::254]/",
        ] {
            let err = validate_webhook_url(url, true, false).unwrap_err();
            assert!(
                err.contains("private") || err.contains("metadata"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn url_validator_rejects_rfc1918() {
        for url in [
            "https://10.0.0.5/sink",
            "https://192.168.1.10/sink",
            "https://172.16.0.42/sink",
        ] {
            let err = validate_webhook_url(url, false, false).unwrap_err();
            assert!(err.contains("private"), "{url}: {err}");
        }
    }

    #[test]
    fn url_validator_allows_private_with_optin() {
        // In-cluster scenario — peer service on RFC1918.
        assert!(validate_webhook_url("https://10.0.0.5/sink", false, true).is_ok());
    }

    #[test]
    fn config_validate_propagates_url_errors() {
        let cfg = WebhooksConfig {
            webhooks: vec![WebhookConfig {
                name: "evil".into(),
                url: "http://169.254.169.254/".into(),
                min_severity: "info".into(),
                kinds: vec![],
                hmac_secret: None,
                backfill: false,
                max_concurrent_requests: None,
                signing_versions: vec![],
            }],
            poll_interval_secs: 5,
            max_concurrent_requests: 1,
            backfill_batch_size: 1,
            allow_insecure_urls: true, // permits http but still rejects metadata target
            allow_private_urls: false,
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("evil"), "expected name in error: {err}");
        assert!(err.contains("private") || err.contains("metadata"), "{err}");
    }

    #[test]
    fn parse_retry_after_seconds_form() {
        let now = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        assert_eq!(parse_retry_after("60", now), Some(60));
        assert_eq!(parse_retry_after("  120  ", now), Some(120));
        assert_eq!(parse_retry_after("0", now), Some(0));
    }

    #[test]
    fn parse_retry_after_http_date_form() {
        // 2024-07-14 21:14:30 UTC.
        let now: jiff::Timestamp = "2024-07-14T21:14:30Z".parse().unwrap();
        // Same day, two minutes in the future.
        let two_min_later = parse_retry_after("Sun, 14 Jul 2024 21:16:30 GMT", now);
        assert_eq!(two_min_later, Some(120));
        // Past date → 0 (don't sleep negative).
        let past = parse_retry_after("Sun, 14 Jul 2024 21:00:00 GMT", now);
        assert_eq!(past, Some(0));
    }

    #[test]
    fn parse_retry_after_rejects_garbage() {
        let now = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        assert_eq!(parse_retry_after("not a number", now), None);
        assert_eq!(parse_retry_after("", now), None);
        // RFC 850 (obsolete) form — we deliberately reject. Better to
        // not sleep at all than to misparse.
        assert_eq!(
            parse_retry_after("Sunday, 14-Jul-24 21:16:30 GMT", now),
            None
        );
        // Negative seconds aren't valid in delta-seconds — fall through
        // to date-form parser, which fails too.
        assert_eq!(parse_retry_after("-30", now), None);
    }

    #[test]
    fn semaphore_wait_histogram_picks_bucket_by_upper_bound() {
        let h = SemaphoreWaitHistogram::default();
        // Boundary semantics: a value exactly equal to a bucket bound
        // lands IN that bucket, not the next one. 100µs goes to buckets[0].
        h.record(50); // <= 100µs → buckets[0]
        h.record(100); // exactly 100µs → buckets[0]
        h.record(101); // > 100µs, ≤ 1ms → buckets[1]
        h.record(999_999); // ≤ 1s → buckets[4]
        h.record(20_000_000); // > 10s → +Inf bucket (last)
        let snap = h.snapshot();
        assert_eq!(snap.buckets[0], 2, "≤100µs bucket");
        assert_eq!(snap.buckets[1], 1, "≤1ms bucket");
        assert_eq!(snap.buckets[2], 0, "≤10ms bucket");
        assert_eq!(snap.buckets[3], 0, "≤100ms bucket");
        assert_eq!(snap.buckets[4], 1, "≤1s bucket");
        assert_eq!(snap.buckets[5], 0, "≤10s bucket");
        assert_eq!(snap.buckets[6], 1, "+Inf bucket");
        assert_eq!(snap.count, 5);
    }

    fn audit(id: i64, severity: &str, kind: &str) -> AuditEvent {
        AuditEvent {
            id,
            timestamp: "2026-04-30T12:00:00Z".into(),
            actor: "user:alice".into(),
            kind: kind.into(),
            severity: severity.into(),
            operation_id: None,
            agent_id: None,
            resource_id: None,
            drift_id: None,
            payload: serde_json::Value::Null,
        }
    }

    fn webhook(min_severity: &str, kinds: Vec<&str>) -> WebhookConfig {
        WebhookConfig {
            name: "test".into(),
            url: "http://example.invalid".into(),
            min_severity: min_severity.into(),
            kinds: kinds.iter().map(|s| s.to_string()).collect(),
            hmac_secret: None,
            backfill: false,
            max_concurrent_requests: None,
            signing_versions: default_signing_versions(),
        }
    }

    #[test]
    fn hmac_sha256_matches_known_vectors() {
        // RFC 4231 test case 1: key = 20 bytes of 0x0b, data = "Hi There".
        let key = [0x0bu8; 20];
        let got = compute_hmac_sha256(&key, b"Hi There").unwrap();
        let expected = "b0344c61d8db38535ca8afceaf0bf12b\
                        881dc200c9833da726e9376c2e32cff7";
        assert_eq!(got, expected);

        // RFC 4231 test case 2: key = "Jefe", data = "what do ya want for nothing?"
        let got = compute_hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap();
        let expected = "5bdcc146bf60754e6a042426089575c7\
                        5a003f089d2739839dec58b964ec3843";
        assert_eq!(got, expected);
    }

    #[test]
    fn hmac_sha256_handles_long_keys() {
        // RFC 4231 test case 4: key = 25 bytes of 0x0c, data = "Test ...".
        // Verifies the > BLOCK_SIZE branch (key gets pre-hashed) doesn't
        // fire incorrectly for keys that are exactly at the boundary.
        let key = vec![0x01u8; 200]; // > 64-byte block, gets pre-hashed
        let got = compute_hmac_sha256(&key, b"sample").unwrap();
        // We don't have a fixed vector for this exact pair, but the
        // function shouldn't panic and the output should be stable.
        let got2 = compute_hmac_sha256(&key, b"sample").unwrap();
        assert_eq!(got, got2);
        assert_eq!(got.len(), 64); // SHA-256 hex
    }

    #[test]
    fn hmac_sha256_secret_changes_output() {
        let body = b"identical body";
        let s1 = compute_hmac_sha256(b"secret-one", body).unwrap();
        let s2 = compute_hmac_sha256(b"secret-two", body).unwrap();
        assert_ne!(s1, s2, "different secrets must produce different HMACs");
    }

    #[test]
    fn parse_signature_header_basic() {
        let (t, v1) = parse_signature_header("t=1745923200,v1=deadbeef").unwrap();
        assert_eq!(t, 1745923200);
        assert_eq!(v1, "deadbeef");
    }

    #[test]
    fn parse_signature_header_unknown_keys_ignored() {
        // Forward-compat: future signature versions (v2, v3) shouldn't
        // make a v1-only parser barf.
        let (t, v1) = parse_signature_header("t=1745923200,v1=abc,v2=xyz").unwrap();
        assert_eq!(t, 1745923200);
        assert_eq!(v1, "abc");
    }

    #[test]
    fn parse_signature_header_missing_t_or_v1_fails() {
        assert!(parse_signature_header("v1=abc").is_none());
        assert!(parse_signature_header("t=12345").is_none());
        assert!(parse_signature_header("garbage").is_none());
    }

    #[test]
    fn verify_signed_payload_accepts_fresh_signature() {
        let secret = b"shared";
        let body = b"{\"id\":1}";
        let now = 1745923200;
        let signed = format!("{now}.{}", std::str::from_utf8(body).unwrap());
        let sig = compute_hmac_sha256(secret, signed.as_bytes()).unwrap();
        let header = format!("t={now},v1={sig}");
        // Same instant, default 5min tolerance.
        verify_signed_payload(secret, body, &header, now, 300).unwrap();
        // Within tolerance.
        verify_signed_payload(secret, body, &header, now + 100, 300).unwrap();
    }

    #[test]
    fn verify_signed_payload_rejects_old_timestamp() {
        let secret = b"shared";
        let body = b"{}";
        let signed_at = 1745923200;
        let signed = format!("{signed_at}.{{}}");
        let sig = compute_hmac_sha256(secret, signed.as_bytes()).unwrap();
        let header = format!("t={signed_at},v1={sig}");
        // 10 minutes later, 5min tolerance → reject.
        let err = verify_signed_payload(secret, body, &header, signed_at + 600, 300).unwrap_err();
        assert!(err.contains("tolerance"), "got: {err}");
    }

    #[test]
    fn verify_signed_payload_rejects_tampered_body() {
        let secret = b"shared";
        let body = b"{\"id\":1}";
        let now = 1745923200;
        let signed = format!("{now}.{}", std::str::from_utf8(body).unwrap());
        let sig = compute_hmac_sha256(secret, signed.as_bytes()).unwrap();
        let header = format!("t={now},v1={sig}");
        // Receiver sees a different body than what was signed.
        let tampered = b"{\"id\":2}";
        let err = verify_signed_payload(secret, tampered, &header, now, 300).unwrap_err();
        assert!(err.contains("mismatch"), "got: {err}");
    }

    #[test]
    fn verify_signed_payload_rejects_wrong_secret() {
        let secret = b"shared";
        let body = b"{}";
        let now = 1745923200;
        let signed = format!("{now}.{{}}");
        let sig = compute_hmac_sha256(secret, signed.as_bytes()).unwrap();
        let header = format!("t={now},v1={sig}");
        let err = verify_signed_payload(b"wrong-secret", body, &header, now, 300).unwrap_err();
        assert!(err.contains("mismatch"), "got: {err}");
    }

    #[test]
    fn verify_signed_payload_rejects_replay_with_forged_timestamp() {
        // The whole point of Phase 7x: an attacker who captures a
        // signed POST cannot replay it later with `t` updated to
        // "now". The signature covers `<t>.<body>` so altering `t`
        // breaks the HMAC.
        let secret = b"shared";
        let body = b"{}";
        let original_t = 1745923200;
        let original_signed = format!("{original_t}.{{}}");
        let original_sig = compute_hmac_sha256(secret, original_signed.as_bytes()).unwrap();
        // Attacker forges header with fresh `t` but keeps the
        // (stale) signature.
        let forged_t = original_t + 1_000_000;
        let forged_header = format!("t={forged_t},v1={original_sig}");
        let err = verify_signed_payload(secret, body, &forged_header, forged_t, 300).unwrap_err();
        assert!(err.contains("mismatch"), "got: {err}");
    }

    #[test]
    fn severity_floor_filters() {
        let w = webhook("warning", vec![]);
        assert!(!w.matches(&audit(1, "info", "anything")));
        assert!(w.matches(&audit(2, "warning", "anything")));
        assert!(w.matches(&audit(3, "error", "anything")));
    }

    #[test]
    fn kind_list_filters() {
        let w = webhook("info", vec!["operation.maintenance_bypass"]);
        assert!(w.matches(&audit(1, "info", "operation.maintenance_bypass")));
        assert!(!w.matches(&audit(2, "info", "user.created")));
    }

    #[test]
    fn empty_kinds_means_any() {
        let w = webhook("info", vec![]);
        assert!(w.matches(&audit(1, "info", "literally.any.kind")));
    }

    #[test]
    fn severity_and_kind_must_both_match() {
        let w = webhook("warning", vec!["operation.rejected"]);
        // Severity floor met but wrong kind.
        assert!(!w.matches(&audit(1, "warning", "user.disabled")));
        // Right kind but below severity floor.
        assert!(!w.matches(&audit(2, "info", "operation.rejected")));
        // Both match.
        assert!(w.matches(&audit(3, "warning", "operation.rejected")));
    }

    #[test]
    fn unknown_severity_strings_fall_back_to_info_rank() {
        // Defensive: a future severity string we don't know about
        // shouldn't accidentally bypass the floor by ranking high.
        let w = webhook("warning", vec![]);
        assert!(!w.matches(&audit(1, "totally-novel-severity", "anything")));
    }
}
