//! Phase 7ad: `GET /v1/metrics` exposes live counters from the
//! webhook dispatcher and the rate limiter.
//!
//! Phase 7af: `?format=prom` renders the OpenMetrics / Prometheus
//! text exposition format so scrapers can wire in directly. Default
//! (no query) returns JSON.

use crate::api::{require_role, BearerToken};
use crate::error::ApiResult;
use crate::identity::Role;
use crate::maintenance::MaintenanceMetricsSnapshot;
use crate::rate_limit::RateLimitMetricsSnapshot;
use crate::server::AppState;
use crate::webhook::{
    PerWebhookSnapshot, SemaphoreWaitHistogramSnapshot, WebhookMetricsSnapshot,
    SEMAPHORE_WAIT_BUCKETS_MICROS,
};
use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/metrics", get(get_metrics))
}

#[derive(Debug, Serialize)]
struct MetricsResponse {
    /// `Some` when the webhook dispatcher is wired in (the
    /// production server always sets this; some test fixtures
    /// don't). `None` lets the endpoint stay 200 in either mode.
    webhook: Option<WebhookMetricsSnapshot>,
    /// Phase 7ae: per-process rate limiter counters.
    rate_limit: RateLimitMetricsSnapshot,
    /// Phase 7ag: maintenance-window submission gate counters.
    maintenance: MaintenanceMetricsSnapshot,
}

#[derive(Debug, Deserialize, Default)]
struct MetricsQuery {
    /// `format=prom` switches to Prometheus text exposition.
    /// Anything else (or absent) renders JSON.
    #[serde(default)]
    format: Option<String>,
}

async fn get_metrics(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Query(q): Query<MetricsQuery>,
) -> ApiResult<Response> {
    require_role(&state, &token, Role::Viewer).await?;
    let webhook = state.webhook_dispatcher.as_ref().map(|d| d.metrics());
    let rate_limit = state.rate_limiter.metrics();
    let maintenance = state.maintenance_metrics.snapshot();

    let want_prom = q.format.as_deref() == Some("prom");
    if want_prom {
        let body = render_prom(webhook.as_ref(), &rate_limit, &maintenance);
        return Ok((
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            body,
        )
            .into_response());
    }
    Ok(Json(MetricsResponse { webhook, rate_limit, maintenance }).into_response())
}

/// Render the metrics in OpenMetrics / Prometheus text exposition
/// format. Each counter gets a `# HELP`, `# TYPE`, and the metric
/// itself. Names follow the `iac_<subsystem>_<name>` convention.
/// Atomic gauges (`in_flight`) get `gauge` type; everything else
/// is `counter`.
fn render_prom(
    webhook: Option<&WebhookMetricsSnapshot>,
    rate_limit: &RateLimitMetricsSnapshot,
    maintenance: &MaintenanceMetricsSnapshot,
) -> String {
    let mut out = String::with_capacity(1024);
    if let Some(w) = webhook {
        push_counter(
            &mut out,
            "iac_webhook_dispatched_ok_total",
            "Successful 2xx webhook deliveries.",
            w.dispatched_ok,
        );
        push_counter(
            &mut out,
            "iac_webhook_dispatched_non_success_total",
            "Non-2xx (other than 429) webhook responses.",
            w.dispatched_non_success,
        );
        push_counter(
            &mut out,
            "iac_webhook_dispatched_ratelimited_total",
            "429 responses (with or without Retry-After).",
            w.dispatched_ratelimited,
        );
        push_counter(
            &mut out,
            "iac_webhook_delivery_errors_total",
            "Network / HTTP errors during webhook delivery.",
            w.delivery_errors,
        );
        // Phase 7bc: OpenMetrics-strict unit suffix. The histogram below is
        // the canonical seconds-form signal; this counter keeps the same
        // microseconds-encoded data with the spec-conformant `_microseconds`
        // suffix for backwards-compat scrapers that haven't migrated to
        // the histogram yet. The legacy `_micros_total` name was dropped in
        // this phase — see TASKS.md "Open after Phase 7bc" for migration
        // guidance.
        push_counter(
            &mut out,
            "iac_webhook_semaphore_wait_microseconds_total",
            "Cumulative microseconds spent waiting on the dispatcher's concurrency semaphore.",
            w.semaphore_wait_micros,
        );
        // Phase 7ap: histogram alongside the cumulative counter. OpenMetrics
        // uses seconds for time-valued histograms, so divide bucket bounds
        // by 1e6 at render time even though we keep them in microseconds
        // internally (avoids float accumulation in the hot path).
        push_semaphore_wait_histogram(&mut out, &w.semaphore_wait_hist, w.semaphore_wait_micros);
        push_gauge(
            &mut out,
            "iac_webhook_in_flight",
            "Currently in-flight webhook HTTP requests.",
            w.in_flight,
        );
        push_gauge(
            &mut out,
            "iac_webhook_in_flight_peak",
            "Peak in-flight webhook HTTP requests since startup.",
            w.in_flight_peak,
        );
        // Phase 7bt: HTTP round-trip duration. Distinct from
        // `semaphore_wait_microseconds_total` (queue time); this is the
        // wall-clock time inside `req.send().await` — the actual
        // receiver latency + network. Operators dividing this by the
        // sum of dispatched_* counters get average HTTP duration.
        push_counter(
            &mut out,
            "iac_webhook_dispatch_duration_microseconds_total",
            "Cumulative microseconds spent in HTTP send (req.send().await), \
             across all receivers and outcomes.",
            w.dispatch_duration_micros,
        );
        // Phase 7bu: HTTP round-trip distribution. Same bucket bounds
        // as the semaphore-wait histogram (powers of 10 in µs). Lets
        // operators distinguish "everything is slow" from "the slow
        // tail is dragging" without per-receiver disaggregation.
        push_dispatch_duration_histogram(
            &mut out,
            &w.dispatch_duration_hist,
            w.dispatch_duration_micros,
        );
        // Phase 7at: per-receiver counter breakdown. Operators with
        // multiple receivers (e.g. one Slack alert + one PagerDuty)
        // see which receiver is misbehaving without the global blend.
        // Emitted with `{webhook="<name>"}` labels per OpenMetrics.
        push_per_webhook_counters(&mut out, &w.per_webhook);
    }
    push_counter(
        &mut out,
        "iac_rate_limit_checks_total",
        "Total rate-limit checks performed (excludes config-disabled short-circuits).",
        rate_limit.checks_total,
    );
    push_counter(
        &mut out,
        "iac_rate_limit_rejected_total",
        "Rate-limit checks that returned TooManyRequests.",
        rate_limit.rejected_total,
    );
    push_counter(
        &mut out,
        "iac_rate_limit_admitted_total",
        "Rate-limit checks that admitted the request.",
        rate_limit.admitted_total,
    );
    push_counter(
        &mut out,
        "iac_maintenance_checks_total",
        "Submissions that ran the maintenance-window gate.",
        maintenance.checks_total,
    );
    push_counter(
        &mut out,
        "iac_maintenance_blocked_total",
        "Submissions blocked by any maintenance window (absolute or recurring).",
        maintenance.blocked_total,
    );
    push_counter(
        &mut out,
        "iac_maintenance_blocked_by_absolute_total",
        "Submissions blocked by an absolute-time maintenance window.",
        maintenance.blocked_by_absolute_total,
    );
    push_counter(
        &mut out,
        "iac_maintenance_blocked_by_recurring_total",
        "Submissions blocked by a recurring (weekly) maintenance window.",
        maintenance.blocked_by_recurring_total,
    );
    push_counter(
        &mut out,
        "iac_maintenance_bypassed_total",
        "Submissions admitted via the admin maintenance-bypass header.",
        maintenance.bypassed_total,
    );
    push_gauge(
        &mut out,
        "iac_maintenance_misconfigured_windows",
        "Number of configured maintenance windows that failed to parse.",
        maintenance.misconfigured_windows,
    );
    // Phase 7bg: per-window block breakdown. Labeled lines emit only
    // when at least one window was registered + matched something — no
    // `# HELP` block at all when the operator has zero configured
    // windows (avoids confusing empty lines in tools that grep the
    // exposition).
    push_per_window_blocked(&mut out, &maintenance.per_window_blocked);
    out
}

fn push_per_window_blocked(
    out: &mut String,
    entries: &[crate::maintenance::PerWindowBlockedEntry],
) {
    if entries.is_empty() {
        return;
    }
    use std::fmt::Write;
    let _ = writeln!(
        out,
        "# HELP iac_maintenance_blocked_per_window_total \
         Submissions blocked, broken out by window kind + name."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_maintenance_blocked_per_window_total counter"
    );
    for e in entries {
        let _ = writeln!(
            out,
            "iac_maintenance_blocked_per_window_total{{window_kind=\"{}\",window_name=\"{}\"}} {}",
            e.kind.as_label(),
            escape_label(&e.name),
            e.count
        );
    }
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    push_metric(out, name, help, "counter", value)
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    push_metric(out, name, help, "gauge", value)
}

fn push_metric(out: &mut String, name: &str, help: &str, type_str: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {type_str}");
    let _ = writeln!(out, "{name} {value}");
}

/// Phase 7at: emit one labeled line per receiver for each of the four
/// dispatch-outcome counters. OpenMetrics groups `# HELP` / `# TYPE`
/// once per metric name; the labeled lines follow.
fn push_per_webhook_counters(out: &mut String, per: &[(String, PerWebhookSnapshot)]) {
    if per.is_empty() {
        return;
    }
    use std::fmt::Write;
    // dispatched_ok
    let _ = writeln!(
        out,
        "# HELP iac_webhook_dispatched_ok_per_receiver_total \
         Successful 2xx webhook deliveries, broken out by receiver name."
    );
    let _ = writeln!(out, "# TYPE iac_webhook_dispatched_ok_per_receiver_total counter");
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_dispatched_ok_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.dispatched_ok
        );
    }
    // dispatched_non_success
    let _ = writeln!(
        out,
        "# HELP iac_webhook_dispatched_non_success_per_receiver_total \
         Non-2xx (other than 429) responses by receiver name."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_webhook_dispatched_non_success_per_receiver_total counter"
    );
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_dispatched_non_success_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.dispatched_non_success
        );
    }
    // dispatched_ratelimited
    let _ = writeln!(
        out,
        "# HELP iac_webhook_dispatched_ratelimited_per_receiver_total \
         429 responses by receiver name."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_webhook_dispatched_ratelimited_per_receiver_total counter"
    );
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_dispatched_ratelimited_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.dispatched_ratelimited
        );
    }
    // delivery_errors
    let _ = writeln!(
        out,
        "# HELP iac_webhook_delivery_errors_per_receiver_total \
         Network / HTTP errors by receiver name."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_webhook_delivery_errors_per_receiver_total counter"
    );
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_delivery_errors_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.delivery_errors
        );
    }
    // Phase 7bq: per-receiver semaphore-wait cumulative microseconds.
    // OpenMetrics naming: cumulative-time counters use `_microseconds_total`
    // (Phase 7bc renamed the global variant to match). Operators
    // dividing this by `dispatched_ok_per_receiver_total` get an
    // average wait per delivery for that receiver — the missing
    // companion to the existing global `iac_webhook_semaphore_wait_microseconds_total`.
    let _ = writeln!(
        out,
        "# HELP iac_webhook_semaphore_wait_microseconds_per_receiver_total \
         Cumulative microseconds this receiver's deliveries spent waiting on \
         permits (global semaphore + optional per-receiver semaphore)."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_webhook_semaphore_wait_microseconds_per_receiver_total counter"
    );
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_semaphore_wait_microseconds_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.semaphore_wait_micros
        );
    }
    // Phase 7bt: per-receiver HTTP round-trip cumulative microseconds.
    let _ = writeln!(
        out,
        "# HELP iac_webhook_dispatch_duration_microseconds_per_receiver_total \
         Cumulative microseconds this receiver's deliveries spent in HTTP send."
    );
    let _ = writeln!(
        out,
        "# TYPE iac_webhook_dispatch_duration_microseconds_per_receiver_total counter"
    );
    for (name, p) in per {
        let _ = writeln!(
            out,
            "iac_webhook_dispatch_duration_microseconds_per_receiver_total{{webhook=\"{}\"}} {}",
            escape_label(name),
            p.dispatch_duration_micros
        );
    }
    // Phase 7bs: per-receiver wait-latency histogram. Same bucket
    // bounds as the global histogram. Single `# HELP` / `# TYPE`
    // declared once; bucket / sum / count lines per receiver follow
    // (OpenMetrics convention groups labeled samples under one type).
    push_per_receiver_histogram(
        out,
        "iac_webhook_semaphore_wait_seconds_per_receiver",
        "Distribution of semaphore-wait latency for webhook dispatches, \
         broken out by receiver name.",
        per,
        |p| (&p.semaphore_wait_hist, p.semaphore_wait_micros),
    );
    // Phase 7bu: per-receiver HTTP-duration histogram. Same shape as
    // the wait histogram above; closes the observability gap from
    // Phase 7bt's cumulative-counter-only approach.
    push_per_receiver_histogram(
        out,
        "iac_webhook_dispatch_duration_seconds_per_receiver",
        "Distribution of HTTP round-trip latency for webhook dispatches, \
         broken out by receiver name.",
        per,
        |p| (&p.dispatch_duration_hist, p.dispatch_duration_micros),
    );
}

/// Phase 7bu: shared per-receiver histogram printer. `extract`
/// projects the snapshot field + sum_micros pair from each
/// PerWebhookSnapshot so the same printer covers wait + duration
/// histograms.
fn push_per_receiver_histogram<F>(
    out: &mut String,
    hist_name: &str,
    help: &str,
    per: &[(String, PerWebhookSnapshot)],
    extract: F,
) where
    F: Fn(&PerWebhookSnapshot) -> (&SemaphoreWaitHistogramSnapshot, u64),
{
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {hist_name} {help}");
    let _ = writeln!(out, "# TYPE {hist_name} histogram");
    for (name, p) in per {
        let escaped = escape_label(name);
        let (h, sum_micros) = extract(p);
        let mut cumulative: u64 = 0;
        for (i, bound_micros) in SEMAPHORE_WAIT_BUCKETS_MICROS.iter().enumerate() {
            cumulative += h.buckets[i];
            let bound_seconds = (*bound_micros as f64) / 1_000_000.0;
            let _ = writeln!(
                out,
                "{hist_name}_bucket{{webhook=\"{escaped}\",le=\"{bound_seconds}\"}} {cumulative}"
            );
        }
        cumulative += h.buckets[SEMAPHORE_WAIT_BUCKETS_MICROS.len()];
        let _ = writeln!(
            out,
            "{hist_name}_bucket{{webhook=\"{escaped}\",le=\"+Inf\"}} {cumulative}"
        );
        let sum_seconds = (sum_micros as f64) / 1_000_000.0;
        let _ = writeln!(out, "{hist_name}_sum{{webhook=\"{escaped}\"}} {sum_seconds}");
        let _ = writeln!(out, "{hist_name}_count{{webhook=\"{escaped}\"}} {}", h.count);
    }
}

/// Escape Prometheus label values per the text exposition format:
/// backslashes, double-quotes, and newlines need backslash-escaping.
/// Webhook names are operator-supplied so we don't trust them.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Phase 7ap: render the semaphore-wait histogram in OpenMetrics text
/// exposition. Storage is non-cumulative; OpenMetrics scrapers expect
/// cumulative `_bucket{le=...}` lines plus `_sum` and `_count` rows.
fn push_semaphore_wait_histogram(
    out: &mut String,
    h: &SemaphoreWaitHistogramSnapshot,
    sum_micros: u64,
) {
    push_named_histogram(
        out,
        "iac_webhook_semaphore_wait_seconds",
        "Distribution of semaphore-wait latency for webhook dispatches.",
        h,
        sum_micros,
    );
}

/// Phase 7bu: render the HTTP-dispatch-duration histogram. Reuses the
/// generic histogram printer with a different name + help text.
fn push_dispatch_duration_histogram(
    out: &mut String,
    h: &SemaphoreWaitHistogramSnapshot,
    sum_micros: u64,
) {
    push_named_histogram(
        out,
        "iac_webhook_dispatch_duration_seconds",
        "Distribution of HTTP round-trip latency for webhook dispatches.",
        h,
        sum_micros,
    );
}

/// Phase 7bu: shared histogram printer. Bucket bounds (in µs) are
/// shared across all wait/duration histograms so the rendered `le`
/// labels match. Internal storage is microseconds; the exposition
/// renders seconds (OpenMetrics convention for time histograms).
fn push_named_histogram(
    out: &mut String,
    name: &str,
    help: &str,
    h: &SemaphoreWaitHistogramSnapshot,
    sum_micros: u64,
) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} histogram");
    let mut cumulative: u64 = 0;
    for (i, bound_micros) in SEMAPHORE_WAIT_BUCKETS_MICROS.iter().enumerate() {
        cumulative += h.buckets[i];
        // Render bucket bounds in seconds. Use scientific-friendly form
        // so 100µs prints as `0.0001` not as something float-rounded.
        let bound_seconds = (*bound_micros as f64) / 1_000_000.0;
        let _ = writeln!(out, "{name}_bucket{{le=\"{bound_seconds}\"}} {cumulative}");
    }
    cumulative += h.buckets[SEMAPHORE_WAIT_BUCKETS_MICROS.len()];
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {cumulative}");
    let sum_seconds = (sum_micros as f64) / 1_000_000.0;
    let _ = writeln!(out, "{name}_sum {sum_seconds}");
    let _ = writeln!(out, "{name}_count {}", h.count);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(checks: u64, rejected: u64) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            checks_total: checks,
            rejected_total: rejected,
            admitted_total: checks.saturating_sub(rejected),
        }
    }

    fn maint(
        checks: u64,
        absolute: u64,
        recurring: u64,
        bypassed: u64,
    ) -> MaintenanceMetricsSnapshot {
        MaintenanceMetricsSnapshot {
            checks_total: checks,
            blocked_total: absolute + recurring,
            blocked_by_absolute_total: absolute,
            blocked_by_recurring_total: recurring,
            bypassed_total: bypassed,
            misconfigured_windows: 0,
            per_window_blocked: vec![],
        }
    }

    fn empty_hist() -> SemaphoreWaitHistogramSnapshot {
        SemaphoreWaitHistogramSnapshot {
            buckets: [0, 0, 0, 0, 0, 0, 0],
            count: 0,
        }
    }

    #[test]
    fn render_prom_emits_counter_and_gauge_blocks() {
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 5,
            dispatched_non_success: 1,
            dispatched_ratelimited: 2,
            delivery_errors: 0,
            semaphore_wait_micros: 1_234_567,
            semaphore_wait_hist: empty_hist(),
            in_flight: 3,
            in_flight_peak: 7,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![],
        };
        // 2 absolute + 1 recurring = 3 total blocked.
        let body = render_prom(Some(&webhook), &rl(10, 4), &maint(20, 2, 1, 1));
        // Spot-check shape.
        assert!(body.contains("# HELP iac_webhook_dispatched_ok_total "));
        assert!(body.contains("# TYPE iac_webhook_dispatched_ok_total counter"));
        assert!(body.contains("\niac_webhook_dispatched_ok_total 5\n"));
        // Gauge typing.
        assert!(body.contains("# TYPE iac_webhook_in_flight gauge"));
        assert!(body.contains("\niac_webhook_in_flight 3\n"));
        assert!(body.contains("\niac_webhook_in_flight_peak 7\n"));
        // Rate limiter always present.
        assert!(body.contains("\niac_rate_limit_checks_total 10\n"));
        assert!(body.contains("\niac_rate_limit_rejected_total 4\n"));
        assert!(body.contains("\niac_rate_limit_admitted_total 6\n"));
        // Phase 7ag: maintenance always present.
        assert!(body.contains("\niac_maintenance_checks_total 20\n"));
        assert!(body.contains("\niac_maintenance_blocked_total 3\n"));
        assert!(body.contains("\niac_maintenance_blocked_by_absolute_total 2\n"));
        assert!(body.contains("\niac_maintenance_blocked_by_recurring_total 1\n"));
        assert!(body.contains("\niac_maintenance_bypassed_total 1\n"));
        // Phase 7ai: misconfigured-windows gauge present (zero in
        // this fixture).
        assert!(body.contains("# TYPE iac_maintenance_misconfigured_windows gauge"));
        assert!(body.contains("\niac_maintenance_misconfigured_windows 0\n"));
    }

    #[test]
    fn render_prom_without_webhook_skips_webhook_block() {
        let body = render_prom(None, &rl(1, 0), &maint(2, 0, 0, 0));
        assert!(!body.contains("iac_webhook_"), "body: {body}");
        assert!(body.contains("iac_rate_limit_"));
        assert!(body.contains("iac_maintenance_"));
    }

    #[test]
    fn render_prom_emits_per_window_labeled_counters() {
        // Phase 7bg: per-window breakdown emits one labeled line per
        // (kind, name) pair. Sorted by (kind, name) ascending so the
        // output is stable.
        use crate::maintenance::{PerWindowBlockedEntry, WindowKind};
        let mut maint = maint(0, 0, 0, 0);
        maint.per_window_blocked = vec![
            PerWindowBlockedEntry { kind: WindowKind::Absolute, name: "freeze-q4".into(), count: 5 },
            PerWindowBlockedEntry { kind: WindowKind::Recurring, name: "weekend".into(), count: 2 },
        ];
        let body = render_prom(None, &rl(0, 0), &maint);
        assert!(body.contains("# TYPE iac_maintenance_blocked_per_window_total counter"));
        assert!(body.contains(
            "iac_maintenance_blocked_per_window_total{window_kind=\"absolute\",window_name=\"freeze-q4\"} 5"
        ));
        assert!(body.contains(
            "iac_maintenance_blocked_per_window_total{window_kind=\"recurring\",window_name=\"weekend\"} 2"
        ));
    }

    #[test]
    fn render_prom_skips_per_window_block_when_empty() {
        // No registered windows → no `# HELP` lines, no labeled rows.
        let body = render_prom(None, &rl(0, 0), &maint(0, 0, 0, 0));
        assert!(
            !body.contains("iac_maintenance_blocked_per_window_total"),
            "should be absent when entries are empty"
        );
    }

    #[test]
    fn render_prom_emits_per_webhook_labeled_counters() {
        // Phase 7at: per-receiver breakdown alongside the global totals.
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 8,
            dispatched_non_success: 1,
            dispatched_ratelimited: 2,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![
                (
                    "alerts".into(),
                    PerWebhookSnapshot {
                        dispatched_ok: 5,
                        dispatched_non_success: 0,
                        dispatched_ratelimited: 2,
                        delivery_errors: 0, semaphore_wait_micros: 0, semaphore_wait_hist: empty_hist(),
                        dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                    },
                ),
                (
                    "audit-archive".into(),
                    PerWebhookSnapshot {
                        dispatched_ok: 3,
                        dispatched_non_success: 1,
                        dispatched_ratelimited: 0,
                        delivery_errors: 0, semaphore_wait_micros: 0, semaphore_wait_hist: empty_hist(),
                        dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                    },
                ),
            ],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        // Global totals still emitted (backward compat).
        assert!(body.contains("\niac_webhook_dispatched_ok_total 8\n"));
        // Per-receiver `# TYPE` declared once per metric.
        assert!(body.contains(
            "# TYPE iac_webhook_dispatched_ok_per_receiver_total counter"
        ));
        // Both receivers labeled, in name-sorted order.
        let alerts_idx = body
            .find("dispatched_ok_per_receiver_total{webhook=\"alerts\"} 5")
            .expect("alerts row");
        let archive_idx = body
            .find("dispatched_ok_per_receiver_total{webhook=\"audit-archive\"} 3")
            .expect("archive row");
        assert!(alerts_idx < archive_idx, "rows must be sorted by name");
        // Other counters present per receiver.
        assert!(body
            .contains("dispatched_ratelimited_per_receiver_total{webhook=\"alerts\"} 2"));
        assert!(body
            .contains("dispatched_non_success_per_receiver_total{webhook=\"audit-archive\"} 1"));
    }

    #[test]
    fn render_prom_emits_dispatch_duration_histogram_global_and_per_receiver() {
        // Phase 7bu: global histogram + per-receiver labeled histogram.
        // Verify the bucket cumulative semantics + name + label shape.
        let make_hist = || {
            let mut h = SemaphoreWaitHistogramSnapshot {
                buckets: [0; 7],
                count: 0,
            };
            // 2 observations under 100ms, 1 under 1s.
            h.buckets[3] = 2;
            h.buckets[4] = 1;
            h.count = 3;
            h
        };
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 3,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 600_000, // 0.6s total
            dispatch_duration_hist: make_hist(),
            per_webhook: vec![(
                "alerts".into(),
                PerWebhookSnapshot {
                    dispatched_ok: 3,
                    dispatched_non_success: 0,
                    dispatched_ratelimited: 0,
                    delivery_errors: 0,
                    semaphore_wait_micros: 0,
                    semaphore_wait_hist: empty_hist(),
                    dispatch_duration_micros: 600_000,
                    dispatch_duration_hist: make_hist(),
                },
            )],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));

        // Global histogram name + cumulative buckets.
        assert!(body.contains(
            "# TYPE iac_webhook_dispatch_duration_seconds histogram"
        ));
        assert!(body.contains("iac_webhook_dispatch_duration_seconds_bucket{le=\"0.1\"} 2"));
        assert!(body.contains("iac_webhook_dispatch_duration_seconds_bucket{le=\"1\"} 3"));
        assert!(body.contains("iac_webhook_dispatch_duration_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(body.contains("iac_webhook_dispatch_duration_seconds_sum 0.6"));
        assert!(body.contains("iac_webhook_dispatch_duration_seconds_count 3"));

        // Per-receiver labeled histogram.
        assert!(body.contains(
            "# TYPE iac_webhook_dispatch_duration_seconds_per_receiver histogram"
        ));
        assert!(body.contains(
            "iac_webhook_dispatch_duration_seconds_per_receiver_bucket{webhook=\"alerts\",le=\"0.1\"} 2"
        ));
        assert!(body.contains(
            "iac_webhook_dispatch_duration_seconds_per_receiver_count{webhook=\"alerts\"} 3"
        ));
    }

    #[test]
    fn render_prom_emits_dispatch_duration_global_and_per_receiver() {
        // Phase 7bt: global counter + per-receiver labeled counter for
        // HTTP round-trip duration. Naming follows the OpenMetrics
        // `_microseconds_total` convention used by Phase 7bc.
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 5,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 12_345, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![(
                "alerts".into(),
                PerWebhookSnapshot {
                    dispatched_ok: 5,
                    dispatched_non_success: 0,
                    dispatched_ratelimited: 0,
                    delivery_errors: 0,
                    semaphore_wait_micros: 0,
                    semaphore_wait_hist: empty_hist(),
                    dispatch_duration_micros: 12_345, dispatch_duration_hist: empty_hist(),
                },
            )],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        // Global counter exists.
        assert!(body.contains(
            "# TYPE iac_webhook_dispatch_duration_microseconds_total counter"
        ));
        assert!(body.contains(
            "\niac_webhook_dispatch_duration_microseconds_total 12345\n"
        ));
        // Per-receiver labeled counter exists.
        assert!(body.contains(
            "# TYPE iac_webhook_dispatch_duration_microseconds_per_receiver_total counter"
        ));
        assert!(body.contains(
            "iac_webhook_dispatch_duration_microseconds_per_receiver_total{webhook=\"alerts\"} 12345"
        ));
    }

    #[test]
    fn render_prom_emits_per_receiver_semaphore_wait_histogram() {
        // Phase 7bs: per-receiver histogram. Verify the label structure
        // (`{webhook="...",le="..."}`) and that the cumulative bucket
        // values are correctly accumulated from a non-trivial bucket
        // distribution.
        let mut hist_alerts = SemaphoreWaitHistogramSnapshot {
            buckets: [0; 7],
            count: 0,
        };
        // 3 observations under 1ms, 1 under 10ms, 0 elsewhere → totals of
        // 3 fast + 1 slow = 4. Order in `buckets` is: <=100µs, <=1ms,
        // <=10ms, <=100ms, <=1s, <=10s, +Inf.
        hist_alerts.buckets[1] = 3; // landed in <=1ms bucket
        hist_alerts.buckets[2] = 1; // landed in <=10ms bucket
        hist_alerts.count = 4;
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 0,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![(
                "alerts".into(),
                PerWebhookSnapshot {
                    dispatched_ok: 4,
                    dispatched_non_success: 0,
                    dispatched_ratelimited: 0,
                    delivery_errors: 0,
                    semaphore_wait_micros: 4_500, // 4.5ms total
                    semaphore_wait_hist: hist_alerts,
                    dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                },
            )],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        assert!(body.contains(
            "# TYPE iac_webhook_semaphore_wait_seconds_per_receiver histogram"
        ));
        // Cumulative buckets (3 + 1 = 4 below ≤10ms; 0 below ≤100µs).
        assert!(body.contains(
            "iac_webhook_semaphore_wait_seconds_per_receiver_bucket{webhook=\"alerts\",le=\"0.0001\"} 0"
        ));
        assert!(body.contains(
            "iac_webhook_semaphore_wait_seconds_per_receiver_bucket{webhook=\"alerts\",le=\"0.001\"} 3"
        ));
        assert!(body.contains(
            "iac_webhook_semaphore_wait_seconds_per_receiver_bucket{webhook=\"alerts\",le=\"0.01\"} 4"
        ));
        // +Inf bucket = total count.
        assert!(body.contains(
            "iac_webhook_semaphore_wait_seconds_per_receiver_bucket{webhook=\"alerts\",le=\"+Inf\"} 4"
        ));
        // _sum is microseconds-as-seconds (4500µs = 0.0045s).
        assert!(
            body.contains("iac_webhook_semaphore_wait_seconds_per_receiver_sum{webhook=\"alerts\"} 0.0045"),
            "body did not contain expected _sum line:\n{body}"
        );
        // _count = total observations.
        assert!(body.contains(
            "iac_webhook_semaphore_wait_seconds_per_receiver_count{webhook=\"alerts\"} 4"
        ));
    }

    #[test]
    fn render_prom_emits_per_receiver_semaphore_wait_counter() {
        // Phase 7bq: per-receiver semaphore_wait_microseconds_total
        // closes the deferred Phase 7bk metric. Operators dividing by
        // dispatched_ok_per_receiver_total get average wait per delivery
        // for that specific receiver.
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 0,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![
                (
                    "fast".into(),
                    PerWebhookSnapshot {
                        dispatched_ok: 10,
                        dispatched_non_success: 0,
                        dispatched_ratelimited: 0,
                        delivery_errors: 0,
                        semaphore_wait_micros: 250, semaphore_wait_hist: empty_hist(),
                        dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                    },
                ),
                (
                    "slow".into(),
                    PerWebhookSnapshot {
                        dispatched_ok: 5,
                        dispatched_non_success: 0,
                        dispatched_ratelimited: 0,
                        delivery_errors: 0,
                        semaphore_wait_micros: 1_500_000,
                        semaphore_wait_hist: empty_hist(),
                        dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                    },
                ),
            ],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        assert!(body.contains(
            "# TYPE iac_webhook_semaphore_wait_microseconds_per_receiver_total counter"
        ));
        assert!(body.contains(
            "iac_webhook_semaphore_wait_microseconds_per_receiver_total{webhook=\"fast\"} 250"
        ));
        assert!(body.contains(
            "iac_webhook_semaphore_wait_microseconds_per_receiver_total{webhook=\"slow\"} 1500000"
        ));
    }

    #[test]
    fn render_prom_escapes_label_values() {
        // Webhook names are operator-supplied; backslash + quote +
        // newline must be escaped per OpenMetrics text exposition.
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 0,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 0,
            semaphore_wait_hist: empty_hist(),
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![(
                "weird\"name\\with\nnewline".into(),
                PerWebhookSnapshot {
                    dispatched_ok: 1,
                    dispatched_non_success: 0,
                    dispatched_ratelimited: 0,
                    delivery_errors: 0, semaphore_wait_micros: 0, semaphore_wait_hist: empty_hist(),
                        dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
                },
            )],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        assert!(body.contains(
            "{webhook=\"weird\\\"name\\\\with\\nnewline\"} 1"
        ));
    }

    #[test]
    fn render_prom_emits_semaphore_wait_histogram_in_seconds() {
        // 7 buckets total: 100µs, 1ms, 10ms, 100ms, 1s, 10s, +Inf.
        // Distribution: 4 in 0.1ms bucket, 3 in 1ms, 2 in 10ms, 1 in 100ms,
        // 0 in 1s, 0 in 10s, 0 in +Inf. Total observations = 10.
        let hist = SemaphoreWaitHistogramSnapshot {
            buckets: [4, 3, 2, 1, 0, 0, 0],
            count: 10,
        };
        let webhook = WebhookMetricsSnapshot {
            dispatched_ok: 0,
            dispatched_non_success: 0,
            dispatched_ratelimited: 0,
            delivery_errors: 0,
            semaphore_wait_micros: 5_500, // 5.5ms total — for `_sum`.
            semaphore_wait_hist: hist,
            in_flight: 0,
            in_flight_peak: 0,
            dispatch_duration_micros: 0, dispatch_duration_hist: empty_hist(),
            per_webhook: vec![],
        };
        let body = render_prom(Some(&webhook), &rl(0, 0), &maint(0, 0, 0, 0));
        // Type marker.
        assert!(body.contains("# TYPE iac_webhook_semaphore_wait_seconds histogram"));
        // Buckets are cumulative: 4, 4+3=7, 7+2=9, 9+1=10, 10, 10, +Inf=10.
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"0.0001\"} 4"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"0.001\"} 7"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"0.01\"} 9"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"0.1\"} 10"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"1\"} 10"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"10\"} 10"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_bucket{le=\"+Inf\"} 10"));
        // Sum is in seconds (5500µs = 0.0055s).
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_sum 0.0055"));
        assert!(body.contains("iac_webhook_semaphore_wait_seconds_count 10"));
        // Legacy cumulative counter still present for backward compat.
        assert!(body.contains("iac_webhook_semaphore_wait_microseconds_total 5500"));
        // Phase 7bc: legacy name removed.
        assert!(
            !body.contains("iac_webhook_semaphore_wait_micros_total"),
            "legacy _micros_total name should be gone"
        );
    }
}
