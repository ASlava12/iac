//! Phase 7i: maintenance windows for operation submission.
//!
//! Operators declare `[[maintenance_windows]]` blocks in the server
//! config. Each names an `environment` (or `"*"` for all envs) and an
//! absolute `start`–`end` interval (RFC3339 timestamps). Submissions
//! during an active window are rejected with 503 + a `Retry-After`
//! header pointing at the window end so well-behaved CI scripts can
//! pause and retry.
//!
//! Recurring windows ("every Tuesday 02:00-04:00 UTC") and per-policy
//! freezes are out of scope here — the primitive is "this absolute
//! window is closed" and operators schedule each maintenance event
//! explicitly. That's deliberate: cron-style recurrence requires
//! teaching operators a syntax, and most maintenance windows are
//! one-shot events anyway.

use crate::error::{ApiError, ApiResult};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Phase 7ag: counters surfaced in `/v1/metrics`. `checks_total`
/// ticks on every submission past auth; `blocked_*` and
/// `bypassed_total` partition the count of submissions that ran into
/// an active window (one or the other will increment, never both —
/// bypass takes the admin escape, block takes the 503 path).
///
/// Phase 7ah splits the blocked counter by window type so dashboards
/// can answer "which kind of window blocked us most." `blocked_total`
/// stays as a backwards-compat alias = `absolute + recurring`.
///
/// Phase 7ai adds `misconfigured_windows` — a gauge of config entries
/// that failed to parse. Computed once at startup; nonzero means the
/// operator typo'd a window definition (and that window is silently
/// excluded from the check).
#[derive(Debug, Default)]
pub struct MaintenanceMetrics {
    pub checks_total: std::sync::atomic::AtomicU64,
    pub blocked_by_absolute_total: std::sync::atomic::AtomicU64,
    pub blocked_by_recurring_total: std::sync::atomic::AtomicU64,
    pub bypassed_total: std::sync::atomic::AtomicU64,
    pub misconfigured_windows: std::sync::atomic::AtomicU64,
    /// Phase 7bg: per-window block counters. Pre-populated at AppState
    /// construction from the configured window list so the hot path is
    /// `&HashMap` lookup + atomic increment, no locks. Key = `(kind,
    /// name)`; rendered with `{window_kind="...", window_name="..."}`
    /// labels in the metrics endpoint. Operators with multiple
    /// windows can finally tell which one is blocking submissions.
    pub per_window_blocked: std::collections::HashMap<(WindowKind, String), std::sync::atomic::AtomicU64>,
}

/// Phase 7bg: kind label for per-window counters. Two windows with
/// the same `name` in different kinds (one absolute, one recurring)
/// stay distinct via this discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowKind {
    Absolute,
    Recurring,
}

impl WindowKind {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::Recurring => "recurring",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceMetricsSnapshot {
    pub checks_total: u64,
    /// Backwards-compat alias for `absolute + recurring`. Existing
    /// dashboards keep working without changes.
    pub blocked_total: u64,
    pub blocked_by_absolute_total: u64,
    pub blocked_by_recurring_total: u64,
    pub bypassed_total: u64,
    /// Gauge: number of configured windows that fail to parse.
    /// Nonzero is a config bug — the operator should investigate.
    pub misconfigured_windows: u64,
    /// Phase 7bg: per-window block counters. Sorted by `(kind, name)`
    /// for deterministic Prom output across calls.
    pub per_window_blocked: Vec<PerWindowBlockedEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerWindowBlockedEntry {
    pub kind: WindowKind,
    pub name: String,
    pub count: u64,
}

impl MaintenanceMetrics {
    pub fn snapshot(&self) -> MaintenanceMetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let abs_blocked = self.blocked_by_absolute_total.load(Relaxed);
        let rec_blocked = self.blocked_by_recurring_total.load(Relaxed);
        // Phase 7bg: snapshot per-window counters in deterministic order
        // (kind first as enum discriminant, then name) so /v1/metrics
        // output is stable across calls. HashMap iteration would
        // otherwise be non-deterministic.
        let mut per_window: Vec<PerWindowBlockedEntry> = self
            .per_window_blocked
            .iter()
            .map(|((kind, name), c)| PerWindowBlockedEntry {
                kind: *kind,
                name: name.clone(),
                count: c.load(Relaxed),
            })
            .collect();
        per_window.sort_by(|a, b| (a.kind.as_label(), &a.name).cmp(&(b.kind.as_label(), &b.name)));
        MaintenanceMetricsSnapshot {
            checks_total: self.checks_total.load(Relaxed),
            blocked_total: abs_blocked + rec_blocked,
            blocked_by_absolute_total: abs_blocked,
            blocked_by_recurring_total: rec_blocked,
            bypassed_total: self.bypassed_total.load(Relaxed),
            misconfigured_windows: self.misconfigured_windows.load(Relaxed),
            per_window_blocked: per_window,
        }
    }

    /// Phase 7ai: scan the config and set the misconfigured-windows
    /// gauge to the count of entries that fail to parse. Called once
    /// at startup; SIGHUP reload (Phase 6i+) would re-run it.
    pub fn record_misconfigured_count(
        &self,
        absolute: &[MaintenanceWindow],
        recurring: &[RecurringMaintenanceWindow],
    ) {
        use std::sync::atomic::Ordering::Relaxed;
        let count = absolute.iter().filter(|w| w.parse().is_err()).count()
            + recurring.iter().filter(|w| w.parse().is_err()).count();
        self.misconfigured_windows
            .store(count as u64, Relaxed);
    }

    /// Phase 7bg: build the per-window counter map, one zero-valued
    /// entry per configured window. Returns a brand-new
    /// `MaintenanceMetrics` rather than mutating in place — `Default`
    /// gives an empty map and `MaintenanceMetrics` lives behind an
    /// `Arc` in `AppState`, so we shape it before wrapping.
    /// Misconfigured windows (those whose `parse()` fails) are
    /// excluded; they can't drive a block anyway.
    pub fn from_config(
        absolute: &[MaintenanceWindow],
        recurring: &[RecurringMaintenanceWindow],
    ) -> Self {
        let mut per_window: std::collections::HashMap<
            (WindowKind, String),
            std::sync::atomic::AtomicU64,
        > = std::collections::HashMap::new();
        for w in absolute {
            if w.parse().is_ok() {
                per_window
                    .entry((WindowKind::Absolute, w.name.clone()))
                    .or_default();
            }
        }
        for w in recurring {
            if w.parse().is_ok() {
                per_window
                    .entry((WindowKind::Recurring, w.name.clone()))
                    .or_default();
            }
        }
        let metrics = Self {
            per_window_blocked: per_window,
            ..Default::default()
        };
        metrics.record_misconfigured_count(absolute, recurring);
        metrics
    }

    /// Phase 7bg: increment the per-window counter for the matched
    /// window. Silently skips when the window name isn't registered —
    /// keeps tests passing without forcing every test to call
    /// `from_config` first, and a missing entry is a metric loss, not
    /// a correctness issue.
    pub fn record_window_block(&self, kind: WindowKind, name: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some(c) = self.per_window_blocked.get(&(kind, name.to_string())) {
            c.fetch_add(1, Relaxed);
        }
    }
}

/// Phase 7aj: structured per-entry detail for the
/// `/v1/admin/config-issues` endpoint. Operators pair this with the
/// `iac_maintenance_misconfigured_windows` gauge to see WHICH entries
/// are broken without grepping server logs.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigIssue {
    /// `"maintenance_window"` or `"recurring_maintenance_window"`.
    pub kind: String,
    /// Operator-supplied `name` field on the offending entry.
    pub name: String,
    /// Parser error message — same string the existing log line carries.
    pub error: String,
}

/// Phase 7bx: compute issues from a full Config — the ergonomic
/// wrapper used by AppState reload. Just dispatches to the more
/// specific `collect_config_issues`.
pub fn compute_config_issues(config: &crate::config::Config) -> Vec<ConfigIssue> {
    collect_config_issues(
        &config.maintenance_windows,
        &config.recurring_maintenance_windows,
    )
}

/// Build the issue list. Walks the existing parse functions and
/// extracts the error from the `Err` arm. Pure; no I/O.
pub fn collect_config_issues(
    absolute: &[MaintenanceWindow],
    recurring: &[RecurringMaintenanceWindow],
) -> Vec<ConfigIssue> {
    let mut out = Vec::new();
    for w in absolute {
        if let Err(e) = w.parse() {
            out.push(ConfigIssue {
                kind: "maintenance_window".into(),
                name: w.name.clone(),
                error: error_message(&e),
            });
        }
    }
    for w in recurring {
        if let Err(e) = w.parse() {
            out.push(ConfigIssue {
                kind: "recurring_maintenance_window".into(),
                name: w.name.clone(),
                error: error_message(&e),
            });
        }
    }
    out
}

/// `ApiError` doesn't expose its inner string directly. The parse
/// functions only ever produce `ApiError::Internal(msg)`, so unwrap
/// that variant; fall back to the `Display` impl for anything else.
fn error_message(e: &ApiError) -> String {
    match e {
        ApiError::Internal(msg) => msg.clone(),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceWindow {
    /// Operator-readable label. Surfaces in the 503 response so the
    /// rejected request gets a meaningful "why" string.
    pub name: String,
    /// Exact-match environment. Wildcard `"*"` matches any env. Defaults
    /// to `"*"` so a window without `environment` set fences everything.
    #[serde(default = "default_env")]
    pub environment: String,
    /// RFC3339 inclusive start.
    pub start: String,
    /// RFC3339 exclusive end. Must be > start.
    pub end: String,
}

fn default_env() -> String {
    "*".into()
}

impl MaintenanceWindow {
    /// Parse `start` / `end`. Returns `BadRequest` (so config-load
    /// surfaces the error) for unparseable timestamps or end <= start.
    pub fn parse(&self) -> ApiResult<(Timestamp, Timestamp)> {
        let start: Timestamp = self.start.parse().map_err(|e| {
            ApiError::Internal(format!("maintenance_window {}: bad start: {e}", self.name))
        })?;
        let end: Timestamp = self.end.parse().map_err(|e| {
            ApiError::Internal(format!("maintenance_window {}: bad end: {e}", self.name))
        })?;
        if end <= start {
            return Err(ApiError::Internal(format!(
                "maintenance_window {}: end must be > start",
                self.name
            )));
        }
        Ok((start, end))
    }
}

/// Phase 7s: weekly-recurring maintenance window. Mirrors the
/// absolute-window struct but expresses time-of-day + weekday set
/// instead of fixed start/end timestamps.
///
/// Phase 7ar: optional `timezone` field. Default behavior (`None` /
/// missing) interprets `start_hhmm` / `end_hhmm` and the weekday set
/// in UTC. Setting `timezone: "America/New_York"` makes the window
/// follow that zone, including DST transitions — the wall-clock
/// `02:00-04:00` shifts in absolute terms across a DST switch.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringMaintenanceWindow {
    pub name: String,
    #[serde(default = "default_env")]
    pub environment: String,
    /// Lowercased three-letter weekday names (`mon`, `tue`, …, `sun`).
    /// Empty list = every day.
    #[serde(default)]
    pub weekdays: Vec<String>,
    /// `HH:MM` inclusive start, interpreted in `timezone` (default UTC).
    pub start_hhmm: String,
    /// `HH:MM` exclusive end. Must be > start (no overnight wrap
    /// support for now — operators who need 22:00-02:00 split it into
    /// two windows: 22:00-23:59 + 00:00-02:00).
    pub end_hhmm: String,
    /// Phase 7ar: IANA timezone (`America/New_York`, `Europe/Moscow`,
    /// `UTC`, …). `None` / unset = UTC. Uses jiff's tzdb at runtime;
    /// names are validated at config-load via `RecurringMaintenanceWindow::parse`.
    #[serde(default)]
    pub timezone: Option<String>,
}

fn parse_hhmm(s: &str) -> Result<u32, String> {
    let (h, m) = s.split_once(':').ok_or_else(|| format!("expected HH:MM, got {s:?}"))?;
    let h: u32 = h.parse().map_err(|_| format!("bad hour {h:?}"))?;
    let m: u32 = m.parse().map_err(|_| format!("bad minute {m:?}"))?;
    if h >= 24 || m >= 60 {
        return Err(format!("HH:MM out of range: {s:?}"));
    }
    Ok(h * 60 + m)
}

fn parse_weekday(s: &str) -> Option<jiff::civil::Weekday> {
    use jiff::civil::Weekday::*;
    Some(match s.to_lowercase().as_str() {
        "mon" => Monday,
        "tue" => Tuesday,
        "wed" => Wednesday,
        "thu" => Thursday,
        "fri" => Friday,
        "sat" => Saturday,
        "sun" => Sunday,
        _ => return None,
    })
}

/// Parsed-and-validated form of a recurring window. Built once via
/// `RecurringMaintenanceWindow::parse`; callers re-use the `tz` Zoned
/// reference instead of re-resolving the IANA name on every check.
pub struct RecurringWindowParsed {
    pub start_min: u32,
    pub end_min: u32,
    pub days: Vec<jiff::civil::Weekday>,
    pub tz: jiff::tz::TimeZone,
}

impl RecurringMaintenanceWindow {
    /// Validate and resolve the human-facing fields into the form
    /// `check_recurring` consumes. Returns `Err` for malformed HH:MM,
    /// unknown weekdays, end ≤ start, or unknown timezone names.
    pub(crate) fn parse(&self) -> ApiResult<RecurringWindowParsed> {
        let start_min = parse_hhmm(&self.start_hhmm).map_err(|e| {
            ApiError::Internal(format!(
                "recurring_maintenance_window {}: bad start_hhmm: {e}",
                self.name
            ))
        })?;
        let end_min = parse_hhmm(&self.end_hhmm).map_err(|e| {
            ApiError::Internal(format!(
                "recurring_maintenance_window {}: bad end_hhmm: {e}",
                self.name
            ))
        })?;
        if end_min <= start_min {
            return Err(ApiError::Internal(format!(
                "recurring_maintenance_window {}: end_hhmm must be > start_hhmm \
                 (split overnight windows into two entries)",
                self.name
            )));
        }
        let mut days: Vec<jiff::civil::Weekday> = Vec::with_capacity(self.weekdays.len());
        for d in &self.weekdays {
            let Some(wd) = parse_weekday(d) else {
                return Err(ApiError::Internal(format!(
                    "recurring_maintenance_window {}: unknown weekday {d:?}",
                    self.name
                )));
            };
            days.push(wd);
        }
        let tz = match self.timezone.as_deref() {
            None | Some("") => jiff::tz::TimeZone::UTC,
            Some(name) => jiff::tz::TimeZone::get(name).map_err(|e| {
                ApiError::Internal(format!(
                    "recurring_maintenance_window {}: unknown timezone {name:?}: {e}",
                    self.name
                ))
            })?,
        };
        Ok(RecurringWindowParsed { start_min, end_min, days, tz })
    }
}

/// If `now` falls inside any window applicable to `environment`, return
/// a 503 with the appropriate `Retry-After`. Otherwise `Ok(())`.
/// Misconfigured windows (unparseable or end <= start) are skipped
/// silently — the alternative would be "broken config blocks all
/// submissions," which is the worst-of-both outcome.
///
/// Phase 7bg: pass the optional `metrics` so a match can record the
/// per-window block counter. `None` skips the recording — every
/// existing test passes `None`; production wires the AppState's metrics
/// arc through.
pub fn check(
    windows: &[MaintenanceWindow],
    environment: &str,
    now: Timestamp,
    metrics: Option<&MaintenanceMetrics>,
) -> ApiResult<()> {
    for w in windows {
        if w.environment != "*" && w.environment != environment {
            continue;
        }
        let Ok((start, end)) = w.parse() else { continue };
        if now >= start && now < end {
            if let Some(m) = metrics {
                m.record_window_block(WindowKind::Absolute, &w.name);
            }
            // Retry-After in seconds until the window closes. Saturating
            // to avoid panics on giant intervals; the cap below keeps it
            // friendly to clients that store the header in a u32.
            let retry_secs = end
                .duration_since(now)
                .as_secs()
                .clamp(1, 24 * 60 * 60);
            return Err(ApiError::ServiceUnavailable {
                reason: format!(
                    "maintenance window {:?} is active until {}",
                    w.name, w.end
                ),
                retry_after_secs: retry_secs as u64,
            });
        }
    }
    Ok(())
}

/// Phase 7s: same shape as `check` but for recurring windows. The
/// caller invokes both at the submit handler.
///
/// Phase 7ar: each window's `timezone` (default UTC) controls how the
/// HH:MM bounds + weekday set are interpreted. We re-zone `now` per
/// window so different windows can live in different timezones in the
/// same config.
pub fn check_recurring(
    windows: &[RecurringMaintenanceWindow],
    environment: &str,
    now: Timestamp,
    metrics: Option<&MaintenanceMetrics>,
) -> ApiResult<()> {
    for w in windows {
        if w.environment != "*" && w.environment != environment {
            continue;
        }
        let Ok(parsed) = w.parse() else { continue };
        let now_zoned = now.to_zoned(parsed.tz.clone());
        let now_minute = now_zoned.hour() as u32 * 60 + now_zoned.minute() as u32;
        let now_weekday = now_zoned.weekday();

        if !parsed.days.is_empty() && !parsed.days.contains(&now_weekday) {
            continue;
        }
        if now_minute >= parsed.start_min && now_minute < parsed.end_min {
            if let Some(m) = metrics {
                m.record_window_block(WindowKind::Recurring, &w.name);
            }
            // Retry-After: seconds left until the end of this window.
            // Computed in the window's local zone since DST can shift
            // the absolute boundary mid-window.
            let retry_minutes = parsed.end_min - now_minute;
            let retry_secs = retry_minutes as u64 * 60 + (60 - now_zoned.second() as u64);
            // Surface the configured timezone in the error message so
            // operators reading the 503 detail know which zone the time
            // refers to. Falls back to "UTC" when none is configured.
            let tz_label = w.timezone.as_deref().unwrap_or("UTC");
            return Err(ApiError::ServiceUnavailable {
                reason: format!(
                    "recurring maintenance window {:?} is active until {} {}",
                    w.name, w.end_hhmm, tz_label
                ),
                retry_after_secs: retry_secs.max(1),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(name: &str, env: &str, start: &str, end: &str) -> MaintenanceWindow {
        MaintenanceWindow {
            name: name.into(),
            environment: env.into(),
            start: start.into(),
            end: end.into(),
        }
    }

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn record_misconfigured_count_counts_unparseable_entries() {
        // Phase 7ai: gauge reflects the number of broken config
        // entries — operators alert on `> 0`.
        let m = MaintenanceMetrics::default();
        let abs = vec![
            w("good", "prod", "2026-05-01T02:00:00Z", "2026-05-01T04:00:00Z"),
            w("bad-start", "prod", "not-a-time", "2026-05-01T04:00:00Z"),
            w(
                "inverted",
                "prod",
                "2026-05-01T04:00:00Z",
                "2026-05-01T02:00:00Z",
            ),
        ];
        let rec = vec![
            rw("good", "prod", &["mon"], "02:00", "04:00"),
            rw("bad-hhmm", "prod", &["mon"], "not-a-time", "04:00"),
            rw("bad-day", "prod", &["munday"], "02:00", "04:00"),
        ];
        m.record_misconfigured_count(&abs, &rec);
        // 2 absolute (bad-start + inverted) + 2 recurring
        // (bad-hhmm + bad-day) = 4 misconfigured.
        assert_eq!(m.snapshot().misconfigured_windows, 4);
    }

    #[test]
    fn from_config_pre_registers_zero_counters_for_each_valid_window() {
        // Phase 7bg: from_config seeds the per_window map; the snapshot
        // returns one entry per valid window, all with count=0 until a
        // block actually fires.
        let abs = vec![
            w("freeze-q4", "prod", "2026-05-01T02:00:00Z", "2026-05-01T04:00:00Z"),
            // misconfigured — must be excluded from the per_window map
            w("bad-start", "prod", "not-a-time", "2026-05-01T04:00:00Z"),
        ];
        let rec = vec![rw("weekend", "*", &["sat", "sun"], "00:00", "23:59")];
        let m = MaintenanceMetrics::from_config(&abs, &rec);
        let entries = m.snapshot().per_window_blocked;
        // freeze-q4 + weekend; bad-start excluded.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "freeze-q4" && e.count == 0));
        assert!(entries.iter().any(|e| e.name == "weekend" && e.count == 0));
        // Misconfigured count still ticks as before.
        assert_eq!(m.snapshot().misconfigured_windows, 1);
    }

    #[test]
    fn check_records_per_window_block() {
        // Phase 7bg: a check that hits an absolute window must
        // increment the per-window counter for that name (and not the
        // counters for any other window).
        let abs = vec![
            w("freeze-a", "prod", "2026-05-01T02:00:00Z", "2026-05-01T04:00:00Z"),
            w("freeze-b", "prod", "2026-05-01T05:00:00Z", "2026-05-01T07:00:00Z"),
        ];
        let m = MaintenanceMetrics::from_config(&abs, &[]);
        let _ = check(&abs, "prod", ts("2026-05-01T03:00:00Z"), Some(&m));
        let entries = m.snapshot().per_window_blocked;
        let a = entries.iter().find(|e| e.name == "freeze-a").unwrap();
        assert_eq!(a.count, 1, "freeze-a should have ticked");
        let b = entries.iter().find(|e| e.name == "freeze-b").unwrap();
        assert_eq!(b.count, 0, "freeze-b should NOT have ticked");
    }

    #[test]
    fn check_recurring_records_per_window_block() {
        // Phase 7bg: same coverage for the recurring path.
        let rec = vec![
            rw("monday-window", "prod", &["mon"], "02:00", "04:00"),
            rw("tuesday-window", "prod", &["tue"], "02:00", "04:00"),
        ];
        let m = MaintenanceMetrics::from_config(&[], &rec);
        // 2026-05-04 is a Monday, 03:00Z = within monday-window.
        let _ = check_recurring(&rec, "prod", ts("2026-05-04T03:00:00Z"), Some(&m));
        let entries = m.snapshot().per_window_blocked;
        assert_eq!(
            entries.iter().find(|e| e.name == "monday-window").unwrap().count,
            1
        );
        assert_eq!(
            entries.iter().find(|e| e.name == "tuesday-window").unwrap().count,
            0
        );
    }

    #[test]
    fn record_window_block_skips_unregistered_names() {
        // Phase 7bg: an unregistered name (e.g., a window the config
        // dropped after the metrics were built) silently no-ops rather
        // than panicking. Operators get one stale row in the snapshot
        // until the next reload, but the metric-recording side stays
        // safe.
        let m = MaintenanceMetrics::default(); // empty per_window
        m.record_window_block(WindowKind::Absolute, "ghost");
        // No panic; snapshot has no row.
        assert!(m.snapshot().per_window_blocked.is_empty());
    }

    #[test]
    fn no_windows_allows_everything() {
        assert!(check(&[], "prod", ts("2026-05-01T12:00:00Z"), None).is_ok());
    }

    #[test]
    fn outside_window_allows() {
        let win = vec![w(
            "may-1",
            "prod",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        // Before window
        assert!(check(&win, "prod", ts("2026-05-01T01:00:00Z"), None).is_ok());
        // After window
        assert!(check(&win, "prod", ts("2026-05-01T05:00:00Z"), None).is_ok());
    }

    #[test]
    fn inside_window_rejects_with_retry_after() {
        let win = vec![w(
            "tuesday",
            "prod",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        let err = check(&win, "prod", ts("2026-05-01T03:00:00Z"), None).unwrap_err();
        match err {
            ApiError::ServiceUnavailable { reason, retry_after_secs } => {
                assert!(reason.contains("tuesday"), "reason: {reason}");
                // 1 hour left in the window.
                assert!(retry_after_secs > 0);
                assert!(retry_after_secs <= 60 * 60);
            }
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_environment_matches_all() {
        let win = vec![w(
            "global",
            "*",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        assert!(check(&win, "prod", ts("2026-05-01T03:00:00Z"), None).is_err());
        assert!(check(&win, "stage", ts("2026-05-01T03:00:00Z"), None).is_err());
    }

    #[test]
    fn environment_specific_window_doesnt_block_other_envs() {
        let win = vec![w(
            "prod-only",
            "prod",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        assert!(check(&win, "stage", ts("2026-05-01T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn end_is_exclusive() {
        // At exactly the end time, the window is over.
        let win = vec![w(
            "exact-end",
            "prod",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        assert!(check(&win, "prod", ts("2026-05-01T04:00:00Z"), None).is_ok());
    }

    #[test]
    fn start_is_inclusive() {
        // At exactly the start time, the window is active.
        let win = vec![w(
            "exact-start",
            "prod",
            "2026-05-01T02:00:00Z",
            "2026-05-01T04:00:00Z",
        )];
        assert!(check(&win, "prod", ts("2026-05-01T02:00:00Z"), None).is_err());
    }

    #[test]
    fn malformed_window_is_skipped_not_blocking() {
        let win = vec![
            w("bad", "prod", "not-a-timestamp", "2026-05-01T04:00:00Z"),
            w(
                "good",
                "prod",
                "2026-05-01T02:00:00Z",
                "2026-05-01T04:00:00Z",
            ),
        ];
        // Good window still enforced.
        assert!(check(&win, "prod", ts("2026-05-01T03:00:00Z"), None).is_err());
        // Bad window doesn't block when no good window is in effect.
        assert!(check(&win[..1], "prod", ts("2026-05-01T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn end_le_start_skipped() {
        let win = vec![w(
            "inverted",
            "prod",
            "2026-05-01T04:00:00Z",
            "2026-05-01T02:00:00Z",
        )];
        // 03:00 is between start (04:00) and end (02:00) — but inverted
        // is invalid; should skip silently.
        assert!(check(&win, "prod", ts("2026-05-01T03:00:00Z"), None).is_ok());
    }

    fn rw(name: &str, env: &str, weekdays: &[&str], start: &str, end: &str) -> RecurringMaintenanceWindow {
        RecurringMaintenanceWindow {
            name: name.into(),
            environment: env.into(),
            weekdays: weekdays.iter().map(|s| s.to_string()).collect(),
            start_hhmm: start.into(),
            end_hhmm: end.into(),
            timezone: None,
        }
    }

    fn rw_tz(
        name: &str,
        env: &str,
        weekdays: &[&str],
        start: &str,
        end: &str,
        tz: &str,
    ) -> RecurringMaintenanceWindow {
        RecurringMaintenanceWindow {
            name: name.into(),
            environment: env.into(),
            weekdays: weekdays.iter().map(|s| s.to_string()).collect(),
            start_hhmm: start.into(),
            end_hhmm: end.into(),
            timezone: Some(tz.into()),
        }
    }

    #[test]
    fn recurring_no_windows_allows() {
        assert!(check_recurring(&[], "prod", ts("2026-05-04T10:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_inside_window_blocks() {
        // 2026-05-04 is a Monday. Window: Mondays 02:00-04:00.
        let win = vec![rw("mon-2-4", "prod", &["mon"], "02:00", "04:00")];
        let err = check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).unwrap_err();
        if let ApiError::ServiceUnavailable { reason, retry_after_secs } = err {
            assert!(reason.contains("mon-2-4"), "reason: {reason}");
            // ~1 hour left in the window. The seconds calculation rolls
            // up to the next minute boundary, so the upper bound is a
            // bit over 60 minutes.
            assert!(
                retry_after_secs > 0 && retry_after_secs <= 65 * 60,
                "retry_after_secs={retry_after_secs}"
            );
        } else {
            panic!("expected ServiceUnavailable");
        }
    }

    #[test]
    fn recurring_outside_window_allows() {
        let win = vec![rw("mon-2-4", "prod", &["mon"], "02:00", "04:00")];
        // Same day, after the window.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T05:00:00Z"), None).is_ok());
        // Earlier same day.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T01:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_wrong_weekday_allows() {
        // Window targets Monday; check on Tuesday.
        let win = vec![rw("mon-only", "prod", &["mon"], "02:00", "04:00")];
        // 2026-05-05 is Tuesday.
        assert!(check_recurring(&win, "prod", ts("2026-05-05T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_empty_weekdays_means_every_day() {
        let win = vec![rw("daily", "prod", &[], "02:00", "04:00")];
        // Both Monday and Saturday should match at the right time.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_err()); // Mon
        assert!(check_recurring(&win, "prod", ts("2026-05-09T03:00:00Z"), None).is_err()); // Sat
    }

    #[test]
    fn recurring_environment_specific() {
        let win = vec![rw("prod-only", "prod", &[], "02:00", "04:00")];
        assert!(check_recurring(&win, "stage", ts("2026-05-04T03:00:00Z"), None).is_ok());
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_err());
    }

    #[test]
    fn recurring_wildcard_environment() {
        let win = vec![rw("global", "*", &[], "02:00", "04:00")];
        assert!(check_recurring(&win, "stage", ts("2026-05-04T03:00:00Z"), None).is_err());
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_err());
    }

    #[test]
    fn recurring_malformed_window_skipped() {
        let win = vec![
            rw("bad", "prod", &["mon"], "not-time", "04:00"),
            rw("good", "prod", &["mon"], "02:00", "04:00"),
        ];
        // Good window still enforced.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_err());
        // Bad window alone doesn't block anything.
        assert!(check_recurring(&win[..1], "prod", ts("2026-05-04T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_unknown_weekday_skipped() {
        let win = vec![rw("typo", "prod", &["munday"], "02:00", "04:00")];
        // Window with unknown weekday is misconfigured → silently skipped.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_end_le_start_skipped() {
        // Reject overnight wrap by silently skipping; operators get a
        // green submit rather than a misleading 503.
        let win = vec![rw("inverted", "prod", &[], "04:00", "02:00")];
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_explicit_utc_matches_default() {
        // `timezone: "UTC"` should behave identically to `timezone: None`.
        let utc_implicit = vec![rw("a", "prod", &[], "02:00", "04:00")];
        let utc_explicit = vec![rw_tz("a", "prod", &[], "02:00", "04:00", "UTC")];
        let now = ts("2026-05-04T03:00:00Z");
        assert!(check_recurring(&utc_implicit, "prod", now, None).is_err());
        assert!(check_recurring(&utc_explicit, "prod", now, None).is_err());
        let outside = ts("2026-05-04T05:00:00Z");
        assert!(check_recurring(&utc_implicit, "prod", outside, None).is_ok());
        assert!(check_recurring(&utc_explicit, "prod", outside, None).is_ok());
    }

    #[test]
    fn recurring_window_in_eastern_time_blocks_at_local_wallclock() {
        // Window: every day 02:00-04:00 New_York time.
        // 2026-05-04 06:30Z = 02:30 EDT (DST active in May, UTC-4).
        // Inside the window → must block.
        let win = vec![rw_tz("ny-2-4", "prod", &[], "02:00", "04:00", "America/New_York")];
        let inside_ny = ts("2026-05-04T06:30:00Z");
        let err = check_recurring(&win, "prod", inside_ny, None).unwrap_err();
        match err {
            ApiError::ServiceUnavailable { reason, .. } => {
                assert!(reason.contains("America/New_York"), "reason: {reason}");
                assert!(reason.contains("ny-2-4"), "reason: {reason}");
            }
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }
        // Same UTC instant, but at 06:30Z the SAME UTC time is 02:30 EDT —
        // so we use a different UTC instant for the "outside" case:
        // 2026-05-04 12:00Z = 08:00 EDT, well past the window.
        assert!(check_recurring(&win, "prod", ts("2026-05-04T12:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_window_in_eastern_time_passes_under_utc_interpretation() {
        // Same wallclock window, but interpreted as UTC. At 02:30 EDT
        // (06:30Z) the UTC view says it's 06:30, well past 04:00 UTC.
        // Expect Ok: under the UTC interpretation, we're outside the window.
        let win = vec![rw("utc-2-4", "prod", &[], "02:00", "04:00")];
        assert!(check_recurring(&win, "prod", ts("2026-05-04T06:30:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_unknown_timezone_skipped() {
        // Like other malformed-window cases: silently skipped, no 503.
        let win = vec![rw_tz(
            "bad-tz",
            "prod",
            &[],
            "02:00",
            "04:00",
            "Atlantis/Lost_City",
        )];
        assert!(check_recurring(&win, "prod", ts("2026-05-04T03:00:00Z"), None).is_ok());
    }

    #[test]
    fn recurring_weekday_uses_local_zone_not_utc() {
        // Saturday 23:30 Asia/Tokyo (UTC+9) = Saturday 14:30Z.
        // Window: Saturdays 23:00-23:59 Asia/Tokyo.
        // The weekday check must consult the LOCAL day, otherwise the
        // boundary case at the dateline gets the wrong answer.
        let win = vec![rw_tz(
            "tokyo-late-sat",
            "prod",
            &["sat"],
            "23:00",
            "23:59",
            "Asia/Tokyo",
        )];
        // 2026-05-09 14:30Z = 23:30 JST on Saturday → block.
        assert!(check_recurring(&win, "prod", ts("2026-05-09T14:30:00Z"), None).is_err());
        // 2026-05-09 13:30Z = 22:30 JST Sat → outside window.
        assert!(check_recurring(&win, "prod", ts("2026-05-09T13:30:00Z"), None).is_ok());
        // 2026-05-09 15:00Z = 00:00 JST Sun → wrong weekday, even though
        // it's still Saturday in UTC.
        assert!(check_recurring(&win, "prod", ts("2026-05-09T15:00:00Z"), None).is_ok());
    }

    #[test]
    fn first_matching_window_wins() {
        // Multiple windows active simultaneously — the first one's
        // name surfaces in the error. The others are immaterial.
        let win = vec![
            w(
                "first",
                "prod",
                "2026-05-01T02:00:00Z",
                "2026-05-01T04:00:00Z",
            ),
            w(
                "second",
                "prod",
                "2026-05-01T03:00:00Z",
                "2026-05-01T05:00:00Z",
            ),
        ];
        let err = check(&win, "prod", ts("2026-05-01T03:30:00Z"), None).unwrap_err();
        if let ApiError::ServiceUnavailable { reason, .. } = err {
            assert!(reason.contains("first"), "reason: {reason}");
        } else {
            panic!("expected ServiceUnavailable");
        }
    }
}
