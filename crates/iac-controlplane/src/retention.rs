//! Phase 6g: periodic data pruning.
//!
//! `audit_events`, `observations`, resolved `drift_events`, terminal
//! `assignments`, and expired `user_tokens` all grow unboundedly without
//! intervention. This module wires a tokio task that periodically deletes
//! rows older than configured retention windows. Defaults are conservative
//! (30-90 days) so existing operators don't lose forensic data on first
//! upgrade — they have to opt into shorter windows.

use crate::error::ApiResult;
use crate::store::{Store, sql};
use jiff::{Span, Timestamp};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Drop audit rows older than this many days.
    #[serde(default = "default_audit_days")]
    pub audit_days: u32,
    /// Drop observations older than this many days.
    #[serde(default = "default_observation_days")]
    pub observation_days: u32,
    /// Phase 7an: cap observations per (agent, resource) to this many of
    /// the newest rows. The cap runs *after* the age-based prune so
    /// combining the two just trims further; you don't lose history
    /// older than `observation_days` because of it.
    ///
    /// Phase 9-F1-fix-2 (real-fleet finding): default raised from `0`
    /// (disabled) to `50`. With the previous default, F1's 7-agent
    /// 24h soak grew the `observations` table to 10.6 M rows in 4 h
    /// and filled the 8.5 GB CP disk. 50 newest per (agent, resource)
    /// gives ample debugging headroom (the most-recent state delta
    /// for every resource on every agent) while keeping disk bounded:
    /// 7 agents × 2 000 resources × 50 = 700 K rows ≈ 500 MB
    /// steady-state, regardless of soak duration.
    #[serde(default = "default_observation_max_per_resource")]
    pub observation_max_per_resource: u32,
    /// Drop resolved drift events older than this many days. Open events
    /// (resolved_at IS NULL) are never pruned.
    #[serde(default = "default_drift_days")]
    pub drift_resolved_days: u32,
    /// Drop assignments in terminal status older than this many days.
    /// "Terminal" = `succeeded`, `failed`, `partially_applied`. Pending /
    /// fetched are kept.
    #[serde(default = "default_assignment_days")]
    pub assignment_terminal_days: u32,
    /// Phase 9-F1-fix-12: cap `desired_states` per `resource_id` to
    /// this many of the newest rows. The assignment-fetch SELECT
    /// projects current state by scanning `desired_states`; without
    /// a cap the table grows linearly (one row per
    /// (operation, resource)) and the SELECT plan deteriorates
    /// past ~150 k rows. F1 72h soak hit this knee at h+55,
    /// driving the tail-latency events that showed up as 0.01 %
    /// failure rate near the end of the soak.
    ///
    /// Default 10 — mirrors `observation_max_per_resource`'s
    /// rationale (the most recent applied state per resource is
    /// what callers actually read; older revisions are
    /// debugging-history that retention can prune). 1400 resources
    /// × cap 10 ≈ 14 k steady-state rows, two orders of magnitude
    /// below the 150 k knee.
    #[serde(default = "default_desired_state_max_per_resource")]
    pub desired_state_max_per_resource: u32,
    /// How often to run the prune loop, in seconds.
    ///
    /// Phase 9-F1-fix-2: default lowered from 3600 (1 h) to 300 (5 min).
    /// Hourly pruning is fine for `audit_events` / `assignments`, but
    /// `observations` accumulate too fast on a busy fleet — at 7
    /// agents × 2 000 resources × 1 obs / poll-cycle (~70 s) that's
    /// 720 K obs/h, and waiting an hour means a half-gigabyte of
    /// short-lived data sits in the DB before the cap fires. 5 min
    /// keeps the working set small enough that the per-resource cap
    /// quickly converges to its 50-row target.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
}

fn default_audit_days() -> u32 {
    90
}
fn default_observation_days() -> u32 {
    30
}
fn default_drift_days() -> u32 {
    30
}
fn default_assignment_days() -> u32 {
    30
}
fn default_interval_secs() -> u64 {
    // Phase 9-F1-fix-7 (gap-#7 from F1 #7, 2026-05-11): kept at
    // 300 (was bumped to 60 in fix-6, then reverted).
    //
    // The fix-6 hypothesis was: 5-min cadence lets observations
    // accumulate too much between prunes; shrink the cadence to
    // 1 min for smaller bursts. Reality on F1 #7: 1-min cadence
    // makes the retention DELETE itself a continuous competitor
    // for the SQLite write path. Slow-statement breakdown around
    // the F1 #7 peak (h11-h13 UTC, when failure rate hit 50 %):
    //
    //     4220 × INSERT INTO observations slow
    //      478 × DELETE FROM observations slow
    //      876 × INSERT INTO operations slow
    //
    // The DELETE-from-observations slow-count is the smoking gun:
    // every minute, a fresh retention pass tries to DELETE rows
    // by per-(agent, resource) cap; with 5 000 resources/agent
    // × 7 agents that's a hot DELETE against the busiest table,
    // blocking concurrent INSERTs. Reverting to 5 min lets one
    // batch finish before the next starts; the WAL bump to
    // 1 GiB (fix-6) gives the per-burst working set headroom.
    //
    // Pair this with DELETE chunking (fix-7, in the per-resource
    // cap path) so a single retention pass doesn't lock the
    // table for the whole pruning window either.
    300
}
fn default_desired_state_max_per_resource() -> u32 {
    // Phase 9-F1-fix-12 (gap-#12 from F1 72h, 2026-05-25): cap
    // desired_states per resource_id. F1 baseline (24h) at
    // ~27 k desired_states held fine; 72h at ~250 k started
    // crossing the SELECT slow threshold around h+55. Cap=10
    // bounds steady-state at 14 k for the trial's 1400-resource
    // pool — far below the 150 k knee.
    10
}
fn default_observation_max_per_resource() -> u32 {
    // Phase 9-F1-fix-8 (gap-#8 from F1 #8, 2026-05-13): lowered
    // from 50 to 10. The 50-row-per-resource cap was set in fix-2
    // for "ample debugging headroom"; F1 #8 showed the per-cap
    // working set scales with fleet × resources × cap, and at
    // fleet=7 × resources=5800 × cap=50 = 2 M rows steady-state,
    // SQLite single-writer throughput knees out: agents pushing
    // observations every poll cycle vs retention DELETE-ing
    // 600 K stale rows per pass = lock contention even with the
    // fix-7 chunking. Cap=10 shrinks steady-state 5× (to ~400 K),
    // keeping the working set well inside SQLite's
    // comfort zone. Debugging-history loss is acceptable: the most
    // recent observation per resource is always preserved, which
    // is what drift detection actually consumes.
    10
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            audit_days: default_audit_days(),
            observation_days: default_observation_days(),
            drift_resolved_days: default_drift_days(),
            assignment_terminal_days: default_assignment_days(),
            interval_secs: default_interval_secs(),
            observation_max_per_resource: default_observation_max_per_resource(),
            desired_state_max_per_resource: default_desired_state_max_per_resource(),
        }
    }
}

impl RetentionConfig {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct PruneStats {
    pub audit: u64,
    pub observations: u64,
    pub drift_resolved: u64,
    pub assignments_terminal: u64,
    pub user_tokens_expired: u64,
    /// Phase 7an: rows dropped by the per-resource cap. Tracked separately
    /// from `observations` so operators can see how much each policy
    /// contributes; sum into `total` for the overall pass count.
    pub observations_per_resource: u64,
    /// Phase 9-F1-fix-12: rows dropped by the desired_states
    /// per-resource cap. Same shape as `observations_per_resource`.
    pub desired_states_per_resource: u64,
}

impl PruneStats {
    pub fn total(&self) -> u64 {
        self.audit
            + self.observations
            + self.drift_resolved
            + self.assignments_terminal
            + self.user_tokens_expired
            + self.observations_per_resource
            + self.desired_states_per_resource
    }
}

/// Run a single prune pass. Each delete is its own statement so a failure
/// in one table doesn't roll back others — best-effort pruning.
pub async fn prune_once(store: &Store, config: &RetentionConfig) -> ApiResult<PruneStats> {
    let mut stats = PruneStats::default();
    if config.audit_days > 0 {
        stats.audit = delete_older_than(
            store,
            "audit_events",
            "timestamp",
            i64::from(config.audit_days),
        )
        .await?;
    }
    if config.observation_days > 0 {
        stats.observations = delete_older_than(
            store,
            "observations",
            "received_at",
            i64::from(config.observation_days),
        )
        .await?;
    }
    if config.observation_max_per_resource > 0 {
        stats.observations_per_resource =
            prune_observations_per_resource(store, i64::from(config.observation_max_per_resource))
                .await?;
    }
    if config.desired_state_max_per_resource > 0 {
        stats.desired_states_per_resource = prune_desired_states_per_resource(
            store,
            i64::from(config.desired_state_max_per_resource),
        )
        .await?;
    }
    if config.drift_resolved_days > 0 {
        stats.drift_resolved = delete_older_than_with_filter(
            store,
            "drift_events",
            "resolved_at",
            i64::from(config.drift_resolved_days),
            "resolved_at IS NOT NULL",
        )
        .await?;
    }
    if config.assignment_terminal_days > 0 {
        stats.assignments_terminal = delete_older_than_with_filter(
            store,
            "assignments",
            "completed_at",
            i64::from(config.assignment_terminal_days),
            "completed_at IS NOT NULL AND \
             status IN ('succeeded', 'failed', 'partially_applied')",
        )
        .await?;
    }
    stats.user_tokens_expired = store.prune_expired_tokens().await?;
    Ok(stats)
}

async fn delete_older_than(store: &Store, table: &str, column: &str, days: i64) -> ApiResult<u64> {
    let cutoff = cutoff_string(days);
    let q = format!("DELETE FROM {table} WHERE {column} < ?");
    let res = sqlx::query(&store.sql(&q))
        .bind(cutoff)
        .execute(store.pool())
        .await?;
    Ok(res.rows_affected())
}

async fn delete_older_than_with_filter(
    store: &Store,
    table: &str,
    column: &str,
    days: i64,
    extra_filter: &str,
) -> ApiResult<u64> {
    let cutoff = cutoff_string(days);
    let q = format!("DELETE FROM {table} WHERE {extra_filter} AND {column} < ?");
    let res = sqlx::query(&store.sql(&q))
        .bind(cutoff)
        .execute(store.pool())
        .await?;
    Ok(res.rows_affected())
}

/// Phase 7an: keep at most `max_per_resource` observations per
/// (agent_id, resource_id), dropping the oldest. Uses `ROW_NUMBER`
/// window-function partitioning, which both SQLite (3.25+) and Postgres
/// support; sqlx::Any passes the SQL through unchanged.
///
/// Tied `observed_at` values are broken by `id DESC` so the higher-id
/// (later-inserted) row always wins — agents that submit batches with
/// identical observed_at don't see arbitrary survivors.
async fn prune_observations_per_resource(store: &Store, max_per_resource: i64) -> ApiResult<u64> {
    // Phase 9-F1-fix-7 (gap-#7 from F1 #7, 2026-05-11): chunked DELETE.
    //
    // The single all-at-once `DELETE FROM observations WHERE id IN
    // (huge subquery)` held a write lock on the table for the entire
    // pruning window, blocking concurrent INSERTs / UPDATEs from the
    // agent fan-out. On F1 #7's load (~600 K candidate rows per pass)
    // each pass blocked the write path for seconds, throttling
    // legitimate observation pushes and pushing the failure rate
    // up to 50 % at peak.
    //
    // Chunked approach: cap each DELETE at CHUNK_SIZE rows; loop
    // until no more candidates. Each chunk is a short transaction
    // that other writers can interleave with. The 50 ms sleep
    // between chunks gives the WAL writer time to commit + checkpoint
    // queued frames between locks — without it, retention still
    // dominates the write path even with small chunks.
    const CHUNK_SIZE: i64 = 5_000;
    const INTER_CHUNK_PAUSE_MS: u64 = 50;
    let q = "DELETE FROM observations
             WHERE id IN (
                 SELECT id FROM (
                     SELECT id,
                            ROW_NUMBER() OVER (
                                PARTITION BY agent_id, resource_id
                                ORDER BY observed_at DESC, id DESC
                            ) AS rn
                     FROM observations
                 ) AS ranked
                 WHERE rn > ?
                 LIMIT ?
             )";
    let mut total = 0u64;
    loop {
        let res = sqlx::query(&store.sql(q))
            .bind(max_per_resource)
            .bind(CHUNK_SIZE)
            .execute(store.pool())
            .await?;
        let n = res.rows_affected();
        total += n;
        if n < CHUNK_SIZE as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(INTER_CHUNK_PAUSE_MS)).await;
    }
    Ok(total)
}

/// Phase 9-F1-fix-12 (gap-#12 from F1 72h, 2026-05-25): keep at
/// most `max_per_resource` desired_states rows per `resource_id`,
/// dropping the oldest by `id` (autoincrement → chronological).
/// Same shape as `prune_observations_per_resource`: ROW_NUMBER
/// window over partitions, chunked DELETE with 50 ms pause to
/// avoid blocking writers.
///
/// The assignment-fetch SELECT crosses its 1 s slow-statement
/// threshold around 150 k desired_states rows. Default cap=10
/// × 1400 trial resources holds steady-state at 14 k, two orders
/// of magnitude below the knee.
async fn prune_desired_states_per_resource(store: &Store, max_per_resource: i64) -> ApiResult<u64> {
    const CHUNK_SIZE: i64 = 5_000;
    const INTER_CHUNK_PAUSE_MS: u64 = 50;
    let q = "DELETE FROM desired_states
             WHERE id IN (
                 SELECT id FROM (
                     SELECT id,
                            ROW_NUMBER() OVER (
                                PARTITION BY resource_id
                                ORDER BY id DESC
                            ) AS rn
                     FROM desired_states
                 ) AS ranked
                 WHERE rn > ?
                 LIMIT ?
             )";
    let mut total = 0u64;
    loop {
        let res = sqlx::query(&store.sql(q))
            .bind(max_per_resource)
            .bind(CHUNK_SIZE)
            .execute(store.pool())
            .await?;
        let n = res.rows_affected();
        total += n;
        if n < CHUNK_SIZE as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(INTER_CHUNK_PAUSE_MS)).await;
    }
    Ok(total)
}

fn cutoff_string(days: i64) -> String {
    // Timestamp arithmetic only supports hours-and-smaller in jiff (no
    // calendar units), so we expand days → hours.
    let hours = days.saturating_mul(24);
    Timestamp::now()
        .checked_sub(Span::new().try_hours(hours).unwrap_or_default())
        .unwrap_or_else(|_| Timestamp::now())
        .to_string()
}

/// Spawn the background prune loop. Returns the JoinHandle; the caller
/// abort()s it on shutdown. Keeps running across individual prune failures —
/// they're logged and the next tick retries.
pub fn spawn_loop(
    store: Store,
    config: RetentionConfig,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick — give the server a beat to come up.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!("retention loop shutting down");
                    break;
                }
                _ = ticker.tick() => {
                    match prune_once(&store, &config).await {
                        Ok(stats) if stats.total() > 0 => {
                            tracing::info!(
                                audit = stats.audit,
                                observations = stats.observations,
                                observations_per_resource = stats.observations_per_resource,
                                drift = stats.drift_resolved,
                                assignments = stats.assignments_terminal,
                                tokens = stats.user_tokens_expired,
                                "retention pass deleted rows"
                            );
                        }
                        Ok(_) => tracing::debug!("retention pass no-op"),
                        Err(e) => tracing::error!(error = %e, "retention pass failed"),
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config as ServerConfig;
    use tempfile::TempDir;

    async fn store_in(dir: &TempDir) -> Store {
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: format!("sqlite://{}/t.db?mode=rwc", dir.path().display()),
            state_dir: dir.path().to_path_buf(),
            max_body_bytes: 1 << 20,
            admin_token: None,
            policies: vec![],
            retention: RetentionConfig::default(),
            rate_limit: crate::rate_limit::RateLimitConfig::default(),
            maintenance_windows: vec![],
            recurring_maintenance_windows: vec![],
            webhooks: crate::webhook::WebhooksConfig::default(),
            tls: crate::tls::TlsConfig::default(),
            secrets: crate::config::SecretsConfig::default(),
            retry_after_format: crate::config::RetryAfterFormat::default(),
            modules: vec![],
            agent_token_ttl_secs: None,
            ssh_targets: vec![],
            wal_checkpoint_interval_secs: 0,
            shutdown_timeout_secs: 1,
            trusted_proxies: vec![],
        };
        Store::connect(&cfg.database_url).await.unwrap()
    }

    async fn insert_audit(store: &Store, timestamp: &str) {
        sqlx::query(&sql("INSERT INTO audit_events
                (timestamp, actor, kind, severity, payload_json)
             VALUES (?, 'admin', 'test', 'info', '{}')"))
        .bind(timestamp)
        .execute(store.pool())
        .await
        .unwrap();
    }

    fn ago(days: i64) -> String {
        Timestamp::now()
            .checked_sub(Span::new().try_hours(days * 24).unwrap())
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn audit_prune_drops_old_keeps_new() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;

        insert_audit(&store, &ago(120)).await; // older than default 90d
        insert_audit(&store, &ago(60)).await; // within 90d
        insert_audit(&store, &ago(1)).await; // very recent

        let cfg = RetentionConfig::default();
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.audit, 1);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM audit_events"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 2);
    }

    #[tokio::test]
    async fn observations_prune_uses_received_at() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        // Need a registered agent for the FK.
        sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at)
             VALUES ('a1', 'agent-a', 'test', 'h', ?)",
        ))
        .bind(ago(0))
        .execute(store.pool())
        .await
        .unwrap();

        sqlx::query(&sql(
            "INSERT INTO observations
                (agent_id, resource_id, kind, observed_at, present, spec_json, facts_json, received_at)
             VALUES ('a1', 'file/test/x', 'file', ?, 1, '{}', '{}', ?)",
        ))
        .bind(ago(60))
        .bind(ago(60))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(&sql(
            "INSERT INTO observations
                (agent_id, resource_id, kind, observed_at, present, spec_json, facts_json, received_at)
             VALUES ('a1', 'file/test/x', 'file', ?, 1, '{}', '{}', ?)",
        ))
        .bind(ago(5))
        .bind(ago(5))
        .execute(store.pool())
        .await
        .unwrap();

        let cfg = RetentionConfig::default();
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.observations, 1);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM observations"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn drift_prune_keeps_open_events_regardless_of_age() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at)
             VALUES ('a1', 'agent-a', 'test', 'h', ?)",
        ))
        .bind(ago(0))
        .execute(store.pool())
        .await
        .unwrap();

        // Old + resolved → prunable.
        sqlx::query(&sql("INSERT INTO drift_events
                (agent_id, resource_id, kind, severity, diff_json, detected_at,
                 received_at, resolved_at)
             VALUES ('a1', 'file/test/x', 'file', 'warning', '{}', ?, ?, ?)"))
        .bind(ago(60))
        .bind(ago(60))
        .bind(ago(60))
        .execute(store.pool())
        .await
        .unwrap();
        // Old + still open → kept.
        sqlx::query(&sql("INSERT INTO drift_events
                (agent_id, resource_id, kind, severity, diff_json, detected_at,
                 received_at)
             VALUES ('a1', 'file/test/y', 'file', 'warning', '{}', ?, ?)"))
        .bind(ago(60))
        .bind(ago(60))
        .execute(store.pool())
        .await
        .unwrap();

        let cfg = RetentionConfig::default();
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.drift_resolved, 1);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM drift_events"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn user_tokens_expired_prune_uses_existing_method() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        // Create a user.
        let id = store
            .create_user(crate::store::CreateUser {
                username: "alice",
                password: "p",
                roles: vec![crate::identity::Role::Operator],
            })
            .await
            .unwrap();
        // Insert two tokens: one expired, one valid.
        sqlx::query(&sql(
            "INSERT INTO user_tokens (token_hash, user_id, issued_at, expires_at)
             VALUES (?, ?, ?, ?)",
        ))
        .bind("expired-hash")
        .bind(&id)
        .bind(ago(2))
        .bind(ago(1))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(&sql(
            "INSERT INTO user_tokens (token_hash, user_id, issued_at, expires_at)
             VALUES (?, ?, ?, ?)",
        ))
        .bind("valid-hash")
        .bind(&id)
        .bind(ago(0))
        .bind(
            Timestamp::now()
                .checked_add(Span::new().try_hours(1).unwrap())
                .unwrap()
                .to_string(),
        )
        .execute(store.pool())
        .await
        .unwrap();

        let cfg = RetentionConfig::default();
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.user_tokens_expired, 1);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM user_tokens"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn zero_days_disables_a_single_dimension() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        insert_audit(&store, &ago(120)).await;

        let cfg = RetentionConfig {
            audit_days: 0,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.audit, 0);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM audit_events"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn empty_db_prune_is_clean_zero() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        let stats = prune_once(&store, &RetentionConfig::default())
            .await
            .unwrap();
        assert_eq!(stats.total(), 0);
    }

    /// Helper for the per-resource cap tests: insert N rows for one
    /// (agent, resource) at strictly increasing observed_at so the cap
    /// has unambiguous order to act on.
    async fn insert_observations_n(store: &Store, agent_id: &str, resource_id: &str, n: usize) {
        for i in 0..n {
            let when = Timestamp::now()
                .checked_sub(Span::new().try_minutes((n - i) as i64).unwrap())
                .unwrap()
                .to_string();
            sqlx::query(&sql(
                "INSERT INTO observations
                    (agent_id, resource_id, kind, observed_at, present, spec_json, facts_json, received_at)
                 VALUES (?, ?, 'file', ?, 1, '{}', '{}', ?)",
            ))
            .bind(agent_id)
            .bind(resource_id)
            .bind(&when)
            .bind(&when)
            .execute(store.pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn per_resource_cap_keeps_n_newest_drops_rest() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at)
             VALUES ('a1', 'agent-a', 'test', 'h', ?)",
        ))
        .bind(ago(0))
        .execute(store.pool())
        .await
        .unwrap();

        // 5 observations of resource X, 3 of resource Y. Cap = 2.
        insert_observations_n(&store, "a1", "file/test/x", 5).await;
        insert_observations_n(&store, "a1", "file/test/y", 3).await;

        // Disable the age-based prune so we exercise the cap in isolation.
        let cfg = RetentionConfig {
            observation_days: 0,
            observation_max_per_resource: 2,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        // X: keep 2, drop 3. Y: keep 2, drop 1. Total dropped = 4.
        assert_eq!(stats.observations, 0, "age-based path should be disabled");
        assert_eq!(stats.observations_per_resource, 4);

        let counts: Vec<(String, i64)> = sqlx::query_as(&sql(
            "SELECT resource_id, COUNT(*) FROM observations GROUP BY resource_id ORDER BY resource_id",
        ))
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(
            counts,
            vec![
                ("file/test/x".to_string(), 2),
                ("file/test/y".to_string(), 2),
            ]
        );
    }

    #[tokio::test]
    async fn per_resource_cap_zero_disables() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at)
             VALUES ('a1', 'agent-a', 'test', 'h', ?)",
        ))
        .bind(ago(0))
        .execute(store.pool())
        .await
        .unwrap();
        insert_observations_n(&store, "a1", "file/test/x", 4).await;

        let cfg = RetentionConfig {
            observation_days: 0,
            observation_max_per_resource: 0,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.observations_per_resource, 0);

        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM observations"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 4);
    }

    /// Phase 9-F1-fix-12 (gap-#12 from F1 72h). Mirrors the
    /// observations per-resource cap test for desired_states.
    /// `desired_states` keys by (operation_id, resource_id) so we
    /// insert N operations × 1 resource → N desired_states rows,
    /// then expect the cap to leave only the newest.
    async fn insert_desired_states_n(store: &Store, resource_id: &str, n: usize) {
        for i in 0..n {
            // operations table requires an id + created_at; we
            // synthesize unique ids so the FK on desired_states
            // (operation_id REFERENCES operations(id) ON DELETE
            // CASCADE) is satisfied.
            let op_id = format!("op-{resource_id}-{i:03}");
            sqlx::query(&sql("INSERT INTO operations
                    (id, kind, environment, requested_by, status, created_at, matched_policies_json)
                 VALUES (?, 'apply', 'test', 'test', 'succeeded', ?, '[]')"))
            .bind(&op_id)
            .bind(ago(0))
            .execute(store.pool())
            .await
            .unwrap();
            sqlx::query(&sql("INSERT INTO desired_states
                    (operation_id, resource_id, kind, environment, spec_json, metadata_json)
                 VALUES (?, ?, 'file', 'test', '{}', '{}')"))
            .bind(&op_id)
            .bind(resource_id)
            .execute(store.pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn desired_states_per_resource_cap_keeps_n_newest() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;

        // 5 ops touching resource X, 3 ops touching resource Y.
        // Each op creates one desired_states row → 5 + 3 = 8 rows.
        // Cap = 2 → keep 2 newest per resource, drop 3 from X +
        // 1 from Y = 4 total.
        insert_desired_states_n(&store, "file/test/x", 5).await;
        insert_desired_states_n(&store, "file/test/y", 3).await;

        let cfg = RetentionConfig {
            // Disable other paths so we exercise the new cap alone.
            audit_days: 0,
            observation_days: 0,
            drift_resolved_days: 0,
            assignment_terminal_days: 0,
            observation_max_per_resource: 0,
            desired_state_max_per_resource: 2,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.desired_states_per_resource, 4);

        let counts: Vec<(String, i64)> = sqlx::query_as(&sql(
            "SELECT resource_id, COUNT(*) FROM desired_states GROUP BY resource_id ORDER BY resource_id",
        ))
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(
            counts,
            vec![
                ("file/test/x".to_string(), 2),
                ("file/test/y".to_string(), 2),
            ]
        );
    }

    #[tokio::test]
    async fn desired_states_per_resource_cap_zero_disables() {
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        insert_desired_states_n(&store, "file/test/x", 4).await;

        let cfg = RetentionConfig {
            audit_days: 0,
            observation_days: 0,
            drift_resolved_days: 0,
            assignment_terminal_days: 0,
            observation_max_per_resource: 0,
            desired_state_max_per_resource: 0,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        assert_eq!(stats.desired_states_per_resource, 0);
        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM desired_states"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 4);
    }

    #[tokio::test]
    async fn per_resource_cap_partitions_by_agent_too() {
        // Two agents reporting the same resource_id → each gets its own
        // top-N, not a global one. Important: a multi-host stand
        // shouldn't see hosts compete for the same retention budget.
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir).await;
        for (id, name) in [("a1", "agent-a"), ("a2", "agent-b")] {
            sqlx::query(&sql(
                "INSERT INTO agents (id, name, environment, token_hash, registered_at)
                 VALUES (?, ?, 'test', 'h', ?)",
            ))
            .bind(id)
            .bind(name)
            .bind(ago(0))
            .execute(store.pool())
            .await
            .unwrap();
            insert_observations_n(&store, id, "file/test/shared", 3).await;
        }

        let cfg = RetentionConfig {
            observation_days: 0,
            observation_max_per_resource: 2,
            ..RetentionConfig::default()
        };
        let stats = prune_once(&store, &cfg).await.unwrap();
        // Each agent has 3 rows of `file/test/shared`; cap of 2 drops 1
        // per agent → total 2 dropped, 4 remaining.
        assert_eq!(stats.observations_per_resource, 2);
        let count: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM observations"))
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 4);
    }
}
