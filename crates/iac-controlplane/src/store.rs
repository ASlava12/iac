//! Async store for the control-plane.
//!
//! Phase 2a launched on SQLite. Phase 7al switches the pool to `sqlx::AnyPool`
//! so we pick the backend at runtime from the database URL scheme:
//!
//!   * `sqlite://…` — embedded, default for dev/single-node.
//!   * `postgres://…` — for shared deployments.
//!
//! Queries use `?` placeholders and the Any layer rewrites them to `$N` for
//! Postgres. We use runtime `sqlx::query` / `sqlx::query_as` (not the `query!`
//! macros) so the build never depends on `DATABASE_URL`.

use crate::auth;
use crate::error::{ApiError, ApiResult};
use iac_core::protocol::v1::{
    AgentHealth, AgentSummary, AssignmentEnvelope, AssignmentPayload, AssignmentResultRequest,
    AssignmentResultStatus, AssignmentView, AuditEvent, DesiredStateItem, DriftItem, DriftSummary,
    HeartbeatRequest, ObservationItem, OperationDesiredStateItem, OperationListItem,
    OperationStatus, OperationView, RegisterRequest,
};
use jiff::Timestamp;

/// Phase 7cj: how long an agent has to POST a result after fetching
/// an assignment before another GET re-claims it. 60s is short
/// enough that a crashed agent recovers within a poll interval, but
/// long enough that a slow but healthy agent (network blip, big
/// payload) doesn't see a duplicate dispatch.
///
/// Override via `IAC_ASSIGNMENT_LEASE_SECS` for stress tests where
/// the test wall-clock is shorter than the default lease and we
/// want to exercise the re-claim path quickly.
fn assignment_lease_secs() -> i64 {
    std::env::var("IAC_ASSIGNMENT_LEASE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60)
}
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyConnection, AnyPool, Row};
use std::borrow::Cow;
use std::sync::{Once, OnceLock};
use std::time::Duration;
use ulid::Ulid;

/// Backend the connected pool is talking to. Picked at `connect` time from
/// the URL scheme; immutable for the lifetime of the `Store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn from_url(url: &str) -> ApiResult<Self> {
        if url.starts_with("sqlite:") {
            Ok(Dialect::Sqlite)
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Ok(Dialect::Postgres)
        } else {
            Err(ApiError::Internal(format!(
                "unsupported database_url scheme: {url:?} (expected sqlite:// or postgres://)"
            )))
        }
    }
}

/// Async pool wrapper with helper queries.
#[derive(Debug, Clone)]
pub struct Store {
    pool: AnyPool,
    dialect: Dialect,
}

static INSTALL_ANY_DRIVERS: Once = Once::new();

/// Active dialect, set by the first `Store::connect` call. Postgres needs `?`
/// rewritten to `$N`; SQLite accepts both, so we keep `?` in source for
/// readability and translate on the way out when the global is Postgres.
///
/// One process talks to one database, so a `OnceLock` is the simplest fit.
/// In test binaries that isolate per-process this is a no-op since SQLite is
/// the implicit default.
static ACTIVE_DIALECT: OnceLock<Dialect> = OnceLock::new();

/// Translate `?` placeholders in `sql` to `$1, $2, …` for the active dialect.
/// Returns the input unchanged when running against SQLite. Skips `?` chars
/// inside single-quoted string literals and `--` line comments so that a SQL
/// literal containing a `?` is left alone.
fn translate_placeholders_to_pg(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut counter: u32 = 0;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                out.push(c);
                while let Some(c2) = chars.next() {
                    out.push(c2);
                    if c2 == '\'' {
                        if chars.peek() == Some(&'\'') {
                            if let Some(c3) = chars.next() {
                                out.push(c3);
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                out.push(c);
                for c2 in chars.by_ref() {
                    out.push(c2);
                    if c2 == '\n' {
                        break;
                    }
                }
            }
            '?' => {
                counter += 1;
                use std::fmt::Write;
                let _ = write!(out, "${counter}");
            }
            _ => out.push(c),
        }
    }
    out
}

/// Translate the SQL string for the active dialect. Borrowed for SQLite
/// (zero-cost), owned for Postgres. Use the wrapper at every `sqlx::query`
/// call site so a `?`-shaped query works on both backends.
pub(crate) fn sql(s: &str) -> Cow<'_, str> {
    match ACTIVE_DIALECT.get().copied().unwrap_or(Dialect::Sqlite) {
        Dialect::Sqlite => Cow::Borrowed(s),
        Dialect::Postgres => Cow::Owned(translate_placeholders_to_pg(s)),
    }
}

#[derive(Debug, Clone)]
pub struct AgentCredentials {
    pub agent_id: String,
    pub token: String,
    /// Phase 7cd: token expiry in ISO 8601. None when no TTL was
    /// configured. Returned through `RegisterResponse` so the agent
    /// can plan its rotation cadence.
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub environment: String,
    pub token_hash: String,
}

impl Store {
    /// Open the store at `database_url` and run pending migrations.
    ///
    /// SQLite-specific PRAGMAs (WAL, busy_timeout, foreign_keys) are run on
    /// every freshly-opened connection via `after_connect`. The Postgres
    /// branch leaves connections at server defaults — operators tune via
    /// `postgresql.conf` / connection-string parameters instead.
    pub async fn connect(database_url: &str) -> ApiResult<Self> {
        INSTALL_ANY_DRIVERS.call_once(sqlx::any::install_default_drivers);

        let dialect = Dialect::from_url(database_url)?;
        // First connect wins — once this process has chosen a dialect, every
        // `sql()` call returns the same translation. Rejecting a re-connect
        // with a different dialect would surprise tests that reuse the same
        // process; instead silently honor the first choice.
        let _ = ACTIVE_DIALECT.set(dialect);

        let mut opts = AnyPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5));

        if dialect == Dialect::Sqlite {
            opts = opts.after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query(&sql("PRAGMA journal_mode = WAL"))
                        .execute(&mut *conn)
                        .await?;
                    // Phase 8.7 (real-hardware finding): bumped from 5s
                    // to 30s. On a Pi 4 with SD-card storage, 10
                    // concurrent agents heartbeating + a 50 RPS submit
                    // burst hit the 5s ceiling and bubbled up as 500.
                    // 30s gives the WAL writer enough headroom on slow
                    // flash storage; on production SSDs this is never
                    // approached. Pairs with the new SQLITE_BUSY → 503
                    // mapping in `error.rs` so persistent contention
                    // still surfaces, just as a retriable signal.
                    sqlx::query(&sql("PRAGMA busy_timeout = 30000"))
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(&sql("PRAGMA foreign_keys = ON"))
                        .execute(&mut *conn)
                        .await?;
                    // Phase 9-F1 (real-fleet finding): cap the WAL
                    // file size. Without this, sustained mixed
                    // read/write traffic (heartbeats fan-out
                    // checkpoints behind readers; submit/result
                    // writes keep adding WAL frames) makes the WAL
                    // grow unboundedly even though `wal_autocheckpoint
                    // = 1000` (default) fires constantly — the
                    // PASSIVE checkpoint pages-back successfully but
                    // the WAL file isn't truncated until a TRUNCATE
                    // checkpoint runs while no readers hold a frame.
                    // The F1 24h soak hit disk-full at ~3 h on an
                    // 8.5 GB VPS because the WAL ballooned to 4 GB
                    // alongside a 3.7 GB DB. `journal_size_limit`
                    // makes SQLite shrink the WAL file back to this
                    // size after every successful checkpoint, so
                    // even if the checkpoint frequency drifts the
                    // disk usage stays bounded.
                    //
                    // Phase 9-F1-fix-6 (gap-#6 from F1 #6, 2026-05-09):
                    // bumped from 256 MiB to 1 GiB. The previous cap
                    // bottomed out on F1's 7-agent, ~5 000-resource-
                    // per-agent steady state — the WAL touched cap
                    // continuously, SQLite throttled writes, INSERT
                    // latency climbed to 4-6 s, longevity failure rate
                    // climbed linearly to ~11 %. 1 GiB gives 4× more
                    // headroom under sustained scaling; combined with
                    // the more aggressive retention interval (60 s
                    // instead of 300 s), the working set stays bounded
                    // well within the new ceiling. On router-class
                    // hardware (8-32 MiB flash), operators override
                    // this in their wal_checkpoint configuration —
                    // tracked as a future config-knob TODO.
                    sqlx::query(&sql("PRAGMA journal_size_limit = 1073741824"))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            });
        }

        let pool = opts
            .connect(database_url)
            .await
            .map_err(|e| ApiError::Internal(format!("connect to {database_url}: {e}")))?;

        run_migrations(&pool, dialect).await?;
        Ok(Self { pool, dialect })
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// Phase 9-F1: bounded WAL maintenance. SQLite's default
    /// `wal_autocheckpoint = 1000` runs PASSIVE checkpoints (page-back
    /// to the main DB) but never shrinks the WAL file — only a
    /// TRUNCATE checkpoint does. Under sustained mixed read/write
    /// load, the WAL grows unboundedly without explicit TRUNCATEs.
    ///
    /// Phase 9-F1-fix-3 (real-fleet finding): TRUNCATE is too
    /// disruptive to run every cycle — under a busy fleet it requires
    /// exclusive access, which can take 30 s of blocking against
    /// concurrent retention DELETE + agent fan-out writes. F1
    /// attempt #3 saw 5xx error rate climb from 0.03 % to 0.5 %
    /// because every minute the CP froze for ~30 s on TRUNCATE.
    ///
    /// New behaviour: run cheap PASSIVE checkpoints by default — they
    /// page-back without blocking — and run an actual TRUNCATE only
    /// every Nth tick so the WAL file size still gets reclaimed
    /// periodically. PASSIVE returns immediately on contention with
    /// `busy=1`, so the cost is at most one no-op syscall per tick.
    /// `journal_size_limit` (set per-connection) caps WAL file growth
    /// regardless, so even in pathological reader-blocking scenarios
    /// the WAL can't exceed the cap.
    ///
    /// `force_truncate=true` forces a TRUNCATE this call (used for
    /// the periodic-truncate cycle and for tests).
    ///
    /// No-op on Postgres — Postgres has its own vacuum / WAL story.
    pub async fn wal_checkpoint(&self, force_truncate: bool) -> ApiResult<()> {
        if self.dialect != Dialect::Sqlite {
            return Ok(());
        }
        let mode = if force_truncate {
            "TRUNCATE"
        } else {
            "PASSIVE"
        };
        sqlx::query(&format!("PRAGMA wal_checkpoint({mode})"))
            .execute(&self.pool)
            .await
            .map_err(|e| ApiError::Internal(format!("wal_checkpoint({mode}): {e}")))?;
        Ok(())
    }

    /// Backwards-compat alias used by older call sites; always TRUNCATEs.
    pub async fn wal_checkpoint_truncate(&self) -> ApiResult<()> {
        self.wal_checkpoint(true).await
    }

    // ---- agents ---------------------------------------------------------

    pub async fn register_agent(
        &self,
        req: &RegisterRequest,
        token_ttl_secs: Option<u64>,
    ) -> ApiResult<AgentCredentials> {
        if req.name.is_empty() || req.environment.is_empty() {
            return Err(ApiError::BadRequest(
                "name and environment must be non-empty".into(),
            ));
        }
        let id = Ulid::new().to_string();
        let (token, token_hash) = auth::issue_token();
        let metadata_json = serde_json::to_string(&req.metadata)?;
        let now = Timestamp::now();
        let now_str = now.to_string();
        // Phase 7cc: stamp expiry only when TTL is configured.
        // None → grandfathered token (NULL in DB). Some(N) → expires
        // at now + N seconds. Auth path rejects expired tokens with
        // 401.
        let expires_at: Option<String> = token_ttl_secs.map(|ttl| {
            now.checked_add(jiff::Span::new().seconds(ttl as i64))
                .unwrap_or(now)
                .to_string()
        });

        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at, metadata_json, token_expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(&req.name)
        .bind(&req.environment)
        .bind(&token_hash)
        .bind(&now_str)
        .bind(metadata_json)
        .bind(&expires_at)
        .execute(&mut *tx)
        .await;

        match res {
            Ok(_) => {
                record_audit_on(
                    &mut tx,
                    AuditRecord::new("system", "agent.registered")
                        .agent(&id)
                        .payload(serde_json::json!({
                            "name": req.name,
                            "environment": req.environment,
                            "token_ttl_secs": token_ttl_secs,
                        })),
                )
                .await?;
                tx.commit().await?;
                Ok(AgentCredentials {
                    agent_id: id,
                    token,
                    expires_at,
                })
            }
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                tx.rollback().await.ok();
                Err(ApiError::Conflict(format!(
                    "agent name {} already taken",
                    req.name
                )))
            }
            Err(e) => {
                tx.rollback().await.ok();
                Err(ApiError::from(e))
            }
        }
    }

    /// Phase 7cc: rotate an agent's bearer token. Auth must already
    /// have validated the *current* token before calling — this just
    /// generates a new one, persists, and returns. Old token's hash
    /// is overwritten so the next request with the old token sees
    /// 401 (constant-time compare against the new hash fails).
    pub async fn rotate_agent_token(
        &self,
        agent_id: &str,
        token_ttl_secs: Option<u64>,
    ) -> ApiResult<AgentCredentials> {
        let (new_token, new_hash) = auth::issue_token();
        let now = Timestamp::now();
        let now_str = now.to_string();
        let new_expires_at: Option<String> = token_ttl_secs.map(|ttl| {
            now.checked_add(jiff::Span::new().seconds(ttl as i64))
                .unwrap_or(now)
                .to_string()
        });

        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(&sql("UPDATE agents
             SET token_hash = ?, token_expires_at = ?
             WHERE id = ?"))
        .bind(&new_hash)
        .bind(&new_expires_at)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        record_audit_on(
            &mut tx,
            AuditRecord::new(&format!("agent:{agent_id}"), "agent.token_rotated")
                .agent(agent_id)
                .payload(serde_json::json!({
                    "token_ttl_secs": token_ttl_secs,
                    "rotated_at": now_str,
                })),
        )
        .await?;
        tx.commit().await?;
        Ok(AgentCredentials {
            agent_id: agent_id.to_string(),
            token: new_token,
            expires_at: new_expires_at,
        })
    }

    /// Find an agent by id and verify the bearer token in constant time.
    /// Phase 7cc: also rejects tokens past their `token_expires_at`.
    /// Tokens with NULL expiry (grandfathered) never expire.
    pub async fn authenticate(&self, agent_id: &str, token: &str) -> ApiResult<AgentRecord> {
        let row = sqlx::query(&sql(
            "SELECT id, name, environment, token_hash, token_expires_at FROM agents WHERE id = ?",
        ))
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            // Same error for "no such agent" and "wrong token" so callers
            // can't enumerate registered ids via 401 vs 404 timing.
            return Err(ApiError::Unauthorized);
        };
        let token_hash: String = row.try_get("token_hash")?;
        let provided_hash = auth::hash_token(token);
        if !auth::ct_eq(provided_hash.as_bytes(), token_hash.as_bytes()) {
            return Err(ApiError::Unauthorized);
        }
        // Phase 7cc: enforce expiry.
        let expires_at: Option<String> = row.try_get("token_expires_at")?;
        if let Some(exp_str) = expires_at {
            // Parse the ISO 8601 timestamp. On parse failure (shouldn't
            // happen — we wrote it via Timestamp::to_string) treat as
            // expired-and-malformed for safety.
            let now = Timestamp::now();
            match exp_str.parse::<Timestamp>() {
                Ok(exp) if now < exp => {
                    // Still valid, fall through.
                }
                Ok(_) => return Err(ApiError::Unauthorized),
                Err(_) => return Err(ApiError::Unauthorized),
            }
        }
        Ok(AgentRecord {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            environment: row.try_get("environment")?,
            token_hash,
        })
    }

    pub async fn record_heartbeat(&self, agent_id: &str, hb: &HeartbeatRequest) -> ApiResult<()> {
        let now = Timestamp::now().to_string();
        let status = match hb.status {
            AgentHealth::Healthy => "healthy",
            AgentHealth::Degraded => "degraded",
            AgentHealth::Unhealthy => "unhealthy",
        };
        sqlx::query(&sql("UPDATE agents SET
                last_heartbeat_at = ?,
                last_status = ?,
                last_managed = ?,
                last_open_drifts = ?
             WHERE id = ?"))
        .bind(&now)
        .bind(status)
        .bind(i64::from(hb.managed))
        .bind(i64::from(hb.open_drifts))
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_agents(&self) -> ApiResult<Vec<AgentSummary>> {
        let rows = sqlx::query(&sql(
            "SELECT id, name, environment, registered_at, last_heartbeat_at,
                    last_observation_at, last_managed, last_open_drifts, last_status, kind
             FROM agents ORDER BY registered_at DESC",
        ))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let status: String = row.try_get("last_status")?;
                Ok(AgentSummary {
                    agent_id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    environment: row.try_get("environment")?,
                    registered_at: row.try_get("registered_at")?,
                    last_heartbeat_at: row.try_get("last_heartbeat_at")?,
                    last_observation_at: row.try_get("last_observation_at")?,
                    open_drifts: row.try_get("last_open_drifts")?,
                    managed: row.try_get("last_managed")?,
                    status: parse_health(&status),
                    kind: row.try_get("kind")?,
                })
            })
            .collect()
    }

    /// Phase 7ck: idempotent upsert for an SSH target. Called at server
    /// startup for every entry in `[[ssh_targets]]`. Reuses the same
    /// agents table so dispatch / canary / phased apply just work —
    /// only difference is `kind = 'ssh'` and the empty token (no
    /// pull-mode auth path applies).
    ///
    /// Returns the agent_id (newly minted ULID for first-time
    /// registration; stable across restarts thereafter).
    pub async fn upsert_ssh_target(&self, name: &str, environment: &str) -> ApiResult<String> {
        let now = Timestamp::now().to_string();
        // Check if a row with this (name, environment, kind='ssh') already exists.
        let existing: Option<String> = sqlx::query_scalar(&sql(
            "SELECT id FROM agents WHERE name = ? AND environment = ? AND kind = 'ssh'",
        ))
        .bind(name)
        .bind(environment)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(id) = existing {
            return Ok(id);
        }
        // Mint a fresh ULID. Empty token_hash — auth never reaches
        // here (the SSH worker pool is what dispatches).
        let id = Ulid::new().to_string();
        sqlx::query(&sql(
            "INSERT INTO agents (id, name, environment, token_hash, registered_at,
                                  metadata_json, kind)
             VALUES (?, ?, ?, '', ?, '{}', 'ssh')",
        ))
        .bind(&id)
        .bind(name)
        .bind(environment)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Phase 7ck: queue scan for the SSH push worker. Returns the
    /// next pending assignment (id, agent_id, payload_json) for any
    /// `kind = 'ssh'` agent matching one of `target_ids`. NULL when
    /// nothing's ready. Atomic: marks the row as `'fetched'` in the
    /// same transaction so two workers can't pick the same job.
    /// Phase 7cq.1 (security fix #4.3): atomic single-row claim via
    /// `UPDATE ... WHERE ... RETURNING ... LIMIT 1`. Pre-fix this was
    /// SELECT-then-UPDATE which races on Postgres READ COMMITTED —
    /// two SSH workers could double-dispatch the same assignment.
    /// The new shape relies on UPDATE row-locks: only one transaction
    /// can win the row, the other sees `status = 'fetched'` and the
    /// WHERE filters it out.
    ///
    /// Note: `LIMIT 1` inside `UPDATE ... WHERE ... LIMIT` is SQLite-
    /// only. On Postgres we use `WHERE id = (SELECT id ... LIMIT 1)`
    /// — the inner SELECT is still racy in isolation, but the outer
    /// UPDATE's row-lock + the WHERE re-evaluation in READ COMMITTED
    /// closes the race. (PG retries the UPDATE against the new row
    /// version and skips it if `status` is no longer 'pending'.)
    pub async fn claim_ssh_pending(
        &self,
        target_ids: &[String],
    ) -> ApiResult<Option<(String, String, String)>> {
        if target_ids.is_empty() {
            return Ok(None);
        }
        let mut tx = self.pool.begin().await?;
        let now_ts = Timestamp::now();
        let lease_cutoff = (now_ts - jiff::ToSpan::seconds(assignment_lease_secs())).to_string();
        let now = now_ts.to_string();
        // Build the IN clause. SQLx Any-pool doesn't support array
        // binding so we render placeholders inline.
        let placeholders = vec!["?"; target_ids.len()].join(", ");
        // UPDATE-RETURNING with a sub-select chooses one candidate
        // atomically. The outer UPDATE row-locks on the chosen id;
        // any concurrent claim sees that lock and re-evaluates its
        // WHERE on the new row version (status='fetched'), skipping
        // the row.
        let q = format!(
            "UPDATE assignments
             SET status = 'fetched', fetched_at = ?
             WHERE id = (
               SELECT id FROM assignments
               WHERE agent_id IN ({placeholders})
                 AND (
                   status = 'pending'
                   OR (status = 'fetched' AND fetched_at IS NOT NULL AND fetched_at < ?)
                 )
               ORDER BY created_at LIMIT 1
             )
             RETURNING id, agent_id, operation_id, payload_json"
        );
        let q = sql(&q);
        let mut query = sqlx::query(&q);
        query = query.bind(&now);
        for id in target_ids {
            query = query.bind(id);
        }
        query = query.bind(&lease_cutoff);
        let row = query.fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let assignment_id: String = row.try_get("id")?;
        let agent_id: String = row.try_get("agent_id")?;
        let op_id: String = row.try_get("operation_id")?;
        let payload_json: String = row.try_get("payload_json")?;
        sqlx::query(&sql(
            "UPDATE operations SET status = 'running', started_at = COALESCE(started_at, ?)
             WHERE id = ? AND status = 'pending'",
        ))
        .bind(&now)
        .bind(&op_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some((assignment_id, agent_id, payload_json)))
    }

    // ---- observations ---------------------------------------------------

    pub async fn record_observations(
        &self,
        agent_id: &str,
        items: &[ObservationItem],
    ) -> ApiResult<u32> {
        if items.is_empty() {
            return Ok(0);
        }
        // Phase 9-F1-fix-4 (real-fleet finding): batch the per-row
        // INSERTs into a single multi-row statement per chunk. The
        // pre-fix code did N separate INSERT statements inside one
        // transaction; under F1's load (7 agents × ~3 200 resources,
        // observation push ≈ 60 INSERTs/s on the CP) each statement
        // contended with the next on WAL frame allocation, INSERT
        // latency hit 4–7 s, and the 5xx rate climbed to ~2 %. One
        // multi-row INSERT pays the WAL overhead once for the whole
        // batch; on F1's load that's a 50× reduction in WAL frame
        // allocations.
        //
        // Chunked at 100 to stay safely under SQLite's older
        // SQLITE_LIMIT_VARIABLE_NUMBER ceiling of 999 placeholders
        // (8 columns × 100 = 800). Modern SQLite raised this to
        // 32 766 but pre-3.32 builds (some embedded targets) still
        // ship the old limit.
        const BATCH_SIZE: usize = 100;
        let now = Timestamp::now().to_string();
        let mut tx = self.pool.begin().await?;
        let total = u32::try_from(items.len()).unwrap_or(u32::MAX);
        for chunk in items.chunks(BATCH_SIZE) {
            // Build "(?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?), ..."
            let placeholders = std::iter::repeat_n("(?,?,?,?,?,?,?,?)", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let stmt = format!(
                "INSERT INTO observations
                  (agent_id, resource_id, kind, observed_at, present, spec_json, facts_json, received_at)
                 VALUES {placeholders}",
            );
            let translated = sql(&stmt);
            let mut q = sqlx::query(&translated);
            for item in chunk {
                let spec_json = serde_json::to_string(&item.spec)?;
                let facts_json = serde_json::to_string(&item.facts)?;
                q = q
                    .bind(agent_id.to_string())
                    .bind(item.resource_id.to_string())
                    .bind(item.resource_id.kind.clone())
                    .bind(item.observed_at.clone())
                    .bind(i64::from(item.present))
                    .bind(spec_json)
                    .bind(facts_json)
                    .bind(now.clone());
            }
            q.execute(&mut *tx).await?;
        }
        sqlx::query(&sql(
            "UPDATE agents SET last_observation_at = ? WHERE id = ?",
        ))
        .bind(&now)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(total)
    }

    // ---- drift ----------------------------------------------------------

    pub async fn record_drift(&self, agent_id: &str, items: &[DriftItem]) -> ApiResult<u32> {
        if items.is_empty() {
            return Ok(0);
        }
        let now = Timestamp::now().to_string();
        let mut tx = self.pool.begin().await?;
        let mut count = 0u32;
        for item in items {
            let diff_json = serde_json::to_string(&item.diff)?;
            let rid = item.resource_id.to_string();
            // Dedupe by (agent_id, resource_id) for open rows: refresh the
            // existing one with new diff/severity/detected_at. Insert a new row
            // only when no open row exists. Resolved rows stay around as
            // history.
            let updated = sqlx::query(&sql("UPDATE drift_events
                 SET kind = ?, severity = ?, diff_json = ?, detected_at = ?, received_at = ?
                 WHERE agent_id = ? AND resource_id = ? AND resolved_at IS NULL"))
            .bind(&item.resource_id.kind)
            .bind(&item.severity)
            .bind(&diff_json)
            .bind(&item.detected_at)
            .bind(&now)
            .bind(agent_id)
            .bind(&rid)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 0 {
                sqlx::query(&sql("INSERT INTO drift_events
                      (agent_id, resource_id, kind, severity, diff_json,
                       detected_at, received_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)"))
                .bind(agent_id)
                .bind(&rid)
                .bind(&item.resource_id.kind)
                .bind(&item.severity)
                .bind(&diff_json)
                .bind(&item.detected_at)
                .bind(&now)
                .execute(&mut *tx)
                .await?;
            }
            count += 1;
        }
        tx.commit().await?;
        Ok(count)
    }

    pub async fn list_open_drift(&self, agent_id: Option<&str>) -> ApiResult<Vec<DriftSummary>> {
        // Active = not resolved AND not currently ignored. We compare
        // `ignored_until > now`; rows with ignored_until in the past or NULL
        // are visible.
        let now = Timestamp::now().to_string();
        let mut q = String::from(
            "SELECT id, agent_id, resource_id, kind, severity, diff_json, detected_at,
                    ignored_until, resolved_at, resolution
             FROM drift_events
             WHERE resolved_at IS NULL
               AND (ignored_until IS NULL OR ignored_until <= ?)",
        );
        if agent_id.is_some() {
            q.push_str(" AND agent_id = ?");
        }
        q.push_str(" ORDER BY detected_at DESC");

        let qs = sql(&q);
        let mut query = sqlx::query(&qs).bind(&now);
        if let Some(id) = agent_id {
            query = query.bind(id);
        }
        let rows = query.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_drift_summary).collect()
    }

    /// Phase 7be: locate the most recent stored desired-state for
    /// `resource_id` so the drift-revert flow can re-submit it. Returns
    /// the full resource JSON (apiVersion / kind / metadata / spec /
    /// policy) plus the environment that operation targeted, or `None`
    /// when no operation has ever covered this resource.
    pub async fn find_latest_resource_for_revert(
        &self,
        resource_id: &str,
    ) -> ApiResult<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(&sql("SELECT environment, spec_json
             FROM desired_states
             WHERE resource_id = ?
             ORDER BY id DESC
             LIMIT 1"))
        .bind(resource_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_drift(&self, drift_id: i64) -> ApiResult<DriftSummary> {
        let row = sqlx::query(&sql(
            "SELECT id, agent_id, resource_id, kind, severity, diff_json, detected_at,
                    ignored_until, resolved_at, resolution
             FROM drift_events WHERE id = ?",
        ))
        .bind(drift_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
        row_to_drift_summary(row)
    }

    /// Mark a drift event accepted: a permanent resolution that doesn't
    /// converge the underlying state. The reason is stored in `resolution`
    /// with an `accepted: ` prefix so we can tell it apart from the natural
    /// "agent stopped reporting" close.
    pub async fn accept_drift(&self, drift_id: i64, actor: &str, reason: &str) -> ApiResult<()> {
        let now = Timestamp::now().to_string();
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(&sql("UPDATE drift_events
             SET resolved_at = ?, resolution = ?, ignored_until = NULL
             WHERE id = ? AND resolved_at IS NULL"))
        .bind(&now)
        .bind(format!("accepted: {reason}"))
        .bind(drift_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        record_audit_on(
            &mut tx,
            AuditRecord::new(actor, "drift.accepted")
                .drift(drift_id)
                .payload(serde_json::json!({ "reason": reason })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Phase 7bf: bulk-accept every open drift event matching a filter
    /// (any combination of `agent_id`, `kind`, `severity`). Returns the
    /// number of events resolved. Each row gets an audit entry tagged
    /// with the originating filter so an audit reader can tell apart
    /// individually-accepted events from a sweep.
    ///
    /// Filter semantics: `None` for a field means "any". Empty filter
    /// (all `None`) accepts every open drift event in the system —
    /// callers should reject that at the API boundary so an operator
    /// doesn't wipe drift history with a typo.
    pub async fn accept_drift_bulk(
        &self,
        filter: &DriftBulkFilter<'_>,
        actor: &str,
        reason: &str,
    ) -> ApiResult<u64> {
        let mut q = String::from(
            "UPDATE drift_events
             SET resolved_at = ?, resolution = ?, ignored_until = NULL
             WHERE resolved_at IS NULL",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(agent_id) = filter.agent_id {
            q.push_str(" AND agent_id = ?");
            binds.push(agent_id.to_string());
        }
        if let Some(kind) = filter.kind {
            q.push_str(" AND kind = ?");
            binds.push(kind.to_string());
        }
        if let Some(severity) = filter.severity {
            q.push_str(" AND severity = ?");
            binds.push(severity.to_string());
        }
        let now = Timestamp::now().to_string();
        let mut tx = self.pool.begin().await?;
        let qs = sql(&q);
        let mut query = sqlx::query(&qs)
            .bind(&now)
            .bind(format!("accepted (bulk): {reason}"));
        for b in &binds {
            query = query.bind(b);
        }
        let affected = query.execute(&mut *tx).await?.rows_affected();
        if affected > 0 {
            record_audit_on(
                &mut tx,
                AuditRecord::new(actor, "drift.accepted_bulk").payload(serde_json::json!({
                    "reason": reason,
                    "matched": affected,
                    "filter": {
                        "agent_id": filter.agent_id,
                        "kind": filter.kind,
                        "severity": filter.severity,
                    },
                })),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(affected)
    }

    /// Phase 7bf: bulk-ignore every matching open drift event for a
    /// duration. Same filter semantics as `accept_drift_bulk`.
    pub async fn ignore_drift_bulk(
        &self,
        filter: &DriftBulkFilter<'_>,
        actor: &str,
        until: &str,
    ) -> ApiResult<u64> {
        let ts: Timestamp = until
            .parse()
            .map_err(|e| ApiError::BadRequest(format!("invalid `until`: {e}")))?;
        let mut q =
            String::from("UPDATE drift_events SET ignored_until = ? WHERE resolved_at IS NULL");
        let mut binds: Vec<String> = Vec::new();
        if let Some(agent_id) = filter.agent_id {
            q.push_str(" AND agent_id = ?");
            binds.push(agent_id.to_string());
        }
        if let Some(kind) = filter.kind {
            q.push_str(" AND kind = ?");
            binds.push(kind.to_string());
        }
        if let Some(severity) = filter.severity {
            q.push_str(" AND severity = ?");
            binds.push(severity.to_string());
        }
        let mut tx = self.pool.begin().await?;
        let qs = sql(&q);
        let mut query = sqlx::query(&qs).bind(ts.to_string());
        for b in &binds {
            query = query.bind(b);
        }
        let affected = query.execute(&mut *tx).await?.rows_affected();
        if affected > 0 {
            record_audit_on(
                &mut tx,
                AuditRecord::new(actor, "drift.ignored_bulk").payload(serde_json::json!({
                    "until": until,
                    "matched": affected,
                    "filter": {
                        "agent_id": filter.agent_id,
                        "kind": filter.kind,
                        "severity": filter.severity,
                    },
                })),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(affected)
    }

    /// Silence a drift event until the given timestamp. While ignored, the
    /// event is excluded from `list_open_drift`. Setting an `until` in the
    /// past is equivalent to clearing the ignore.
    pub async fn ignore_drift(&self, drift_id: i64, actor: &str, until: &str) -> ApiResult<()> {
        // Validate the timestamp parses; we store a normalized RFC3339
        // representation regardless of what the operator sent.
        let ts: Timestamp = until
            .parse()
            .map_err(|e| ApiError::BadRequest(format!("invalid `until`: {e}")))?;
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(&sql("UPDATE drift_events SET ignored_until = ?
             WHERE id = ? AND resolved_at IS NULL"))
        .bind(ts.to_string())
        .bind(drift_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        record_audit_on(
            &mut tx,
            AuditRecord::new(actor, "drift.ignored")
                .drift(drift_id)
                .payload(serde_json::json!({ "until": ts.to_string() })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Mark agent's open drift entries that aren't in the most-recent push as
    /// resolved. Phase 2a calls this after each observation push so drift
    /// auto-clears the moment the agent stops reporting it.
    pub async fn close_drift_not_in(&self, agent_id: &str, current: &[String]) -> ApiResult<u64> {
        let mut tx = self.pool.begin().await?;
        let now = Timestamp::now().to_string();
        let res = if current.is_empty() {
            sqlx::query(&sql(
                "UPDATE drift_events SET resolved_at = ?, resolution = 'agent stopped reporting'
                 WHERE agent_id = ? AND resolved_at IS NULL",
            ))
            .bind(&now)
            .bind(agent_id)
            .execute(&mut *tx)
            .await?
        } else {
            // SQLite doesn't support arrays; build an `IN (?,?,?)` placeholder.
            let placeholders = std::iter::repeat_n("?", current.len())
                .collect::<Vec<_>>()
                .join(",");
            let q = format!(
                "UPDATE drift_events SET resolved_at = ?, resolution = 'agent stopped reporting'
                 WHERE agent_id = ? AND resolved_at IS NULL
                 AND resource_id NOT IN ({placeholders})"
            );
            let qs = sql(&q);
            let mut query = sqlx::query(&qs).bind(&now).bind(agent_id);
            for r in current {
                query = query.bind(r);
            }
            query.execute(&mut *tx).await?
        };
        tx.commit().await?;
        Ok(res.rows_affected())
    }
}

/// Phase 7bf: filter passed to `accept_drift_bulk` / `ignore_drift_bulk`.
/// Borrowed-string fields keep the call sites zero-allocation. `None`
/// means "any" for that dimension; an all-`None` filter accepts every
/// open event in the system, which the API layer rejects to keep typos
/// from wiping the drift history.
#[derive(Debug, Clone, Copy, Default)]
pub struct DriftBulkFilter<'a> {
    pub agent_id: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub severity: Option<&'a str>,
}

impl<'a> DriftBulkFilter<'a> {
    pub fn is_empty(&self) -> bool {
        self.agent_id.is_none() && self.kind.is_none() && self.severity.is_none()
    }
}

// ---- operations / assignments (Phase 2b) -----------------------------------

#[derive(Debug, Clone)]
pub struct ResourceForRouting {
    pub resource_id: String,
    pub kind: String,
    pub environment: String,
    /// JSON of the entire `Resource` (apiVersion/kind/metadata/spec/policy).
    pub resource_json: String,
    /// `metadata.name` — used as the agent name fallback when the resource
    /// has no `spec.hostSelector.name` and the environment has multiple agents.
    pub name: String,
    /// Optional `spec.hostSelector.name` (or null).
    pub host_selector: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateOperationOutcome {
    pub operation_id: String,
    pub assignment_count: u32,
    pub unrouted: Vec<(String, String)>, // (resource_id, reason)
    pub matched_policies: Vec<String>,
    pub requires_approval: bool,
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_operation(
        &self,
        environment: &str,
        requested_by: &str,
        actor: &str,
        source_commit: Option<&str>,
        summary: Option<&str>,
        resources: &[ResourceForRouting],
        matched_policies: &[String],
        requires_approval: bool,
        canary: Option<iac_core::protocol::v1::CanarySpec>,
    ) -> ApiResult<CreateOperationOutcome> {
        // Snapshot the agent table into an environment → name → id map.
        let agents: Vec<(String, String, String)> =
            sqlx::query_as(&sql("SELECT id, name, environment FROM agents"))
                .fetch_all(&self.pool)
                .await?;

        let mut tx = self.pool.begin().await?;
        let op_id = Ulid::new().to_string();
        let now = Timestamp::now().to_string();
        let initial_status = if requires_approval {
            "pending_approval"
        } else {
            "pending"
        };
        let policies_json = serde_json::to_string(matched_policies)?;
        sqlx::query(&sql(
            "INSERT INTO operations (id, kind, environment, requested_by, status,
                                     source_commit, summary, created_at,
                                     requires_approval, matched_policies_json)
             VALUES (?, 'apply', ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(&op_id)
        .bind(environment)
        .bind(requested_by)
        .bind(initial_status)
        .bind(source_commit)
        .bind(summary)
        .bind(&now)
        .bind(i64::from(requires_approval))
        .bind(policies_json)
        .execute(&mut *tx)
        .await?;

        // Phase 7by: layer-aware grouping. Routing list is already
        // topo-sorted (caller does this via `topo_sort_by_depends_on`),
        // so we can compute layers in-line. Bucket key is now
        // (agent_id, layer) so resources at different layers go into
        // different assignments — layer-N+1 holds in 'pending_layer'
        // until layer-N succeeds across every agent.
        let layers = crate::depsort::compute_resource_layers(resources)?;
        let mut buckets: std::collections::BTreeMap<(String, i32), Vec<&ResourceForRouting>> =
            std::collections::BTreeMap::new();
        let mut unrouted: Vec<(String, String)> = Vec::new();

        for (i, r) in resources.iter().enumerate() {
            sqlx::query(&sql(
                "INSERT INTO desired_states (operation_id, resource_id, kind, environment,
                                              spec_json, metadata_json)
                 VALUES (?, ?, ?, ?, ?, ?)",
            ))
            .bind(&op_id)
            .bind(&r.resource_id)
            .bind(&r.kind)
            .bind(&r.environment)
            .bind(&r.resource_json)
            .bind("{}") // metadata_json placeholder; the full resource JSON has metadata
            .execute(&mut *tx)
            .await?;

            let target = route_resource(r, environment, &agents);
            match target {
                Ok(agent_id) => buckets.entry((agent_id, layers[i])).or_default().push(r),
                Err(reason) => unrouted.push((r.resource_id.clone(), reason)),
            }
        }

        // Defer assignment creation when approval is required. The buckets
        // are still computed so we can surface unrouted resources in the
        // submit response, but no assignment rows exist until approve fires.
        let mut assignment_count = 0u32;
        if !requires_approval {
            // Phase 7cg: when canary is requested, split agents within
            // each layer into batch 0 (canary) and batch 1 (baseline).
            // Layer-0 canary ships immediately; baseline holds in
            // `pending_canary`. Layer-N (N > 0) of either batch holds
            // in `pending_layer` until the previous layer's baseline
            // completes — phased apply still gates per-layer.
            let agents_per_layer = bucket_agents_per_layer(&buckets);
            let canary_assignment = compute_canary_split(&agents_per_layer, canary);

            for ((agent_id, layer), items) in &buckets {
                let assignment_id = Ulid::new().to_string();
                let mut resources_for_payload: Vec<serde_json::Value> =
                    Vec::with_capacity(items.len());
                for r in items.iter() {
                    let mut value: serde_json::Value = serde_json::from_str(&r.resource_json)?;
                    strip_routing_hints(&mut value);
                    resources_for_payload.push(value);
                }
                let payload = AssignmentPayload {
                    resources: resources_for_payload,
                };
                let payload_json = serde_json::to_string(&payload)?;

                let batch = canary_assignment.get(&(agent_id.clone(), *layer)).copied();
                let initial_assignment_status = match (*layer, batch) {
                    // Phase 7by: layer-0 ships immediately if there's
                    // no canary, OR if it's the canary batch.
                    (0, None) => "pending",
                    (0, Some(0)) => "pending",
                    // Phase 7cg: layer-0 baseline waits on canary.
                    (0, Some(1)) => "pending_canary",
                    // Phase 7by: any layer beyond 0 waits on the prior
                    // layer to fully settle (canary AND baseline).
                    _ => "pending_layer",
                };
                sqlx::query(&sql(
                    "INSERT INTO assignments
                      (id, agent_id, operation_id, payload_json, created_at, status, kind, layer, batch)
                     VALUES (?, ?, ?, ?, ?, ?, 'apply', ?, ?)",
                ))
                .bind(&assignment_id)
                .bind(agent_id)
                .bind(&op_id)
                .bind(&payload_json)
                .bind(&now)
                .bind(initial_assignment_status)
                .bind(i64::from(*layer))
                .bind(batch.map(i64::from))
                .execute(&mut *tx)
                .await?;
                assignment_count += 1;
            }

            // If nothing was routed, mark op succeeded immediately (no work to do).
            if assignment_count == 0 {
                sqlx::query(&sql(
                    "UPDATE operations SET status = 'succeeded', started_at = ?, finished_at = ?
                     WHERE id = ?",
                ))
                .bind(&now)
                .bind(&now)
                .bind(&op_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Audit: capture both clean submits and pending-approval submits with
        // the matched policy names so operators see WHY a gate fired.
        let kind = if requires_approval {
            "operation.pending_approval"
        } else {
            "operation.submitted"
        };
        record_audit_on(
            &mut tx,
            AuditRecord::new(actor, kind)
                .operation(&op_id)
                .payload(serde_json::json!({
                    "environment": environment,
                    "requested_by": requested_by,
                    "resource_count": resources.len(),
                    "assignment_count": assignment_count,
                    "unrouted_count": unrouted.len(),
                    "source_commit": source_commit,
                    "matched_policies": matched_policies,
                })),
        )
        .await?;

        tx.commit().await?;
        Ok(CreateOperationOutcome {
            operation_id: op_id,
            assignment_count,
            unrouted,
            matched_policies: matched_policies.to_vec(),
            requires_approval,
        })
    }

    /// Approve a `pending_approval` operation: recompute routing from the
    /// stored desired_states, create assignment rows, and transition the
    /// operation to `pending`.
    pub async fn approve_operation(
        &self,
        op_id: &str,
        approver_display: &str,
        actor: &str,
        reason: Option<&str>,
    ) -> ApiResult<u32> {
        let row = sqlx::query(&sql(
            "SELECT environment, status FROM operations WHERE id = ?",
        ))
        .bind(op_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
        let status: String = row.try_get("status")?;
        let environment: String = row.try_get("environment")?;
        if status != "pending_approval" {
            return Err(ApiError::Conflict(format!(
                "operation is in status {status:?}, not pending_approval"
            )));
        }

        // Snapshot the desired_states and registered agents so we can re-route.
        let desired_rows = sqlx::query(&sql("SELECT resource_id, kind, environment, spec_json
             FROM desired_states WHERE operation_id = ?"))
        .bind(op_id)
        .fetch_all(&self.pool)
        .await?;
        let agents: Vec<(String, String, String)> =
            sqlx::query_as(&sql("SELECT id, name, environment FROM agents"))
                .fetch_all(&self.pool)
                .await?;

        let mut tx = self.pool.begin().await?;
        let now = Timestamp::now().to_string();

        // Phase 7by: rebuild the full ResourceForRouting list, topo-sort
        // it, compute layers — same pipeline the submit path uses, just
        // running on persisted desired_states. Bucket by (agent, layer)
        // so approved operations also get phased dispatch.
        let mut routing_list: Vec<ResourceForRouting> = Vec::with_capacity(desired_rows.len());
        for r in &desired_rows {
            let resource_json: String = r.try_get("spec_json")?;
            let value: serde_json::Value = serde_json::from_str(&resource_json)?;
            let host_selector = value
                .get("spec")
                .and_then(|s| s.get("hostSelector"))
                .and_then(|h| h.get("name"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            routing_list.push(ResourceForRouting {
                resource_id: r.try_get("resource_id")?,
                kind: r.try_get("kind")?,
                environment: r.try_get("environment")?,
                resource_json,
                name: value
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                host_selector,
            });
        }
        // Topo-sort + layer computation. Approval-time errors are
        // surfaced as Internal because the submit-time validation
        // already accepted the dependsOn graph; failure here means
        // either persisted state is corrupt or compute_resource_layers
        // has a precondition bug — both call for operator inspection.
        crate::depsort::topo_sort_by_depends_on(&mut routing_list)?;
        let layers = crate::depsort::compute_resource_layers(&routing_list)?;

        let mut buckets: std::collections::BTreeMap<(String, i32), Vec<String>> =
            std::collections::BTreeMap::new();
        for (i, routing) in routing_list.iter().enumerate() {
            match route_resource(routing, &environment, &agents) {
                Ok(agent_id) => {
                    let mut stripped: serde_json::Value =
                        serde_json::from_str(&routing.resource_json)?;
                    strip_routing_hints(&mut stripped);
                    buckets
                        .entry((agent_id, layers[i]))
                        .or_default()
                        .push(serde_json::to_string(&stripped)?);
                }
                Err(_) => {
                    // Mid-approval routing failures land as silent skips; the
                    // operator sees them in `OperationView.assignments` as
                    // "missing" and can resubmit. We still proceed with what
                    // we have so partial deployment is possible.
                }
            }
        }

        let mut assignment_count = 0u32;
        for ((agent_id, layer), items_json) in &buckets {
            let assignment_id = Ulid::new().to_string();
            let resources_for_payload: Vec<serde_json::Value> = items_json
                .iter()
                .map(|s| serde_json::from_str(s))
                .collect::<Result<_, _>>()?;
            let payload = AssignmentPayload {
                resources: resources_for_payload,
            };
            let payload_json = serde_json::to_string(&payload)?;
            let initial_status = if *layer == 0 {
                "pending"
            } else {
                "pending_layer"
            };
            sqlx::query(&sql("INSERT INTO assignments
                  (id, agent_id, operation_id, payload_json, created_at, status, kind, layer)
                 VALUES (?, ?, ?, ?, ?, ?, 'apply', ?)"))
            .bind(&assignment_id)
            .bind(agent_id)
            .bind(op_id)
            .bind(&payload_json)
            .bind(&now)
            .bind(initial_status)
            .bind(i64::from(*layer))
            .execute(&mut *tx)
            .await?;
            assignment_count += 1;
        }

        let new_status = if assignment_count == 0 {
            "succeeded"
        } else {
            "pending"
        };
        let finished_at = if assignment_count == 0 {
            Some(now.as_str())
        } else {
            None
        };
        sqlx::query(&sql("UPDATE operations
             SET status = ?, approved_by = ?, approved_at = ?, approval_reason = ?,
                 finished_at = COALESCE(?, finished_at)
             WHERE id = ?"))
        .bind(new_status)
        .bind(approver_display)
        .bind(&now)
        .bind(reason)
        .bind(finished_at)
        .bind(op_id)
        .execute(&mut *tx)
        .await?;

        record_audit_on(
            &mut tx,
            AuditRecord::new(actor, "operation.approved")
                .operation(op_id)
                .payload(serde_json::json!({
                    "approver": approver_display,
                    "reason": reason,
                    "assignment_count": assignment_count,
                })),
        )
        .await?;

        tx.commit().await?;
        Ok(assignment_count)
    }

    /// Phase 7ci: build the resources list for a rollback of `op_id`.
    /// For every resource that was part of the target operation, find
    /// the most recent prior `desired_states` row from a *terminal*
    /// operation (succeeded / partially_applied) so we can re-apply
    /// that earlier spec.
    ///
    /// Returns `(reverted, orphaned, environment)` where:
    /// * `reverted` = resources we have a prior spec for (these are
    ///   the resources the rollback operation will dispatch).
    /// * `orphaned` = resource_ids that were first-applied in the
    ///   target op and have no prior state. The caller surfaces
    ///   these so the operator knows about manual cleanup.
    ///
    /// The target op must be terminal — no rolling back something
    /// that's still rolling out (would race with assignment dispatch).
    pub async fn prepare_rollback(
        &self,
        op_id: &str,
    ) -> ApiResult<(Vec<ResourceForRouting>, Vec<String>, String)> {
        // 1. Validate target op exists + is terminal.
        let row = sqlx::query(&sql(
            "SELECT environment, status FROM operations WHERE id = ?",
        ))
        .bind(op_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::NotFound)?;
        let environment: String = row.try_get("environment")?;
        let status: String = row.try_get("status")?;
        match status.as_str() {
            "succeeded" | "partially_applied" | "failed" => {}
            other => {
                return Err(ApiError::Conflict(format!(
                    "rollback only on terminal operations; current status: {other}"
                )));
            }
        }

        // 2. List the resources that were touched by this op.
        let target_rows = sqlx::query(&sql(
            "SELECT resource_id FROM desired_states WHERE operation_id = ?",
        ))
        .bind(op_id)
        .fetch_all(&self.pool)
        .await?;

        let mut reverted = Vec::new();
        let mut orphaned = Vec::new();

        for r in target_rows {
            let resource_id: String = r.try_get("resource_id")?;
            // 3. Find the most recent terminal-and-successful prior op
            //    that touched the same resource_id. We exclude the
            //    target op itself + any op that didn't reach a useful
            //    terminal state. Newest-first via the join's ORDER BY.
            let prior = sqlx::query(&sql("SELECT ds.spec_json, ds.kind, ds.environment
                 FROM desired_states ds
                 JOIN operations o ON o.id = ds.operation_id
                 WHERE ds.resource_id = ?
                   AND ds.operation_id != ?
                   AND o.status IN ('succeeded', 'partially_applied')
                   AND o.created_at < (
                       SELECT created_at FROM operations WHERE id = ?
                   )
                 ORDER BY o.created_at DESC, ds.id DESC
                 LIMIT 1"))
            .bind(&resource_id)
            .bind(op_id)
            .bind(op_id)
            .fetch_optional(&self.pool)
            .await?;
            let Some(prior_row) = prior else {
                orphaned.push(resource_id);
                continue;
            };

            let spec_json: String = prior_row.try_get("spec_json")?;
            let kind: String = prior_row.try_get("kind")?;
            let resource_env: String = prior_row.try_get("environment")?;
            let value: serde_json::Value = serde_json::from_str(&spec_json)?;
            let name = value
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let host_selector = value
                .get("spec")
                .and_then(|s| s.get("hostSelector"))
                .and_then(|h| h.get("name"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            reverted.push(ResourceForRouting {
                resource_id,
                kind,
                environment: resource_env,
                resource_json: spec_json,
                name,
                host_selector,
            });
        }

        Ok((reverted, orphaned, environment))
    }

    pub async fn reject_operation(
        &self,
        op_id: &str,
        rejector_display: &str,
        actor: &str,
        reason: &str,
    ) -> ApiResult<()> {
        if reason.trim().is_empty() {
            return Err(ApiError::BadRequest("reason must not be empty".into()));
        }
        let mut tx = self.pool.begin().await?;
        let now = Timestamp::now().to_string();
        let res = sqlx::query(&sql("UPDATE operations
             SET status = 'rejected', rejected_by = ?, rejected_at = ?,
                 rejection_reason = ?, finished_at = ?
             WHERE id = ? AND status = 'pending_approval'"))
        .bind(rejector_display)
        .bind(&now)
        .bind(reason)
        .bind(&now)
        .bind(op_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::Conflict(
                "operation not found or not in pending_approval".into(),
            ));
        }
        record_audit_on(
            &mut tx,
            AuditRecord::new(actor, "operation.rejected")
                .severity("warning")
                .operation(op_id)
                .payload(serde_json::json!({
                    "rejector": rejector_display,
                    "reason": reason,
                })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Returns pending assignments for the agent, marking them as fetched.
    ///
    /// Phase 7cq.1 (security fix #4.3): claim is now atomic via
    /// `UPDATE ... WHERE ... RETURNING` instead of the previous
    /// SELECT-then-UPDATE pattern. On Postgres READ COMMITTED two
    /// concurrent fetches could both SELECT the same row and both
    /// UPDATE it — net result was double-dispatch (the assignment
    /// runs twice). With UPDATE-RETURNING, row-level locks during
    /// the UPDATE serialize the claim; whichever tx wins owns the
    /// row, the other sees `status = 'fetched'` and the WHERE filters
    /// it out. Works identically on SQLite (single-writer) and
    /// Postgres.
    ///
    /// Phase 7cj: also re-claims assignments whose lease expired
    /// ('fetched' but older than ASSIGNMENT_LEASE_SECS without a
    /// result POST). Without this, an agent that crashed between
    /// GET and POST orphans the assignment indefinitely.
    pub async fn fetch_pending_assignments(
        &self,
        agent_id: &str,
    ) -> ApiResult<Vec<AssignmentEnvelope>> {
        let mut tx = self.pool.begin().await?;
        let now_ts = Timestamp::now();
        let lease_cutoff = (now_ts - jiff::ToSpan::seconds(assignment_lease_secs())).to_string();
        let now = now_ts.to_string();
        let rows = sqlx::query(&sql("UPDATE assignments
             SET status = 'fetched', fetched_at = ?
             WHERE agent_id = ?
               AND (
                 status = 'pending'
                 OR (status = 'fetched' AND fetched_at IS NOT NULL AND fetched_at < ?)
               )
             RETURNING id, operation_id, kind, payload_json, created_at, expires_at"))
        .bind(&now)
        .bind(agent_id)
        .bind(&lease_cutoff)
        .fetch_all(&mut *tx)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        let mut op_ids_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let payload_json: String = row.try_get("payload_json")?;
            let payload: AssignmentPayload = serde_json::from_str(&payload_json)?;
            let op_id: String = row.try_get("operation_id")?;
            if op_ids_seen.insert(op_id.clone()) {
                // Mark the operation running on first fetch (per op).
                sqlx::query(&sql(
                    "UPDATE operations SET status = 'running', started_at = COALESCE(started_at, ?)
                     WHERE id = ? AND status = 'pending'",
                ))
                .bind(&now)
                .bind(&op_id)
                .execute(&mut *tx)
                .await?;
            }
            out.push(AssignmentEnvelope {
                assignment_id: id,
                operation_id: op_id,
                kind: row.try_get("kind")?,
                created_at: row.try_get("created_at")?,
                expires_at: row.try_get("expires_at")?,
                payload,
                // Signature + key_id are filled in by the API handler — the
                // store stays oblivious to crypto so the keypair can rotate
                // without touching DB rows.
                key_id: String::new(),
                signature: String::new(),
            });
        }
        // Order by created_at to preserve the previous semantics.
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        tx.commit().await?;
        Ok(out)
    }

    pub async fn complete_assignment(
        &self,
        agent_id: &str,
        assignment_id: &str,
        result: &AssignmentResultRequest,
    ) -> ApiResult<()> {
        self.complete_assignment_with_extra_audit(agent_id, assignment_id, result, None)
            .await
    }

    /// Phase 7dg: same as [`Self::complete_assignment`] but stages an
    /// additional audit row inside the same transaction. SSH push
    /// uses this to record `ssh.push_*` events atomically with the
    /// status transition — without it, `wait_terminal`-style polls
    /// could see the operation finish before the audit row lands.
    pub async fn complete_assignment_with_extra_audit<'a>(
        &self,
        agent_id: &str,
        assignment_id: &str,
        result: &AssignmentResultRequest,
        extra_audit: Option<AuditRecord<'a>>,
    ) -> ApiResult<()> {
        let mut tx = self.pool.begin().await?;
        // Verify the assignment belongs to this agent and is in a fetchable state.
        let op_id: Option<String> = sqlx::query_scalar(
            "SELECT operation_id FROM assignments
             WHERE id = ? AND agent_id = ? AND status IN ('pending', 'fetched')",
        )
        .bind(assignment_id)
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await?;
        let op_id = op_id.ok_or(ApiError::NotFound)?;

        let result_json = serde_json::to_string(result)?;
        let status = match result.status {
            AssignmentResultStatus::Succeeded => "succeeded",
            AssignmentResultStatus::PartiallyApplied => "partially_applied",
            AssignmentResultStatus::Failed => "failed",
        };
        let now = Timestamp::now().to_string();
        sqlx::query(&sql("UPDATE assignments
             SET status = ?, completed_at = ?, result_json = ?
             WHERE id = ?"))
        .bind(status)
        .bind(&now)
        .bind(&result_json)
        .bind(assignment_id)
        .execute(&mut *tx)
        .await?;

        // Phase 7by: advance the phased-apply state machine. If this
        // completion finishes a layer, promote the next layer's
        // `pending_layer` assignments to `pending`. If it failed,
        // cancel all subsequent `pending_layer` assignments so the
        // failure stops at the boundary.
        advance_phased_apply(&mut tx, &op_id, &now).await?;

        // Roll up to operation status when all assignments for this op are terminal.
        roll_up_operation(&mut tx, &op_id, &now).await?;

        // Audit the agent's report.
        let actor = format!("agent:{agent_id}");
        let severity = match result.status {
            AssignmentResultStatus::Failed => "warning",
            AssignmentResultStatus::PartiallyApplied => "warning",
            AssignmentResultStatus::Succeeded => "info",
        };
        record_audit_on(
            &mut tx,
            AuditRecord::new(&actor, "assignment.completed")
                .severity(severity)
                .operation(&op_id)
                .agent(agent_id)
                .payload(serde_json::json!({
                    "assignment_id": assignment_id,
                    "status": status,
                    "item_count": result.items.len(),
                    "summary": result.summary,
                })),
        )
        .await?;

        // Phase 7dg: caller-supplied audit (e.g. SSH push's
        // `ssh.push_succeeded`) goes into the same tx so observers
        // that see the operation transition to terminal can also
        // see the audit row.
        if let Some(extra) = extra_audit {
            record_audit_on(&mut tx, extra).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// What the agent should be watching: the latest desired spec per
    /// `resource_id` across every assignment we have ever dispatched to this
    /// agent (excluding ones that ended in failure). Routing hints
    /// (`spec.hostSelector`) are stripped so the agent sees the same shape
    /// it gets in apply assignments.
    pub async fn list_desired_state_for_agent(
        &self,
        agent_id: &str,
    ) -> ApiResult<Vec<DesiredStateItem>> {
        let rows = sqlx::query(&sql(
            "SELECT ds.resource_id, ds.spec_json AS resource_json, ds.operation_id, o.created_at
             FROM desired_states ds
             JOIN operations o ON o.id = ds.operation_id
             JOIN assignments a ON a.operation_id = ds.operation_id
             WHERE a.agent_id = ?
               AND a.status != 'failed'
             ORDER BY ds.resource_id, o.created_at DESC, ds.id DESC",
        ))
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;

        // Collapse to the latest entry per resource_id (rows are ordered with
        // newest first within each resource_id group).
        let mut out: Vec<DesiredStateItem> = Vec::new();
        let mut last_seen: Option<String> = None;
        for row in rows {
            let rid: String = row.try_get("resource_id")?;
            if last_seen.as_deref() == Some(&rid) {
                continue;
            }
            let raw_json: String = row.try_get("resource_json")?;
            let mut value: serde_json::Value = serde_json::from_str(&raw_json)?;
            strip_routing_hints(&mut value);
            out.push(DesiredStateItem {
                resource_id: rid.clone(),
                operation_id: row.try_get("operation_id")?,
                created_at: row.try_get("created_at")?,
                resource: value,
            });
            last_seen = Some(rid);
        }
        Ok(out)
    }

    /// Phase 7b: list every primitive an operation will (or did) write,
    /// each tagged with the agent it routes to. Reads `desired_states`
    /// directly so the answer is meaningful even for `pending_approval`
    /// operations where no assignments exist yet. Resources whose host
    /// selector or environment can't be routed are still returned with
    /// `agent_id = ""` so approvers see them flagged.
    pub async fn list_desired_state_for_operation(
        &self,
        operation_id: &str,
    ) -> ApiResult<Vec<OperationDesiredStateItem>> {
        let op_row = sqlx::query(&sql("SELECT environment FROM operations WHERE id = ?"))
            .bind(operation_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ApiError::NotFound)?;
        let environment: String = op_row.try_get("environment")?;

        let rows = sqlx::query(&sql("SELECT resource_id, kind, environment, spec_json
             FROM desired_states WHERE operation_id = ?
             ORDER BY id"))
        .bind(operation_id)
        .fetch_all(&self.pool)
        .await?;

        let agents: Vec<(String, String, String)> =
            sqlx::query_as(&sql("SELECT id, name, environment FROM agents"))
                .fetch_all(&self.pool)
                .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let resource_id: String = r.try_get("resource_id")?;
            let kind: String = r.try_get("kind")?;
            let resource_env: String = r.try_get("environment")?;
            let resource_json: String = r.try_get("spec_json")?;
            let mut value: serde_json::Value = serde_json::from_str(&resource_json)?;
            let host_selector = value
                .get("spec")
                .and_then(|s| s.get("hostSelector"))
                .and_then(|h| h.get("name"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let routing = ResourceForRouting {
                resource_id: resource_id.clone(),
                kind: kind.clone(),
                environment: resource_env,
                resource_json: resource_json.clone(),
                name: value
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                host_selector,
            };
            let agent_id = route_resource(&routing, &environment, &agents).unwrap_or_default();
            strip_routing_hints(&mut value);
            out.push(OperationDesiredStateItem {
                resource_id,
                kind,
                agent_id,
                resource: value,
            });
        }
        Ok(out)
    }

    /// List operations, newest first, optionally filtered by status.
    /// Returns slim `OperationListItem` rows (no assignments / no
    /// matched_policies — fetch those via `get_operation` when needed).
    /// `limit` is clamped to [1, 1000] so a stray `--limit 1_000_000`
    /// can't OOM the CP.
    pub async fn list_operations(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> ApiResult<Vec<OperationListItem>> {
        let limit = limit.clamp(1, 1000);
        let base = "SELECT id, kind, environment, requested_by, status,
                           created_at, started_at, finished_at
                    FROM operations";
        let mut items = Vec::new();
        let rows = match status {
            Some(s) => {
                sqlx::query(&sql(&format!(
                    "{base} WHERE status = ? ORDER BY created_at DESC LIMIT ?"
                )))
                .bind(s)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(&sql(&format!("{base} ORDER BY created_at DESC LIMIT ?")))
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        for r in rows {
            let status_str: String = r.try_get("status")?;
            items.push(OperationListItem {
                id: r.try_get("id")?,
                kind: r.try_get("kind")?,
                environment: r.try_get("environment")?,
                requested_by: r.try_get("requested_by")?,
                status: parse_operation_status(&status_str),
                created_at: r.try_get("created_at")?,
                started_at: r.try_get("started_at")?,
                finished_at: r.try_get("finished_at")?,
            });
        }
        Ok(items)
    }

    pub async fn get_operation(&self, operation_id: &str) -> ApiResult<OperationView> {
        let row = sqlx::query(&sql(
            "SELECT id, kind, environment, requested_by, status, created_at,
                    started_at, finished_at, matched_policies_json,
                    approved_by, approved_at, rejected_by, rejected_at,
                    rejection_reason
             FROM operations WHERE id = ?",
        ))
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ApiError::NotFound)?;

        let assignments_rows = sqlx::query(&sql(
            "SELECT id, agent_id, status, created_at, fetched_at, completed_at, result_json
             FROM assignments WHERE operation_id = ? ORDER BY created_at",
        ))
        .bind(operation_id)
        .fetch_all(&self.pool)
        .await?;

        let mut assignments = Vec::with_capacity(assignments_rows.len());
        for r in assignments_rows {
            let result_json: Option<String> = r.try_get("result_json")?;
            let result = match result_json {
                Some(s) => serde_json::from_str::<serde_json::Value>(&s).ok(),
                None => None,
            };
            assignments.push(AssignmentView {
                id: r.try_get("id")?,
                agent_id: r.try_get("agent_id")?,
                status: r.try_get("status")?,
                created_at: r.try_get("created_at")?,
                fetched_at: r.try_get("fetched_at")?,
                completed_at: r.try_get("completed_at")?,
                result,
            });
        }

        let status_str: String = row.try_get("status")?;
        let matched_json: String = row.try_get("matched_policies_json")?;
        let matched_policies: Vec<String> = serde_json::from_str(&matched_json).unwrap_or_default();
        Ok(OperationView {
            id: row.try_get("id")?,
            kind: row.try_get("kind")?,
            environment: row.try_get("environment")?,
            requested_by: row.try_get("requested_by")?,
            status: parse_operation_status(&status_str),
            created_at: row.try_get("created_at")?,
            started_at: row.try_get("started_at")?,
            finished_at: row.try_get("finished_at")?,
            assignments,
            matched_policies,
            approved_by: row.try_get("approved_by")?,
            approved_at: row.try_get("approved_at")?,
            rejected_by: row.try_get("rejected_by")?,
            rejected_at: row.try_get("rejected_at")?,
            rejection_reason: row.try_get("rejection_reason")?,
        })
    }
}

fn parse_operation_status(s: &str) -> OperationStatus {
    match s {
        "running" => OperationStatus::Running,
        "partially_applied" => OperationStatus::PartiallyApplied,
        "failed" => OperationStatus::Failed,
        "succeeded" => OperationStatus::Succeeded,
        "pending_approval" => OperationStatus::PendingApproval,
        "rejected" => OperationStatus::Rejected,
        _ => OperationStatus::Pending,
    }
}

/// Phase 7by: advance the phased-apply state machine. Called after
/// every assignment-completion. If a layer is now fully terminal:
///
///   * All `succeeded` → promote next layer's `pending_layer`
///     assignments to `pending` so agents pick them up.
///   * Any `failed` / `partially_applied` → cancel ALL remaining
///     `pending_layer` assignments. The rollout stops at the first
///     failed layer instead of cascading damage downstream.
///
/// Idempotent — re-running on the same state is a no-op (no rows
/// match the promote / cancel queries). Safe to call from multiple
/// completions racing against each other; SQL row updates serialize
/// via the active transaction.
async fn advance_phased_apply(conn: &mut AnyConnection, op_id: &str, now: &str) -> ApiResult<()> {
    // Phase 7cg: canary gating runs first. Within any layer that has
    // pending_canary baseline assignments, check the canary batch:
    //   * Any canary failure → cancel both rest of canary and the
    //     baseline. Same blast-radius containment as a layer failure.
    //   * All canary done + succeeded → promote baseline `pending_canary`
    //     → `pending` so the baseline rollout can start.
    advance_canary(conn, op_id, now).await?;

    // Find the lowest layer that still has any `pending_layer`
    // assignments. That's the next candidate for promotion or
    // cancellation. If none, phasing is already settled.
    let next_layer: Option<i64> = sqlx::query_scalar(&sql("SELECT MIN(layer) FROM assignments
         WHERE operation_id = ? AND status = 'pending_layer'"))
    .bind(op_id)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    let Some(next_layer) = next_layer else {
        return Ok(());
    };

    // Inspect the layer immediately below — that's the gate. If it
    // has no rows at all (could happen after cancellation pruning),
    // treat as 'all succeeded' so the next layer flows through.
    let prev_layer = next_layer - 1;
    let rows: Vec<(String, i64)> = sqlx::query_as(&sql("SELECT status, COUNT(*) FROM assignments
         WHERE operation_id = ? AND layer = ?
         GROUP BY status"))
    .bind(op_id)
    .bind(prev_layer)
    .fetch_all(&mut *conn)
    .await?;

    let (mut still_running, mut failed_count, mut succeeded_count) = (0i64, 0i64, 0i64);
    for (s, n) in rows {
        match s.as_str() {
            // Phase 7cg: pending_canary is "still running" for the
            // purpose of gating the next layer — baseline hasn't even
            // started yet.
            "pending" | "fetched" | "pending_layer" | "pending_canary" => still_running += n,
            "failed" | "partially_applied" => failed_count += n,
            "succeeded" => succeeded_count += n,
            "cancelled" => {} // cancelled prev layer is unusual but doesn't gate us
            _ => {}
        }
    }
    if still_running > 0 {
        // Previous layer not done yet — wait.
        return Ok(());
    }

    if failed_count > 0 {
        // Phase 7by: any failure in the prev layer cancels the entire
        // remaining rollout. Mark every remaining `pending_layer`
        // assignment as `cancelled` with completed_at=now so the op
        // rollup sees them as terminal.
        sqlx::query(&sql("UPDATE assignments
             SET status = 'cancelled', completed_at = ?
             WHERE operation_id = ? AND status = 'pending_layer'"))
        .bind(now)
        .bind(op_id)
        .execute(&mut *conn)
        .await?;
        return Ok(());
    }

    if succeeded_count == 0 {
        // Edge case: no rows at prev_layer at all (e.g. all routed to
        // agents that never registered). Treat as success so next
        // layer flows through. This is consistent with the pre-7by
        // flat-dispatch semantics — a layer with no rows can't fail.
    }

    // Promote the next layer's pending_layer → pending so agents
    // start picking them up on their next poll.
    sqlx::query(&sql("UPDATE assignments
         SET status = 'pending'
         WHERE operation_id = ? AND layer = ? AND status = 'pending_layer'"))
    .bind(op_id)
    .bind(next_layer)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Phase 7cg: gate the canary-to-baseline transition within each
/// layer. For every layer that has at least one `pending_canary`
/// (baseline) assignment, look at its canary batch (batch=0):
///
///   * Any failure → cancel rest of canary AND the baseline at this
///     layer + any later layers (cascading the same way layer
///     failures cascade in `advance_phased_apply`). Operator sees
///     a clean "canary failed; rollout aborted" outcome.
///   * Still running → do nothing; we'll be called again on the
///     next completion.
///   * All canary done + at least one succeeded + zero failures →
///     promote `pending_canary` → `pending` so baseline picks up.
///     (Edge: zero canary at this layer → degenerate; promote
///     baseline immediately.)
///
/// Operates on every layer that has waiting baseline rows, so a
/// single completion that finishes layer-0 canary and triggers
/// promotion of layer-0 baseline doesn't need a separate trip
/// through this function.
async fn advance_canary(conn: &mut AnyConnection, op_id: &str, now: &str) -> ApiResult<()> {
    // Distinct layers with pending_canary baseline waiting.
    let waiting_layers: Vec<i64> =
        sqlx::query_scalar(&sql("SELECT DISTINCT layer FROM assignments
         WHERE operation_id = ? AND status = 'pending_canary'"))
        .bind(op_id)
        .fetch_all(&mut *conn)
        .await?;
    if waiting_layers.is_empty() {
        return Ok(());
    }

    for layer in waiting_layers {
        // Inspect the canary batch (batch = 0) at this layer.
        let rows: Vec<(String, i64)> =
            sqlx::query_as(&sql("SELECT status, COUNT(*) FROM assignments
             WHERE operation_id = ? AND layer = ? AND batch = 0
             GROUP BY status"))
            .bind(op_id)
            .bind(layer)
            .fetch_all(&mut *conn)
            .await?;

        let (mut still_running, mut failed_count, mut succeeded_count) = (0i64, 0i64, 0i64);
        for (s, n) in rows {
            match s.as_str() {
                "pending" | "fetched" => still_running += n,
                "failed" | "partially_applied" => failed_count += n,
                "succeeded" => succeeded_count += n,
                _ => {}
            }
        }

        if failed_count > 0 {
            // Cancel rest of canary at this layer (any pending/fetched
            // canary stops mid-flight) AND cancel everything still
            // pending_canary or pending_layer for this op. Operator
            // sees the smallest blast radius — only the failed canary
            // ever touched real state.
            sqlx::query(&sql("UPDATE assignments
                 SET status = 'cancelled', completed_at = ?
                 WHERE operation_id = ?
                   AND status IN ('pending_canary', 'pending_layer', 'pending', 'fetched')
                   AND NOT (layer = ? AND batch = 0)"))
            .bind(now)
            .bind(op_id)
            .bind(layer)
            .execute(&mut *conn)
            .await?;
            // Don't bother promoting other layers in this loop — the
            // cancellation just nuked their pending_canary rows.
            return Ok(());
        }

        if still_running > 0 {
            // Canary not done at this layer — wait.
            continue;
        }

        if succeeded_count == 0 {
            // No canary rows at all (degenerate — shouldn't happen
            // because compute_canary_split skips layers with ≤1
            // agent). Promote baseline anyway so the rollout doesn't
            // hang.
        }

        // Promote baseline at this layer.
        sqlx::query(&sql(
            "UPDATE assignments
             SET status = 'pending'
             WHERE operation_id = ? AND layer = ? AND status = 'pending_canary'",
        ))
        .bind(op_id)
        .bind(layer)
        .execute(&mut *conn)
        .await?;
    }

    Ok(())
}

async fn roll_up_operation(conn: &mut AnyConnection, op_id: &str, now: &str) -> ApiResult<()> {
    // Count assignment statuses for this op.
    let rows: Vec<(String, i64)> = sqlx::query_as(&sql(
        "SELECT status, COUNT(*) FROM assignments WHERE operation_id = ? GROUP BY status",
    ))
    .bind(op_id)
    .fetch_all(&mut *conn)
    .await?;

    // Phase 7by: pending_layer means "waiting for an earlier layer";
    // cancelled means "earlier layer failed, this layer never ran." Both
    // are factored in: pending_layer keeps the op non-terminal; cancelled
    // counts as a failure flavor for the final status.
    let (
        mut pending,
        mut fetched,
        mut pending_layer,
        mut pending_canary,
        mut succeeded,
        mut partial,
        mut failed,
        mut cancelled,
    ) = (0i64, 0i64, 0i64, 0i64, 0i64, 0i64, 0i64, 0i64);
    for (s, n) in rows {
        match s.as_str() {
            "pending" => pending = n,
            "fetched" => fetched = n,
            "pending_layer" => pending_layer = n,
            // Phase 7cg: baseline waiting on canary — still in flight.
            "pending_canary" => pending_canary = n,
            "succeeded" => succeeded = n,
            "partially_applied" => partial = n,
            "failed" => failed = n,
            "cancelled" => cancelled = n,
            _ => {}
        }
    }
    if pending + fetched + pending_layer + pending_canary > 0 {
        return Ok(());
    }
    let any_failure = failed + partial + cancelled > 0;
    let new_status = if any_failure {
        if succeeded > 0 || partial > 0 {
            "partially_applied"
        } else {
            "failed"
        }
    } else {
        "succeeded"
    };
    sqlx::query(&sql(
        "UPDATE operations SET status = ?, finished_at = ? WHERE id = ?",
    ))
    .bind(new_status)
    .bind(now)
    .bind(op_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// `hostSelector` is a server-side routing hint that lives at `spec.hostSelector`
/// Phase 7cg: collect distinct agents per layer in stable order.
/// The agent_ids are de-duplicated and sorted so the canary split
/// is deterministic — same submission always picks the same canary
/// agents, easing operator debugging ("which agent is the canary?").
fn bucket_agents_per_layer(
    buckets: &std::collections::BTreeMap<(String, i32), Vec<&ResourceForRouting>>,
) -> std::collections::BTreeMap<i32, Vec<String>> {
    let mut per_layer: std::collections::BTreeMap<i32, Vec<String>> =
        std::collections::BTreeMap::new();
    for (agent_id, layer) in buckets.keys() {
        let v = per_layer.entry(*layer).or_default();
        if !v.contains(agent_id) {
            v.push(agent_id.clone());
        }
    }
    for v in per_layer.values_mut() {
        v.sort();
    }
    per_layer
}

/// Phase 7cg: compute which `(agent_id, layer)` pairs go into the
/// canary batch (0) vs. the baseline batch (1). When canary is None,
/// returns an empty map and the caller falls back to NULL `batch`
/// (pre-7cg behavior).
///
/// The split is per-layer because each layer's agent set differs
/// (some agents may not have work at every layer). Per-layer counts
/// also keep the canary blast radius proportional within each phase
/// of the rollout.
///
/// We always leave at least one agent in the baseline; otherwise
/// "canary" devolves to "everyone goes first" which provides no
/// gating. Per-layer agent counts of 1 → no canary at that layer
/// (the single agent goes straight to batch 0 = pending; no
/// baseline batch to gate).
fn compute_canary_split(
    agents_per_layer: &std::collections::BTreeMap<i32, Vec<String>>,
    canary: Option<iac_core::protocol::v1::CanarySpec>,
) -> std::collections::HashMap<(String, i32), u8> {
    let mut out = std::collections::HashMap::new();
    let Some(spec) = canary else {
        return out;
    };
    let pct = spec.pct.clamp(1, 99) as u32;
    let min_count = spec.min_count.unwrap_or(1).max(1);
    for (layer, agents) in agents_per_layer {
        let n = agents.len() as u32;
        if n <= 1 {
            // Trivial layer — no point splitting.
            continue;
        }
        // ceil(n * pct / 100)
        let from_pct = n.saturating_mul(pct).div_ceil(100);
        let canary_count = from_pct.max(min_count).min(n - 1) as usize;
        for (i, agent) in agents.iter().enumerate() {
            let batch: u8 = if i < canary_count { 0 } else { 1 };
            out.insert((agent.clone(), *layer), batch);
        }
    }
    out
}

/// in the original manifest. The agent's provider doesn't know about it (and
/// would reject it as an unknown field), so we drop it from each resource
/// before sealing the assignment payload.
fn strip_routing_hints(value: &mut serde_json::Value) {
    if let Some(spec) = value.get_mut("spec").and_then(|s| s.as_object_mut()) {
        spec.remove("hostSelector");
    }
}

/// Decide which agent should receive a resource. Rules:
///
/// 1. If `spec.hostSelector.name` is set, route to the agent with that exact
///    `agent.name`. If the named agent isn't registered yet, the resource is
///    unrouted (the operator must register the agent first).
/// 2. Otherwise, if there's exactly one agent in `environment`, route there.
/// 3. Otherwise, the resource is ambiguous and added to `unrouted`.
fn route_resource(
    r: &ResourceForRouting,
    operation_env: &str,
    agents: &[(String, String, String)], // (id, name, environment)
) -> Result<String, String> {
    if let Some(host) = &r.host_selector {
        for (id, name, env) in agents {
            if name == host && env == operation_env {
                return Ok(id.clone());
            }
        }
        return Err(format!(
            "hostSelector.name={host:?} but no agent registered in environment={operation_env:?}"
        ));
    }
    let env_agents: Vec<&(String, String, String)> = agents
        .iter()
        .filter(|(_, _, env)| env == operation_env)
        .collect();
    match env_agents.len() {
        0 => Err(format!(
            "no agents registered in environment={operation_env:?}"
        )),
        1 => Ok(env_agents[0].0.clone()),
        n => Err(format!(
            "{n} agents in environment={operation_env:?}; resource needs spec.hostSelector.name"
        )),
    }
}

fn row_to_drift_summary(row: AnyRow) -> ApiResult<DriftSummary> {
    let diff_json: String = row.try_get("diff_json")?;
    let diff: iac_core::diff::Diff = serde_json::from_str(&diff_json)?;
    Ok(DriftSummary {
        id: row.try_get("id")?,
        agent_id: row.try_get("agent_id")?,
        resource_id: row.try_get("resource_id")?,
        kind: row.try_get("kind")?,
        severity: row.try_get("severity")?,
        detected_at: row.try_get("detected_at")?,
        diff,
        ignored_until: row.try_get("ignored_until")?,
        resolved_at: row.try_get("resolved_at")?,
        resolution: row.try_get("resolution")?,
    })
}

// ---- RBAC users (Phase 6e) -------------------------------------------------

#[derive(Debug, Clone)]
pub struct CreateUser<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub roles: Vec<crate::identity::Role>,
}

impl Store {
    /// Create a user with an Argon2 password hash + initial role list.
    /// Returns the new user id.
    pub async fn create_user(&self, req: CreateUser<'_>) -> ApiResult<String> {
        if req.username.is_empty() || req.password.is_empty() {
            return Err(ApiError::BadRequest(
                "username and password must be non-empty".into(),
            ));
        }
        let id = Ulid::new().to_string();
        let hash = crate::identity::hash_password(req.password)?;
        let roles_json = serde_json::to_string(&req.roles)?;
        let now = Timestamp::now().to_string();
        let res = sqlx::query(&sql(
            "INSERT INTO users (id, username, password_hash, roles_json, created_at)
             VALUES (?, ?, ?, ?, ?)",
        ))
        .bind(&id)
        .bind(req.username)
        .bind(hash)
        .bind(roles_json)
        .bind(&now)
        .execute(&self.pool)
        .await;
        match res {
            Ok(_) => Ok(id),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Err(ApiError::Conflict(
                format!("user {:?} already exists", req.username),
            )),
            Err(e) => Err(ApiError::from(e)),
        }
    }

    /// Verify a (username, password) pair and issue a fresh token. Returns
    /// `(token, expires_at, user_record)` on success.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        ttl_secs: i64,
    ) -> ApiResult<(String, String, crate::identity::UserRecord)> {
        let row = sqlx::query(&sql(
            "SELECT id, username, password_hash, roles_json, disabled_at
             FROM users WHERE username = ?",
        ))
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(ApiError::Unauthorized);
        };
        let disabled_at: Option<String> = row.try_get("disabled_at")?;
        if disabled_at.is_some() {
            return Err(ApiError::Unauthorized);
        }
        let hash: String = row.try_get("password_hash")?;
        if !crate::identity::verify_password(password, &hash)? {
            return Err(ApiError::Unauthorized);
        }
        let id: String = row.try_get("id")?;
        let username: String = row.try_get("username")?;
        let roles_json: String = row.try_get("roles_json")?;
        let roles: Vec<crate::identity::Role> =
            serde_json::from_str(&roles_json).unwrap_or_default();

        // Issue token. Same shape as agent tokens: 256-bit random,
        // sha256(token) stored.
        let (token, token_hash) = crate::auth::issue_token();
        let now = Timestamp::now();
        let expires = now
            .checked_add(
                jiff::Span::new()
                    .try_seconds(ttl_secs)
                    .map_err(|e| ApiError::Internal(format!("ttl span: {e}")))?,
            )
            .map_err(|e| ApiError::Internal(format!("ttl arithmetic: {e}")))?;
        sqlx::query(&sql(
            "INSERT INTO user_tokens (token_hash, user_id, issued_at, expires_at)
             VALUES (?, ?, ?, ?)",
        ))
        .bind(&token_hash)
        .bind(&id)
        .bind(now.to_string())
        .bind(expires.to_string())
        .execute(&self.pool)
        .await?;

        Ok((
            token,
            expires.to_string(),
            crate::identity::UserRecord {
                id,
                username,
                roles,
            },
        ))
    }

    /// Phase 7e: rotate a user token. Verifies the old token is still
    /// valid (not expired, owner not disabled), reads the owner's *current*
    /// role list (so a recently-elevated user picks up the new roles), then
    /// atomically inserts a fresh token row and revokes the old one.
    /// Returns the same shape as `login` so the auth handler can reuse the
    /// `LoginResponse` body.
    pub async fn refresh_user_token(
        &self,
        token: &str,
        ttl_secs: i64,
    ) -> ApiResult<(String, String, crate::identity::UserRecord)> {
        let old_hash = crate::auth::hash_token(token);
        let now = Timestamp::now();
        let now_str = now.to_string();

        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(&sql("SELECT u.id, u.username, u.roles_json, u.disabled_at
             FROM user_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND t.expires_at > ?"))
        .bind(&old_hash)
        .bind(&now_str)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await.ok();
            return Err(ApiError::Unauthorized);
        };
        let disabled_at: Option<String> = row.try_get("disabled_at")?;
        if disabled_at.is_some() {
            tx.rollback().await.ok();
            return Err(ApiError::Unauthorized);
        }
        let id: String = row.try_get("id")?;
        let username: String = row.try_get("username")?;
        let roles_json: String = row.try_get("roles_json")?;
        let roles: Vec<crate::identity::Role> =
            serde_json::from_str(&roles_json).unwrap_or_default();

        let (new_token, new_hash) = crate::auth::issue_token();
        let expires = now
            .checked_add(
                jiff::Span::new()
                    .try_seconds(ttl_secs)
                    .map_err(|e| ApiError::Internal(format!("ttl span: {e}")))?,
            )
            .map_err(|e| ApiError::Internal(format!("ttl arithmetic: {e}")))?;
        sqlx::query(&sql(
            "INSERT INTO user_tokens (token_hash, user_id, issued_at, expires_at)
             VALUES (?, ?, ?, ?)",
        ))
        .bind(&new_hash)
        .bind(&id)
        .bind(&now_str)
        .bind(expires.to_string())
        .execute(&mut *tx)
        .await?;
        sqlx::query(&sql("DELETE FROM user_tokens WHERE token_hash = ?"))
            .bind(&old_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        Ok((
            new_token,
            expires.to_string(),
            crate::identity::UserRecord {
                id,
                username,
                roles,
            },
        ))
    }

    /// Find a user by their bearer token, treating expired entries as not
    /// present. Hot path for auth — keeps the query simple.
    pub async fn find_user_by_token(
        &self,
        token: &str,
    ) -> ApiResult<Option<crate::identity::UserRecord>> {
        let token_hash = crate::auth::hash_token(token);
        let now = Timestamp::now().to_string();
        let row = sqlx::query(&sql("SELECT u.id, u.username, u.roles_json, u.disabled_at
             FROM user_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ? AND t.expires_at > ?"))
        .bind(token_hash)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let disabled_at: Option<String> = row.try_get("disabled_at")?;
        if disabled_at.is_some() {
            return Ok(None);
        }
        let roles_json: String = row.try_get("roles_json")?;
        let roles: Vec<crate::identity::Role> =
            serde_json::from_str(&roles_json).unwrap_or_default();
        Ok(Some(crate::identity::UserRecord {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            roles,
        }))
    }

    /// Revoke a single token. Used by logout.
    pub async fn revoke_user_token(&self, token: &str) -> ApiResult<()> {
        let token_hash = crate::auth::hash_token(token);
        sqlx::query(&sql("DELETE FROM user_tokens WHERE token_hash = ?"))
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revoke any token whose expiry has passed. Suitable for periodic cleanup.
    pub async fn prune_expired_tokens(&self) -> ApiResult<u64> {
        let now = Timestamp::now().to_string();
        let res = sqlx::query(&sql("DELETE FROM user_tokens WHERE expires_at <= ?"))
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn user_count(&self) -> ApiResult<i64> {
        let row: (i64,) = sqlx::query_as(&sql("SELECT COUNT(*) FROM users"))
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }

    /// Phase 6h: list every user (including disabled). Sorted by `created_at`
    /// so the bootstrap admin shows up first.
    pub async fn list_users(&self) -> ApiResult<Vec<UserListRow>> {
        let rows = sqlx::query(&sql(
            "SELECT id, username, roles_json, created_at, disabled_at
             FROM users ORDER BY created_at",
        ))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let roles_json: String = row.try_get("roles_json")?;
                let roles: Vec<crate::identity::Role> =
                    serde_json::from_str(&roles_json).unwrap_or_default();
                Ok(UserListRow {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    roles,
                    created_at: row.try_get("created_at")?,
                    disabled_at: row.try_get("disabled_at")?,
                })
            })
            .collect()
    }

    /// Replace a user's role list. Phase 7d adds a "must keep at least
    /// one active Admin" guard: if this change would leave zero active
    /// admins (target user was the last one and the new role set drops
    /// Admin), the call returns `Conflict`.
    pub async fn update_user_roles(
        &self,
        user_id: &str,
        roles: &[crate::identity::Role],
    ) -> ApiResult<()> {
        let mut tx = self.pool.begin().await?;
        ensure_active_admin_remains(&mut *tx, user_id, ProposedChange::SetRoles(roles)).await?;
        let roles_json = serde_json::to_string(roles)?;
        let res = sqlx::query(&sql("UPDATE users SET roles_json = ? WHERE id = ?"))
            .bind(roles_json)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Soft delete: set `disabled_at` so the user can no longer log in. All
    /// existing tokens are revoked at the same time. Phase 7d adds a
    /// "must keep at least one active Admin" guard — disabling the last
    /// active admin returns `Conflict`.
    pub async fn disable_user(&self, user_id: &str) -> ApiResult<()> {
        let mut tx = self.pool.begin().await?;
        ensure_active_admin_remains(&mut *tx, user_id, ProposedChange::Disable).await?;
        let now = Timestamp::now().to_string();
        let res = sqlx::query(&sql("UPDATE users SET disabled_at = ?
             WHERE id = ? AND disabled_at IS NULL"))
        .bind(&now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        // Revoke any active tokens. `find_user_by_token` already filters
        // disabled users, but the explicit delete keeps the table tight.
        sqlx::query(&sql("DELETE FROM user_tokens WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Re-enable a previously-disabled user. Doesn't issue a fresh token —
    /// the user must `iac login` again.
    pub async fn enable_user(&self, user_id: &str) -> ApiResult<()> {
        let res = sqlx::query(&sql("UPDATE users SET disabled_at = NULL
             WHERE id = ? AND disabled_at IS NOT NULL"))
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(ApiError::NotFound);
        }
        Ok(())
    }

    /// Admin-driven password reset. Existing user tokens are revoked so the
    /// user has to `iac login` with the new password.
    pub async fn set_user_password(&self, user_id: &str, new_password: &str) -> ApiResult<()> {
        if new_password.is_empty() {
            return Err(ApiError::BadRequest("password must not be empty".into()));
        }
        let hash = crate::identity::hash_password(new_password)?;
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(&sql("UPDATE users SET password_hash = ? WHERE id = ?"))
            .bind(hash)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await.ok();
            return Err(ApiError::NotFound);
        }
        sqlx::query(&sql("DELETE FROM user_tokens WHERE user_id = ?"))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Row returned by `list_users`. Plain struct (no PHC hash) — handlers
/// project this into `UserView` on the wire.
#[derive(Debug, Clone)]
pub struct UserListRow {
    pub id: String,
    pub username: String,
    pub roles: Vec<crate::identity::Role>,
    pub created_at: String,
    pub disabled_at: Option<String>,
}

/// Phase 7d: what we're about to do to the target user. The guard reads
/// the post-change snapshot to count remaining active admins.
enum ProposedChange<'a> {
    /// Set `disabled_at` (soft delete). The user retains their roles in
    /// the row but no longer counts as active.
    Disable,
    /// Replace the user's role list.
    SetRoles(&'a [crate::identity::Role]),
}

/// Reject the change only if it would *transition* admin count from
/// ≥1 active admins to 0. "Active admin" = `disabled_at IS NULL` AND
/// roles_json contains `Role::Admin`. Runs inside the caller's
/// transaction so concurrent demotions can't both pass the check and
/// together leave zero admins.
///
/// We compare before vs. after instead of just checking after-count > 0
/// because deployments without any User-table admins (legacy admin_token
/// only) have an honest zero baseline — non-admin user changes there
/// shouldn't be blocked. The guard kicks in the moment user-table
/// admins exist.
///
/// The legacy `admin_token` is intentionally NOT counted: operators who
/// rely on it can always break-glass, but the moment they migrate off,
/// they expect the user-side guarantee to hold.
async fn ensure_active_admin_remains<'a>(
    conn: impl sqlx::Executor<'a, Database = sqlx::Any>,
    target_user_id: &str,
    change: ProposedChange<'_>,
) -> ApiResult<()> {
    use crate::identity::Role;
    let rows = sqlx::query(&sql("SELECT id, roles_json, disabled_at FROM users"))
        .fetch_all(conn)
        .await?;

    let mut before = 0i64;
    let mut after = 0i64;
    for row in rows {
        let id: String = row.try_get("id")?;
        let roles_json: String = row.try_get("roles_json")?;
        let disabled_at: Option<String> = row.try_get("disabled_at")?;
        let current_roles: Vec<Role> = serde_json::from_str(&roles_json).unwrap_or_default();
        let currently_disabled = disabled_at.is_some();
        if !currently_disabled && current_roles.contains(&Role::Admin) {
            before += 1;
        }
        let (effective_disabled, effective_roles) = if id == target_user_id {
            match &change {
                ProposedChange::Disable => (true, current_roles),
                ProposedChange::SetRoles(new_roles) => (currently_disabled, new_roles.to_vec()),
            }
        } else {
            (currently_disabled, current_roles)
        };
        if !effective_disabled && effective_roles.contains(&Role::Admin) {
            after += 1;
        }
    }

    if before > 0 && after == 0 {
        return Err(ApiError::Conflict(
            "refusing change: at least one active admin must remain".into(),
        ));
    }
    Ok(())
}

// ---- audit log (Phase 6c) --------------------------------------------------

/// Builder for a single audit row. Most callers fill 2-3 fields.
#[derive(Debug, Clone, Default)]
pub struct AuditRecord<'a> {
    pub actor: &'a str,
    pub kind: &'a str,
    pub severity: &'a str,
    pub operation_id: Option<&'a str>,
    pub agent_id: Option<&'a str>,
    pub resource_id: Option<&'a str>,
    pub drift_id: Option<i64>,
    pub payload: serde_json::Value,
}

impl<'a> AuditRecord<'a> {
    pub fn new(actor: &'a str, kind: &'a str) -> Self {
        Self {
            actor,
            kind,
            severity: "info",
            payload: serde_json::Value::Null,
            ..Default::default()
        }
    }
    #[must_use]
    pub fn severity(mut self, s: &'a str) -> Self {
        self.severity = s;
        self
    }
    #[must_use]
    pub fn operation(mut self, op: &'a str) -> Self {
        self.operation_id = Some(op);
        self
    }
    #[must_use]
    pub fn agent(mut self, agent: &'a str) -> Self {
        self.agent_id = Some(agent);
        self
    }
    #[must_use]
    pub fn resource(mut self, rid: &'a str) -> Self {
        self.resource_id = Some(rid);
        self
    }
    #[must_use]
    pub fn drift(mut self, id: i64) -> Self {
        self.drift_id = Some(id);
        self
    }
    #[must_use]
    pub fn payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct AuditFilter {
    pub since: Option<String>,
    /// Phase 9 follow-up: id-based cursor for `tail -f` polling.
    /// `since_id = N` returns only rows with `id > N`. Independent
    /// of `since` (timestamp) — combine them at your own risk;
    /// callers either use timestamp filtering or id-cursor, not
    /// both. id-based is more reliable for polling because ids are
    /// monotonic by insert order even when many rows share a
    /// timestamp at second-level resolution.
    pub since_id: Option<i64>,
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub operation_id: Option<String>,
    pub agent_id: Option<String>,
    pub limit: Option<i64>,
}

impl Store {
    pub async fn record_audit(&self, rec: AuditRecord<'_>) -> ApiResult<()> {
        // Phase 7da.5: chain hash + tip update have to commit
        // atomically with the row, so this entry-point opens its own
        // tx. Existing callers that already hold a tx keep using
        // `record_audit_on(&mut *tx, ...)` directly.
        let mut tx = self.pool.begin().await?;
        record_audit_on(&mut tx, rec).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Phase 7da.5: return the current chain tip — `(last_id, last_hash)`.
    /// Operators log this out-of-band (syslog / S3 / external auditor)
    /// to make tampering detectable: re-walking the chain and
    /// comparing the hash of the row at `last_id` with the recorded
    /// `last_hash` would reveal any mid-chain edit.
    pub async fn audit_chain_tip(&self) -> ApiResult<AuditChainTip> {
        let row = sqlx::query(&sql(
            "SELECT last_id, last_hash, updated_at FROM audit_chain_tip WHERE id = 1",
        ))
        .fetch_one(&self.pool)
        .await?;
        Ok(AuditChainTip {
            last_id: row.try_get("last_id")?,
            last_hash: row.try_get("last_hash")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    /// Phase 7da.5: walk every row in id-order and verify each
    /// `row_hash` matches `sha256(canonical_inputs)`. Returns
    /// `Ok(None)` when the chain is intact; `Ok(Some(broken_id))`
    /// for the first row whose stored hash disagrees with the
    /// computed hash. Pre-7da.5 rows have NULL `row_hash`/`prev_hash`
    /// columns and are skipped (legacy data is not retroactively
    /// chained).
    pub async fn audit_verify_chain(&self) -> ApiResult<Option<i64>> {
        // Phase 9 follow-up: the pre-fix implementation called
        // `fetch_all` against the whole `audit_events` table. F1
        // stress burst grew the chain to 615 k rows in 24 h and the
        // verify endpoint timed out (Postgres path loaded every row
        // into memory; SQLite path was slow but technically
        // completed inside SQLite, just past HTTP's deadline). The
        // chunked walk below bounds memory regardless of chain size
        // and lets the loop exit on first mismatch without having
        // already pulled everything.
        self.audit_verify_chain_from(0).await
    }

    /// Phase 9 follow-up: verify the audit chain from id `from_id`
    /// onward (verifying `id > from_id`). Operators wanting a quick
    /// integrity check on the recent tail pass the chain tip from
    /// their last known-good snapshot here; the endpoint walks only
    /// new rows. `from_id = 0` walks the whole chain.
    ///
    /// Memory is bounded by `CHUNK`. On a broken chain returns the
    /// first id where stored hash disagrees with computed hash;
    /// `Ok(None)` means clean.
    pub async fn audit_verify_chain_from(&self, from_id: i64) -> ApiResult<Option<i64>> {
        const CHUNK: i64 = 10_000;
        // Seed prev_hash from the row at `from_id` (or "" if 0). We
        // verify rows with `id > from_id`; their `prev_hash` field
        // must match row[from_id].row_hash.
        let mut prev_hash: String = if from_id <= 0 {
            String::new()
        } else {
            sqlx::query(&sql(
                "SELECT row_hash FROM audit_events WHERE id = ? AND row_hash IS NOT NULL",
            ))
            .bind(from_id)
            .fetch_optional(&self.pool)
            .await?
            .and_then(|r| r.try_get::<String, _>("row_hash").ok())
            .unwrap_or_default()
        };
        let mut last_seen: i64 = from_id;
        loop {
            let rows = sqlx::query(&sql(
                "SELECT id, timestamp, actor, kind, severity, operation_id, agent_id,
                        resource_id, drift_id, payload_json, prev_hash, row_hash
                 FROM audit_events
                 WHERE row_hash IS NOT NULL AND id > ?
                 ORDER BY id ASC
                 LIMIT ?",
            ))
            .bind(last_seen)
            .bind(CHUNK)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                return Ok(None);
            }
            for row in &rows {
                let id: i64 = row.try_get("id")?;
                let stored_row_hash: String = row.try_get("row_hash")?;
                let stored_prev_hash: Option<String> = row.try_get("prev_hash")?;
                let stored_prev = stored_prev_hash.unwrap_or_default();
                if stored_prev != prev_hash {
                    return Ok(Some(id));
                }
                let owned = row_to_audit_inputs(row)?;
                let computed = compute_audit_row_hash(&prev_hash, 0, &owned.as_ref());
                if computed != stored_row_hash {
                    return Ok(Some(id));
                }
                prev_hash = stored_row_hash;
                last_seen = id;
            }
            // If we fetched fewer than CHUNK rows, the chain ends
            // here — short-circuit the next LIMIT query.
            if (rows.len() as i64) < CHUNK {
                return Ok(None);
            }
        }
    }

    pub async fn list_audit(&self, filter: AuditFilter) -> ApiResult<Vec<AuditEvent>> {
        let mut q = String::from(
            "SELECT id, timestamp, actor, kind, severity, operation_id, agent_id,
                    resource_id, drift_id, payload_json
             FROM audit_events
             WHERE 1=1",
        );
        let mut binds: Vec<String> = Vec::new();
        if let Some(s) = filter.since {
            q.push_str(" AND timestamp >= ?");
            binds.push(s);
        }
        // Phase 9 follow-up: id-based cursor for tail -f polling.
        // Bind as String so the binds Vec stays homogeneous; SQLite
        // coerces TEXT-bound integers automatically. (Postgres path
        // is unaffected: numeric bind via prepared statement.)
        if let Some(id) = filter.since_id {
            q.push_str(" AND id > ?");
            binds.push(id.to_string());
        }
        if let Some(k) = filter.kind {
            q.push_str(" AND kind = ?");
            binds.push(k);
        }
        if let Some(a) = filter.actor {
            q.push_str(" AND actor = ?");
            binds.push(a);
        }
        if let Some(op) = filter.operation_id {
            q.push_str(" AND operation_id = ?");
            binds.push(op);
        }
        if let Some(ag) = filter.agent_id {
            q.push_str(" AND agent_id = ?");
            binds.push(ag);
        }
        q.push_str(" ORDER BY id DESC LIMIT ?");
        let limit = filter.limit.unwrap_or(200).clamp(1, 1000);

        let qs = sql(&q);
        let mut query = sqlx::query(&qs);
        for b in &binds {
            query = query.bind(b);
        }
        query = query.bind(limit);
        let rows = query.fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                let payload_json: String = row.try_get("payload_json")?;
                let payload: serde_json::Value = serde_json::from_str(&payload_json)?;
                Ok(AuditEvent {
                    id: row.try_get("id")?,
                    timestamp: row.try_get("timestamp")?,
                    actor: row.try_get("actor")?,
                    kind: row.try_get("kind")?,
                    severity: row.try_get("severity")?,
                    operation_id: row.try_get("operation_id")?,
                    agent_id: row.try_get("agent_id")?,
                    resource_id: row.try_get("resource_id")?,
                    drift_id: row.try_get("drift_id")?,
                    payload,
                })
            })
            .collect()
    }
}

/// Audit recorder that runs inside an existing transaction. Each high-level
/// store method that opens a tx (e.g. `create_operation`) calls this so the
/// audit row commits with its source of truth.
///
/// Phase 7da.5: extends the row with `prev_hash` + `row_hash` (Merkle
/// chain) and updates the materialised `audit_chain_tip` row in the
/// same tx. Tampering with any historical row breaks the chain at
/// that point; operators detect via [`Store::audit_verify_chain`].
async fn record_audit_on(tx: &mut sqlx::AnyConnection, rec: AuditRecord<'_>) -> ApiResult<()> {
    let payload_json = serde_json::to_string(&rec.payload)?;
    let now = Timestamp::now().to_string();
    // Read the current chain tip. Default to "" if the table is fresh
    // (first-ever audit row). Inside the same tx as the insert, this
    // read sees committed state through the start of the tx — the
    // SQLite write serialisation guarantees no torn read here.
    let tip_row = sqlx::query(&sql(
        "SELECT last_id, last_hash FROM audit_chain_tip WHERE id = 1",
    ))
    .fetch_optional(&mut *tx)
    .await?;
    let prev_hash: String = tip_row
        .as_ref()
        .and_then(|r| r.try_get::<String, _>("last_hash").ok())
        .unwrap_or_default();
    let inputs = AuditRowInputs {
        timestamp: &now,
        actor: rec.actor,
        kind: rec.kind,
        severity: rec.severity,
        operation_id: rec.operation_id,
        agent_id: rec.agent_id,
        resource_id: rec.resource_id,
        drift_id: rec.drift_id,
        payload_json: &payload_json,
    };
    // We don't yet know the row id (autoincrement), but the hash
    // doesn't actually need the id — `prev_hash` plus the row's
    // own field bytes uniquely identifies the row's chain position.
    // Including the id would require a second UPDATE pass post-
    // INSERT, doubling the writes. Skipping it keeps the chain
    // single-pass without weakening tamper detection: editing a
    // row's id while preserving every other field is easy to spot
    // (id no longer monotonically increases).
    let row_hash = compute_audit_row_hash(&prev_hash, 0, &inputs);
    sqlx::query(&sql("INSERT INTO audit_events
            (timestamp, actor, kind, severity,
             operation_id, agent_id, resource_id, drift_id, payload_json,
             prev_hash, row_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"))
    .bind(&now)
    .bind(rec.actor)
    .bind(rec.kind)
    .bind(rec.severity)
    .bind(rec.operation_id)
    .bind(rec.agent_id)
    .bind(rec.resource_id)
    .bind(rec.drift_id)
    .bind(&payload_json)
    .bind(&prev_hash)
    .bind(&row_hash)
    .execute(&mut *tx)
    .await?;
    // Update the tip — the new row's id is the autoincrement value
    // we just consumed. SQLite's `last_insert_rowid()` (Postgres:
    // `lastval()`) would let us read it back, but we don't need
    // it for the hash itself; just update timestamp + hash for
    // operator-visible "chain has progressed" signal.
    let prev_last_id: i64 = tip_row
        .as_ref()
        .and_then(|r| r.try_get::<i64, _>("last_id").ok())
        .unwrap_or(0);
    sqlx::query(&sql("UPDATE audit_chain_tip
         SET last_id = ?, last_hash = ?, updated_at = ?
         WHERE id = 1"))
    .bind(prev_last_id + 1)
    .bind(&row_hash)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

/// Phase 7da.5: byte inputs that go into a row's hash. `id` is
/// included as 0 today — see comment in `record_audit_on` for the
/// design choice. Future versions can promote it to a real id with
/// a second-pass UPDATE if monotonic-id-checks turn out insufficient.
struct AuditRowInputs<'a> {
    timestamp: &'a str,
    actor: &'a str,
    kind: &'a str,
    severity: &'a str,
    operation_id: Option<&'a str>,
    agent_id: Option<&'a str>,
    resource_id: Option<&'a str>,
    drift_id: Option<i64>,
    payload_json: &'a str,
}

fn row_to_audit_inputs(row: &sqlx::any::AnyRow) -> ApiResult<OwnedAuditInputs> {
    Ok(OwnedAuditInputs {
        timestamp: row.try_get("timestamp")?,
        actor: row.try_get("actor")?,
        kind: row.try_get("kind")?,
        severity: row.try_get("severity")?,
        operation_id: row.try_get("operation_id")?,
        agent_id: row.try_get("agent_id")?,
        resource_id: row.try_get("resource_id")?,
        drift_id: row.try_get("drift_id")?,
        payload_json: row.try_get("payload_json")?,
    })
}

struct OwnedAuditInputs {
    timestamp: String,
    actor: String,
    kind: String,
    severity: String,
    operation_id: Option<String>,
    agent_id: Option<String>,
    resource_id: Option<String>,
    drift_id: Option<i64>,
    payload_json: String,
}

impl OwnedAuditInputs {
    fn as_ref(&self) -> AuditRowInputs<'_> {
        AuditRowInputs {
            timestamp: &self.timestamp,
            actor: &self.actor,
            kind: &self.kind,
            severity: &self.severity,
            operation_id: self.operation_id.as_deref(),
            agent_id: self.agent_id.as_deref(),
            resource_id: self.resource_id.as_deref(),
            drift_id: self.drift_id,
            payload_json: &self.payload_json,
        }
    }
}

/// Phase 7da.5: canonical concatenation of audit-row fields. Format:
/// every field length-prefixed (as 8-byte big-endian) so distinct
/// fields can't collide via concatenation tricks. NULL is encoded
/// as length=u64::MAX (a value no real string can have).
fn compute_audit_row_hash(prev_hash: &str, id: i64, r: &AuditRowInputs<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(id.to_be_bytes());
    write_field(&mut h, r.timestamp.as_bytes());
    write_field(&mut h, r.actor.as_bytes());
    write_field(&mut h, r.kind.as_bytes());
    write_field(&mut h, r.severity.as_bytes());
    write_optional_str(&mut h, r.operation_id);
    write_optional_str(&mut h, r.agent_id);
    write_optional_str(&mut h, r.resource_id);
    match r.drift_id {
        Some(n) => {
            h.update([1u8]);
            h.update(n.to_be_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
    write_field(&mut h, r.payload_json.as_bytes());
    hex::encode(h.finalize())
}

fn write_field(h: &mut sha2::Sha256, bytes: &[u8]) {
    use sha2::Digest;
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn write_optional_str(h: &mut sha2::Sha256, s: Option<&str>) {
    use sha2::Digest;
    match s {
        Some(s) => {
            h.update([1u8]);
            write_field(h, s.as_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
}

/// Phase 7da.5: row returned by `Store::audit_chain_tip`. Suitable
/// for serialisation back to operators via `GET /v1/audit/chain-tip`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditChainTip {
    pub last_id: i64,
    pub last_hash: String,
    pub updated_at: String,
}

fn parse_health(s: &str) -> AgentHealth {
    match s {
        "degraded" => AgentHealth::Degraded,
        "unhealthy" => AgentHealth::Unhealthy,
        _ => AgentHealth::Healthy,
    }
}

// ---- migrations ------------------------------------------------------------
//
// Each migration is `(version, sql)`, applied once and tracked in the
// `_iac_migrations` table. Migrations are append-only: never edit a migration
// already shipped, add a new one. Plain SQL keeps us off `sqlx::migrate!` (see
// the workspace Cargo.toml note explaining why).
//
// Phase 7al: Postgres has a parallel `migrations-postgres/` set with the same
// version numbers. Differences are autoincrement (BIGSERIAL vs INTEGER … AUTO-
// INCREMENT) and integer width (BIGINT throughout PG so `i64` binds match).
// Adding a new migration requires writing both files in lock-step.

const MIGRATIONS_SQLITE: &[(i64, &str)] = &[
    (1, include_str!("../migrations/20260429000001_init.sql")),
    (
        2,
        include_str!("../migrations/20260429000002_assignments.sql"),
    ),
    (
        3,
        include_str!("../migrations/20260429000003_drift_workflow.sql"),
    ),
    (4, include_str!("../migrations/20260429000004_audit.sql")),
    (5, include_str!("../migrations/20260430000005_approval.sql")),
    (6, include_str!("../migrations/20260430000006_rbac.sql")),
    (
        7,
        include_str!("../migrations/20260430000007_webhook_state.sql"),
    ),
    (
        8,
        include_str!("../migrations/20260501000008_webhook_backoff.sql"),
    ),
    (
        9,
        include_str!("../migrations/20260501000009_phased_apply.sql"),
    ),
    (
        10,
        include_str!("../migrations/20260501000010_agent_token_ttl.sql"),
    ),
    (11, include_str!("../migrations/20260502000011_canary.sql")),
    (
        12,
        include_str!("../migrations/20260502000012_ssh_targets.sql"),
    ),
    (
        13,
        include_str!("../migrations/20260503000013_audit_chain.sql"),
    ),
];

const MIGRATIONS_POSTGRES: &[(i64, &str)] = &[
    (
        1,
        include_str!("../migrations-postgres/20260429000001_init.sql"),
    ),
    (
        2,
        include_str!("../migrations-postgres/20260429000002_assignments.sql"),
    ),
    (
        3,
        include_str!("../migrations-postgres/20260429000003_drift_workflow.sql"),
    ),
    (
        4,
        include_str!("../migrations-postgres/20260429000004_audit.sql"),
    ),
    (
        5,
        include_str!("../migrations-postgres/20260430000005_approval.sql"),
    ),
    (
        6,
        include_str!("../migrations-postgres/20260430000006_rbac.sql"),
    ),
    (
        7,
        include_str!("../migrations-postgres/20260430000007_webhook_state.sql"),
    ),
    (
        8,
        include_str!("../migrations-postgres/20260501000008_webhook_backoff.sql"),
    ),
    (
        9,
        include_str!("../migrations-postgres/20260501000009_phased_apply.sql"),
    ),
    (
        10,
        include_str!("../migrations-postgres/20260501000010_agent_token_ttl.sql"),
    ),
    (
        11,
        include_str!("../migrations-postgres/20260502000011_canary.sql"),
    ),
    (
        12,
        include_str!("../migrations-postgres/20260502000012_ssh_targets.sql"),
    ),
    (
        13,
        include_str!("../migrations-postgres/20260503000013_audit_chain.sql"),
    ),
];

fn chunk_has_sql(s: &str) -> bool {
    s.lines().any(|line| {
        let t = line.trim();
        !t.is_empty() && !t.starts_with("--")
    })
}

async fn run_migrations(pool: &AnyPool, dialect: Dialect) -> ApiResult<()> {
    let migrations = match dialect {
        Dialect::Sqlite => MIGRATIONS_SQLITE,
        Dialect::Postgres => MIGRATIONS_POSTGRES,
    };
    // Postgres needs BIGINT to match the i64 we bind for `version`. SQLite
    // is dynamically typed and treats both as integers.
    let version_type = match dialect {
        Dialect::Sqlite => "INTEGER",
        Dialect::Postgres => "BIGINT",
    };
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS _iac_migrations (
            version {version_type} PRIMARY KEY,
            applied_at TEXT NOT NULL
         )"
    ))
    .execute(pool)
    .await?;

    // Phase 7cs.2 (security fix #4.12): refuse to start when the
    // DB has been migrated past what this binary knows about. A
    // rollback after a forward-migrating canary would otherwise
    // silently misinterpret renamed columns / new constraints.
    // Strict-go-or-no-go is safer than "run anyway with mystery
    // schema."
    let max_known: i64 = migrations.iter().map(|(v, _)| *v).max().unwrap_or(0);
    // `MAX(version)` returns NULL on an empty table — first-connect
    // case. Bind as `Option<i64>` so we don't trip the i64 decoder.
    let max_applied: Option<(Option<i64>,)> =
        sqlx::query_as(&sql("SELECT MAX(version) FROM _iac_migrations"))
            .fetch_optional(pool)
            .await?;
    let max_applied = max_applied.and_then(|(v,)| v).unwrap_or(0);
    if max_applied > max_known {
        return Err(ApiError::Internal(format!(
            "schema_version mismatch: DB has migration {max_applied} applied, \
             this binary only knows up to {max_known}. Refusing to start — a \
             newer iac-controlplane wrote this DB. Roll forward to a binary \
             that includes migration {max_applied} or restore an older DB \
             backup."
        )));
    }

    for (version, body) in migrations {
        let row: Option<(i64,)> = sqlx::query_as(&sql(
            "SELECT version FROM _iac_migrations WHERE version = ?",
        ))
        .bind(*version)
        .fetch_optional(pool)
        .await?;
        if row.is_some() {
            continue;
        }
        let mut tx = pool.begin().await?;
        // Strip `-- ...` line comments BEFORE splitting on `;`. Without this,
        // a stray `;` inside a comment line splits the chunk and the
        // remainder gets fed to SQLite as malformed SQL. Migrations are plain
        // DDL — we don't have to worry about block comments or `;` inside
        // string literals (none of our migrations contain either).
        let mut decommented = String::with_capacity(body.len());
        for line in body.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("--") {
                continue;
            }
            decommented.push_str(line);
            decommented.push('\n');
        }
        for stmt in decommented.split(';') {
            if !chunk_has_sql(stmt) {
                continue;
            }
            sqlx::query(stmt).execute(&mut *tx).await?;
        }
        sqlx::query(&sql(
            "INSERT INTO _iac_migrations (version, applied_at) VALUES (?, ?)",
        ))
        .bind(*version)
        .bind(jiff::Timestamp::now().to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        tracing::info!(version, "applied migration");
    }
    Ok(())
}
