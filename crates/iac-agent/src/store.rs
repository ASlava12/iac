//! SQLite store for the agent: observation history, drift events, agent run audit.
//!
//! Contract: every public method is sync. Async callers should wrap them in
//! `tokio::task::spawn_blocking` (the [`Agent`] does this for us).
//!
//! Schema is created idempotently on `open` and tracked via a `schema_version`
//! row. Phase 1 starts at version 1; future migrations append rows.

use anyhow::{Context, Result};
use iac_core::ResourceId;
use iac_core::diff::Diff;
use iac_core::state::ObservedState;
use jiff::Timestamp;
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::Path;

// Phase 7cz.8 (replay protection) bumped schema 1 → 2 by adding the
// `processed_assignments` table. Version checks gate startup so a
// rolled-back agent binary against a v2 store fails loudly rather
// than corrupting state.
const SCHEMA_VERSION: i64 = 2;

/// Phase 9-F1-fix-3: how many observation rows the agent keeps per
/// `resource_id`. The agent's runtime only needs the single newest row
/// (for drift detection in `last_observation`); the rest is rolling
/// debugging history. 10 ≈ 10 minutes of observations at the typical
/// 1/min poll cadence — enough to investigate a recent regression
/// without ballooning the agent's local DB.
const AGENT_OBSERVATION_HISTORY_CAP: i64 = 10;

#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftRow {
    pub id: i64,
    pub resource_id: String,
    pub kind: String,
    pub severity: String,
    pub diff: Diff,
    pub detected_at: String,
    pub resolved_at: Option<String>,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunRow {
    pub id: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub resources_observed: i64,
    pub drift_detected: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRow {
    pub resource_id: String,
    pub kind: String,
    pub observed_at: String,
    pub present: bool,
    pub spec: serde_json::Value,
    pub facts: serde_json::Value,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        // WAL improves concurrent reads (status command can read while
        // observe loop writes).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // The DB holds observation history + drift events + dispatch
        // metadata; on a multi-user host (typically not the case for a
        // dedicated agent VM, but cheap to defend) this stops a
        // non-`iac` UID from reading the file just because the
        // surrounding state_dir was created with a loose umask.
        // Windows + journal_mode=WAL also creates `-wal` and `-shm`
        // sidecars; we restrict those too once they're materialised.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            for ext in ["-wal", "-shm"] {
                let mut sidecar = path.to_path_buf().into_os_string();
                sidecar.push(ext);
                let sidecar = std::path::PathBuf::from(sidecar);
                if sidecar.exists() {
                    let _ = std::fs::set_permissions(
                        &sidecar,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
            }
        }
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                present INTEGER NOT NULL,
                spec_json TEXT NOT NULL,
                facts_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_observations_resource
                ON observations(resource_id, observed_at DESC);

            CREATE TABLE IF NOT EXISTS drift_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                diff_json TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                resolved_at TEXT,
                resolution TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_drift_open
                ON drift_events(resource_id) WHERE resolved_at IS NULL;

            CREATE TABLE IF NOT EXISTS agent_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                resources_observed INTEGER NOT NULL DEFAULT 0,
                drift_detected INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );

            -- Phase 7cz.8: replay protection. The agent has rejected
            -- envelopes older than 24h since 7cs.2, but inside that
            -- freshness window an attacker who has captured an envelope
            -- could re-submit it (e.g. by replaying the polling response
            -- to the agent over a controlled network path). We persist
            -- every assignment_id we've executed; a duplicate is logged
            -- and silently no-op'd. The rolling cleanup (`vacuum_replay`)
            -- prunes rows older than 7d to bound disk growth — well
            -- beyond the 24h envelope-freshness window so we never miss
            -- a replay because we forgot.
            CREATE TABLE IF NOT EXISTS processed_assignments (
                assignment_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL,
                status TEXT NOT NULL  -- 'succeeded' | 'failed' | 'capability_denied'
            );
            CREATE INDEX IF NOT EXISTS idx_processed_assignments_at
                ON processed_assignments(processed_at);
            ",
        )?;

        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM schema_version WHERE version = ?",
                params![SCHEMA_VERSION],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                params![SCHEMA_VERSION, Timestamp::now().to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Phase 7cz.8: returns `Some(prior_status)` when this assignment
    /// has already been processed; `None` for first-time receipt.
    /// The caller no-ops on `Some` to defeat replay.
    pub fn assignment_already_processed(&self, assignment_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock();
        match conn.query_row(
            "SELECT status FROM processed_assignments WHERE assignment_id = ?",
            params![assignment_id],
            |r| r.get::<_, String>(0),
        ) {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Phase 7cz.8: record an executed assignment. Idempotent — re-
    /// inserting the same id is a no-op (PRIMARY KEY conflict).
    pub fn mark_assignment_processed(&self, assignment_id: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT OR IGNORE INTO processed_assignments (assignment_id, processed_at, status) \
             VALUES (?, ?, ?)",
            params![assignment_id, Timestamp::now().to_string(), status],
        )?;
        Ok(())
    }

    /// Phase 7cz.8: prune rows older than `days` to bound disk growth.
    /// Default caller passes 7 days, well beyond the 24h envelope-
    /// freshness window enforced by `verify_envelope`.
    pub fn vacuum_replay(&self, retain_days: i64) -> Result<u64> {
        let conn = self.conn.lock();
        // jiff's `Timestamp::checked_sub` only accepts time-unit spans
        // (seconds/minutes/hours), not calendar-unit spans (days), so
        // expand explicitly. 86400 s/day is fine for the rolling-prune
        // semantic — leap seconds aren't load-bearing here.
        let cutoff = Timestamp::now()
            .checked_sub(jiff::Span::new().seconds(retain_days * 86_400))
            .unwrap_or_else(|_| Timestamp::now())
            .to_string();
        let n = conn.execute(
            "DELETE FROM processed_assignments WHERE processed_at < ?",
            params![cutoff],
        )?;
        Ok(n as u64)
    }

    pub fn record_observation(
        &self,
        resource_id: &ResourceId,
        observed: &ObservedState,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let spec_json = serde_json::to_string(&observed.spec)?;
        let facts_json = serde_json::to_string(&observed.facts)?;
        conn.execute(
            "INSERT INTO observations (resource_id, kind, observed_at, present, spec_json, facts_json)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                resource_id.to_string(),
                resource_id.kind,
                observed.observed_at.to_string(),
                i64::from(observed.present),
                spec_json,
                facts_json,
            ],
        )?;
        // Phase 9-F1-fix-3: cap per-resource observation history. The
        // agent's only consumer of the table is `last_observation`,
        // which reads the single newest row for drift detection.
        // Older rows are pure history — useful for post-hoc debugging
        // but not for the runtime path. Without this cap, every poll
        // cycle (~1/min/resource) appends one row forever, so a
        // 24-hour soak with 2 000 resources fills the agent's disk:
        // F1 attempt #3 saw 2.5 M rows / 1.4 GB on each agent.db
        // after 5.5 h. Keeping 10 newest per resource gives plenty of
        // debugging headroom (~10 minutes of history at 1/min) while
        // bounding the table at resources × 10 ≈ 20 K rows ≈ 20 MB.
        // Inline DELETE on every INSERT is OK because the LIMIT-OFFSET
        // SELECT hits only the index `idx_observations_resource` and
        // touches at most a handful of rows.
        conn.execute(
            "DELETE FROM observations
             WHERE id IN (
                 SELECT id FROM observations
                 WHERE resource_id = ?
                 ORDER BY observed_at DESC, id DESC
                 LIMIT -1 OFFSET ?
             )",
            params![resource_id.to_string(), AGENT_OBSERVATION_HISTORY_CAP],
        )?;
        Ok(())
    }

    pub fn last_observation(&self, resource_id: &str) -> Result<Option<ObservationRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT resource_id, kind, observed_at, present, spec_json, facts_json
             FROM observations
             WHERE resource_id = ?
             ORDER BY observed_at DESC
             LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![resource_id], row_to_observation)
            .optional()
            .map_err(anyhow::Error::from)?;
        Ok(row)
    }

    pub fn open_drift(&self, resource_id: &ResourceId, severity: &str, diff: &Diff) -> Result<i64> {
        let conn = self.conn.lock();
        // If there's already an unresolved drift for this resource_id, just
        // bump the diff_json so we don't accumulate duplicates per cycle.
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM drift_events
                 WHERE resource_id = ? AND resolved_at IS NULL
                 ORDER BY detected_at DESC LIMIT 1",
                params![resource_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let diff_json = serde_json::to_string(diff)?;
        if let Some(id) = existing {
            conn.execute(
                "UPDATE drift_events SET diff_json = ?, severity = ?, detected_at = ?
                 WHERE id = ?",
                params![diff_json, severity, Timestamp::now().to_string(), id],
            )?;
            Ok(id)
        } else {
            conn.execute(
                "INSERT INTO drift_events (resource_id, kind, severity, diff_json, detected_at)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    resource_id.to_string(),
                    resource_id.kind,
                    severity,
                    diff_json,
                    Timestamp::now().to_string()
                ],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }

    pub fn resolve_drift(&self, id: i64, resolution: &str) -> Result<usize> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE drift_events SET resolved_at = ?, resolution = ?
             WHERE id = ? AND resolved_at IS NULL",
            params![Timestamp::now().to_string(), resolution, id],
        )?;
        Ok(n)
    }

    pub fn close_open_drift_for(
        &self,
        resource_id: &ResourceId,
        resolution: &str,
    ) -> Result<usize> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE drift_events
             SET resolved_at = ?, resolution = ?
             WHERE resource_id = ? AND resolved_at IS NULL",
            params![
                Timestamp::now().to_string(),
                resolution,
                resource_id.to_string()
            ],
        )?;
        Ok(n)
    }

    pub fn list_open_drifts(&self) -> Result<Vec<DriftRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, resource_id, kind, severity, diff_json, detected_at, resolved_at, resolution
             FROM drift_events
             WHERE resolved_at IS NULL
             ORDER BY detected_at DESC",
        )?;
        let rows = stmt
            .query_map([], row_to_drift)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn open_drift_count(&self) -> Result<i64> {
        let conn = self.conn.lock();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM drift_events WHERE resolved_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    pub fn record_run(
        &self,
        started_at: Timestamp,
        finished_at: Option<Timestamp>,
        resources_observed: i64,
        drift_detected: i64,
        error: Option<&str>,
    ) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO agent_runs (started_at, finished_at, resources_observed, drift_detected, error)
             VALUES (?, ?, ?, ?, ?)",
            params![
                started_at.to_string(),
                finished_at.map(|t| t.to_string()),
                resources_observed,
                drift_detected,
                error,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent_runs(&self, limit: u32) -> Result<Vec<AgentRunRow>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, started_at, finished_at, resources_observed, drift_detected, error
             FROM agent_runs ORDER BY id DESC LIMIT ?",
        )?;
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(AgentRunRow {
                    id: r.get(0)?,
                    started_at: r.get(1)?,
                    finished_at: r.get(2)?,
                    resources_observed: r.get(3)?,
                    drift_detected: r.get(4)?,
                    error: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn row_to_drift(r: &rusqlite::Row<'_>) -> rusqlite::Result<DriftRow> {
    let diff_json: String = r.get(4)?;
    let diff: Diff = serde_json::from_str(&diff_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(DriftRow {
        id: r.get(0)?,
        resource_id: r.get(1)?,
        kind: r.get(2)?,
        severity: r.get(3)?,
        diff,
        detected_at: r.get(5)?,
        resolved_at: r.get(6)?,
        resolution: r.get(7)?,
    })
}

fn row_to_observation(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObservationRow> {
    let spec_json: String = r.get(4)?;
    let facts_json: String = r.get(5)?;
    let spec: serde_json::Value = serde_json::from_str(&spec_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let facts: serde_json::Value = serde_json::from_str(&facts_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(ObservationRow {
        resource_id: r.get(0)?,
        kind: r.get(1)?,
        observed_at: r.get(2)?,
        present: {
            let i: i64 = r.get(3)?;
            i != 0
        },
        spec,
        facts,
    })
}

// rusqlite::OptionalExtension's `optional` shadow we use above.
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::diff::DiffKind;
    use indexmap::IndexMap;
    use tempfile::TempDir;

    fn store() -> (Store, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.db");
        let s = Store::open(&path).unwrap();
        (s, dir)
    }

    fn make_observed() -> ObservedState {
        ObservedState {
            present: true,
            spec: serde_yaml_ng::Value::String("hi".into()),
            facts: IndexMap::new(),
            observed_at: Timestamp::now(),
        }
    }

    #[test]
    fn replay_protection_round_trip() {
        // Phase 7cz.8: first sighting returns None, second returns
        // Some(prior_status). Mark is idempotent (PRIMARY KEY conflict
        // is silently absorbed).
        let (s, _dir) = store();
        assert_eq!(s.assignment_already_processed("asg-1").unwrap(), None);
        s.mark_assignment_processed("asg-1", "succeeded").unwrap();
        assert_eq!(
            s.assignment_already_processed("asg-1").unwrap(),
            Some("succeeded".into())
        );
        // Second mark with a different status doesn't overwrite —
        // we want the original status preserved so a replay sees
        // the same answer.
        s.mark_assignment_processed("asg-1", "failed").unwrap();
        assert_eq!(
            s.assignment_already_processed("asg-1").unwrap(),
            Some("succeeded".into())
        );
    }

    #[test]
    fn replay_protection_vacuum_prunes_old_rows() {
        let (s, _dir) = store();
        // Insert a fresh row + an artificially-old one (bypassing
        // the helper to control timestamp).
        s.mark_assignment_processed("recent", "succeeded").unwrap();
        {
            let conn = s.conn.lock();
            conn.execute(
                "INSERT INTO processed_assignments (assignment_id, processed_at, status) \
                 VALUES (?, ?, ?)",
                params!["ancient", "1990-01-01T00:00:00Z", "succeeded"],
            )
            .unwrap();
        }
        let pruned = s.vacuum_replay(7).unwrap();
        assert_eq!(pruned, 1);
        // Recent survives.
        assert!(s.assignment_already_processed("recent").unwrap().is_some());
        // Ancient is gone.
        assert!(s.assignment_already_processed("ancient").unwrap().is_none());
    }

    #[test]
    fn migration_creates_schema() {
        let (s, _dir) = store();
        let conn = s.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert!(count >= 1);
    }

    #[test]
    fn observation_round_trip() {
        let (s, _dir) = store();
        let id = ResourceId::new("file", "test", "x");
        s.record_observation(&id, &make_observed()).unwrap();
        let row = s.last_observation(&id.to_string()).unwrap().unwrap();
        assert_eq!(row.resource_id, id.to_string());
        assert!(row.present);
    }

    #[test]
    fn observation_history_capped_per_resource() {
        // Phase 9-F1-fix-3: insert (cap + 5) observations for one
        // resource and confirm only `cap` remain. `last_observation`
        // must always return the newest.
        let (s, _dir) = store();
        let id = ResourceId::new("file", "test", "capped");
        let cap = AGENT_OBSERVATION_HISTORY_CAP as usize;
        for _ in 0..(cap + 5) {
            s.record_observation(&id, &make_observed()).unwrap();
        }
        let conn = s.conn.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM observations WHERE resource_id = ?",
                params![id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, AGENT_OBSERVATION_HISTORY_CAP);
    }

    #[test]
    fn observation_cap_isolates_per_resource() {
        // The cap must be per-resource, not global — observing
        // resource A many times must not evict resource B's history.
        let (s, _dir) = store();
        let a = ResourceId::new("file", "test", "a");
        let b = ResourceId::new("file", "test", "b");
        s.record_observation(&b, &make_observed()).unwrap();
        for _ in 0..(AGENT_OBSERVATION_HISTORY_CAP as usize + 5) {
            s.record_observation(&a, &make_observed()).unwrap();
        }
        // b still has its single row.
        let row_b = s.last_observation(&b.to_string()).unwrap();
        assert!(row_b.is_some(), "resource b's observation must survive");
    }

    #[test]
    fn drift_dedupes_open_event_per_resource() {
        let (s, _dir) = store();
        let id = ResourceId::new("file", "test", "x");
        let diff = Diff::no_change(); // shape doesn't matter for this test
        let id1 = s.open_drift(&id, "warning", &diff).unwrap();
        let id2 = s.open_drift(&id, "warning", &diff).unwrap();
        assert_eq!(id1, id2, "second open should reuse the existing row");
        let open = s.list_open_drifts().unwrap();
        assert_eq!(open.len(), 1);
    }

    #[test]
    fn drift_close_marks_resolved() {
        let (s, _dir) = store();
        let id = ResourceId::new("file", "test", "x");
        let mut diff = Diff::no_change();
        diff.kind = DiffKind::Update;
        s.open_drift(&id, "warning", &diff).unwrap();
        let n = s.close_open_drift_for(&id, "auto-resolved").unwrap();
        assert_eq!(n, 1);
        assert_eq!(s.open_drift_count().unwrap(), 0);
    }

    #[test]
    fn record_run_and_list() {
        let (s, _dir) = store();
        let now = Timestamp::now();
        s.record_run(now, Some(now), 3, 1, None).unwrap();
        s.record_run(now, Some(now), 4, 0, Some("oops")).unwrap();
        let runs = s.recent_runs(10).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].error.as_deref(), Some("oops"));
    }
}
