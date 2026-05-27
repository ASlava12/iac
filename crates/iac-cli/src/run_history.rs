//! Phase 7da.3: local audit log for `iac run` invocations that don't
//! have a control plane to talk to.
//!
//! Writes append-only NDJSON to `<state_dir>/run-history.jsonl`. One
//! line per `iac run` invocation, with timestamp, actor, command,
//! per-host outcome. Newer entries on the bottom; the file grows
//! unbounded — operators rotate via standard `logrotate` if it gets
//! large.
//!
//! When `iac run --server <url>` is used (control-plane path), audit
//! goes through the existing `audit_events` table; this local log is
//! only the standalone fallback.

use crate::ssh_dispatch::DispatchOutcome;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const HISTORY_FILE: &str = "run-history.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub timestamp: String,
    pub actor: String,
    pub command: String,
    pub host_count: usize,
    pub ok_count: usize,
    pub failed_count: usize,
    pub hosts: Vec<HostOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOutcome {
    pub label: String,
    pub status: String,
    pub summary: String,
}

impl RunRecord {
    pub fn new(actor: &str, command: &str, outcomes: &[DispatchOutcome]) -> Self {
        let mut ok_count = 0;
        let mut failed_count = 0;
        let hosts: Vec<HostOutcome> = outcomes
            .iter()
            .map(|o| {
                let s = format!("{:?}", o.status);
                let lower = s.to_ascii_lowercase();
                if lower == "succeeded" {
                    ok_count += 1;
                } else if lower == "failed" {
                    failed_count += 1;
                }
                HostOutcome {
                    label: o.label.clone(),
                    status: s,
                    summary: o.summary.clone(),
                }
            })
            .collect();
        Self {
            timestamp: jiff::Timestamp::now().to_string(),
            actor: actor.to_string(),
            command: command.to_string(),
            host_count: outcomes.len(),
            ok_count,
            failed_count,
            hosts,
        }
    }
}

/// Append `record` to `<state_dir>/run-history.jsonl`. Creates the
/// directory + file if missing. Errors are surfaced to the caller —
/// the CLI logs them as warnings rather than failing the run, since
/// audit-log persistence is a "nice to have" and the operator
/// already saw the per-host output on stdout.
pub fn append(state_dir: &Path, record: RunRecord) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating state_dir {} for run-history", state_dir.display()))?;
    let path = state_dir.join(HISTORY_FILE);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let line = serde_json::to_string(&record).with_context(|| "serialising run-history record")?;
    writeln!(file, "{line}").with_context(|| format!("writing to {}", path.display()))?;
    Ok(())
}

/// Read the last `limit` records from the run history. Empty vec if
/// the file doesn't exist. Malformed lines are skipped silently.
pub fn read_recent(state_dir: &Path, limit: usize) -> Result<Vec<RunRecord>> {
    let path = state_dir.join(HISTORY_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut records: Vec<RunRecord> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<RunRecord>(line).ok())
        .collect();
    let len = records.len();
    if len > limit {
        records.drain(..len - limit);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::protocol::v1::AssignmentResultStatus;
    use tempfile::TempDir;

    fn outcome(label: &str, status: AssignmentResultStatus) -> DispatchOutcome {
        DispatchOutcome {
            label: label.into(),
            status,
            summary: "ok".into(),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn append_creates_file_and_writes_ndjson() {
        let dir = TempDir::new().unwrap();
        let outcomes = vec![
            outcome("web-01", AssignmentResultStatus::Succeeded),
            outcome("web-02", AssignmentResultStatus::Failed),
        ];
        let rec = RunRecord::new("alice", "uptime", &outcomes);
        append(dir.path(), rec).unwrap();
        let file = dir.path().join(HISTORY_FILE);
        let content = std::fs::read_to_string(&file).unwrap();
        assert_eq!(content.lines().count(), 1);
        let parsed: RunRecord = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.actor, "alice");
        assert_eq!(parsed.command, "uptime");
        assert_eq!(parsed.host_count, 2);
        assert_eq!(parsed.ok_count, 1);
        assert_eq!(parsed.failed_count, 1);
        assert_eq!(parsed.hosts.len(), 2);
    }

    #[test]
    fn append_is_append_only() {
        let dir = TempDir::new().unwrap();
        let r1 = RunRecord::new(
            "bob",
            "ls",
            &[outcome("h1", AssignmentResultStatus::Succeeded)],
        );
        let r2 = RunRecord::new(
            "bob",
            "df",
            &[outcome("h1", AssignmentResultStatus::Succeeded)],
        );
        append(dir.path(), r1).unwrap();
        append(dir.path(), r2).unwrap();
        let recent = read_recent(dir.path(), 100).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].command, "ls");
        assert_eq!(recent[1].command, "df");
    }

    #[test]
    fn read_recent_caps_at_limit() {
        let dir = TempDir::new().unwrap();
        for i in 0..10 {
            let r = RunRecord::new(
                "carol",
                &format!("cmd-{i}"),
                &[outcome("h1", AssignmentResultStatus::Succeeded)],
            );
            append(dir.path(), r).unwrap();
        }
        let recent = read_recent(dir.path(), 3).unwrap();
        assert_eq!(recent.len(), 3);
        // Last 3 — the trailing entries.
        assert_eq!(recent[0].command, "cmd-7");
        assert_eq!(recent[2].command, "cmd-9");
    }

    #[test]
    fn read_recent_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let recent = read_recent(dir.path(), 100).unwrap();
        assert!(recent.is_empty());
    }
}
