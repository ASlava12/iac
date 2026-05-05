//! Agent health snapshot, written to a JSON file after each observe cycle.

use crate::config::Config;
use anyhow::{Context, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub started_at: Timestamp,
    pub last_observe_at: Option<Timestamp>,
    pub last_observe_summary: Option<ObserveCycleSummary>,
    pub managed_resource_count: usize,
    pub open_drift_count: usize,
    /// `true` while the most recent observe cycle completed without errors.
    pub healthy: bool,
    pub manifests_dir: String,
    pub state_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveCycleSummary {
    pub at: Timestamp,
    pub duration_ms: u64,
    pub observed: usize,
    pub drift_detected: usize,
    pub errors: Vec<String>,
}

impl ObserveCycleSummary {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

impl AgentStatus {
    pub fn initial(config: &Config) -> Self {
        Self {
            started_at: Timestamp::now(),
            last_observe_at: None,
            last_observe_summary: None,
            managed_resource_count: 0,
            open_drift_count: 0,
            healthy: true,
            manifests_dir: config.manifests_dir.display().to_string(),
            state_dir: config.state_dir.display().to_string(),
        }
    }

    pub fn record_cycle(&mut self, summary: ObserveCycleSummary, open_drift: usize, managed: usize) {
        self.last_observe_at = Some(summary.at);
        self.healthy = summary.is_clean();
        self.last_observe_summary = Some(summary);
        self.open_drift_count = open_drift;
        self.managed_resource_count = managed;
    }
}

pub fn write_status(path: &Path, status: &AgentStatus) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(status)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating status dir {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("status")
    ));
    std::fs::write(&tmp, &bytes)
        .with_context(|| format!("writing temp status {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming status to {}", path.display()))?;
    Ok(())
}

pub fn read_status(path: &Path) -> Result<AgentStatus> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading status {}", path.display()))?;
    let status: AgentStatus = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing status {}", path.display()))?;
    Ok(status)
}
