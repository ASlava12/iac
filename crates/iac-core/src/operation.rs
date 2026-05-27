use crate::id::ResourceId;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use ulid::Ulid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Ulid,
    /// Provider-defined action, e.g. `file.write`, `systemd.reload`.
    pub action: String,
    pub description: String,
    /// Whether this individual step can be undone via `Provider::rollback`.
    pub reversible: bool,
    /// Step-specific input. Provider parses to its own typed payload.
    #[serde(default)]
    pub payload: Json,
    pub status: StepStatus,
    #[serde(default)]
    pub started_at: Option<Timestamp>,
    #[serde(default)]
    pub finished_at: Option<Timestamp>,
}

impl Step {
    pub fn new(action: impl Into<String>, description: impl Into<String>, payload: Json) -> Self {
        Self {
            id: Ulid::new(),
            action: action.into(),
            description: description.into(),
            reversible: true,
            payload,
            status: StepStatus::Pending,
            started_at: None,
            finished_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub status: StepStatus,
    pub message: String,
    /// Provider-defined output (sha hashes, version strings, etc).
    #[serde(default)]
    pub data: Json,
    /// Set when status is `Failed`.
    #[serde(default)]
    pub error: Option<String>,
}

impl StepResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            status: StepStatus::Succeeded,
            message: message.into(),
            data: Json::Null,
            error: None,
        }
    }

    pub fn skipped(message: impl Into<String>) -> Self {
        Self {
            status: StepStatus::Skipped,
            message: message.into(),
            data: Json::Null,
            error: None,
        }
    }

    pub fn failed(error: impl Into<String>) -> Self {
        let err = error.into();
        Self {
            status: StepStatus::Failed,
            message: err.clone(),
            data: Json::Null,
            error: Some(err),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Pending,
    Planning,
    WaitingApproval,
    Running,
    PartiallyApplied,
    Failed,
    RollingBack,
    RolledBack,
    Succeeded,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub id: Ulid,
    /// e.g. `apply`, `rollback`, `observe`.
    pub kind: String,
    pub status: OperationStatus,
    pub source_commit: Option<String>,
    pub requested_by: String,
    pub created_at: Timestamp,
    #[serde(default)]
    pub started_at: Option<Timestamp>,
    #[serde(default)]
    pub finished_at: Option<Timestamp>,
}

impl Operation {
    pub fn new(kind: impl Into<String>, requested_by: impl Into<String>) -> Self {
        Self {
            id: Ulid::new(),
            kind: kind.into(),
            status: OperationStatus::Pending,
            source_commit: None,
            requested_by: requested_by.into(),
            created_at: Timestamp::now(),
            started_at: None,
            finished_at: None,
        }
    }
}

/// Snapshot the executor takes before applying so a step can be undone later.
/// `data` is provider-specific (file backup path, package version string, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: Ulid,
    pub resource_id: ResourceId,
    pub operation_id: Ulid,
    pub created_at: Timestamp,
    pub data: Json,
}

impl Checkpoint {
    pub fn new(resource_id: ResourceId, operation_id: Ulid, data: Json) -> Self {
        Self {
            id: Ulid::new(),
            resource_id,
            operation_id,
            created_at: Timestamp::now(),
            data,
        }
    }
}
