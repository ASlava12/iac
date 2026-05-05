use indexmap::IndexMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

/// What the user/operator has declared the resource should be.
/// Generation increases monotonically each time the desired state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesiredState {
    pub spec: Value,
    pub generation: u64,
    pub source_commit: Option<String>,
}

/// What the system actually finds when it inspects the resource right now.
/// `present = false` means the resource doesn't exist in the world yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedState {
    pub present: bool,
    /// Spec equivalent to a desired-state representation of what's currently there.
    /// May be `Null` when `present = false`.
    pub spec: Value,
    /// Out-of-band facts the provider gathered that aren't part of the spec
    /// but useful for plan/audit (file mode, package version, systemd active state, etc).
    #[serde(default)]
    pub facts: IndexMap<String, Value>,
    pub observed_at: Timestamp,
}

impl ObservedState {
    pub fn absent() -> Self {
        Self {
            present: false,
            spec: Value::Null,
            facts: IndexMap::new(),
            observed_at: Timestamp::now(),
        }
    }

    pub fn present(spec: Value) -> Self {
        Self {
            present: true,
            spec,
            facts: IndexMap::new(),
            observed_at: Timestamp::now(),
        }
    }
}

/// What this tool last successfully applied. Stored in the local state dir.
/// In Phase 2+ this lives in PostgreSQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedState {
    pub spec: Value,
    pub generation: u64,
    pub operation_id: Option<ulid::Ulid>,
    pub applied_at: Timestamp,
}
