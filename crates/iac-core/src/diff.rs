use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    NoChange,
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Dotted path identifying the field, e.g. `spec.upstream.port` or `content.sha256`.
    pub field: String,
    pub from: Option<Value>,
    pub to: Option<Value>,
    /// Hint for renderers: don't print the value in plan output.
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub kind: DiffKind,
    #[serde(default)]
    pub changes: Vec<FieldChange>,
    /// Free-form human-readable reasons for this diff. e.g. "content sha256 differs".
    #[serde(default)]
    pub reasons: Vec<String>,
    /// True if undoing this diff doesn't require special manual recovery.
    #[serde(default = "default_reversible")]
    pub reversible: bool,
}

fn default_reversible() -> bool {
    true
}

impl Diff {
    pub fn no_change() -> Self {
        Self { kind: DiffKind::NoChange, changes: vec![], reasons: vec![], reversible: true }
    }

    pub fn is_change(&self) -> bool {
        !matches!(self.kind, DiffKind::NoChange)
    }
}
