//! `file` provider: manages absolute paths on the local filesystem.
//!
//! Spec:
//! ```yaml
//! kind: file
//! spec:
//!   path: /etc/nginx/nginx.conf
//!   state: present | absent       # default: present
//!   mode: "0644"                  # optional, octal string
//!   owner: root                   # name or numeric uid
//!   group: root                   # name or numeric gid
//!   content: |                    # optional, utf-8
//!     ...
//! ```
//!
//! Phase 0: inline UTF-8 content only. Binary content via `content_sha256` +
//! source URL is a Phase 5 concern.

mod ops;
mod spec;

// Phase 7cz.20: typed action namespace. `pre_apply` / `apply` parse
// the wire string into this enum, so adding a new variant without a
// match arm is a compile error rather than a runtime "unknown step".
crate::step_actions!(FileAction {
    Write  => "file.write",
    Delete => "file.delete",
});

use iac_core::{
    Error, Result,
    diff::{Diff, DiffKind, FieldChange},
    operation::{Checkpoint, Step, StepResult},
    provider::{ApplyContext, Provider, VerifyOutcome},
    resource::Resource,
    state::ObservedState,
};
use serde_json::{Value as Json, json};
use std::path::Path;

pub use spec::{FileSpec, FileState};

#[derive(Debug, Default)]
pub struct FileProvider;

impl FileProvider {
    pub fn new() -> Self {
        Self
    }

    fn parse_spec(&self, resource: &Resource) -> Result<FileSpec> {
        FileSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(resource.id().to_string(), format!("invalid file spec: {e}"))
        })
    }
}

impl Provider for FileProvider {
    fn kind(&self) -> &str {
        "file"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(&spec)
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let spec = self.parse_spec(resource)?;
        Ok(ops::diff(&spec, observed))
    }

    fn plan(&self, resource: &Resource, diff: &Diff) -> Result<Vec<Step>> {
        let spec = self.parse_spec(resource)?;
        let action = match diff.kind {
            DiffKind::NoChange => return Ok(vec![]),
            DiffKind::Create | DiffKind::Update => match spec.state {
                FileState::Present => FileAction::Write,
                FileState::Absent => FileAction::Delete,
            },
            DiffKind::Delete => FileAction::Delete,
        };
        let description = match action {
            FileAction::Write => format!("write {}", spec.path.display()),
            FileAction::Delete => format!("delete {}", spec.path.display()),
        };
        Ok(vec![Step::new(
            action.as_str(),
            description,
            json!({ "path": spec.path }),
        )])
    }

    fn pre_apply(&self, resource: &Resource, step: &Step, ctx: &ApplyContext) -> Result<Json> {
        let spec = self.parse_spec(resource)?;
        // pre_apply is the same backup operation regardless of which
        // action follows — but we still parse here to fail loudly on
        // an unknown wire-format action instead of silently backing
        // up nothing.
        let _ = FileAction::parse(&step.action)?;
        ops::backup(&spec.path, &ctx.workspace)
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        match FileAction::parse(&step.action)? {
            FileAction::Write => ops::write(&spec),
            FileAction::Delete => ops::delete(&spec.path),
        }
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let observed = ops::observe(&spec)?;
        let diff = ops::diff(&spec, &observed);
        if diff.is_change() {
            let mut changes: Vec<FieldChange> = diff.changes;
            if changes.is_empty() {
                changes.push(FieldChange {
                    field: "state".to_string(),
                    from: None,
                    to: None,
                    sensitive: false,
                });
            }
            Ok(VerifyOutcome::Mismatch(changes))
        } else {
            Ok(VerifyOutcome::Match)
        }
    }

    fn rollback(
        &self,
        resource: &Resource,
        checkpoint: &Checkpoint,
        workspace: &Path,
    ) -> Result<()> {
        // Trust order, tightest to loosest:
        //
        //   1. live `resource.spec` — set by the executor's
        //      `synthesize_resource`, which since Phase 9 reads it
        //      from the persisted `checkpoint.resource_spec`. This
        //      is the operator-authored spec at apply time and
        //      doesn't depend on the provider-controlled `data`
        //      field, so the path can't be steered by a tampered
        //      checkpoint payload.
        //   2. `checkpoint.data["path"]` — last-resort fallback for
        //      legacy on-disk checkpoints written before the spec
        //      snapshot existed. Stays guarded by the path-mismatch
        //      sanity check + backup_name path-separator escape
        //      (Phase 7cz.1) inside `ops::restore`. Once an operator
        //      has rolled past any legacy checkpoint, this branch
        //      stops firing and the trust on `data["path"]` falls
        //      out of the live surface.
        let target_from_spec = self.parse_spec(resource).ok().map(|s| s.path);
        let target_from_checkpoint: Option<std::path::PathBuf> = checkpoint
            .data
            .get("path")
            .and_then(|v| v.as_str())
            .map(std::path::PathBuf::from);
        let target = target_from_spec.or(target_from_checkpoint).ok_or_else(|| {
            Error::provider(
                "file",
                "rollback: neither resource spec nor checkpoint carried a path",
            )
        })?;
        ops::restore(&target, &checkpoint.data, workspace)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        Ok(vec![spec.path.display().to_string()])
    }
}
