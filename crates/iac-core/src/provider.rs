use crate::diff::{Diff, FieldChange};
use crate::operation::{Checkpoint, Step, StepResult};
use crate::resource::Resource;
use crate::state::ObservedState;
use crate::Result;
use serde_json::Value as Json;
use std::path::{Path, PathBuf};
use ulid::Ulid;

/// Outcome of a post-apply verification.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// Observed state matches desired state; nothing to do.
    Match,
    /// Observed state still differs after apply. Useful diagnostic info.
    Mismatch(Vec<FieldChange>),
}

impl VerifyOutcome {
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

/// Per-step execution context. Every `pre_apply` / `apply` / `rollback` call
/// gets one. The workspace directory is provider-private scratch space tied
/// to a single checkpoint — the provider may write any backup files it needs
/// there, and they remain available during `rollback`.
#[derive(Debug, Clone)]
pub struct ApplyContext {
    pub operation_id: Ulid,
    /// Filesystem directory unique to this `(operation, step)` pair.
    /// Created by the executor before `pre_apply` is called and preserved
    /// until the checkpoint is pruned.
    pub workspace: PathBuf,
}

impl ApplyContext {
    pub fn workspace_path(&self, name: &str) -> PathBuf {
        self.workspace.join(name)
    }
}

/// Lifecycle interface every resource type must implement.
///
/// Order: `observe` → `diff` → `plan` → for each step: `pre_apply` → `apply` → `verify`.
/// `rollback` is invoked on failure to undo an applied step using its checkpoint.
///
/// Sync only for Phase 0 — local file/process operations don't need async.
/// Phase 1 (agent) will run providers on a blocking pool.
pub trait Provider: Send + Sync + std::fmt::Debug {
    /// `kind` matches the resource manifest's `kind` field.
    fn kind(&self) -> &str;

    /// Inspect the world. Must not mutate.
    fn observe(&self, resource: &Resource) -> Result<ObservedState>;

    /// Compare desired (in `resource.spec`) against observed.
    /// Pure function: no I/O.
    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff>;

    /// Translate a non-trivial diff into concrete steps the executor will run.
    /// May return empty if the diff has `kind == NoChange`.
    fn plan(&self, resource: &Resource, diff: &Diff) -> Result<Vec<Step>>;

    /// Snapshot enough state into the workspace and return JSON metadata so
    /// that `rollback` can later restore the resource. May be a no-op for
    /// providers that derive rollback purely from the resource spec.
    fn pre_apply(&self, resource: &Resource, step: &Step, ctx: &ApplyContext) -> Result<Json>;

    /// Execute one step. Side effects allowed.
    fn apply(&self, resource: &Resource, step: &Step, ctx: &ApplyContext) -> Result<StepResult>;

    /// Re-observe and confirm the resource matches desired.
    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome>;

    /// Restore state from a checkpoint produced during `pre_apply`.
    /// `workspace` points at the same directory `pre_apply` wrote into.
    fn rollback(
        &self,
        resource: &Resource,
        checkpoint: &Checkpoint,
        workspace: &Path,
    ) -> Result<()>;

    /// Phase 7ao: return the capability identifier(s) this resource governs.
    /// The agent's allowlist matches each key against per-kind glob rules.
    ///
    /// Examples (one key per resource is the common case):
    ///   * `file`             → `vec![spec.path]`
    ///   * `package`          → `vec![spec.name]`
    ///   * `systemd.unit`     → `vec![<name>.<type>]` (with auto-suffix)
    ///   * `docker.container` → `vec![spec.name]`
    ///
    /// Default: empty vec — resources of this kind are unrestricted unless
    /// the agent's `default_kind_policy = deny` kicks in. A provider that
    /// can't decide a key (e.g. a malformed spec) returns `Err` and the
    /// agent fails the resource closed.
    fn capability_keys(&self, _resource: &Resource) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
}
