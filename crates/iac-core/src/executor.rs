//! Local executor: walks resources, calls providers, persists checkpoints.
//!
//! Phase 0 contract: stops at the first failed step on a given resource and
//! marks the operation `PartiallyApplied`. Auto-rollback is not done — the
//! caller invokes `Executor::rollback` explicitly if they want to undo.

use crate::diff::{Diff, DiffKind};
use crate::id::ResourceId;
use crate::operation::{Checkpoint, Operation, OperationStatus, Step, StepResult, StepStatus};
use crate::provider::{ApplyContext, VerifyOutcome};
use crate::registry::ProviderRegistry;
use crate::resource::Resource;
use crate::state::AppliedState;
use crate::{Error, Result};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Outcome of a planning phase. Pure: no side effects on the host.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlanResult {
    pub operation: Operation,
    pub items: Vec<PlanItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlanItem {
    pub resource_id: ResourceId,
    pub kind: String,
    pub diff: Diff,
    pub steps: Vec<Step>,
}

impl PlanResult {
    pub fn has_changes(&self) -> bool {
        self.items.iter().any(|i| i.diff.is_change())
    }

    pub fn change_count(&self) -> usize {
        self.items.iter().filter(|i| i.diff.is_change()).count()
    }
}

/// Outcome of an apply phase.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApplyResult {
    pub operation: Operation,
    pub items: Vec<ApplyItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplyItem {
    pub resource_id: ResourceId,
    pub kind: String,
    pub status: ItemStatus,
    pub steps: Vec<StepRecord>,
    pub verify: Option<VerifySummary>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    NoChange,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StepRecord {
    pub step: Step,
    pub result: StepResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifySummary {
    pub matched: bool,
    pub mismatch: Option<Vec<crate::diff::FieldChange>>,
}

impl From<&VerifyOutcome> for VerifySummary {
    fn from(v: &VerifyOutcome) -> Self {
        match v {
            VerifyOutcome::Match => Self {
                matched: true,
                mismatch: None,
            },
            VerifyOutcome::Mismatch(c) => Self {
                matched: false,
                mismatch: Some(c.clone()),
            },
        }
    }
}

/// How many `operations/<ulid>/` directories to keep on disk after
/// each apply. Phase 9-F1-fix-10: the F1 PASS finalize uncovered
/// agent disk-pressure on 2 of 7 VPS (agent-05 / agent-07) — root
/// cause was `executor/operations/` growing unbounded to ~57k
/// directories (1.6 GB) over a 24h soak. Pre-fix behaviour: write
/// per-op dir, never delete. Post-fix: prune to the newest N by
/// ULID lexicographic order after each apply.
///
/// 200 chosen because: per-dir overhead is ~28 KB, so the steady-
/// state footprint is ~5.6 MB — three orders of magnitude under
/// the disk-pressure threshold seen on the trial VPS. It also
/// preserves enough recent history for operator-triggered rollback
/// (`iac-agent rollback <op-id>`) of any operation from the last
/// several minutes of typical fleet activity. Rollback of an
/// operation older than the most-recent-N window is not supported
/// — the operator must re-apply the desired state instead.
const EXECUTOR_OPERATIONS_KEEP: usize = 200;

/// Executor orchestrates plan/apply against a `ProviderRegistry`.
///
/// State directory layout:
/// ```text
/// <state-dir>/
///   applied/<kind>__<env>__<name>.json    # last applied state per resource
///   operations/<ulid>/
///     operation.json                      # operation record (final)
///     plan.json                           # the plan that was executed
///     checkpoints/<kind>__<env>__<name>/<step-ulid>/
///       checkpoint.json                   # checkpoint payload
///       <provider workspace files>        # backups, etc.
/// ```
///
/// `operations/` is bounded to the newest [`EXECUTOR_OPERATIONS_KEEP`]
/// directories (see const above). Older dirs are deleted post-apply.
pub struct Executor<'a> {
    registry: &'a ProviderRegistry,
    state_dir: PathBuf,
    actor: String,
}

impl<'a> std::fmt::Debug for Executor<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor")
            .field("state_dir", &self.state_dir)
            .field("actor", &self.actor)
            .finish()
    }
}

impl<'a> Executor<'a> {
    pub fn new(
        registry: &'a ProviderRegistry,
        state_dir: PathBuf,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            state_dir,
            actor: actor.into(),
        }
    }

    /// Compute a plan without making any host changes.
    pub fn plan(&self, resources: &[Resource]) -> Result<PlanResult> {
        let mut op = Operation::new("plan", &self.actor);
        op.status = OperationStatus::Planning;
        let mut items: Vec<PlanItem> = Vec::with_capacity(resources.len());
        for resource in resources {
            let provider = self.registry.require(&resource.kind)?;
            let observed = provider.observe(resource)?;
            let mut diff = provider.diff(resource, &observed)?;
            mark_secret_changes(resource, &mut diff);
            let steps = if diff.is_change() {
                provider.plan(resource, &diff)?
            } else {
                Vec::new()
            };
            items.push(PlanItem {
                resource_id: resource.id(),
                kind: resource.kind.clone(),
                diff,
                steps,
            });
        }
        op.finished_at = Some(Timestamp::now());
        op.status = OperationStatus::Succeeded;
        Ok(PlanResult {
            operation: op,
            items,
        })
    }

    /// Apply the resources to the host. Stops the resource on the first failed
    /// step but continues with subsequent resources.
    pub fn apply(&self, resources: &[Resource]) -> Result<ApplyResult> {
        let mut op = Operation::new("apply", &self.actor);
        op.started_at = Some(Timestamp::now());
        op.status = OperationStatus::Running;

        ensure_dir(&self.operation_dir(&op))?;

        let mut items: Vec<ApplyItem> = Vec::with_capacity(resources.len());
        let mut any_failed = false;
        let mut any_changed = false;

        for resource in resources {
            let item = self.apply_one(resource, &op)?;
            match item.status {
                ItemStatus::Failed => any_failed = true,
                ItemStatus::Succeeded => any_changed = true,
                ItemStatus::NoChange | ItemStatus::Skipped => {}
            }
            items.push(item);
        }

        op.finished_at = Some(Timestamp::now());
        op.status = match (any_failed, any_changed) {
            (true, true) => OperationStatus::PartiallyApplied,
            (true, false) => OperationStatus::Failed,
            (false, _) => OperationStatus::Succeeded,
        };

        // Persist final operation + plan-like result for audit.
        let op_dir = self.operation_dir(&op);
        let result = ApplyResult {
            operation: op,
            items,
        };
        write_json(&op_dir.join("operation.json"), &result.operation)?;
        write_json(&op_dir.join("apply-result.json"), &result)?;

        // GC older operations dirs (Phase 9-F1-fix-10). Errors here
        // are logged via tracing but never propagated — a stuck GC
        // pass must NOT fail the apply that just succeeded. The disk
        // pressure it prevents is real but the apply itself is
        // already on disk, so the caller's contract is preserved.
        if let Err(e) = self.gc_operation_dirs(EXECUTOR_OPERATIONS_KEEP) {
            tracing::warn!(error = %e, "executor operations GC failed; will retry next apply");
        }

        Ok(result)
    }

    /// Keep the newest `keep` `operations/<ulid>/` directories;
    /// delete the rest. ULIDs sort lexicographically by creation
    /// time so `sort()` then `iter().rev()` is the natural ordering.
    ///
    /// Quiet on missing operations/ (first-ever apply hasn't created
    /// it yet) and on individual delete failures (a concurrent reader
    /// or transient ENOENT after listdir is harmless to skip).
    fn gc_operation_dirs(&self, keep: usize) -> Result<()> {
        let ops_root = self.state_dir.join("operations");
        if !ops_root.exists() {
            return Ok(());
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(&ops_root)
            .map_err(|e| Error::Io {
                path: ops_root.clone(),
                source: e,
            })?
            .filter_map(|r| r.ok())
            .filter(|e| e.file_type().ok().is_some_and(|t| t.is_dir()))
            .map(|e| e.path())
            .collect();
        if entries.len() <= keep {
            return Ok(());
        }
        // ULID file names are 26 chars and sort lex == chronologically.
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        let drop_count = entries.len() - keep;
        for old in entries.iter().take(drop_count) {
            if let Err(e) = fs::remove_dir_all(old) {
                // ENOENT is the only "expected" race; everything else
                // logs but doesn't propagate (see caller comment).
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %old.display(), error = %e, "executor GC: remove_dir_all failed");
                }
            }
        }
        Ok(())
    }

    fn apply_one(&self, resource: &Resource, op: &Operation) -> Result<ApplyItem> {
        let provider = self.registry.require(&resource.kind)?;
        let observed = provider.observe(resource)?;
        let mut diff = provider.diff(resource, &observed)?;
        mark_secret_changes(resource, &mut diff);
        if matches!(diff.kind, DiffKind::NoChange) {
            // Even no-change runs may want to refresh applied state metadata.
            self.write_applied(resource, op.id)?;
            return Ok(ApplyItem {
                resource_id: resource.id(),
                kind: resource.kind.clone(),
                status: ItemStatus::NoChange,
                steps: vec![],
                verify: None,
                error: None,
            });
        }

        let steps = provider.plan(resource, &diff)?;
        let mut records: Vec<StepRecord> = Vec::with_capacity(steps.len());
        let mut last_error: Option<String> = None;

        for step in steps {
            let workspace = self.checkpoint_workspace(op, &resource.id(), &step);
            ensure_dir(&workspace)?;

            let ctx = ApplyContext {
                operation_id: op.id,
                workspace: workspace.clone(),
            };

            let mut s = step;
            s.started_at = Some(Timestamp::now());
            s.status = StepStatus::Running;

            let pre_data = match provider.pre_apply(resource, &s, &ctx) {
                Ok(d) => d,
                Err(e) => {
                    let msg = format!("pre_apply failed: {e}");
                    s.status = StepStatus::Failed;
                    s.finished_at = Some(Timestamp::now());
                    let result = StepResult::failed(msg.clone());
                    records.push(StepRecord { step: s, result });
                    last_error = Some(msg);
                    break;
                }
            };

            // Phase 9 follow-up: persist the resource spec alongside the
            // provider's pre_apply data. Rollback then reconstructs a
            // real Resource (not a Null-spec stub) and providers like
            // file/ops can derive the target path from the spec rather
            // than from `data["path"]` — closing the last fallback that
            // 7cz.1 left documented as untrusted-JSON-after-checkpoint-
            // tamper.
            let checkpoint =
                Checkpoint::with_spec(resource.id(), op.id, pre_data, resource.spec.clone());
            write_json(&workspace.join("checkpoint.json"), &checkpoint)?;

            let result = match provider.apply(resource, &s, &ctx) {
                Ok(r) => r,
                Err(e) => StepResult::failed(format!("apply failed: {e}")),
            };
            s.status = result.status;
            s.finished_at = Some(Timestamp::now());

            let failed = result.status == StepStatus::Failed;
            records.push(StepRecord { step: s, result });
            if failed {
                last_error = Some(
                    records
                        .last()
                        .and_then(|r| r.result.error.clone())
                        .unwrap_or_default(),
                );
                break;
            }
        }

        if last_error.is_some() {
            return Ok(ApplyItem {
                resource_id: resource.id(),
                kind: resource.kind.clone(),
                status: ItemStatus::Failed,
                steps: records,
                verify: None,
                error: last_error,
            });
        }

        let verify = provider.verify(resource)?;
        let summary = VerifySummary::from(&verify);
        if summary.matched {
            self.write_applied(resource, op.id)?;
        }
        Ok(ApplyItem {
            resource_id: resource.id(),
            kind: resource.kind.clone(),
            status: if summary.matched {
                ItemStatus::Succeeded
            } else {
                ItemStatus::Failed
            },
            steps: records,
            verify: Some(summary),
            error: None,
        })
    }

    /// Rollback all checkpoints for an operation, in reverse order.
    pub fn rollback(&self, operation_id: ulid::Ulid) -> Result<()> {
        let op_dir = self
            .state_dir
            .join("operations")
            .join(operation_id.to_string());
        if !op_dir.exists() {
            return Err(Error::Checkpoint {
                resource: format!("operation {operation_id}"),
                message: format!("operation directory {} does not exist", op_dir.display()),
            });
        }
        let cp_root = op_dir.join("checkpoints");
        if !cp_root.exists() {
            return Ok(());
        }
        let mut checkpoints: Vec<(PathBuf, Checkpoint, Resource)> = Vec::new();
        // We don't have the original Resource stored separately — for Phase 0
        // we reconstruct minimally from the checkpoint's resource_id.
        for resource_dir in fs::read_dir(&cp_root).map_err(|e| Error::Io {
            path: cp_root.clone(),
            source: e,
        })? {
            let resource_dir = resource_dir.map_err(|e| Error::Io {
                path: cp_root.clone(),
                source: e,
            })?;
            for step_dir in fs::read_dir(resource_dir.path()).map_err(|e| Error::Io {
                path: resource_dir.path(),
                source: e,
            })? {
                let step_dir = step_dir.map_err(|e| Error::Io {
                    path: resource_dir.path(),
                    source: e,
                })?;
                let cp_path = step_dir.path().join("checkpoint.json");
                if !cp_path.exists() {
                    continue;
                }
                let bytes = fs::read(&cp_path).map_err(|e| Error::Io {
                    path: cp_path.clone(),
                    source: e,
                })?;
                let cp: Checkpoint = serde_json::from_slice(&bytes)?;
                let resource = synthesize_resource(&cp);
                checkpoints.push((step_dir.path(), cp, resource));
            }
        }
        // Reverse-time order: highest ULID first.
        checkpoints.sort_by_key(|entry| std::cmp::Reverse(entry.1.id));

        for (workspace, cp, resource) in checkpoints {
            let provider = self.registry.require(&resource.kind)?;
            provider.rollback(&resource, &cp, &workspace)?;
        }
        Ok(())
    }

    fn write_applied(&self, resource: &Resource, op_id: ulid::Ulid) -> Result<()> {
        let dir = self.state_dir.join("applied");
        ensure_dir(&dir)?;
        let path = dir.join(format!("{}.json", resource.id().fs_key()));
        let value = AppliedState {
            spec: resource.spec.clone(),
            generation: 1,
            operation_id: Some(op_id),
            applied_at: Timestamp::now(),
        };
        write_json(&path, &value)?;
        Ok(())
    }

    fn operation_dir(&self, op: &Operation) -> PathBuf {
        self.state_dir.join("operations").join(op.id.to_string())
    }

    fn checkpoint_workspace(&self, op: &Operation, rid: &ResourceId, step: &Step) -> PathBuf {
        self.operation_dir(op)
            .join("checkpoints")
            .join(rid.fs_key())
            .join(step.id.to_string())
    }
}

/// Phase 9 follow-up #15: annotation the control-plane stamps onto a
/// resource (under `metadata.annotations`) listing the JSON-pointer
/// paths whose original value carried a `${secret://...}` reference.
/// Kept in `iac.dev/` namespace to avoid colliding with operator
/// annotations. Mirrored in `iac-controlplane/src/api/agents.rs` —
/// keep the two constants in sync if either crate changes the key.
pub const SECRET_FIELDS_ANNOTATION: &str = "iac.dev/secret-fields";

/// If the resource was tagged by the control-plane as carrying secret
/// substitutions, redact every FieldChange in the supplied diff. The
/// granular pointer→field mapping is provider-specific and not always
/// 1:1 (a docker.container env-var map's secret pointer can't be
/// projected onto the provider's coarse "env" FieldChange), so the
/// conservative shape — "any secret -> the whole diff is sensitive" —
/// is what we apply. The render layer already replaces from/to with
/// `<sensitive>` placeholders when the flag is set, so this prevents
/// resolved plaintext from leaking through drift reports and local
/// plan/apply output.
fn mark_secret_changes(resource: &Resource, diff: &mut crate::diff::Diff) {
    let has_secrets = resource
        .metadata
        .annotations
        .get(SECRET_FIELDS_ANNOTATION)
        .is_some_and(|v| !v.is_empty());
    if !has_secrets {
        return;
    }
    for change in &mut diff.changes {
        change.sensitive = true;
    }
}

fn synthesize_resource(cp: &Checkpoint) -> Resource {
    use crate::resource::{Metadata, SourceLocation};
    Resource {
        api_version: crate::resource::API_VERSION.into(),
        kind: cp.resource_id.kind.clone(),
        metadata: Metadata {
            name: cp.resource_id.name.clone(),
            environment: cp.resource_id.environment.clone(),
            owner: None,
            labels: Default::default(),
            annotations: Default::default(),
        },
        // Phase 9 follow-up: prefer the spec snapshot the apply path
        // persisted; fall back to Null for legacy checkpoints written
        // before the field existed. Providers that need spec fields
        // (file/ops::rollback wanting spec.path) now get the real
        // value, dropping the per-field-from-checkpoint-data fallback
        // out of the trust boundary.
        spec: cp.resource_spec.clone().unwrap_or(serde_yaml_ng::Value::Null),
        policy: serde_yaml_ng::Value::Null,
        source: SourceLocation::default(),
    }
}

fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| Error::Io {
        path: path.into(),
        source: e,
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let parent = path.parent().unwrap_or(Path::new("."));
    ensure_dir(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("out")
    ));
    fs::write(&tmp, &bytes).map_err(|e| Error::Io {
        path: tmp.clone(),
        source: e,
    })?;
    fs::rename(&tmp, path).map_err(|e| Error::Io {
        path: path.into(),
        source: e,
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
