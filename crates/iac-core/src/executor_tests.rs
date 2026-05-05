use super::*;
use crate::diff::{Diff, DiffKind, FieldChange};
use crate::operation::{Step, StepResult};
use crate::provider::{ApplyContext, Provider, VerifyOutcome};
use crate::resource::{Metadata, Resource, SourceLocation, API_VERSION};
use crate::state::ObservedState;
use serde_json::{json, Value as Json};
use serde_yaml_ng::Value as YamlValue;
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

#[allow(dead_code)] // some fields are mutated only via lock; clippy thinks unused
const _UNUSED: () = ();

/// A provider backed by an in-memory string. Lets executor tests run without
/// touching the filesystem or shelling out.
#[derive(Debug, Default)]
struct FakeProvider {
    state: Mutex<Option<String>>, // None = absent
    fail_apply: Mutex<Option<String>>,
    fail_verify: Mutex<bool>,
    apply_calls: Mutex<u32>,
    rollback_calls: Mutex<u32>,
}

impl Provider for FakeProvider {
    fn kind(&self) -> &str {
        "fake"
    }

    fn observe(&self, _resource: &Resource) -> Result<ObservedState> {
        let cur = self.state.lock().unwrap().clone();
        Ok(match cur {
            Some(s) => ObservedState::present(YamlValue::String(s)),
            None => ObservedState::absent(),
        })
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let want = resource.spec.as_str().unwrap_or("").to_string();
        let have = observed.spec.as_str().unwrap_or("").to_string();
        if !observed.present {
            return Ok(Diff {
                kind: DiffKind::Create,
                changes: vec![FieldChange {
                    field: "value".into(),
                    from: None,
                    to: Some(YamlValue::String(want)),
                    sensitive: false,
                }],
                reasons: vec!["create".into()],
                reversible: true,
            });
        }
        if want == have {
            Ok(Diff::no_change())
        } else {
            Ok(Diff {
                kind: DiffKind::Update,
                changes: vec![FieldChange {
                    field: "value".into(),
                    from: Some(YamlValue::String(have)),
                    to: Some(YamlValue::String(want)),
                    sensitive: false,
                }],
                reasons: vec!["update".into()],
                reversible: true,
            })
        }
    }

    fn plan(&self, _resource: &Resource, diff: &Diff) -> Result<Vec<Step>> {
        if !diff.is_change() {
            return Ok(vec![]);
        }
        Ok(vec![Step::new("fake.set", "set value", Json::Null)])
    }

    fn pre_apply(&self, _resource: &Resource, _step: &Step, _ctx: &ApplyContext) -> Result<Json> {
        Ok(json!({ "previous": self.state.lock().unwrap().clone() }))
    }

    fn apply(&self, resource: &Resource, _step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        *self.apply_calls.lock().unwrap() += 1;
        if let Some(err) = self.fail_apply.lock().unwrap().take() {
            return Ok(StepResult::failed(err));
        }
        let want = resource.spec.as_str().unwrap_or("").to_string();
        *self.state.lock().unwrap() = Some(want);
        Ok(StepResult::ok("set"))
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        if *self.fail_verify.lock().unwrap() {
            return Ok(VerifyOutcome::Mismatch(vec![FieldChange {
                field: "value".into(),
                from: None,
                to: None,
                sensitive: false,
            }]));
        }
        let want = resource.spec.as_str().unwrap_or("").to_string();
        let have = self.state.lock().unwrap().clone().unwrap_or_default();
        if want == have {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Mismatch(vec![]))
        }
    }

    fn rollback(
        &self,
        _resource: &Resource,
        checkpoint: &crate::operation::Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        *self.rollback_calls.lock().unwrap() += 1;
        let prev = checkpoint
            .data
            .get("previous")
            .and_then(|v| {
                if v.is_null() {
                    Some(None)
                } else {
                    v.as_str().map(|s| Some(s.to_string()))
                }
            })
            .unwrap_or(None);
        *self.state.lock().unwrap() = prev;
        Ok(())
    }
}

fn mk_resource(name: &str, value: &str) -> Resource {
    Resource {
        api_version: API_VERSION.into(),
        kind: "fake".into(),
        metadata: Metadata {
            name: name.into(),
            environment: "test".into(),
            owner: None,
            labels: Default::default(),
            annotations: Default::default(),
        },
        spec: YamlValue::String(value.into()),
        policy: YamlValue::Null,
        source: SourceLocation::default(),
    }
}

fn make_registry() -> ProviderRegistry {
    let mut r = ProviderRegistry::new();
    r.register(Box::new(FakeProvider::default()));
    r
}

#[test]
fn plan_reports_create_for_absent_resource() {
    let reg = make_registry();
    let dir = TempDir::new().unwrap();
    let exec = Executor::new(&reg, dir.path().into(), "test");
    let resources = vec![mk_resource("a", "hello")];
    let plan = exec.plan(&resources).unwrap();
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].diff.kind, DiffKind::Create);
    assert_eq!(plan.change_count(), 1);
}

#[test]
fn apply_then_replan_is_no_change() {
    let reg = make_registry();
    let dir = TempDir::new().unwrap();
    let exec = Executor::new(&reg, dir.path().into(), "test");
    let resources = vec![mk_resource("a", "hello")];

    let result = exec.apply(&resources).unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].status, ItemStatus::Succeeded);
    assert_eq!(result.operation.status, OperationStatus::Succeeded);

    // Re-plan is no-change.
    let plan = exec.plan(&resources).unwrap();
    assert_eq!(plan.change_count(), 0);

    // Applied state was persisted.
    let applied = dir
        .path()
        .join("applied")
        .join(format!("{}.json", resources[0].id().fs_key()));
    assert!(applied.exists());
}

#[test]
fn apply_records_failure_and_partial_status() {
    // Two resources: the first fails, the second succeeds. Status should be PartiallyApplied.
    let mut reg = ProviderRegistry::new();
    let prov = FakeProvider::default();
    *prov.fail_apply.lock().unwrap() = Some("boom".into());
    reg.register(Box::new(prov));

    let dir = TempDir::new().unwrap();
    let exec = Executor::new(&reg, dir.path().into(), "test");

    let resources = vec![mk_resource("a", "v1"), mk_resource("b", "v2")];
    let result = exec.apply(&resources).unwrap();
    assert_eq!(result.items[0].status, ItemStatus::Failed);
    assert_eq!(result.items[1].status, ItemStatus::Succeeded);
    assert_eq!(result.operation.status, OperationStatus::PartiallyApplied);
    assert!(result.items[0].error.as_deref().unwrap().contains("boom"));
}

#[test]
fn rollback_restores_previous_state() {
    let mut reg = ProviderRegistry::new();
    reg.register(Box::new(FakeProvider::default()));

    let dir = TempDir::new().unwrap();
    let exec = Executor::new(&reg, dir.path().into(), "test");
    let resources = vec![mk_resource("a", "first")];

    let r1 = exec.apply(&resources).unwrap();
    let op_id = r1.operation.id;

    // Now change desired and apply again.
    let resources2 = vec![mk_resource("a", "second")];
    exec.apply(&resources2).unwrap();
    {
        let prov = reg.get("fake").unwrap();
        // Cast back via observe to read current state through provider API.
        let observed = prov.observe(&resources2[0]).unwrap();
        assert_eq!(observed.spec.as_str(), Some("second"));
    }

    // Rollback the FIRST operation: that brings state back to absent (its checkpoint
    // recorded `previous: null`).
    exec.rollback(op_id).unwrap();
    let prov = reg.get("fake").unwrap();
    let observed = prov.observe(&resources2[0]).unwrap();
    assert!(!observed.present);
}
