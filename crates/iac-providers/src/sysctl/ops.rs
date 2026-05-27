//! Phase 7cb: sysctl ops — observe / diff / plan / apply / rollback.
//!
//! v1 ships only Present semantics: declare a kernel parameter must
//! equal a value. apply writes if drift; pre_apply captures the
//! previous value for rollback. Reverting via Absent state needs an
//! ApplyContext-carried checkpoint that doesn't exist in v1; deferred.

use super::backend::{SysctlBackend, read_current};
use super::spec::SysctlSettingSpec;
use iac_core::{
    Result,
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn SysctlBackend, spec: &SysctlSettingSpec) -> Result<ObservedState> {
    let current = read_current(backend, spec)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    let mut spec_value = Mapping::new();
    spec_value.insert("key".into(), YamlValue::String(spec.key.clone()));

    match current {
        None => {
            facts.insert("exists".into(), YamlValue::Bool(false));
            Ok(ObservedState {
                present: false,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        Some(value) => {
            facts.insert("exists".into(), YamlValue::Bool(true));
            facts.insert("value".into(), YamlValue::String(value.clone()));
            spec_value.insert("value".into(), YamlValue::String(value));
            Ok(ObservedState {
                present: true,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
    }
}

pub fn diff(spec: &SysctlSettingSpec, observed: &ObservedState) -> Diff {
    let exists = observed
        .facts
        .get("exists")
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);
    let observed_value = observed
        .facts
        .get("value")
        .and_then(YamlValue::as_str)
        .map(str::to_string);

    if !exists {
        return Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "exists".into(),
                from: Some(YamlValue::Bool(false)),
                to: Some(YamlValue::Bool(true)),
                sensitive: false,
            }],
            reasons: vec![format!(
                "kernel parameter {} not present on this system",
                spec.key
            )],
            reversible: false,
        };
    }

    if observed_value.as_deref() == Some(spec.value.as_str()) {
        Diff::no_change()
    } else {
        Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "value".into(),
                from: observed_value.clone().map(YamlValue::String),
                to: Some(YamlValue::String(spec.value.clone())),
                sensitive: false,
            }],
            reasons: vec![format!(
                "{} {:?} -> {:?}",
                spec.key,
                observed_value.as_deref().unwrap_or(""),
                spec.value
            )],
            reversible: true,
        }
    }
}

pub fn plan(spec: &SysctlSettingSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    vec![Step::new(
        super::SysctlAction::Set.as_str(),
        format!("sysctl.setting/{}", spec.key),
        json!({ "key": spec.key }),
    )]
}

pub fn pre_apply(backend: &dyn SysctlBackend, spec: &SysctlSettingSpec) -> Result<Json> {
    // Capture current value as the rollback target. Stored in the
    // checkpoint for rollback() to read later.
    let current = read_current(backend, spec)?;
    Ok(json!({ "previous_value": current }))
}

pub fn apply(
    backend: &dyn SysctlBackend,
    spec: &SysctlSettingSpec,
    step: &Step,
) -> Result<StepResult> {
    // Single-action provider: parse for compile-time exhaustiveness.
    let _ = super::SysctlAction::parse(&step.action)?;
    let path = spec.proc_path();
    backend.write(&path, &spec.value)?;
    Ok(StepResult::ok(format!(
        "set {} = {:?}",
        spec.key, spec.value
    )))
}

pub fn rollback(
    backend: &dyn SysctlBackend,
    spec: &SysctlSettingSpec,
    checkpoint: &Json,
) -> Result<()> {
    let prev = checkpoint
        .get("previous_value")
        .and_then(|v| if v.is_null() { None } else { Some(v) })
        .and_then(Json::as_str);
    let path = spec.proc_path();
    match prev {
        Some(p) => {
            backend.write(&path, p)?;
            Ok(())
        }
        None => {
            // Checkpoint has no previous value — typically means
            // pre_apply ran when the parameter didn't exist. Nothing
            // sensible to roll back to; succeed silently.
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockSysctl;
    use super::*;

    fn spec(key: &str, value: &str) -> SysctlSettingSpec {
        SysctlSettingSpec {
            key: key.into(),
            value: value.into(),
            state: super::super::spec::SysctlState::Present,
        }
    }

    #[test]
    fn observe_returns_value_from_backend() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "1");
        let s = spec("net.ipv4.ip_forward", "1");
        let obs = observe(&backend, &s).unwrap();
        assert!(obs.present);
        assert_eq!(
            obs.facts.get("value").and_then(YamlValue::as_str),
            Some("1")
        );
    }

    #[test]
    fn observe_strict_missing_path_reports_not_present() {
        let backend = MockSysctl::new();
        backend.set_strict(true);
        let s = spec("net.does.not.exist", "1");
        let obs = observe(&backend, &s).unwrap();
        assert!(!obs.present);
        assert_eq!(
            obs.facts.get("exists").and_then(YamlValue::as_bool),
            Some(false)
        );
    }

    #[test]
    fn diff_no_change_when_already_matches() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "1");
        let s = spec("net.ipv4.ip_forward", "1");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert!(!d.is_change());
    }

    #[test]
    fn diff_update_when_value_differs() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "0");
        let s = spec("net.ipv4.ip_forward", "1");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.changes.iter().any(|c| c.field == "value"));
    }

    #[test]
    fn diff_update_when_path_missing() {
        let backend = MockSysctl::new();
        backend.set_strict(true);
        let s = spec("net.bogus.param", "1");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.reasons[0].contains("not present"));
        assert!(!d.reversible, "missing path is not reversibly fixable");
    }

    #[test]
    fn apply_writes_via_backend() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "0");
        let s = spec("net.ipv4.ip_forward", "1");
        let step = Step::new("sysctl.set", format!("sysctl.setting/{}", s.key), json!({}));
        apply(&backend, &s, &step).unwrap();
        assert_eq!(
            backend.current("/proc/sys/net/ipv4/ip_forward").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn pre_apply_captures_current_value() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "0");
        let s = spec("net.ipv4.ip_forward", "1");
        let cp = pre_apply(&backend, &s).unwrap();
        assert_eq!(cp["previous_value"], "0");
    }

    #[test]
    fn rollback_restores_previous_value() {
        let backend = MockSysctl::new();
        backend.seed("/proc/sys/net/ipv4/ip_forward", "0");
        let s = spec("net.ipv4.ip_forward", "1");
        let cp = pre_apply(&backend, &s).unwrap();

        // Apply changes value to 1.
        let step = Step::new("sysctl.set", "x".to_string(), json!({}));
        apply(&backend, &s, &step).unwrap();
        assert_eq!(
            backend.current("/proc/sys/net/ipv4/ip_forward").as_deref(),
            Some("1")
        );

        // Rollback restores the captured 0.
        rollback(&backend, &s, &cp).unwrap();
        assert_eq!(
            backend.current("/proc/sys/net/ipv4/ip_forward").as_deref(),
            Some("0")
        );
    }

    #[test]
    fn rollback_with_no_previous_is_noop() {
        let backend = MockSysctl::new();
        let s = spec("net.bogus", "1");
        rollback(&backend, &s, &json!({})).unwrap();
        // Nothing was written.
        assert!(backend.writes().is_empty());
    }

    #[test]
    fn plan_emits_set_step() {
        let s = spec("a.b", "1");
        let d = Diff {
            kind: DiffKind::Update,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        };
        let steps = plan(&s, &d);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "sysctl.set");
    }

    #[test]
    fn unknown_action_errors() {
        let backend = MockSysctl::new();
        let s = spec("a.b", "1");
        let step = Step::new("bogus.action", "x".to_string(), json!({}));
        let err = apply(&backend, &s, &step).unwrap_err();
        // Phase 7cz.20: error now comes from the typed-action parser.
        assert!(err.to_string().contains("unknown step action"));
    }
}
