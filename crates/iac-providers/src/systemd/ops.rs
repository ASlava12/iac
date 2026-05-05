use super::backend::{Systemctl, UnitInfo};
use super::spec::SystemdUnitSpec;
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn Systemctl, spec: &SystemdUnitSpec) -> Result<ObservedState> {
    let unit = spec.unit_name();
    let info = backend.show(&unit)?;
    Ok(observation_from_info(&unit, &info))
}

fn observation_from_info(unit: &str, info: &UnitInfo) -> ObservedState {
    let mut spec_value = Mapping::new();
    spec_value.insert("name".into(), YamlValue::String(unit.to_string()));
    spec_value.insert("active".into(), YamlValue::Bool(info.is_active()));
    spec_value.insert("enabled".into(), YamlValue::Bool(info.is_enabled()));

    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    facts.insert("load_state".into(), YamlValue::String(info.load_state.clone()));
    facts.insert("active_state".into(), YamlValue::String(info.active_state.clone()));
    facts.insert("sub_state".into(), YamlValue::String(info.sub_state.clone()));
    facts.insert("unit_file_state".into(), YamlValue::String(info.unit_file_state.clone()));
    facts.insert("masked".into(), YamlValue::Bool(info.is_masked()));
    facts.insert("static".into(), YamlValue::Bool(info.is_static()));

    let present = info.is_loaded();

    ObservedState {
        present,
        spec: if present { YamlValue::Mapping(spec_value) } else { YamlValue::Null },
        facts,
        observed_at: jiff::Timestamp::now(),
    }
}

pub fn diff(spec: &SystemdUnitSpec, observed: &ObservedState) -> Diff {
    let masked = observed.facts.get("masked").and_then(YamlValue::as_bool).unwrap_or(false);
    if masked {
        return Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "masked".into(),
                from: Some(YamlValue::Bool(true)),
                to: Some(YamlValue::Bool(false)),
                sensitive: false,
            }],
            reasons: vec!["unit is masked; refusing to manage".into()],
            reversible: false,
        };
    }
    if !observed.present {
        return Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "load_state".into(),
                from: observed.facts.get("load_state").cloned(),
                to: Some(YamlValue::String("loaded".into())),
                sensitive: false,
            }],
            reasons: vec!["unit is not loaded; install the unit file first".into()],
            reversible: false,
        };
    }

    let mut changes: Vec<FieldChange> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let observed_active = observed
        .spec
        .as_mapping()
        .and_then(|m| m.get(YamlValue::String("active".into())))
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);
    let observed_enabled = observed
        .spec
        .as_mapping()
        .and_then(|m| m.get(YamlValue::String("enabled".into())))
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);
    let is_static = observed.facts.get("static").and_then(YamlValue::as_bool).unwrap_or(false);

    if spec.enabled != observed_enabled {
        if is_static && spec.enabled != observed_enabled {
            reasons.push("unit is static; cannot toggle enabled state".into());
        } else {
            changes.push(FieldChange {
                field: "enabled".into(),
                from: Some(YamlValue::Bool(observed_enabled)),
                to: Some(YamlValue::Bool(spec.enabled)),
                sensitive: false,
            });
            reasons.push(format!("enabled {observed_enabled} -> {}", spec.enabled));
        }
    }
    if spec.active != observed_active {
        changes.push(FieldChange {
            field: "active".into(),
            from: Some(YamlValue::Bool(observed_active)),
            to: Some(YamlValue::Bool(spec.active)),
            sensitive: false,
        });
        reasons.push(format!("active {observed_active} -> {}", spec.active));
    }

    if changes.is_empty() {
        Diff::no_change()
    } else {
        Diff { kind: DiffKind::Update, changes, reasons, reversible: true }
    }
}

pub fn plan(spec: &SystemdUnitSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return vec![];
    }
    let unit = spec.unit_name();
    let mut steps: Vec<Step> = Vec::new();

    let want_enabled = changed_to_bool(diff, "enabled");
    let want_active = changed_to_bool(diff, "active");

    // Order: enable before start, stop before disable.
    if matches!(want_enabled, Some(true)) {
        steps.push(Step::new(
            super::SystemdAction::Enable.as_str(),
            format!("enable {unit}"),
            json!({ "unit": unit }),
        ));
    }
    if matches!(want_active, Some(true)) {
        steps.push(Step::new(
            super::SystemdAction::Start.as_str(),
            format!("start {unit}"),
            json!({ "unit": unit }),
        ));
    }
    if matches!(want_active, Some(false)) {
        steps.push(Step::new(
            super::SystemdAction::Stop.as_str(),
            format!("stop {unit}"),
            json!({ "unit": unit }),
        ));
    }
    if matches!(want_enabled, Some(false)) {
        steps.push(Step::new(
            super::SystemdAction::Disable.as_str(),
            format!("disable {unit}"),
            json!({ "unit": unit }),
        ));
    }

    steps
}

fn changed_to_bool(diff: &Diff, field: &str) -> Option<bool> {
    diff.changes
        .iter()
        .find(|c| c.field == field)
        .and_then(|c| c.to.as_ref())
        .and_then(YamlValue::as_bool)
}

pub fn pre_apply(backend: &dyn Systemctl, spec: &SystemdUnitSpec) -> Result<Json> {
    let info = backend.show(&spec.unit_name())?;
    Ok(json!({
        "unit": spec.unit_name(),
        "previous_active": info.is_active(),
        "previous_enabled": info.is_enabled(),
    }))
}

pub fn apply(backend: &dyn Systemctl, step: &Step) -> Result<StepResult> {
    let unit = step
        .payload
        .get("unit")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::provider("systemd", "step payload missing 'unit'"))?;
    match super::SystemdAction::parse(&step.action)? {
        super::SystemdAction::Enable => {
            backend.enable(unit)?;
            Ok(StepResult::ok(format!("enabled {unit}")))
        }
        super::SystemdAction::Disable => {
            backend.disable(unit)?;
            Ok(StepResult::ok(format!("disabled {unit}")))
        }
        super::SystemdAction::Start => {
            backend.start(unit)?;
            Ok(StepResult::ok(format!("started {unit}")))
        }
        super::SystemdAction::Stop => {
            backend.stop(unit)?;
            Ok(StepResult::ok(format!("stopped {unit}")))
        }
        super::SystemdAction::Restart => {
            backend.restart(unit)?;
            Ok(StepResult::ok(format!("restarted {unit}")))
        }
        super::SystemdAction::Reload => {
            backend.reload(unit)?;
            Ok(StepResult::ok(format!("reloaded {unit}")))
        }
    }
}

pub fn rollback(backend: &dyn Systemctl, checkpoint: &Json) -> Result<()> {
    let unit = checkpoint
        .get("unit")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::provider("systemd", "checkpoint missing 'unit'"))?;
    let prev_active = checkpoint.get("previous_active").and_then(Json::as_bool).unwrap_or(false);
    let prev_enabled = checkpoint.get("previous_enabled").and_then(Json::as_bool).unwrap_or(false);

    let cur = backend.show(unit)?;

    if cur.is_enabled() && !prev_enabled {
        backend.disable(unit)?;
    } else if !cur.is_enabled() && prev_enabled {
        backend.enable(unit)?;
    }
    if cur.is_active() && !prev_active {
        backend.stop(unit)?;
    } else if !cur.is_active() && prev_active {
        backend.start(unit)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::backend::{MockSystemctl, UnitInfo};
    use iac_core::operation::StepStatus;

    fn info(load: &str, active: &str, ufs: &str) -> UnitInfo {
        UnitInfo {
            load_state: load.into(),
            active_state: active.into(),
            sub_state: "running".into(),
            unit_file_state: ufs.into(),
        }
    }

    #[test]
    fn diff_when_already_correct() {
        let backend = MockSystemctl::new();
        backend.insert("nginx.service", info("loaded", "active", "enabled"));
        let spec = SystemdUnitSpec {
            name: "nginx".into(),
            unit_type: super::super::spec::UnitType::Service,
            enabled: true,
            active: true,
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::NoChange);
    }

    #[test]
    fn diff_and_plan_enable_and_start() {
        let backend = MockSystemctl::new();
        backend.insert("nginx.service", info("loaded", "inactive", "disabled"));
        let spec = SystemdUnitSpec {
            name: "nginx".into(),
            unit_type: super::super::spec::UnitType::Service,
            enabled: true,
            active: true,
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        let actions: Vec<_> = steps.iter().map(|s| s.action.as_str()).collect();
        assert_eq!(actions, vec!["systemd.enable", "systemd.start"]);
    }

    #[test]
    fn diff_and_plan_stop_and_disable_in_correct_order() {
        let backend = MockSystemctl::new();
        backend.insert("nginx.service", info("loaded", "active", "enabled"));
        let spec = SystemdUnitSpec {
            name: "nginx".into(),
            unit_type: super::super::spec::UnitType::Service,
            enabled: false,
            active: false,
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        let actions: Vec<_> = steps.iter().map(|s| s.action.as_str()).collect();
        assert_eq!(actions, vec!["systemd.stop", "systemd.disable"]);
    }

    #[test]
    fn apply_enable_then_start_round_trip() {
        let backend = MockSystemctl::new();
        backend.insert("nginx.service", info("loaded", "inactive", "disabled"));
        let spec = SystemdUnitSpec {
            name: "nginx".into(),
            unit_type: super::super::spec::UnitType::Service,
            enabled: true,
            active: true,
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();
        for s in &steps {
            let r = apply(&backend, s).unwrap();
            assert_eq!(r.status, StepStatus::Succeeded);
        }
        // Verify by re-observing.
        let observed2 = observe(&backend, &spec).unwrap();
        let d2 = diff(&spec, &observed2);
        assert_eq!(d2.kind, DiffKind::NoChange);

        // Rollback.
        rollback(&backend, &cp).unwrap();
        let observed3 = observe(&backend, &spec).unwrap();
        assert_eq!(
            observed3.facts.get("active_state").and_then(YamlValue::as_str),
            Some("inactive")
        );
        assert_eq!(
            observed3.facts.get("unit_file_state").and_then(YamlValue::as_str),
            Some("disabled")
        );
    }

    #[test]
    fn masked_unit_refuses_management() {
        let backend = MockSystemctl::new();
        backend.insert("nginx.service", info("masked", "inactive", "masked"));
        let spec = SystemdUnitSpec {
            name: "nginx".into(),
            unit_type: super::super::spec::UnitType::Service,
            enabled: true,
            active: true,
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(!d.reversible);
        assert!(d.reasons.iter().any(|r| r.contains("masked")));
    }
}

