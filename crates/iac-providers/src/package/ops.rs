use super::backend::{InstallStatus, PackageBackend};
use super::spec::{PackageSpec, PackageState};
use iac_core::{
    Error, Result,
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn PackageBackend, spec: &PackageSpec) -> Result<ObservedState> {
    let status = backend.query(&spec.name)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    match &status {
        InstallStatus::NotInstalled => {
            facts.insert("installed".into(), YamlValue::Bool(false));
            Ok(ObservedState {
                present: false,
                spec: YamlValue::Null,
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        InstallStatus::Installed {
            status: dpkg_status,
            version,
        } => {
            let installed = status.is_installed();
            facts.insert("installed".into(), YamlValue::Bool(installed));
            facts.insert("dpkg_status".into(), YamlValue::String(dpkg_status.clone()));
            facts.insert("version".into(), YamlValue::String(version.clone()));

            let mut spec_value = Mapping::new();
            spec_value.insert("name".into(), YamlValue::String(spec.name.clone()));
            spec_value.insert(
                "state".into(),
                YamlValue::String(if installed { "present" } else { "absent" }.into()),
            );
            spec_value.insert("version".into(), YamlValue::String(version.clone()));
            Ok(ObservedState {
                present: installed,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
    }
}

pub fn diff(spec: &PackageSpec, observed: &ObservedState) -> Diff {
    let installed = observed
        .facts
        .get("installed")
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);
    let observed_version = observed
        .facts
        .get("version")
        .and_then(YamlValue::as_str)
        .map(str::to_string);

    match (spec.state, installed) {
        (PackageState::Absent, false) => Diff::no_change(),
        (PackageState::Absent, true) => Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "installed".into(),
                from: Some(YamlValue::Bool(true)),
                to: Some(YamlValue::Bool(false)),
                sensitive: false,
            }],
            reasons: vec![format!("uninstall {}", spec.name)],
            reversible: true,
        },
        (PackageState::Present, false) => Diff {
            kind: DiffKind::Create,
            changes: vec![FieldChange {
                field: "installed".into(),
                from: Some(YamlValue::Bool(false)),
                to: Some(YamlValue::Bool(true)),
                sensitive: false,
            }],
            reasons: vec![format!("install {}", spec.name)],
            reversible: true,
        },
        (PackageState::Present, true) => {
            // Already installed. Check version pin if present.
            if let Some(pin) = &spec.version {
                let observed_version = observed_version.as_deref().unwrap_or("");
                if observed_version != pin {
                    return Diff {
                        kind: DiffKind::Update,
                        changes: vec![FieldChange {
                            field: "version".into(),
                            from: Some(YamlValue::String(observed_version.into())),
                            to: Some(YamlValue::String(pin.clone())),
                            sensitive: false,
                        }],
                        reasons: vec![format!("version pin {observed_version} -> {pin}")],
                        reversible: true,
                    };
                }
            }
            Diff::no_change()
        }
    }
}

pub fn plan(spec: &PackageSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return vec![];
    }
    match spec.state {
        PackageState::Present => vec![Step::new(
            super::PackageAction::Install.as_str(),
            format!("install {}", spec.name),
            json!({
                "name": spec.name,
                "version": spec.version,
            }),
        )],
        PackageState::Absent => vec![Step::new(
            super::PackageAction::Remove.as_str(),
            format!("remove {}", spec.name),
            json!({ "name": spec.name }),
        )],
    }
}

pub fn pre_apply(backend: &dyn PackageBackend, spec: &PackageSpec) -> Result<Json> {
    let status = backend.query(&spec.name)?;
    Ok(match status {
        InstallStatus::NotInstalled => json!({
            "name": spec.name,
            "previous_installed": false,
            "previous_version": null,
        }),
        InstallStatus::Installed { version, .. } => json!({
            "name": spec.name,
            "previous_installed": true,
            "previous_version": version,
        }),
    })
}

pub fn apply(backend: &dyn PackageBackend, step: &Step) -> Result<StepResult> {
    let name = step
        .payload
        .get("name")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::provider("package", "step payload missing 'name'"))?;
    match super::PackageAction::parse(&step.action)? {
        super::PackageAction::Install => {
            let version = step.payload.get("version").and_then(Json::as_str);
            backend.install(name, version)?;
            Ok(StepResult::ok(format!("installed {name}")))
        }
        super::PackageAction::Remove => {
            backend.remove(name)?;
            Ok(StepResult::ok(format!("removed {name}")))
        }
    }
}

pub fn rollback(backend: &dyn PackageBackend, checkpoint: &Json) -> Result<()> {
    let name = checkpoint
        .get("name")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::provider("package", "checkpoint missing 'name'"))?;
    let prev_installed = checkpoint
        .get("previous_installed")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    let prev_version = checkpoint.get("previous_version").and_then(Json::as_str);

    let cur = backend.query(name)?;
    match (cur.is_installed(), prev_installed) {
        (true, true) => {
            // Reinstall pinned version if it differed.
            if let Some(prev_v) = prev_version
                && cur.version() != Some(prev_v)
            {
                backend.install(name, Some(prev_v))?;
            }
        }
        (true, false) => backend.remove(name)?,
        (false, true) => backend.install(name, prev_version)?,
        (false, false) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockPackageBackend;
    use super::*;
    use iac_core::operation::StepStatus;

    fn spec_install(name: &str) -> PackageSpec {
        PackageSpec {
            name: name.into(),
            state: PackageState::Present,
            version: None,
            backend: "apt".into(),
        }
    }

    #[test]
    fn install_when_absent() {
        let backend = MockPackageBackend::new();
        let spec = spec_install("nginx");
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Create);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();
        let r = apply(&backend, &steps[0]).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        assert!(backend.calls().contains(&"install nginx".to_string()));

        // Rollback should remove what we installed.
        rollback(&backend, &cp).unwrap();
        let after = backend.query("nginx").unwrap();
        assert!(!after.is_installed());
    }

    #[test]
    fn idempotent_when_present() {
        let backend = MockPackageBackend::new();
        backend.preinstall("nginx", "1.0");
        let spec = spec_install("nginx");
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::NoChange);
    }

    #[test]
    fn version_pin_drives_update() {
        let backend = MockPackageBackend::new();
        backend.preinstall("nginx", "1.0");
        let spec = PackageSpec {
            name: "nginx".into(),
            state: PackageState::Present,
            version: Some("2.0".into()),
            backend: "apt".into(),
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();
        apply(&backend, &steps[0]).unwrap();
        assert_eq!(backend.query("nginx").unwrap().version(), Some("2.0"));
        // Rollback to 1.0.
        rollback(&backend, &cp).unwrap();
        assert_eq!(backend.query("nginx").unwrap().version(), Some("1.0"));
    }

    #[test]
    fn remove_when_present() {
        let backend = MockPackageBackend::new();
        backend.preinstall("nginx", "1.0");
        let spec = PackageSpec {
            name: "nginx".into(),
            state: PackageState::Absent,
            version: None,
            backend: "apt".into(),
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();
        apply(&backend, &steps[0]).unwrap();
        assert!(!backend.query("nginx").unwrap().is_installed());
        // Rollback to installed.
        rollback(&backend, &cp).unwrap();
        let q = backend.query("nginx").unwrap();
        assert!(q.is_installed());
        assert_eq!(q.version(), Some("1.0"));
    }
}
