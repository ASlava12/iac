use super::backend::NginxBackend;
use super::render;
use super::spec::{NginxState, NginxVhostSpec};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    hash::sha256_hex,
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn NginxBackend, spec: &NginxVhostSpec) -> Result<ObservedState> {
    let content = backend.read_config(&spec.config_path)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    match content {
        Some(text) => {
            let sha = sha256_hex(text.as_bytes());
            facts.insert("present".into(), YamlValue::Bool(true));
            facts.insert("content_sha256".into(), YamlValue::String(sha.clone()));
            facts.insert("size".into(), YamlValue::Number(serde_yaml_ng::Number::from(text.len() as u64)));
            let mut spec_value = Mapping::new();
            spec_value.insert("config_path".into(), YamlValue::String(spec.config_path.display().to_string()));
            spec_value.insert("content_sha256".into(), YamlValue::String(sha));
            Ok(ObservedState {
                present: true,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        None => {
            facts.insert("present".into(), YamlValue::Bool(false));
            Ok(ObservedState {
                present: false,
                spec: YamlValue::Null,
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
    }
}

pub fn diff(spec: &NginxVhostSpec, observed: &ObservedState) -> Diff {
    match (spec.state, observed.present) {
        (NginxState::Absent, false) => Diff::no_change(),
        (NginxState::Absent, true) => Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "state".into(),
                from: Some(YamlValue::String("present".into())),
                to: Some(YamlValue::String("absent".into())),
                sensitive: false,
            }],
            reasons: vec![format!("remove {}", spec.config_path.display())],
            reversible: true,
        },
        (NginxState::Present, false) => Diff {
            kind: DiffKind::Create,
            changes: vec![FieldChange {
                field: "state".into(),
                from: Some(YamlValue::String("absent".into())),
                to: Some(YamlValue::String("present".into())),
                sensitive: false,
            }],
            reasons: vec![format!("create {}", spec.config_path.display())],
            reversible: true,
        },
        (NginxState::Present, true) => {
            let desired_sha = sha256_hex(render::render(spec).as_bytes());
            let observed_sha = observed
                .facts
                .get("content_sha256")
                .and_then(YamlValue::as_str)
                .unwrap_or("")
                .to_string();
            if desired_sha == observed_sha {
                Diff::no_change()
            } else {
                Diff {
                    kind: DiffKind::Update,
                    changes: vec![FieldChange {
                        field: "content_sha256".into(),
                        from: Some(YamlValue::String(observed_sha)),
                        to: Some(YamlValue::String(desired_sha)),
                        sensitive: false,
                    }],
                    reasons: vec!["rendered config differs".into()],
                    reversible: true,
                }
            }
        }
    }
}

pub fn plan(spec: &NginxVhostSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return vec![];
    }
    match spec.state {
        NginxState::Present => vec![Step::new(
            super::NginxAction::Write.as_str(),
            format!("write {}", spec.config_path.display()),
            json!({ "path": spec.config_path }),
        )],
        NginxState::Absent => vec![Step::new(
            super::NginxAction::Remove.as_str(),
            format!("remove {}", spec.config_path.display()),
            json!({ "path": spec.config_path }),
        )],
    }
}

pub fn pre_apply(backend: &dyn NginxBackend, spec: &NginxVhostSpec) -> Result<Json> {
    let content = backend.read_config(&spec.config_path)?;
    Ok(match content {
        Some(text) => json!({
            "path": spec.config_path,
            "existed": true,
            "content": text,
        }),
        None => json!({
            "path": spec.config_path,
            "existed": false,
        }),
    })
}

/// Apply with strict atomicity: write the new config, run `nginx -t`, and
/// only reload on success. If validation fails, restore the previous
/// content (or remove the file if it didn't exist) before returning the
/// error so the on-disk state matches the pre-apply checkpoint.
pub fn apply(
    backend: &dyn NginxBackend,
    spec: &NginxVhostSpec,
    step: &Step,
    checkpoint: &Json,
) -> Result<StepResult> {
    match super::NginxAction::parse(&step.action)? {
        super::NginxAction::Write => {
            let content = render::render(spec);
            backend.write_config(&spec.config_path, &content)?;
            if let Err(e) = backend.validate() {
                restore(backend, &spec.config_path, checkpoint)?;
                return Err(Error::provider(
                    "nginx",
                    format!("nginx -t rejected the rendered config; restored: {e}"),
                ));
            }
            backend.reload()?;
            Ok(StepResult {
                status: iac_core::operation::StepStatus::Succeeded,
                message: format!("wrote and reloaded {}", spec.config_path.display()),
                data: json!({
                    "path": spec.config_path,
                    "bytes": content.len(),
                    "content_sha256": sha256_hex(content.as_bytes()),
                }),
                error: None,
            })
        }
        super::NginxAction::Remove => {
            backend.remove_config(&spec.config_path)?;
            // Validate after removal too — sometimes a removal leaves dangling
            // includes in nginx.conf and we'd rather catch that here than via
            // a failed reload.
            if let Err(e) = backend.validate() {
                restore(backend, &spec.config_path, checkpoint)?;
                return Err(Error::provider(
                    "nginx",
                    format!("nginx -t rejected the post-removal state; restored: {e}"),
                ));
            }
            backend.reload()?;
            Ok(StepResult::ok(format!("removed and reloaded {}", spec.config_path.display())))
        }
    }
}

fn restore(backend: &dyn NginxBackend, path: &std::path::Path, checkpoint: &Json) -> Result<()> {
    let existed = checkpoint.get("existed").and_then(Json::as_bool).unwrap_or(false);
    if existed {
        if let Some(content) = checkpoint.get("content").and_then(Json::as_str) {
            backend.write_config(path, content)?;
        }
    } else {
        backend.remove_config(path)?;
    }
    Ok(())
}

pub fn rollback(
    backend: &dyn NginxBackend,
    spec: &NginxVhostSpec,
    checkpoint: &Json,
) -> Result<()> {
    restore(backend, &spec.config_path, checkpoint)?;
    // Best-effort reload after rollback. If validate fails we surface it
    // but the file was already restored, so the caller can intervene.
    backend.validate()?;
    backend.reload()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockNginx;
    use super::super::spec::{NginxState, NginxVhostSpec};
    use super::*;
    use iac_core::operation::StepStatus;
    use std::path::PathBuf;

    fn base() -> NginxVhostSpec {
        NginxVhostSpec {
            config_path: PathBuf::from("/etc/nginx/conf.d/app.conf"),
            state: NginxState::Present,
            server_names: vec!["app.example.com".into()],
            listen: vec![80],
            upstream: Some("http://127.0.0.1:8080".into()),
            client_max_body_size: None,
            proxy_read_timeout: None,
            tls: None,
            extra_locations: vec![],
        }
    }

    #[test]
    fn create_when_absent() {
        let backend = MockNginx::new();
        let spec = base();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Create);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();
        let r = apply(&backend, &spec, &steps[0], &cp).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        // validate + reload were called.
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("validate")));
        assert!(calls.iter().any(|c| c.starts_with("reload")));
    }

    #[test]
    fn idempotent_when_content_matches() {
        let backend = MockNginx::new();
        let spec = base();
        // Pre-seed the backend with the rendered config.
        backend
            .configs
            .lock()
            .unwrap()
            .insert(spec.config_path.clone(), super::super::render::render(&spec));
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::NoChange);
    }

    #[test]
    fn validate_failure_restores_previous_content() {
        let backend = MockNginx::new();
        // There is a previous config in place.
        let prev = "# old\nserver { listen 80; }\n".to_string();
        backend
            .configs
            .lock()
            .unwrap()
            .insert(PathBuf::from("/etc/nginx/conf.d/app.conf"), prev.clone());

        let spec = base();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();

        backend.fail_validate_once("invalid syntax");
        let err = apply(&backend, &spec, &steps[0], &cp).unwrap_err();
        assert!(err.to_string().contains("rejected"));

        // The restored content should be the previous one.
        let now =
            backend.configs.lock().unwrap().get(&spec.config_path).cloned().unwrap();
        assert_eq!(now, prev);
        // reload should NOT have been called.
        assert!(!backend.calls().iter().any(|c| c.starts_with("reload")));
    }

    #[test]
    fn validate_failure_for_create_removes_file() {
        let backend = MockNginx::new();
        let spec = base();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&backend, &spec).unwrap();

        backend.fail_validate_once("syntax");
        let err = apply(&backend, &spec, &steps[0], &cp).unwrap_err();
        assert!(err.to_string().contains("rejected"));

        // Since there was no previous content, the file should now be absent.
        assert!(backend.configs.lock().unwrap().get(&spec.config_path).is_none());
    }

    #[test]
    fn remove_when_present() {
        let backend = MockNginx::new();
        backend
            .configs
            .lock()
            .unwrap()
            .insert(PathBuf::from("/etc/nginx/conf.d/app.conf"), "old".into());
        let spec = NginxVhostSpec {
            state: NginxState::Absent,
            server_names: vec![],
            upstream: None,
            ..base()
        };
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        assert_eq!(steps[0].action, "nginx.remove");
        let cp = pre_apply(&backend, &spec).unwrap();
        let r = apply(&backend, &spec, &steps[0], &cp).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        assert!(backend.configs.lock().unwrap().get(&spec.config_path).is_none());
    }

    #[test]
    fn rollback_restores_and_reloads() {
        let backend = MockNginx::new();
        let prev = "# previous\n".to_string();
        backend
            .configs
            .lock()
            .unwrap()
            .insert(PathBuf::from("/etc/nginx/conf.d/app.conf"), prev.clone());
        let spec = base();
        let cp = pre_apply(&backend, &spec).unwrap();
        // Simulate an apply happened (write new content).
        backend.write_config(&spec.config_path, "# new\n").unwrap();
        // Rollback.
        rollback(&backend, &spec, &cp).unwrap();
        let now = backend.configs.lock().unwrap().get(&spec.config_path).cloned().unwrap();
        assert_eq!(now, prev);
    }

    #[test]
    fn rollback_when_no_previous_removes_file() {
        let backend = MockNginx::new();
        let spec = base();
        let cp = pre_apply(&backend, &spec).unwrap();
        backend.write_config(&spec.config_path, "# new\n").unwrap();
        rollback(&backend, &spec, &cp).unwrap();
        assert!(backend.configs.lock().unwrap().get(&spec.config_path).is_none());
    }
}
