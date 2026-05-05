//! Phase 7cw: lifecycle implementation for `docker.compose`.
//!
//! Stack-as-resource approach: we track the project as a single entity.
//! Drift sources:
//!   * No containers exist for this project → re-up.
//!   * On-disk compose file's sha256 != the spec's source sha256 → re-up.
//!   * The spec says `state: absent` but services still exist → down.
//!
//! Per-service drift (e.g. an operator manually `docker rm`'d one service
//! out of three) is detected via the "no containers" path — the operator
//! gets a re-up that brings everything back into sync.

use super::backend::{ComposeBackend, ComposeService};
use super::spec::{ComposeState, DockerComposeSpec};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::Value as YamlValue;
use std::path::Path;

pub fn observe(backend: &dyn ComposeBackend, spec: &DockerComposeSpec) -> Result<ObservedState> {
    let services = backend.list_services(&spec.project)?;
    let on_disk_sha = read_sha256_of_file(&spec.compose_file());
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    facts.insert(
        "service_count".into(),
        YamlValue::Number((services.len() as u64).into()),
    );
    facts.insert(
        "on_disk_sha256".into(),
        match &on_disk_sha {
            Some(s) => YamlValue::String(s.clone()),
            None => YamlValue::Null,
        },
    );
    facts.insert(
        "running_count".into(),
        YamlValue::Number(
            (services.iter().filter(|s| s.state == "running").count() as u64).into(),
        ),
    );
    let present = !services.is_empty();
    Ok(ObservedState {
        present,
        spec: services_to_yaml(&services),
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

fn services_to_yaml(services: &[ComposeService]) -> YamlValue {
    let mut seq = Vec::with_capacity(services.len());
    for s in services {
        let mut m = serde_yaml_ng::Mapping::new();
        m.insert("name".into(), YamlValue::String(s.name.clone()));
        m.insert("state".into(), YamlValue::String(s.state.clone()));
        m.insert("image".into(), YamlValue::String(s.image.clone()));
        seq.push(YamlValue::Mapping(m));
    }
    YamlValue::Sequence(seq)
}

fn read_sha256_of_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(iac_core::hash::sha256_hex(&bytes))
}

pub fn diff(spec: &DockerComposeSpec, observed: &ObservedState) -> Result<Diff> {
    let observed_sha = observed
        .facts
        .get("on_disk_sha256")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let services_present = observed.present;
    match spec.state {
        ComposeState::Absent => {
            if !services_present {
                Ok(Diff::no_change())
            } else {
                Ok(Diff {
                    kind: DiffKind::Update,
                    changes: vec![FieldChange {
                        field: "state".into(),
                        from: Some(YamlValue::String("present".into())),
                        to: Some(YamlValue::String("absent".into())),
                        sensitive: false,
                    }],
                    reasons: vec![format!("tear down compose project {}", spec.project)],
                    reversible: false,
                })
            }
        }
        ComposeState::Present => {
            let desired_sha = spec.source_sha256();
            if !services_present {
                return Ok(Diff {
                    kind: DiffKind::Create,
                    changes: vec![FieldChange {
                        field: "state".into(),
                        from: Some(YamlValue::String("absent".into())),
                        to: Some(YamlValue::String("present".into())),
                        sensitive: false,
                    }],
                    reasons: vec![format!("bring up compose project {}", spec.project)],
                    reversible: true,
                });
            }
            if observed_sha.as_deref() != Some(desired_sha.as_str()) {
                return Ok(Diff {
                    kind: DiffKind::Update,
                    changes: vec![FieldChange {
                        field: "source_sha256".into(),
                        from: observed_sha.map(YamlValue::String),
                        to: Some(YamlValue::String(desired_sha)),
                        sensitive: false,
                    }],
                    reasons: vec![format!(
                        "compose source changed for project {}; recreating",
                        spec.project
                    )],
                    reversible: true,
                });
            }
            Ok(Diff::no_change())
        }
    }
}

pub fn plan(spec: &DockerComposeSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    let action = match spec.state {
        ComposeState::Present => super::ComposeAction::Up,
        ComposeState::Absent => super::ComposeAction::Down,
    };
    vec![Step::new(
        action.as_str(),
        format!("{action} project={}", spec.project),
        Json::Null,
    )]
}

pub fn pre_apply(
    backend: &dyn ComposeBackend,
    spec: &DockerComposeSpec,
) -> Result<Json> {
    // Snapshot what's currently on host for rollback.
    let services = backend.list_services(&spec.project)?;
    let on_disk_sha = read_sha256_of_file(&spec.compose_file());
    let prior_source = std::fs::read_to_string(spec.compose_file()).ok();
    Ok(json!({
        "service_count": services.len(),
        "running_count": services.iter().filter(|s| s.state == "running").count(),
        "on_disk_sha256": on_disk_sha,
        "prior_source": prior_source,
    }))
}

pub fn apply(
    backend: &dyn ComposeBackend,
    spec: &DockerComposeSpec,
    step: &Step,
) -> Result<StepResult> {
    match super::ComposeAction::parse(&step.action)? {
        super::ComposeAction::Up => {
            // Materialise the source to disk so the operator can also
            // run `docker compose ps -p <project>` from the same dir.
            let dir = spec.project_dir();
            std::fs::create_dir_all(&dir).map_err(|e| {
                Error::provider(
                    "docker.compose",
                    format!("create_dir_all {}: {e}", dir.display()),
                )
            })?;
            let file = spec.compose_file();
            let source = spec.source.as_deref().ok_or_else(|| {
                Error::provider("docker.compose", "compose-up requires source")
            })?;
            std::fs::write(&file, source).map_err(|e| {
                Error::provider(
                    "docker.compose",
                    format!("write {}: {e}", file.display()),
                )
            })?;
            backend.up(&spec.project, &file, spec.env_file.as_deref())?;
            Ok(StepResult::ok(format!(
                "compose-up project={}",
                spec.project
            )))
        }
        super::ComposeAction::Down => {
            let file = spec.compose_file();
            let file_arg = if file.exists() { Some(file.as_path()) } else { None };
            backend.down(&spec.project, file_arg)?;
            // Best-effort cleanup of the materialised compose dir; the
            // failure mode here is non-fatal — operator can rm it later.
            let _ = std::fs::remove_dir_all(spec.project_dir());
            Ok(StepResult::ok(format!(
                "compose-down project={}",
                spec.project
            )))
        }
    }
}

pub fn rollback(
    backend: &dyn ComposeBackend,
    spec: &DockerComposeSpec,
    checkpoint: &Json,
) -> Result<()> {
    let prior_source = checkpoint.get("prior_source").and_then(|v| v.as_str());
    match prior_source {
        Some(src) if !src.is_empty() => {
            // Re-materialise the prior compose file and re-up.
            let dir = spec.project_dir();
            std::fs::create_dir_all(&dir).map_err(|e| {
                Error::provider(
                    "docker.compose",
                    format!("rollback create_dir_all {}: {e}", dir.display()),
                )
            })?;
            let file = spec.compose_file();
            std::fs::write(&file, src).map_err(|e| {
                Error::provider(
                    "docker.compose",
                    format!("rollback write {}: {e}", file.display()),
                )
            })?;
            backend.up(&spec.project, &file, spec.env_file.as_deref())
        }
        _ => {
            // No prior source → checkpoint says project was absent
            // before this apply. Tear it down.
            backend.down(&spec.project, None)?;
            let _ = std::fs::remove_dir_all(spec.project_dir());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockCompose;
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn spec_with_workdir(
        project: &str,
        state: &str,
        source: Option<&str>,
        workdir: &Path,
    ) -> DockerComposeSpec {
        use serde_yaml_ng::{Mapping, Value};
        let mut m = Mapping::new();
        m.insert(Value::String("project".into()), Value::String(project.into()));
        m.insert(Value::String("state".into()), Value::String(state.into()));
        if let Some(s) = source {
            m.insert(Value::String("source".into()), Value::String(s.into()));
        }
        m.insert(
            Value::String("workdir".into()),
            Value::String(workdir.to_string_lossy().into_owned()),
        );
        DockerComposeSpec::from_value(&Value::Mapping(m)).unwrap()
    }

    #[test]
    fn diff_no_change_when_absent_and_no_services() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "absent", None, dir.path());
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::NoChange));
    }

    #[test]
    fn diff_create_when_present_but_no_services() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "present", Some("services:\n  a:\n    image: x\n"), dir.path());
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Create));
    }

    #[test]
    fn diff_update_when_source_changed() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "present", Some("services:\n  a:\n    image: nginx\n"), dir.path());
        // Pre-populate observed services and a stale on-disk file.
        backend.set_state(
            "p1",
            vec![ComposeService {
                name: "a".into(),
                state: "running".into(),
                status: "Up".into(),
                image: "nginx".into(),
            }],
        );
        std::fs::create_dir_all(spec.project_dir()).unwrap();
        std::fs::write(
            spec.compose_file(),
            "services:\n  a:\n    image: nginx:OLD\n",
        )
        .unwrap();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Update));
        assert!(d.reasons[0].contains("source changed"));
    }

    #[test]
    fn diff_no_change_when_source_matches() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let source = "services:\n  a:\n    image: nginx:1\n";
        let spec = spec_with_workdir("p1", "present", Some(source), dir.path());
        backend.set_state(
            "p1",
            vec![ComposeService {
                name: "a".into(),
                state: "running".into(),
                status: "Up".into(),
                image: "nginx:1".into(),
            }],
        );
        std::fs::create_dir_all(spec.project_dir()).unwrap();
        std::fs::write(spec.compose_file(), source).unwrap();
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::NoChange), "got {d:?}");
    }

    #[test]
    fn diff_update_when_absent_but_services_present() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "absent", None, dir.path());
        backend.set_state(
            "p1",
            vec![ComposeService {
                name: "a".into(),
                state: "running".into(),
                status: "Up".into(),
                image: "x".into(),
            }],
        );
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Update));
        assert!(d.reasons[0].contains("tear down"));
    }

    #[test]
    fn apply_up_writes_file_and_calls_up() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let source = "services:\n  web:\n    image: nginx\n";
        let spec = spec_with_workdir("proj1", "present", Some(source), dir.path());
        let step = Step::new("compose-up", "test", Json::Null);
        apply(&backend, &spec, &step).unwrap();
        let on_disk = std::fs::read_to_string(spec.compose_file()).unwrap();
        assert_eq!(on_disk, source);
        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("up project=proj1"));
    }

    #[test]
    fn apply_down_calls_backend_and_removes_dir() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("proj1", "absent", None, dir.path());
        std::fs::create_dir_all(spec.project_dir()).unwrap();
        std::fs::write(spec.compose_file(), "services: {}\n").unwrap();
        let step = Step::new("compose-down", "test", Json::Null);
        apply(&backend, &spec, &step).unwrap();
        assert!(!spec.compose_file().exists());
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("down project=proj1")));
    }

    #[test]
    fn pre_apply_captures_prior_source() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "present", Some("services:\n  a:\n    image: new\n"), dir.path());
        std::fs::create_dir_all(spec.project_dir()).unwrap();
        std::fs::write(spec.compose_file(), "services:\n  a:\n    image: old\n").unwrap();
        let cp = pre_apply(&backend, &spec).unwrap();
        assert!(cp.get("prior_source").unwrap().as_str().unwrap().contains("old"));
    }

    #[test]
    fn rollback_with_prior_source_re_ups() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "present", Some("services:\n  a:\n    image: new\n"), dir.path());
        let cp = json!({"prior_source": "services:\n  a:\n    image: old\n"});
        rollback(&backend, &spec, &cp).unwrap();
        let on_disk = std::fs::read_to_string(spec.compose_file()).unwrap();
        assert!(on_disk.contains("old"));
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("up project=p1")));
    }

    #[test]
    fn rollback_with_no_prior_source_tears_down() {
        let backend = MockCompose::new();
        let dir = TempDir::new().unwrap();
        let spec = spec_with_workdir("p1", "present", Some("services:\n  a:\n    image: x\n"), dir.path());
        let cp = json!({"prior_source": null});
        rollback(&backend, &spec, &cp).unwrap();
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("down project=p1")));
    }
}
