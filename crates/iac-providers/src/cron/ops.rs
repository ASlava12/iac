//! `cron.job` lifecycle. The on-disk format is `/etc/cron.d/<name>` with the
//! rendered contents from [`render::render`]. We piggy-back on the file
//! provider's atomic-write semantics by going through a small filesystem
//! helper here — the cron daemon picks up changes automatically.

use super::render;
use super::spec::{CronJobSpec, CronState};
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
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn observe(spec: &CronJobSpec) -> Result<ObservedState> {
    let path = spec.config_path();
    match fs::read_to_string(&path) {
        Ok(text) => {
            let sha = sha256_hex(text.as_bytes());
            let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
            facts.insert("present".into(), YamlValue::Bool(true));
            facts.insert("content_sha256".into(), YamlValue::String(sha.clone()));
            facts.insert(
                "size".into(),
                YamlValue::Number(serde_yaml_ng::Number::from(text.len() as u64)),
            );
            let mut spec_value = Mapping::new();
            spec_value.insert("path".into(), YamlValue::String(path.display().to_string()));
            spec_value.insert("content_sha256".into(), YamlValue::String(sha));
            Ok(ObservedState {
                present: true,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
            facts.insert("present".into(), YamlValue::Bool(false));
            Ok(ObservedState {
                present: false,
                spec: YamlValue::Null,
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        Err(e) => Err(Error::Io { path, source: e }),
    }
}

pub fn diff(spec: &CronJobSpec, observed: &ObservedState) -> Diff {
    match (spec.state, observed.present) {
        (CronState::Absent, false) => Diff::no_change(),
        (CronState::Absent, true) => Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "state".into(),
                from: Some(YamlValue::String("present".into())),
                to: Some(YamlValue::String("absent".into())),
                sensitive: false,
            }],
            reasons: vec![format!("remove cron job {}", spec.name)],
            reversible: true,
        },
        (CronState::Present, false) => Diff {
            kind: DiffKind::Create,
            changes: vec![FieldChange {
                field: "state".into(),
                from: Some(YamlValue::String("absent".into())),
                to: Some(YamlValue::String("present".into())),
                sensitive: false,
            }],
            reasons: vec![format!("install cron job {}", spec.name)],
            reversible: true,
        },
        (CronState::Present, true) => {
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
                    reasons: vec!["rendered cron file differs".into()],
                    reversible: true,
                }
            }
        }
    }
}

pub fn plan(spec: &CronJobSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return vec![];
    }
    let path = spec.config_path();
    match spec.state {
        CronState::Present => vec![Step::new(
            super::CronAction::Write.as_str(),
            format!("write {}", path.display()),
            json!({ "path": path }),
        )],
        CronState::Absent => vec![Step::new(
            super::CronAction::Remove.as_str(),
            format!("remove {}", path.display()),
            json!({ "path": path }),
        )],
    }
}

pub fn pre_apply(spec: &CronJobSpec) -> Result<Json> {
    let path = spec.config_path();
    match fs::read_to_string(&path) {
        Ok(text) => Ok(json!({
            "path": path,
            "existed": true,
            "content": text,
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "path": path,
            "existed": false,
        })),
        Err(e) => Err(Error::Io { path, source: e }),
    }
}

pub fn apply(spec: &CronJobSpec, step: &Step) -> Result<StepResult> {
    let path = spec.config_path();
    match super::CronAction::parse(&step.action)? {
        super::CronAction::Write => {
            let content = render::render(spec);
            atomic_write(&path, &content, 0o644)?;
            let sha = sha256_hex(content.as_bytes());
            Ok(StepResult {
                status: iac_core::operation::StepStatus::Succeeded,
                message: format!("wrote {} ({} bytes)", path.display(), content.len()),
                data: json!({
                    "path": path,
                    "bytes": content.len(),
                    "content_sha256": sha,
                }),
                error: None,
            })
        }
        super::CronAction::Remove => {
            match fs::remove_file(&path) {
                Ok(()) => Ok(StepResult::ok(format!("removed {}", path.display()))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Ok(StepResult::skipped(format!("{} already absent", path.display())))
                }
                Err(e) => Err(Error::Io { path, source: e }),
            }
        }
    }
}

pub fn rollback(spec: &CronJobSpec, checkpoint: &Json) -> Result<()> {
    let path = spec.config_path();
    let existed = checkpoint.get("existed").and_then(Json::as_bool).unwrap_or(false);
    if existed {
        if let Some(content) = checkpoint.get("content").and_then(Json::as_str) {
            atomic_write(&path, content, 0o644)?;
        }
    } else {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io { path, source: e }),
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, content: &str, mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::provider("cron", format!("path has no parent: {}", path.display()))
    })?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| Error::Io { path: parent.into(), source: e })?;
    }
    let tmp = temp_path_in(parent, path);
    fs::write(&tmp, content).map_err(|e| Error::Io { path: tmp.clone(), source: e })?;
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(&tmp, perms).map_err(|e| Error::Io { path: tmp.clone(), source: e })?;
    fs::rename(&tmp, path).map_err(|e| Error::Io { path: path.into(), source: e })?;
    Ok(())
}

fn temp_path_in(dir: &Path, target: &Path) -> PathBuf {
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    let ulid = ulid::Ulid::new();
    dir.join(format!(".{stem}.iac.{ulid}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::super::spec::{CronJobSpec, CronState};
    use super::*;
    use indexmap::IndexMap;
    use tempfile::TempDir;

    fn base(dir: &TempDir) -> CronJobSpec {
        CronJobSpec {
            name: "backup".into(),
            state: CronState::Present,
            schedule: Some("0 3 * * *".into()),
            command: Some("/bin/true".into()),
            user: "root".into(),
            env: IndexMap::new(),
            cron_dir: Some(dir.path().to_path_buf()),
        }
    }

    #[test]
    fn create_then_idempotent_then_drift() {
        let dir = TempDir::new().unwrap();
        let spec = base(&dir);

        // Create.
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Create);
        let steps = plan(&spec, &d);
        let cp = pre_apply(&spec).unwrap();
        apply(&spec, &steps[0]).unwrap();
        assert!(spec.config_path().exists());

        // Idempotent.
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::NoChange);

        // Drift the file out of band.
        std::fs::write(spec.config_path(), "tampered").unwrap();
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);

        // Rollback to checkpoint (previously absent → file removed).
        rollback(&spec, &cp).unwrap();
        assert!(!spec.config_path().exists());
    }

    #[test]
    fn remove_when_present() {
        let dir = TempDir::new().unwrap();
        let mut spec = base(&dir);
        // Pre-seed.
        std::fs::write(spec.config_path(), "old").unwrap();
        spec.state = CronState::Absent;
        spec.schedule = None;
        spec.command = None;

        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed);
        assert_eq!(d.kind, DiffKind::Update);
        let steps = plan(&spec, &d);
        assert_eq!(steps[0].action, "cron.remove");
        apply(&spec, &steps[0]).unwrap();
        assert!(!spec.config_path().exists());
    }

    #[test]
    fn rollback_restores_previous_content() {
        let dir = TempDir::new().unwrap();
        let prev = "old\n";
        let path = dir.path().join("backup");
        std::fs::write(&path, prev).unwrap();

        let spec = base(&dir);
        let cp = pre_apply(&spec).unwrap();
        apply(&spec, &plan(&spec, &diff(&spec, &observe(&spec).unwrap()))[0]).unwrap();
        // After apply the file changed.
        let after_apply = std::fs::read_to_string(&path).unwrap();
        assert_ne!(after_apply, prev);

        rollback(&spec, &cp).unwrap();
        let restored = std::fs::read_to_string(&path).unwrap();
        assert_eq!(restored, prev);
    }
}
