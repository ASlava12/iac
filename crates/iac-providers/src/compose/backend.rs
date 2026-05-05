//! Phase 7cw: backend trait for the `docker.compose` provider.
//!
//! Real impl shells out to the `docker compose` plugin (V2 — the V1
//! `docker-compose` Python tool is EOL since 2023, we don't support it).
//! Tests use [`MockCompose`] that records calls and returns scripted
//! outputs.

use iac_core::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;
use crate::subprocess::{run_capture_stdout, run_check_status};
use std::process::{Command, Stdio};
use std::time::Duration;

// Phase 7di.6.7: per-operation timeouts. `compose up` pulls images
// + starts containers — slow networks make this minutes-long.
// `compose down` should be quick but rare orphan-cleanup edge
// cases benefit from the slack. `ps` is just a status read and
// must be fast.
const COMPOSE_PS_TIMEOUT: Duration = Duration::from_secs(30);
const COMPOSE_UP_TIMEOUT: Duration = Duration::from_secs(600);
const COMPOSE_DOWN_TIMEOUT: Duration = Duration::from_secs(120);

/// Snapshot of one container in a compose project (`docker compose ps`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeService {
    pub name: String,
    pub state: String,
    pub status: String,
    pub image: String,
}

pub trait ComposeBackend: std::fmt::Debug + Send + Sync {
    /// Return the per-service state for the project. Empty vec means
    /// the project has no containers (either never created, or fully
    /// torn down).
    fn list_services(&self, project: &str) -> Result<Vec<ComposeService>>;

    /// Run `docker compose -f <file> -p <project> [--env-file …] up -d --remove-orphans`.
    fn up(
        &self,
        project: &str,
        compose_file: &Path,
        env_file: Option<&Path>,
    ) -> Result<()>;

    /// Run `docker compose -p <project> down --remove-orphans` (keeps volumes).
    fn down(&self, project: &str, compose_file: Option<&Path>) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct ComposeCli;

impl ComposeBackend for ComposeCli {
    fn list_services(&self, project: &str) -> Result<Vec<ComposeService>> {
        let mut cmd = Command::new("docker");
        cmd.args(["compose", "-p", project, "ps", "--format", "json", "--all"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let stdout = run_capture_stdout(
            cmd,
            b"",
            COMPOSE_PS_TIMEOUT,
            "docker.compose",
            &format!("docker compose ps -p {project}"),
        )?;
        // `docker compose ps --format json` outputs one JSON object per
        // line (NDJSON), not a JSON array. Parse line-by-line.
        let mut services = Vec::new();
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| Error::provider("docker.compose", format!("docker compose ps json: {e}")))?;
            services.push(ComposeService {
                name: v.get("Service").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                state: v.get("State").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                status: v.get("Status").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                image: v.get("Image").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            });
        }
        services.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(services)
    }

    fn up(
        &self,
        project: &str,
        compose_file: &Path,
        env_file: Option<&Path>,
    ) -> Result<()> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose")
            .arg("-p").arg(project)
            .arg("-f").arg(compose_file);
        if let Some(env) = env_file {
            cmd.arg("--env-file").arg(env);
        }
        cmd.arg("up").arg("-d").arg("--remove-orphans");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_check_status(
            cmd,
            b"",
            COMPOSE_UP_TIMEOUT,
            "docker.compose",
            &format!("docker compose up -p {project}"),
        )
    }

    fn down(&self, project: &str, compose_file: Option<&Path>) -> Result<()> {
        let mut cmd = Command::new("docker");
        cmd.arg("compose").arg("-p").arg(project);
        if let Some(f) = compose_file {
            cmd.arg("-f").arg(f);
        }
        cmd.arg("down").arg("--remove-orphans");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        run_check_status(
            cmd,
            b"",
            COMPOSE_DOWN_TIMEOUT,
            "docker.compose",
            &format!("docker compose down -p {project}"),
        )
    }
}

/// In-memory mock for tests. Records each call so assertions can check
/// the exact sequence of operations performed.
///
/// Phase 7cz.18: bookkeeping (calls + per-op failure injection) is
/// shared via [`MockJournal`]. Provider-specific state (project →
/// services map) is the `S` parameter.
#[derive(Debug, Default)]
pub struct MockCompose {
    journal: crate::mock_journal::MockJournal<ComposeMockState>,
}

#[derive(Debug, Default)]
struct ComposeMockState {
    /// project → services
    services_by_project: BTreeMap<String, Vec<ComposeService>>,
}

impl MockCompose {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate observed services for a project.
    pub fn set_state(&self, project: &str, services: Vec<ComposeService>) {
        self.journal.with_state_mut(|s| {
            s.services_by_project.insert(project.to_string(), services);
        });
    }

    pub fn calls(&self) -> Vec<String> {
        self.journal.calls()
    }

    pub fn fail_next_up(&self, msg: impl Into<String>) {
        self.journal.fail_next("up", msg);
    }

    pub fn fail_next_down(&self, msg: impl Into<String>) {
        self.journal.fail_next("down", msg);
    }
}

impl ComposeBackend for MockCompose {
    fn list_services(&self, project: &str) -> Result<Vec<ComposeService>> {
        Ok(self.journal.with_state(|s| {
            s.services_by_project.get(project).cloned().unwrap_or_default()
        }))
    }

    fn up(
        &self,
        project: &str,
        compose_file: &Path,
        env_file: Option<&Path>,
    ) -> Result<()> {
        let line = format!(
            "up project={project} file={} env={}",
            compose_file.display(),
            env_file.map(|p| p.display().to_string()).unwrap_or_else(|| "-".into()),
        );
        // Read the file BEFORE entering the locked section: file IO
        // shouldn't happen under the mutex, and the closure is meant
        // to be quick state ops only.
        let prepared_services: Option<Vec<ComposeService>> = std::fs::read_to_string(compose_file)
            .ok()
            .map(|text| {
                parse_service_names_from_yaml(&text)
                    .into_iter()
                    .map(|name| ComposeService {
                        name,
                        state: "running".into(),
                        status: "Up".into(),
                        image: "mock".into(),
                    })
                    .collect()
            });
        match self.journal.record("up", line, |s| {
            // Materialise: if no state yet, populate with the parsed
            // services. Otherwise leave existing state alone
            // (idempotent up).
            if !s.services_by_project.contains_key(project) {
                s.services_by_project
                    .insert(project.to_string(), prepared_services.unwrap_or_default());
            }
        }) {
            Ok(()) => Ok(()),
            Err(msg) => Err(Error::provider("docker.compose", msg)),
        }
    }

    fn down(&self, project: &str, _compose_file: Option<&Path>) -> Result<()> {
        match self.journal.record("down", format!("down project={project}"), |s| {
            s.services_by_project.remove(project);
        }) {
            Ok(()) => Ok(()),
            Err(msg) => Err(Error::provider("docker.compose", msg)),
        }
    }
}

/// Cheap YAML scanner — pulls top-level service names from a compose
/// document without dragging in a full YAML parser dependency that
/// `serde_yaml_ng` would already provide. Used only by `MockCompose`
/// to invent a plausible "after-up" state.
fn parse_service_names_from_yaml(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text)
        && let Some(services) = doc.get("services").and_then(|v| v.as_mapping())
    {
        for (k, _v) in services {
            if let Some(name) = k.as_str() {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn mock_round_trip() {
        let m = MockCompose::new();
        assert_eq!(m.list_services("x").unwrap(), vec![]);
        let f = std::env::temp_dir().join("iac-mock-compose-rt.yml");
        std::fs::write(&f, "services:\n  app:\n    image: nginx\n").unwrap();
        m.up("x", &f, None).unwrap();
        let got = m.list_services("x").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "app");
        m.down("x", None).unwrap();
        assert_eq!(m.list_services("x").unwrap(), vec![]);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn mock_records_calls() {
        let m = MockCompose::new();
        m.up("a", &PathBuf::from("/tmp/x.yml"), None).unwrap();
        m.down("a", None).unwrap();
        assert_eq!(m.calls(), vec![
            "up project=a file=/tmp/x.yml env=-".to_string(),
            "down project=a".to_string(),
        ]);
    }

    #[test]
    fn mock_fails_when_armed() {
        let m = MockCompose::new();
        m.fail_next_up("nope");
        let f = PathBuf::from("/dev/null");
        let err = m.up("a", &f, None).unwrap_err();
        assert!(err.to_string().contains("nope"));
        // Subsequent up should succeed
        m.up("a", &f, None).unwrap();
    }

    #[test]
    fn parse_service_names_handles_nested() {
        let yaml = r#"
services:
  web:
    image: nginx
  db:
    image: postgres:16
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data:
"#;
        let names = parse_service_names_from_yaml(yaml);
        assert_eq!(names, vec!["db", "web"]);
    }
}
