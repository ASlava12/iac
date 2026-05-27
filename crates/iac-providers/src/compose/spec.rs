//! Phase 7cw: spec for the `docker.compose` provider.
//!
//! ```yaml
//! kind: docker.compose
//! spec:
//!   project: web-stack          # docker-compose project name (required)
//!   state: present | absent     # default: present
//!   source: |                   # inline compose YAML (required when present)
//!     services:
//!       app:
//!         image: nginx:1.27
//!         ports: ["8080:80"]
//!   env_file: /etc/iac/web.env  # optional, passed via --env-file
//!   workdir: /var/lib/iac/compose  # optional override; default below
//! ```
//!
//! Compose treats a stack as one resource. Services aren't tracked
//! individually — the operator's source-of-truth is the YAML. We compute
//! `sha256(source)` to detect spec drift; observed state of containers
//! tells us whether the stack is up.
//!
//! Why not `docker-compose.yml` on disk? Operators write the manifest in
//! one place; making them split between iac manifest and a separate
//! YAML doubles the files-to-track count. Inline keeps it together. We
//! still need the YAML on disk for the `docker compose` CLI, so we
//! materialise it under `workdir/<project>/docker-compose.yml` at apply
//! time — operators get a clear breadcrumb when they run `docker compose
//! ps` manually for debugging.

use serde::Deserialize;
use serde_yaml_ng::Value as YamlValue;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DockerComposeSpec {
    pub project: String,
    #[serde(default)]
    pub state: ComposeState,
    /// Inline compose YAML. Required when `state == Present`.
    #[serde(default)]
    pub source: Option<String>,
    /// Optional env file passed to `docker compose --env-file`.
    #[serde(default)]
    pub env_file: Option<PathBuf>,
    /// Optional override for the workdir where the materialised
    /// `docker-compose.yml` lives. Defaults to `/var/lib/iac/compose`.
    #[serde(default)]
    pub workdir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ComposeState {
    #[default]
    Present,
    Absent,
}

impl DockerComposeSpec {
    pub fn from_value(v: &YamlValue) -> Result<Self, String> {
        let spec: Self = serde_yaml_ng::from_value(v.clone()).map_err(|e| format!("parse: {e}"))?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), String> {
        if self.project.is_empty() {
            return Err("project must not be empty".into());
        }
        // Compose project names are restricted: lowercase alphanum +
        // [_-]. Mirror docker's own validation so operators don't
        // discover the rule via a confusing CLI error.
        if !self.project.chars().all(valid_project_char) {
            return Err(format!(
                "project {:?}: only lowercase ASCII letters, digits, '_' and '-' allowed",
                self.project
            ));
        }
        if self.state == ComposeState::Present
            && self.source.as_deref().unwrap_or("").trim().is_empty()
        {
            return Err("source must be a non-empty compose YAML when state=present".into());
        }
        if let Some(p) = &self.env_file
            && !p.is_absolute()
        {
            return Err(format!("env_file {} must be absolute", p.display()));
        }
        if let Some(p) = &self.workdir
            && !p.is_absolute()
        {
            return Err(format!("workdir {} must be absolute", p.display()));
        }
        Ok(())
    }

    /// `<workdir>/<project>` — where the materialised `docker-compose.yml`
    /// goes. Operator can `cd` here for ad-hoc `docker compose` debugging.
    pub fn project_dir(&self) -> PathBuf {
        self.workdir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/iac/compose"))
            .join(&self.project)
    }

    pub fn compose_file(&self) -> PathBuf {
        self.project_dir().join("docker-compose.yml")
    }

    /// Stable digest of the source YAML — used to detect spec drift
    /// without rewriting/comparing the on-disk file byte-for-byte.
    pub fn source_sha256(&self) -> String {
        iac_core::hash::sha256_hex(self.source.as_deref().unwrap_or("").as_bytes())
    }
}

fn valid_project_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(s: &str) -> YamlValue {
        serde_yaml_ng::from_str(s).unwrap()
    }

    #[test]
    fn parses_minimal_present() {
        let v = yaml(
            r#"
project: web
source: |
  services:
    app:
      image: nginx:latest
"#,
        );
        let s = DockerComposeSpec::from_value(&v).unwrap();
        assert_eq!(s.project, "web");
        assert_eq!(s.state, ComposeState::Present);
        assert!(s.source.as_deref().unwrap().contains("nginx"));
    }

    #[test]
    fn rejects_empty_project() {
        let v = yaml("project: \"\"\nsource: 'services: {}'\n");
        let err = DockerComposeSpec::from_value(&v).unwrap_err();
        assert!(err.contains("project"));
    }

    #[test]
    fn rejects_uppercase_project() {
        let v = yaml("project: WebStack\nsource: 'services: {}'\n");
        let err = DockerComposeSpec::from_value(&v).unwrap_err();
        assert!(err.contains("lowercase"));
    }

    #[test]
    fn requires_source_for_present() {
        let v = yaml("project: web\n");
        let err = DockerComposeSpec::from_value(&v).unwrap_err();
        assert!(err.contains("source"), "{err}");
    }

    #[test]
    fn allows_absent_without_source() {
        let v = yaml("project: web\nstate: absent\n");
        let s = DockerComposeSpec::from_value(&v).unwrap();
        assert_eq!(s.state, ComposeState::Absent);
    }

    #[test]
    fn rejects_relative_env_file() {
        let v = yaml("project: web\nsource: 'services: {}'\nenv_file: compose.env\n");
        let err = DockerComposeSpec::from_value(&v).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn project_dir_uses_default_workdir() {
        let v = yaml("project: x\nsource: 'services: {}'\n");
        let s = DockerComposeSpec::from_value(&v).unwrap();
        assert_eq!(s.project_dir(), PathBuf::from("/var/lib/iac/compose/x"));
        assert_eq!(
            s.compose_file(),
            PathBuf::from("/var/lib/iac/compose/x/docker-compose.yml")
        );
    }

    #[test]
    fn project_dir_respects_override() {
        let v = yaml("project: x\nsource: 'services: {}'\nworkdir: /tmp/custom\n");
        let s = DockerComposeSpec::from_value(&v).unwrap();
        assert_eq!(s.project_dir(), PathBuf::from("/tmp/custom/x"));
    }

    #[test]
    fn source_sha256_is_deterministic() {
        let v1 = yaml("project: x\nsource: 'services: { a: { image: nginx } }'\n");
        let v2 = yaml("project: x\nsource: 'services: { a: { image: nginx } }'\n");
        let v3 = yaml("project: x\nsource: 'services: { a: { image: redis } }'\n");
        let s1 = DockerComposeSpec::from_value(&v1).unwrap();
        let s2 = DockerComposeSpec::from_value(&v2).unwrap();
        let s3 = DockerComposeSpec::from_value(&v3).unwrap();
        assert_eq!(s1.source_sha256(), s2.source_sha256());
        assert_ne!(s1.source_sha256(), s3.source_sha256());
    }

    #[test]
    fn rejects_unknown_field() {
        let v = yaml("project: x\nsource: 'services: {}'\njunk: ignored\n");
        assert!(DockerComposeSpec::from_value(&v).is_err());
    }
}
