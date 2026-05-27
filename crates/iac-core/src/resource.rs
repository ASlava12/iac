use crate::id::ResourceId;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_yaml_ng::Value;
use std::path::PathBuf;

/// API version is `<group>/<version>`. We keep a single group for now.
pub const API_VERSION: &str = "iac.example/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub name: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub labels: IndexMap<String, String>,
    #[serde(default)]
    pub annotations: IndexMap<String, String>,
}

fn default_environment() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub document_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    #[serde(default)]
    pub spec: Value,
    #[serde(default)]
    pub policy: Value,
    /// Set by the loader, not present in the YAML itself.
    #[serde(skip)]
    pub source: SourceLocation,
}

impl Resource {
    pub fn id(&self) -> ResourceId {
        ResourceId::new(&self.kind, &self.metadata.environment, &self.metadata.name)
    }

    /// Validate the basic shape of a resource manifest.
    /// Per-provider schema validation happens via `Provider::diff`/`apply`.
    ///
    /// Phase 7dh.12 (invariant audit): `name`, `environment`, and
    /// `kind` are tightened beyond the original `is_empty()` check.
    /// They flow into [`ResourceId`] which is used as a DB-row key,
    /// audit-log column, capability allowlist key, and
    /// [`ResourceId::fs_key`] (filesystem path segment). A name with
    /// embedded `\n` round-trips through audit-log JSON cleanly but
    /// confuses every grep / dashboard / log-aggregator the operator
    /// owns; a name that's all-whitespace passes `is_empty()` but
    /// renders as a "ghost" agent in `iac agents list`. Reject both
    /// upfront — fail-loud at parse time, not silently in downstream
    /// tooling.
    pub fn validate_shape(&self) -> crate::Result<()> {
        validate_required_identifier(self.id().to_string(), "apiVersion", &self.api_version)?;
        validate_required_identifier(self.id().to_string(), "kind", &self.kind)?;
        validate_required_identifier(self.id().to_string(), "metadata.name", &self.metadata.name)?;
        validate_required_identifier(
            self.id().to_string(),
            "metadata.environment",
            &self.metadata.environment,
        )?;
        Ok(())
    }
}

/// Reject empty / whitespace-only / control-char-bearing identifiers.
/// Used at manifest-load and re-used by the agent/server when receiving
/// resource refs over the wire so the same rule lands everywhere.
fn validate_required_identifier(id: String, field: &str, value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Err(crate::Error::validation(
            id,
            format!("{field} must not be empty"),
        ));
    }
    if value.trim().is_empty() {
        return Err(crate::Error::validation(
            id,
            format!("{field} must not be whitespace-only (got {value:?})"),
        ));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(crate::Error::validation(
            id,
            format!("{field} contains control characters (got {value:?})"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use serde_yaml_ng::Value;

    fn mk(name: &str, env: &str) -> Resource {
        Resource {
            api_version: API_VERSION.into(),
            kind: "file".into(),
            metadata: Metadata {
                name: name.into(),
                environment: env.into(),
                owner: None,
                labels: IndexMap::new(),
                annotations: IndexMap::new(),
            },
            spec: Value::Null,
            policy: Value::Null,
            source: SourceLocation::default(),
        }
    }

    #[test]
    fn validate_accepts_normal_identifiers() {
        assert!(mk("nginx-main", "prod").validate_shape().is_ok());
        // Phase 7dh.12: dots/underscores/digits are still allowed —
        // these are common in real fleet naming (`vm-01.pool.dc-east`).
        assert!(mk("vm-01.pool", "dc-east").validate_shape().is_ok());
    }

    #[test]
    fn validate_rejects_empty_name() {
        let err = mk("", "prod").validate_shape().unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_rejects_whitespace_only_name() {
        // Pre-7dh.12 this slipped past `is_empty()` and rendered as a
        // "ghost" agent in `iac agents list`.
        let err = mk("   ", "prod").validate_shape().unwrap_err();
        assert!(err.to_string().contains("whitespace-only"));
    }

    #[test]
    fn validate_rejects_whitespace_only_environment() {
        let err = mk("nginx", "\t\t").validate_shape().unwrap_err();
        assert!(err.to_string().contains("whitespace-only"));
    }

    #[test]
    fn validate_rejects_newline_in_name() {
        // Newline-bearing names round-trip through audit-log JSON
        // cleanly but break grep / dashboards / line-buffered logs.
        let err = mk("nginx\nmain", "prod").validate_shape().unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn validate_rejects_null_byte_in_environment() {
        let err = mk("nginx", "prod\0").validate_shape().unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }

    #[test]
    fn validate_rejects_tab_in_kind() {
        let mut r = mk("nginx", "prod");
        r.kind = "file\t".into();
        let err = r.validate_shape().unwrap_err();
        assert!(err.to_string().contains("control characters"));
    }
}
