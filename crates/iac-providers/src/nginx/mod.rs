//! `nginx.vhost` provider: renders a single nginx server block to a config
//! snippet, validates with `nginx -t`, and reloads via `systemctl reload nginx`.
//!
//! Phase 5b is intentionally narrow:
//!   * One `server` block per resource (not multi-host).
//!   * `proxy_pass` upstreams only — no static roots, no fastcgi.
//!   * No TLS (`listen 443` renders plain HTTP — TLS support is Phase 5b.1).
//!   * No `location` blocks beyond `/`.
//!
//! Apply semantics are atomic by design: we write the new file, run
//! `nginx -t`, and only call reload on success. A failed `nginx -t` triggers
//! an immediate restore to the pre-apply checkpoint, so on-disk state never
//! deviates from "either old or new, both valid."

mod backend;
mod ops;
mod render;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(NginxAction {
    Write  => "nginx.write",
    Remove => "nginx.remove",
});

pub use backend::{MockNginx, NginxBackend, NginxCli};
pub use spec::{NginxState, NginxVhostSpec};

use iac_core::{
    Error, Result,
    diff::Diff,
    operation::{Checkpoint, Step, StepResult},
    provider::{ApplyContext, Provider, VerifyOutcome},
    resource::Resource,
    state::ObservedState,
};
use serde_json::Value as Json;
use std::path::Path;

#[derive(Debug)]
pub struct NginxProvider {
    backend: Box<dyn NginxBackend>,
}

impl Default for NginxProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NginxProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(NginxCli),
        }
    }

    /// Phase 7dh.8: test-only dependency injection. Pre-7dh.8 this
    /// was a public API surface, but the only call site was a single
    /// unit test in `ops.rs`; gating to `#[cfg(test)]` keeps the
    /// surface honest.
    #[cfg(test)]
    pub fn with_backend(backend: Box<dyn NginxBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<NginxVhostSpec> {
        NginxVhostSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid nginx.vhost spec: {e}"),
            )
        })
    }
}

impl Provider for NginxProvider {
    fn kind(&self) -> &str {
        "nginx.vhost"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(self.backend.as_ref(), &spec)
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let spec = self.parse_spec(resource)?;
        Ok(ops::diff(&spec, observed))
    }

    fn plan(&self, resource: &Resource, diff: &Diff) -> Result<Vec<Step>> {
        let spec = self.parse_spec(resource)?;
        Ok(ops::plan(&spec, diff))
    }

    fn pre_apply(&self, resource: &Resource, _step: &Step, _ctx: &ApplyContext) -> Result<Json> {
        let spec = self.parse_spec(resource)?;
        ops::pre_apply(self.backend.as_ref(), &spec)
    }

    fn apply(&self, resource: &Resource, step: &Step, ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        // The executor wrote the checkpoint file before `apply`; we read it
        // back to know what to restore from on validation failure.
        let cp_path = ctx.workspace.join("checkpoint.json");
        let checkpoint: Json = if cp_path.exists() {
            let bytes = std::fs::read(&cp_path).map_err(|e| Error::Io {
                path: cp_path.clone(),
                source: e,
            })?;
            serde_json::from_slice::<iac_core::operation::Checkpoint>(&bytes)
                .map_err(Error::from)?
                .data
        } else {
            // Fall back to a fresh observation if the executor didn't persist
            // the checkpoint. Should not happen in normal flow.
            ops::pre_apply(self.backend.as_ref(), &spec)?
        };
        ops::apply(self.backend.as_ref(), &spec, step, &checkpoint)
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let observed = ops::observe(self.backend.as_ref(), &spec)?;
        let diff = ops::diff(&spec, &observed);
        if diff.is_change() {
            Ok(VerifyOutcome::Mismatch(diff.changes))
        } else {
            Ok(VerifyOutcome::Match)
        }
    }

    fn rollback(
        &self,
        resource: &Resource,
        checkpoint: &Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        let spec = self.parse_spec(resource)?;
        ops::rollback(self.backend.as_ref(), &spec, &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        Ok(vec![spec.config_path.display().to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
    use indexmap::IndexMap;
    use serde_yaml_ng::{Mapping, Value as YamlValue};
    use tempfile::TempDir;

    fn mk_resource(config_path: &str) -> Resource {
        let mut spec = Mapping::new();
        spec.insert("config_path".into(), YamlValue::String(config_path.into()));
        spec.insert(
            "server_names".into(),
            YamlValue::Sequence(vec![YamlValue::String("app.example.com".into())]),
        );
        spec.insert(
            "upstream".into(),
            YamlValue::String("http://127.0.0.1:8080".into()),
        );
        Resource {
            api_version: API_VERSION.into(),
            kind: "nginx.vhost".into(),
            metadata: Metadata {
                name: "app".into(),
                environment: "test".into(),
                owner: None,
                labels: IndexMap::new(),
                annotations: IndexMap::new(),
            },
            spec: YamlValue::Mapping(spec),
            policy: YamlValue::Null,
            source: SourceLocation::default(),
        }
    }

    /// Drives the Provider trait the way the executor would, including the
    /// disk round-trip for the checkpoint. Catches regressions in
    /// `NginxProvider::apply`'s checkpoint-reading path that the pure ops
    /// tests bypass.
    #[test]
    fn provider_apply_reads_checkpoint_from_workspace() {
        use iac_core::hash::sha256_hex;
        use iac_core::operation::Checkpoint;

        let workspace = TempDir::new().unwrap();
        let mock = MockNginx::new();
        let prev = "# previous valid\n".to_string();
        mock.configs.lock().unwrap().insert(
            std::path::PathBuf::from("/etc/nginx/conf.d/app.conf"),
            prev.clone(),
        );
        mock.fail_validate_once("syntax error at line 1");

        let provider = NginxProvider::with_backend(Box::new(mock));
        let resource = mk_resource("/etc/nginx/conf.d/app.conf");

        let observed = provider.observe(&resource).unwrap();
        let diff = provider.diff(&resource, &observed).unwrap();
        assert!(diff.is_change());
        let steps = provider.plan(&resource, &diff).unwrap();
        assert_eq!(steps.len(), 1);

        let ctx = ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: workspace.path().to_path_buf(),
        };
        let cp_data = provider.pre_apply(&resource, &steps[0], &ctx).unwrap();
        let cp = Checkpoint::new(resource.id(), ctx.operation_id, cp_data);
        std::fs::write(
            workspace.path().join("checkpoint.json"),
            serde_json::to_vec_pretty(&cp).unwrap(),
        )
        .unwrap();

        // Apply: validate fails → previous content is restored.
        let err = provider.apply(&resource, &steps[0], &ctx).unwrap_err();
        assert!(err.to_string().contains("rejected"));

        // Verify the restored on-disk state matches `prev` by re-observing
        // through the provider rather than reaching into the mock.
        let restored_observed = provider.observe(&resource).unwrap();
        let restored_sha = restored_observed
            .facts
            .get("content_sha256")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert_eq!(restored_sha, sha256_hex(prev.as_bytes()));
    }
}
