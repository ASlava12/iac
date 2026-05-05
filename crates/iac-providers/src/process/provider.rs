//! Phase 7db.2: external-process plugin runtime.
//!
//! Phase 7di.1 — the per-Provider boilerplate moved to
//! [`crate::plugin::PluginProvider`]. What remains here is the
//! transport-only [`PluginRuntime`] impl on top of [`PluginHandle`]
//! (the long-running NDJSON-RPC daemon).

use super::handle::PluginHandle;
use super::proto::methods;
use super::spec::ExternalProviderSpec;
use crate::plugin::{CapabilityKeysStrategy, PluginProvider, PluginRuntime};
use iac_core::Result;
use serde_json::Value as Json;
use std::sync::Arc;

/// Transport-only struct: holds the daemon handle, exposes `call`
/// and `supports` to the shared `PluginProvider`.
pub struct ExternalRuntime {
    handle: Arc<PluginHandle>,
}

impl std::fmt::Debug for ExternalRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalRuntime")
            .field("kind", &self.handle.kind())
            .finish()
    }
}

/// Public-facing alias kept for source compatibility with the agent
/// and tests. Constructor moved one layer deeper (see migration in
/// [`ExternalRuntime::new`] / [`ExternalRuntime::into_provider`]).
pub type ExternalProvider = PluginProvider<ExternalRuntime>;

impl ExternalRuntime {
    pub fn new(spec: ExternalProviderSpec) -> std::result::Result<Self, String> {
        spec.validate()?;
        Ok(Self {
            handle: Arc::new(PluginHandle::new(spec)),
        })
    }

    /// Wrap into the shared `PluginProvider`. Equivalent to the old
    /// `ExternalProvider::new(spec)` two-step.
    pub fn into_provider(self) -> ExternalProvider {
        PluginProvider::new(self)
    }
}

impl PluginRuntime for ExternalRuntime {
    fn kind(&self) -> &str {
        self.handle.kind()
    }

    fn call(&self, method: &str, params: Json) -> Result<Json> {
        self.handle.call(method, params)
    }

    fn supports(&self, method: &str) -> bool {
        // The plugin's hello message lists the optional methods it
        // implements. Empty list (or no hello yet) means
        // "I implement only the required `observe` + `apply` pair";
        // the host falls back to its built-in defaults.
        self.handle
            .hello()
            .map(|h| h.methods.iter().any(|m| m == method))
            .unwrap_or(false)
    }

    fn capability_keys_strategy(&self) -> CapabilityKeysStrategy {
        // Capability keys come from the plugin's `hello` — operators
        // pin them in the binary so a misconfigured `[[external_providers]]`
        // block can't widen access. If the plugin hasn't connected
        // yet, the host treats the empty list as "no capabilities
        // advertised", which is the right fail-closed behaviour.
        CapabilityKeysStrategy::Templates(
            self.handle.hello().map(|h| h.capability_keys).unwrap_or_default(),
        )
    }
}

// Phase 7di.1: `methods::*` constants are still exported from
// `super::proto` for tests that reach for them; nothing in this file
// needs them anymore (literals everywhere thanks to the unified
// PluginProvider).
#[allow(unused_imports)]
use methods as _legacy_methods_constants;

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::diff::DiffKind;
    use iac_core::operation::StepStatus;
    use iac_core::provider::{ApplyContext, Provider};
    use iac_core::resource::{Metadata, Resource, SourceLocation, API_VERSION};
    use indexmap::IndexMap;
    use serde_yaml_ng::Value as YamlValue;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::TempDir;

    fn mk_plugin(dir: &Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("plug.sh");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        f.write_all(body.as_bytes()).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    fn mk_resource(name: &str, spec_yaml: &str) -> Resource {
        let spec: YamlValue = serde_yaml_ng::from_str(spec_yaml).unwrap();
        Resource {
            api_version: API_VERSION.into(),
            kind: "t.ext".into(),
            metadata: Metadata {
                name: name.into(),
                environment: "test".into(),
                owner: None,
                labels: IndexMap::new(),
                annotations: IndexMap::new(),
            },
            spec,
            policy: YamlValue::Null,
            source: SourceLocation::default(),
        }
    }

    fn provider_with(plugin_path: std::path::PathBuf) -> ExternalProvider {
        let spec = ExternalProviderSpec {
            kind: "t.ext".into(),
            binary: plugin_path,
            args: vec![],
            env: vec![],
            restart_on_crash: false,
            handshake_timeout_secs: 3,
            call_timeout_secs: 3,
            binary_sha256: None,
        };
        ExternalRuntime::new(spec).unwrap().into_provider()
    }

    #[test]
    fn full_create_flow_with_plugin() {
        let tmp = TempDir::new().unwrap();
        // Plugin: hello → observe (absent) → apply (ok). One process,
        // multiple round-trips.
        let plug = mk_plugin(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"t.ext","capability_keys":["{{ name }}"],"methods":["observe","apply"]}}'
while read REQ; do
  case "$REQ" in
    *'"method":"observe"'*)
      ID=$(echo "$REQ" | sed -E 's/.*"id":([0-9]+).*/\1/')
      echo "{\"id\":$ID,\"result\":{\"present\":false}}"
      ;;
    *'"method":"apply"'*)
      ID=$(echo "$REQ" | sed -E 's/.*"id":([0-9]+).*/\1/')
      echo "{\"id\":$ID,\"result\":{\"status\":\"ok\",\"message\":\"created\"}}"
      ;;
    *'"method":"shutdown"'*)
      exit 0
      ;;
  esac
done
"#,
        );
        let provider = provider_with(plug);
        let res = mk_resource("vm-1", "name: vm-1\nflavor: small\n");

        let observed = provider.observe(&res).unwrap();
        assert!(!observed.present);

        let diff = provider.diff(&res, &observed).unwrap();
        assert_eq!(diff.kind, DiffKind::Create);

        let steps = provider.plan(&res, &diff).unwrap();
        assert_eq!(steps.len(), 1);
        // Phase 7di.1: action prefix unified across runtimes —
        // formerly "external-create".
        assert_eq!(steps[0].action, "plugin-create");

        let ctx = ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: tmp.path().to_path_buf(),
        };
        let _cp = provider.pre_apply(&res, &steps[0], &ctx).unwrap();
        let r = provider.apply(&res, &steps[0], &ctx).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        assert!(r.message.contains("created"));

        let keys = provider.capability_keys(&res).unwrap();
        assert_eq!(keys, vec!["vm-1"]);
    }

    #[test]
    fn plugin_can_return_application_error() {
        let tmp = TempDir::new().unwrap();
        let plug = mk_plugin(
            tmp.path(),
            r#"
echo '{"hello":{"protocol_version":1,"kind":"t.ext"}}'
while read REQ; do
  ID=$(echo "$REQ" | sed -E 's/.*"id":([0-9]+).*/\1/')
  echo "{\"id\":$ID,\"error\":\"upstream offline\"}"
done
"#,
        );
        let provider = provider_with(plug);
        let res = mk_resource("vm-1", "name: vm-1\n");
        let err = provider.observe(&res).unwrap_err();
        assert!(err.to_string().contains("upstream offline"), "got: {err}");
    }
}
