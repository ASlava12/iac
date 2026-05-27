//! Phase 7dc: Provider impl backed by a sandboxed WASM module.
//!
//! Re-uses the same JSON envelope shape as the shellout / external-
//! process variants — operators learn one wire format, switch
//! runtimes by changing config. Auto-derives `diff` / `verify` /
//! `rollback` / `pre_apply` when the module doesn't opt in via its
//! `iac_methods` export.
//!
//! Phase 7di.1: Provider trait body is shared via
//! [`crate::plugin::PluginProvider`]; what's left here is the
//! transport-only `PluginRuntime` impl on top of [`WasmRuntime`].

use super::runtime::WasmRuntime;
use super::spec::WasmProviderSpec;
use crate::plugin::{CapabilityKeysStrategy, PluginProvider, PluginRuntime};
use iac_core::{Error, Result};
use parking_lot::Mutex;
use serde_json::Value as Json;
use std::sync::Arc;

/// Transport-only struct: holds the `WasmRuntime` plus a lazily-
/// computed cache of optional methods the module exports.
pub struct WasmRuntimeAdapter {
    runtime: Arc<WasmRuntime>,
    /// Methods the module opted into beyond the required pair. Filled
    /// on first use (lazy because reading the export instantiates the
    /// module — we'd rather pay that once, on first observe).
    optional_methods: Mutex<Option<Vec<String>>>,
}

impl std::fmt::Debug for WasmRuntimeAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmRuntimeAdapter")
            .field("kind", &self.runtime.kind())
            .finish()
    }
}

/// Public-facing alias kept for source compatibility with the agent
/// and tests.
pub type WasmProvider = PluginProvider<WasmRuntimeAdapter>;

impl WasmRuntimeAdapter {
    pub fn new(spec: WasmProviderSpec) -> std::result::Result<Self, String> {
        spec.validate()?;
        let runtime = WasmRuntime::new(spec).map_err(|e| format!("{e:?}"))?;
        runtime.validate_kind().map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            runtime: Arc::new(runtime),
            optional_methods: Mutex::new(None),
        })
    }

    /// Internal-test path that takes a pre-built runtime.
    #[cfg(test)]
    pub(crate) fn from_runtime(runtime: WasmRuntime) -> Self {
        Self {
            runtime: Arc::new(runtime),
            optional_methods: Mutex::new(None),
        }
    }

    /// Wrap into the shared `PluginProvider`.
    pub fn into_provider(self) -> WasmProvider {
        PluginProvider::new(self)
    }
}

impl PluginRuntime for WasmRuntimeAdapter {
    fn kind(&self) -> &str {
        self.runtime.kind()
    }

    fn call(&self, method: &str, params: Json) -> Result<Json> {
        // Encode → call → decode. The WasmRuntime's `call` takes a
        // byte slice and returns a string for historical reasons; we
        // adapt at the trait boundary so the rest of the plugin
        // module sees pure JSON.
        let bytes = serde_json::to_vec(&params)
            .map_err(|e| Error::provider(self.runtime.kind(), format!("encode {method}: {e}")))?;
        let resp = self.runtime.call(method, &bytes)?;
        if resp.is_empty() {
            return Ok(Json::Null);
        }
        serde_json::from_str(&resp).map_err(|e| {
            Error::provider(
                self.runtime.kind(),
                format!("decode {method}: {e}: {resp:?}"),
            )
        })
    }

    fn supports(&self, method: &str) -> bool {
        let mut slot = self.optional_methods.lock();
        if slot.is_none() {
            // Best-effort: a failure here means the plugin's
            // `iac_methods` is malformed. Fail-closed (treat as no
            // optional methods) — the host fallbacks always work.
            *slot = Some(self.runtime.read_methods().unwrap_or_default());
        }
        slot.as_ref()
            .map(|m| m.iter().any(|x| x == method))
            .unwrap_or(false)
    }

    fn capability_keys_strategy(&self) -> CapabilityKeysStrategy {
        // WASM plugins compute keys themselves via the optional
        // `iac_capability_keys(envelope) -> Vec<String>` export.
        // Unlike shellout/external-process we don't take templates
        // from a hello message — the plugin reaches into nested spec
        // fields without us inventing a template language.
        CapabilityKeysStrategy::Plugin
    }
}

#[cfg(test)]
mod tests {
    use super::super::spec::WasmRuntimeKind;
    use super::*;
    use iac_core::diff::DiffKind;
    use iac_core::operation::StepStatus;
    use iac_core::provider::{ApplyContext, Provider};
    use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
    use indexmap::IndexMap;
    use serde_yaml_ng::Value as YamlValue;

    /// Same `iac_observe` plugin from `runtime::tests::fixture_wat`
    /// but with the apply path also returning a real JSON object so
    /// the Provider trait round-trips end-to-end.
    fn fixture_wat() -> &'static str {
        r#"
(module
  (memory (export "memory") 1)
  (data (i32.const 16) "test.kind")
  (data (i32.const 64) "{\"present\":false}")
  (data (i32.const 128) "{\"status\":\"ok\",\"message\":\"applied\"}")
  (data (i32.const 256) "[]")
  (global $next (mut i32) (i32.const 4096))
  (func (export "iac_alloc") (param $size i32) (result i32)
    (local $ret i32)
    (local.set $ret (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $size)))
    (local.get $ret))
  (func (export "iac_dealloc") (param i32 i32) nop)
  (func (export "iac_kind") (result i64)
    (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 9)))
  (func (export "iac_observe") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.const 64) (i64.const 32)) (i64.const 17)))
  (func (export "iac_apply") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.const 128) (i64.const 32)) (i64.const 35)))
  (func (export "iac_methods") (result i64)
    (i64.or (i64.shl (i64.const 256) (i64.const 32)) (i64.const 2)))
)
"#
    }

    fn build_provider() -> WasmProvider {
        let bytes = wat::parse_str(fixture_wat()).unwrap();
        let spec = WasmProviderSpec {
            kind: "test.kind".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 10_000_000,
            runtime: WasmRuntimeKind::Core,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let runtime = WasmRuntime::from_bytes(spec, &bytes).unwrap();
        runtime.validate_kind().unwrap();
        WasmRuntimeAdapter::from_runtime(runtime).into_provider()
    }

    fn mk_resource(name: &str, spec_yaml: &str) -> Resource {
        let spec: YamlValue = serde_yaml_ng::from_str(spec_yaml).unwrap();
        Resource {
            api_version: API_VERSION.into(),
            kind: "test.kind".into(),
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

    #[test]
    fn full_create_path_through_provider_trait() {
        let p = build_provider();
        let res = mk_resource("widget1", "name: widget1\nvalue: 42\n");

        // Plugin says present=false → diff should be Create.
        let observed = p.observe(&res).unwrap();
        assert!(!observed.present);

        let diff = p.diff(&res, &observed).unwrap();
        assert_eq!(diff.kind, DiffKind::Create);

        let steps = p.plan(&res, &diff).unwrap();
        assert_eq!(steps.len(), 1);
        // Phase 7di.1: action prefix unified — was "wasm-create".
        assert_eq!(steps[0].action, "plugin-create");

        let ctx = ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: std::path::PathBuf::from("/tmp"),
        };
        let r = p.apply(&res, &steps[0], &ctx).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        assert!(r.message.contains("applied"));
    }
}
