//! Phase 7dd: component-model + WIT-typed plugin runtime.
//!
//! Wraps the wasmtime component-model API in a `Provider` impl. The
//! plugin author writes a Rust crate that targets `wasm32-unknown-
//! unknown` with `cargo-component` (or any wit-bindgen language
//! binding), implements the [`iac:plugin/provider`](../../wit/plugin.wit)
//! exports, and ships one `.component.wasm` artifact.
//!
//! Compared to the core-wasm runtime ([`super::WasmProvider`]):
//!
//! * no manual `iac_alloc` / `iac_dealloc` — strings + lists pass as
//!   typed values across the host↔guest boundary;
//! * the `metadata`/`observed` shapes are structured records, not
//!   stringly-typed JSON envelopes the plugin parses by hand;
//! * the same fuel + memory caps still bound execution — this is a
//!   DX upgrade, not a security trade.

use super::spec::{WasiConfig, WasmProviderSpec};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Checkpoint, Step, StepResult, StepStatus},
    provider::{ApplyContext, Provider, VerifyOutcome},
    resource::Resource,
    state::ObservedState,
    Error, Result,
};
use parking_lot::Mutex;
use serde_json::{json, Value as Json};
use serde_yaml_ng::Value as YamlValue;
use std::path::Path;
use wasmtime::component::{Component, Linker as ComponentLinker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiView};

// `bindgen!` synthesises Rust types + a `Plugin` instantiation
// helper from the .wit. We pull in only the world we actually need;
// the macro re-exports `Plugin`, the `iac::plugin::provider` module
// (renamed via `with`), and the typed records.
wasmtime::component::bindgen!({
    world: "plugin",
    path: "wit/plugin.wit",
});

use exports::iac::plugin::provider::{
    ApplyOutcome, DiffKind as WitDiffKind, DiffResult, FieldChange as WitFieldChange,
    Metadata, Observed, Phase, VerifyOutcome as WitVerifyOutcome,
};

/// Component-model variant of [`super::WasmProvider`]. Same wire
/// envelope semantics, different runtime path: the host hands the
/// guest typed values via the canonical-ABI memory layout instead
/// of byte-staged JSON.
pub struct WasmComponentProvider {
    spec: WasmProviderSpec,
    engine: Engine,
    component: Component,
    /// Cached at first instantiation so the `kind` / `methods`
    /// metadata isn't fetched on every call.
    cached_meta: Mutex<Option<CachedMeta>>,
}

#[derive(Clone)]
struct CachedMeta {
    kind: String,
    methods: Vec<String>,
}

/// Per-call host state owned by the wasmtime [`Store`]. Carries the
/// memory limiter, the WASI context (when configured), and the
/// resource table WASI's component-model bindings need.
struct CompState {
    limiter: MemLimiter,
    wasi: WasiCtx,
    resources: ResourceTable,
}

impl WasiView for CompState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.resources
    }
}

struct MemLimiter {
    max_bytes: usize,
}

impl ResourceLimiter for MemLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, anyhow::Error> {
        Ok(desired <= self.max_bytes)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> std::result::Result<bool, anyhow::Error> {
        Ok(true)
    }
}

/// Build a [`WasiCtx`] from the operator's [`WasiConfig`]. Empty
/// config returns a minimal ctx with no I/O — equivalent to "WASI
/// imports exist but every syscall is denied at the capability
/// level".
fn build_wasi(cfg: &WasiConfig) -> Result<WasiCtx> {
    let mut builder = WasiCtxBuilder::new();
    for p in &cfg.preopens {
        let (dir_perms, file_perms) = if p.writable {
            (DirPerms::all(), FilePerms::all())
        } else {
            (DirPerms::READ, FilePerms::READ)
        };
        builder.preopened_dir(&p.host, &p.guest, dir_perms, file_perms).map_err(|e| {
            Error::provider(
                "wasm",
                format!(
                    "preopen {}->{}: {e}",
                    p.host.display(),
                    p.guest
                ),
            )
        })?;
    }
    for kv in &cfg.env {
        if let Some((k, v)) = kv.split_once('=') {
            builder.env(k, v);
        }
    }
    if cfg.inherit_stdout {
        builder.inherit_stdout();
    }
    if cfg.inherit_stderr {
        builder.inherit_stderr();
    }
    if cfg.allow_network {
        builder.inherit_network();
    }
    Ok(builder.build())
}

impl std::fmt::Debug for WasmComponentProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmComponentProvider")
            .field("kind", &self.spec.kind)
            .finish()
    }
}

impl WasmComponentProvider {
    pub fn new(spec: WasmProviderSpec) -> std::result::Result<Self, String> {
        spec.validate()?;
        let inner = Self::build(spec).map_err(|e| format!("{e:?}"))?;
        // Validate the kind once at construction time so a misnamed
        // .component.wasm doesn't lurk until the first observe.
        inner.refresh_meta().map_err(|e| format!("{e:?}"))?;
        if let Some(m) = inner.cached_meta.lock().as_ref()
            && m.kind != inner.spec.kind
        {
            return Err(format!(
                "module reports kind={:?}, config expects {:?}",
                m.kind, inner.spec.kind
            ));
        }
        Ok(inner)
    }

    fn build(spec: WasmProviderSpec) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config).map_err(|e| {
            Error::provider(&spec.kind, format!("wasmtime engine init: {e}"))
        })?;
        let bytes = std::fs::read(&spec.module).map_err(|e| {
            Error::provider(
                &spec.kind,
                format!("read component {}: {e}", spec.module.display()),
            )
        })?;
        // Phase 7dh.4: pin verification before compile, mirroring
        // the core-wasm path. The check is identical for both
        // runtimes — pinned hash matches sha256 of the raw bytes
        // on disk.
        if let Some(expected) = spec.module_sha256.as_deref() {
            super::spec::verify_sha256(&bytes, expected, "module").map_err(|e| {
                Error::provider(&spec.kind, e)
            })?;
        }
        let component = Component::new(&engine, &bytes).map_err(|e| {
            Error::provider(
                &spec.kind,
                format!("compile component {}: {e}", spec.module.display()),
            )
        })?;
        Ok(Self {
            spec,
            engine,
            component,
            cached_meta: Mutex::new(None),
        })
    }

    /// Test-only constructor that takes pre-compiled component bytes
    /// in memory. The `wit-component` crate lets tests roll their
    /// own components from WAT without writing a fixture file.
    #[cfg(test)]
    pub fn from_component_bytes(
        spec: WasmProviderSpec,
        bytes: &[u8],
    ) -> std::result::Result<Self, String> {
        spec.validate()?;
        let mut config = Config::new();
        config.consume_fuel(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config).map_err(|e| format!("engine init: {e}"))?;
        let component =
            Component::new(&engine, bytes).map_err(|e| format!("component compile: {e}"))?;
        let inner = Self {
            spec,
            engine,
            component,
            cached_meta: Mutex::new(None),
        };
        inner.refresh_meta().map_err(|e| format!("{e:?}"))?;
        Ok(inner)
    }

    fn store(&self) -> Result<Store<CompState>> {
        let wasi = build_wasi(&self.spec.wasi)?;
        let mut store = Store::new(
            &self.engine,
            CompState {
                limiter: MemLimiter {
                    max_bytes: usize::try_from(self.spec.max_memory_bytes)
                        .unwrap_or(usize::MAX),
                },
                wasi,
                resources: ResourceTable::new(),
            },
        );
        store.limiter(|s| &mut s.limiter);
        let _ = store.set_fuel(self.spec.fuel_per_call);
        Ok(store)
    }

    fn instantiate(
        &self,
        store: &mut Store<CompState>,
    ) -> Result<Plugin> {
        let mut linker: ComponentLinker<CompState> = ComponentLinker::new(&self.engine);
        // Phase 7de: register WASI preview2 imports only when the
        // operator opted in. Empty config keeps the linker pristine
        // — plugins that never reference `wasi:*` interfaces don't
        // pay the linker setup cost. wasmtime-wasi 26 splits the
        // surface into sync vs async; the sync variant matches our
        // synchronous `Provider::observe` blocking-pool model.
        if !self.spec.wasi.is_empty() {
            wasmtime_wasi::add_to_linker_sync(&mut linker).map_err(|e| {
                Error::provider(&self.spec.kind, format!("link wasi: {e}"))
            })?;
        }
        Plugin::instantiate(store, &self.component, &linker).map_err(|e| {
            Error::provider(&self.spec.kind, format!("instantiate component: {e}"))
        })
    }

    fn refresh_meta(&self) -> Result<()> {
        let mut store = self.store()?;
        let plugin = self.instantiate(&mut store)?;
        let prov = plugin.iac_plugin_provider();
        let kind = prov.call_kind(&mut store).map_err(|e| {
            Error::provider(&self.spec.kind, format!("kind(): {e}"))
        })?;
        let methods = prov.call_methods(&mut store).map_err(|e| {
            Error::provider(&self.spec.kind, format!("methods(): {e}"))
        })?;
        *self.cached_meta.lock() = Some(CachedMeta { kind, methods });
        Ok(())
    }

    fn supports(&self, method: &str) -> bool {
        self.cached_meta
            .lock()
            .as_ref()
            .map(|m| m.methods.iter().any(|x| x == method))
            .unwrap_or(false)
    }

    fn metadata_for(resource: &Resource) -> Metadata {
        Metadata {
            name: resource.metadata.name.clone(),
            environment: resource.metadata.environment.clone(),
            labels: resource
                .metadata
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            annotations: resource
                .metadata
                .annotations
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    fn spec_json(resource: &Resource) -> String {
        serde_json::to_string(&yaml_to_json(&resource.spec)).unwrap_or_else(|_| "null".into())
    }
}

impl Provider for WasmComponentProvider {
    fn kind(&self) -> &str {
        &self.spec.kind
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let mut store = self.store()?;
        let plugin = self.instantiate(&mut store)?;
        let prov = plugin.iac_plugin_provider();
        let result = prov
            .call_observe(&mut store, &Self::metadata_for(resource), &Self::spec_json(resource))
            .map_err(|e| Error::provider(&self.spec.kind, format!("observe call: {e}")))?;
        let observed: Observed = result
            .map_err(|msg| Error::provider(&self.spec.kind, format!("observe: {msg}")))?;
        if observed.present {
            let v: Json = serde_json::from_str(&observed.spec_json).map_err(|e| {
                Error::provider(
                    &self.spec.kind,
                    format!("observe spec-json parse: {e}: {:?}", observed.spec_json),
                )
            })?;
            Ok(ObservedState::present(json_to_yaml(&v)))
        } else {
            Ok(ObservedState::absent())
        }
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        // Phase 7df: typed diff export. Plugins that opted into
        // `"diff"` via their `methods()` get full control over the
        // comparison; everyone else falls through to spec-equality
        // diffing. The WIT shape mirrors the host's `Diff` exactly
        // — only the JSON-encoded `from`/`to` payloads need
        // converting back to the host's YAML `Value`.
        if self.supports("diff") {
            let mut store = self.store()?;
            let plugin = self.instantiate(&mut store)?;
            let prov = plugin.iac_plugin_provider();
            let observed_wit = observed_to_wit(observed);
            let result = prov
                .call_diff(
                    &mut store,
                    &Self::metadata_for(resource),
                    &Self::spec_json(resource),
                    &observed_wit,
                )
                .map_err(|e| {
                    Error::provider(&self.spec.kind, format!("diff call: {e}"))
                })?;
            return Ok(diff_from_wit(result));
        }

        let desired_absent = matches!(
            spec_state_field(&resource.spec).as_deref(),
            Some("absent")
        );
        match (observed.present, desired_absent) {
            (false, true) => Ok(Diff::no_change()),
            (false, false) => Ok(Diff {
                kind: DiffKind::Create,
                changes: vec![],
                reasons: vec!["resource absent on host".into()],
                reversible: true,
            }),
            (true, true) => Ok(Diff {
                kind: DiffKind::Delete,
                changes: vec![],
                reasons: vec!["state=absent and resource present".into()],
                reversible: true,
            }),
            (true, false) => {
                let want = yaml_to_json(&resource.spec);
                let have = yaml_to_json(&observed.spec);
                if want == have {
                    Ok(Diff::no_change())
                } else {
                    Ok(Diff {
                        kind: DiffKind::Update,
                        changes: collect_top_level_changes(&want, &have),
                        reasons: vec!["spec differs from observed".into()],
                        reversible: true,
                    })
                }
            }
        }
    }

    fn plan(&self, _resource: &Resource, diff: &Diff) -> Result<Vec<Step>> {
        if !diff.is_change() {
            return Ok(vec![]);
        }
        let action = match diff.kind {
            DiffKind::Create => "wasm-component-create",
            DiffKind::Update => "wasm-component-update",
            DiffKind::Delete => "wasm-component-delete",
            DiffKind::NoChange => unreachable!("filtered above"),
        };
        Ok(vec![Step::new(
            action,
            format!("{action} via {}", self.spec.kind),
            Json::Null,
        )])
    }

    fn pre_apply(
        &self,
        resource: &Resource,
        _step: &Step,
        _ctx: &ApplyContext,
    ) -> Result<Json> {
        // Phase 7dg: typed pre-apply opt-in. The plugin returns a
        // JSON-encoded checkpoint string we wrap in a tagged
        // envelope so `rollback` can route it back to the typed
        // path even if the plugin's `methods()` list mutates
        // between calls (a binary swap shouldn't desync the two).
        if self.supports("pre-apply") {
            let mut store = self.store()?;
            let plugin = self.instantiate(&mut store)?;
            let prov = plugin.iac_plugin_provider();
            let result = prov
                .call_pre_apply(
                    &mut store,
                    &Self::metadata_for(resource),
                    &Self::spec_json(resource),
                )
                .map_err(|e| {
                    Error::provider(&self.spec.kind, format!("pre-apply call: {e}"))
                })?;
            let checkpoint_json = result.map_err(|msg| {
                Error::provider(&self.spec.kind, format!("pre-apply: {msg}"))
            })?;
            return Ok(json!({
                "wit_checkpoint": checkpoint_json,
            }));
        }
        // Host fallback: snapshot via observe.
        let observed = self.observe(resource)?;
        Ok(json!({
            "prior_present": observed.present,
            "prior_spec": yaml_to_json(&observed.spec),
        }))
    }

    fn apply(
        &self,
        resource: &Resource,
        step: &Step,
        _ctx: &ApplyContext,
    ) -> Result<StepResult> {
        let phase = match step.action.as_str() {
            "wasm-component-create" => Phase::Create,
            "wasm-component-update" => Phase::Update,
            "wasm-component-delete" => Phase::Delete,
            other => {
                return Err(Error::provider(
                    &self.spec.kind,
                    format!("unknown step action {other:?}"),
                ));
            }
        };
        let mut store = self.store()?;
        let plugin = self.instantiate(&mut store)?;
        let prov = plugin.iac_plugin_provider();
        let outcome: ApplyOutcome = prov
            .call_apply(
                &mut store,
                &Self::metadata_for(resource),
                &Self::spec_json(resource),
                phase,
            )
            .map_err(|e| Error::provider(&self.spec.kind, format!("apply call: {e}")))?;
        let label = match phase {
            Phase::Create => "create",
            Phase::Update => "update",
            Phase::Delete => "delete",
        };
        if outcome.ok {
            Ok(StepResult::ok(if outcome.message.is_empty() {
                format!("{label} via {}", self.spec.kind)
            } else {
                outcome.message
            }))
        } else {
            Ok(StepResult {
                status: StepStatus::Failed,
                message: outcome.message.clone(),
                data: Json::Null,
                error: Some(outcome.message),
            })
        }
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        // Phase 7df: typed verify export. Same opt-in pattern as
        // `diff` — plugin lists `"verify"` in its `methods()` to
        // override the host's re-observe-and-diff fallback.
        if self.supports("verify") {
            let mut store = self.store()?;
            let plugin = self.instantiate(&mut store)?;
            let prov = plugin.iac_plugin_provider();
            let outcome = prov
                .call_verify(
                    &mut store,
                    &Self::metadata_for(resource),
                    &Self::spec_json(resource),
                )
                .map_err(|e| {
                    Error::provider(&self.spec.kind, format!("verify call: {e}"))
                })?;
            return Ok(verify_from_wit(outcome));
        }
        let observed = self.observe(resource)?;
        let d = self.diff(resource, &observed)?;
        if matches!(d.kind, DiffKind::NoChange) {
            Ok(VerifyOutcome::Match)
        } else {
            Ok(VerifyOutcome::Mismatch(d.changes))
        }
    }

    fn rollback(
        &self,
        resource: &Resource,
        checkpoint: &Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        // Phase 7dg: typed rollback opt-in. We route through the
        // typed path under TWO conditions:
        //   * the plugin currently lists `"rollback"`, AND
        //   * the checkpoint actually came from `pre-apply` (we
        //     tagged it `wit_checkpoint`).
        // Both gates matter — they let an operator hot-swap a
        // plugin from non-typed to typed (or vice versa) without
        // breaking inflight rollbacks.
        let typed_checkpoint = checkpoint
            .data
            .get("wit_checkpoint")
            .and_then(|v| v.as_str())
            .map(String::from);
        if let Some(cp) = typed_checkpoint
            && self.supports("rollback")
        {
            let mut store = self.store()?;
            let plugin = self.instantiate(&mut store)?;
            let prov = plugin.iac_plugin_provider();
            let result = prov
                .call_rollback(&mut store, &Self::metadata_for(resource), &cp)
                .map_err(|e| {
                    Error::provider(&self.spec.kind, format!("rollback call: {e}"))
                })?;
            return result.map_err(|msg| {
                Error::provider(&self.spec.kind, format!("rollback: {msg}"))
            });
        }
        // Host fallback: synthesise an apply against the prior
        // observed state. Reads the host-shaped checkpoint shape
        // (`prior_present` / `prior_spec`).
        let prior_present = checkpoint
            .data
            .get("prior_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let prior_spec = checkpoint
            .data
            .get("prior_spec")
            .cloned()
            .unwrap_or(Json::Null);
        let phase = if prior_present {
            Phase::Update
        } else {
            Phase::Delete
        };
        let mut store = self.store()?;
        let plugin = self.instantiate(&mut store)?;
        let prov = plugin.iac_plugin_provider();
        let outcome: ApplyOutcome = prov
            .call_apply(
                &mut store,
                &Self::metadata_for(resource),
                &serde_json::to_string(&prior_spec).unwrap_or_else(|_| "null".into()),
                phase,
            )
            .map_err(|e| {
                Error::provider(&self.spec.kind, format!("rollback apply call: {e}"))
            })?;
        if !outcome.ok {
            return Err(Error::provider(
                &self.spec.kind,
                format!(
                    "rollback failed: {}",
                    if outcome.message.is_empty() {
                        "no message"
                    } else {
                        &outcome.message
                    }
                ),
            ));
        }
        Ok(())
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let mut store = self.store()?;
        let plugin = self.instantiate(&mut store)?;
        let prov = plugin.iac_plugin_provider();
        prov.call_capability_keys(
            &mut store,
            &Self::metadata_for(resource),
            &Self::spec_json(resource),
        )
        .map_err(|e| Error::provider(&self.spec.kind, format!("capability_keys: {e}")))
    }
}

// Phase 7di.2: yaml↔json + diff change-collection moved to
// `iac_core::convert`. Provider-local `spec_state_field` stays.
use iac_core::convert::{collect_top_level_changes, json_to_yaml, yaml_to_json};

fn spec_state_field(spec: &YamlValue) -> Option<String> {
    spec.as_mapping()
        .and_then(|m| m.get(YamlValue::String("state".into())))
        .and_then(|v| v.as_str())
        .map(String::from)
}

// ---- Phase 7df: WIT ↔ host type conversions for diff/verify ----------------

fn observed_to_wit(observed: &ObservedState) -> Observed {
    Observed {
        present: observed.present,
        spec_json: if observed.present {
            serde_json::to_string(&yaml_to_json(&observed.spec))
                .unwrap_or_else(|_| "null".into())
        } else {
            String::new()
        },
    }
}

fn diff_from_wit(d: DiffResult) -> Diff {
    Diff {
        kind: match d.kind {
            WitDiffKind::NoChange => DiffKind::NoChange,
            WitDiffKind::Create => DiffKind::Create,
            WitDiffKind::Update => DiffKind::Update,
            WitDiffKind::Delete => DiffKind::Delete,
        },
        changes: d.changes.into_iter().map(field_change_from_wit).collect(),
        reasons: d.reasons,
        reversible: d.reversible,
    }
}

fn field_change_from_wit(c: WitFieldChange) -> FieldChange {
    FieldChange {
        field: c.field,
        from: c.from_json.and_then(parse_json_to_yaml),
        to: c.to_json.and_then(parse_json_to_yaml),
        sensitive: c.sensitive,
    }
}

fn parse_json_to_yaml(s: String) -> Option<YamlValue> {
    if s.is_empty() {
        return None;
    }
    let v: Json = serde_json::from_str(&s).ok()?;
    Some(json_to_yaml(&v))
}

fn verify_from_wit(o: WitVerifyOutcome) -> VerifyOutcome {
    match o {
        WitVerifyOutcome::Ok => VerifyOutcome::Match,
        WitVerifyOutcome::Mismatch(changes) => VerifyOutcome::Mismatch(
            changes.into_iter().map(field_change_from_wit).collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use iac_core::resource::{Metadata, Resource, SourceLocation, API_VERSION};

    #[test]
    fn rejects_core_wasm_as_component() {
        let core_wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "noop"))
            )
        "#;
        let core_bytes = wat::parse_str(core_wat).unwrap();
        let spec = WasmProviderSpec {
            kind: "x".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 1024 * 1024,
            fuel_per_call: 1_000_000,
            runtime: super::super::spec::WasmRuntimeKind::Component,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let err =
            WasmComponentProvider::from_component_bytes(spec, &core_bytes).unwrap_err();
        assert!(
            err.contains("compile") || err.contains("component"),
            "expected component-compile error, got: {err}"
        );
    }

    #[test]
    fn rejects_garbage_bytes() {
        let spec = WasmProviderSpec {
            kind: "x".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 1024 * 1024,
            fuel_per_call: 1_000_000,
            runtime: super::super::spec::WasmRuntimeKind::Component,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        let err = WasmComponentProvider::from_component_bytes(spec, b"not wasm")
            .unwrap_err();
        assert!(!err.is_empty());
    }

    /// Path to the cdylib core-wasm that `tests/fixtures/test-plugin`
    /// produces. The file gets built on demand by `componentise_fixture`
    /// below; if that bootstrap can't run (missing wasm32 target,
    /// offline cargo cache) the fixture-dependent tests skip.
    fn fixture_core_wasm_path() -> std::path::PathBuf {
        let crate_dir = env!("CARGO_MANIFEST_DIR");
        std::path::PathBuf::from(crate_dir)
            .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/iac_test_component_plugin.wasm")
    }

    /// Read the fixture's core wasm and wrap it as a WIT component
    /// using `wit_component::ComponentEncoder`. Skipped (returns
    /// `None`) when the fixture artifact isn't on disk — keeps the
    /// suite green on machines without `wasm32-unknown-unknown`.
    fn componentise_fixture() -> Option<Vec<u8>> {
        let core = std::fs::read(fixture_core_wasm_path()).ok()?;
        let bytes = wit_component::ComponentEncoder::default()
            .module(&core)
            .ok()?
            .validate(true)
            .encode()
            .ok()?;
        Some(bytes)
    }

    fn mk_resource(name: &str, spec_yaml: &str) -> Resource {
        let spec: YamlValue = serde_yaml_ng::from_str(spec_yaml).unwrap();
        Resource {
            api_version: API_VERSION.into(),
            kind: "test.plugin".into(),
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

    fn build_provider() -> Option<WasmComponentProvider> {
        let bytes = componentise_fixture()?;
        let spec = WasmProviderSpec {
            kind: "test.plugin".into(),
            module: "/dev/null".into(),
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 100_000_000,
            runtime: super::super::spec::WasmRuntimeKind::Component,
            wasi: super::super::spec::WasiConfig::default(),
            module_sha256: None,
        };
        WasmComponentProvider::from_component_bytes(spec, &bytes).ok()
    }

    #[test]
    fn observe_present_branch() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: build the fixture with `cargo build --release --target wasm32-unknown-unknown` in tests/fixtures/test-plugin");
            return;
        };
        // The fixture reports present iff the resource name starts
        // with "exists-" — this exercises the present branch.
        let res = mk_resource("exists-1", "name: exists-1\n");
        let observed = p.observe(&res).unwrap();
        assert!(observed.present);
    }

    #[test]
    fn observe_absent_branch() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("missing-thing", "name: missing-thing\n");
        let observed = p.observe(&res).unwrap();
        assert!(!observed.present);
    }

    #[test]
    fn full_create_flow() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("missing-x", "name: missing-x\n");
        let observed = p.observe(&res).unwrap();
        let diff = p.diff(&res, &observed).unwrap();
        assert_eq!(diff.kind, DiffKind::Create);

        let steps = p.plan(&res, &diff).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "wasm-component-create");

        let ctx = ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: std::path::PathBuf::from("/tmp"),
        };
        let r = p.apply(&res, &steps[0], &ctx).unwrap();
        assert_eq!(r.status, StepStatus::Succeeded);
        assert!(
            r.message.contains("create missing-x via test.plugin"),
            "got: {}",
            r.message
        );
    }

    #[test]
    fn capability_keys_round_trip() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("widget-7", "name: widget-7\n");
        let keys = p.capability_keys(&res).unwrap();
        assert_eq!(keys, vec!["widget-7"]);
    }

    /// Phase 7df: the fixture opts into typed `diff` via its
    /// `methods()` list. When the resource isn't observed
    /// (`missing-*`), the plugin's diff returns Create with one
    /// structured field-change ("spec.name") and a custom reason.
    /// Confirms host wires through to the typed export.
    #[test]
    fn typed_diff_routes_through_plugin() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("missing-x", "name: missing-x\n");
        let observed = p.observe(&res).unwrap();
        let d = p.diff(&res, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::Create);
        assert!(
            d.reasons.iter().any(|r| r.contains("typed-diff")),
            "expected plugin's reason in {:?}",
            d.reasons
        );
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].field, "spec.name");
    }

    /// Same fixture, present branch: the plugin's typed diff
    /// returns NoChange with no field-changes.
    #[test]
    fn typed_diff_no_change_path() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("exists-1", "name: exists-1\n");
        let observed = p.observe(&res).unwrap();
        let d = p.diff(&res, &observed).unwrap();
        assert_eq!(d.kind, DiffKind::NoChange);
        assert!(d.changes.is_empty());
    }

    /// Phase 7df: typed verify routes through the plugin's typed
    /// export. The fixture returns `Ok` for "exists-*" names and
    /// `Mismatch(_)` otherwise.
    #[test]
    fn typed_verify_match_branch() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("exists-2", "name: exists-2\n");
        let outcome = p.verify(&res).unwrap();
        assert!(outcome.is_match(), "expected Match, got {outcome:?}");
    }

    #[test]
    fn typed_verify_mismatch_branch() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("missing-y", "name: missing-y\n");
        let outcome = p.verify(&res).unwrap();
        match outcome {
            VerifyOutcome::Mismatch(changes) => {
                assert_eq!(changes.len(), 1);
                assert_eq!(changes[0].field, "spec.name");
            }
            VerifyOutcome::Match => panic!("expected Mismatch, got Match"),
        }
    }

    /// Phase 7dg: typed pre-apply round-trip. Plugin returns its
    /// own JSON-encoded checkpoint; host wraps it in
    /// `{ "wit_checkpoint": "..." }`. Then rollback unwraps and
    /// hands the inner string back to the plugin verbatim.
    #[test]
    fn typed_pre_apply_then_rollback_round_trip() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("checkpoint-x", "name: checkpoint-x\n");
        let ctx = ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: std::path::PathBuf::from("/tmp"),
        };
        let step = iac_core::operation::Step::new(
            "wasm-component-create",
            "test",
            serde_json::Value::Null,
        );
        let cp_value = p.pre_apply(&res, &step, &ctx).unwrap();
        // Host envelope holds the plugin's JSON string verbatim.
        let inner = cp_value
            .get("wit_checkpoint")
            .and_then(|v| v.as_str())
            .expect("wit_checkpoint envelope");
        assert!(inner.contains(r#""plugin":"test.plugin""#));
        assert!(inner.contains(r#""pre_name":"checkpoint-x""#));

        // Now drive rollback against this checkpoint.
        let checkpoint = iac_core::operation::Checkpoint::new(
            iac_core::ResourceId::new("test.plugin", "test", "checkpoint-x"),
            ctx.operation_id,
            cp_value,
        );
        p.rollback(&res, &checkpoint, &ctx.workspace).unwrap();
    }

    /// Phase 7dg: typed rollback fails loudly when the plugin's
    /// validation rejects the checkpoint. Confirms errors round-trip
    /// from the WIT `result<_, string>` failure variant back to the
    /// host's `Error::Provider`.
    #[test]
    fn typed_rollback_propagates_plugin_error() {
        let Some(p) = build_provider() else {
            eprintln!("skipping: fixture not built");
            return;
        };
        let res = mk_resource("checkpoint-y", "name: checkpoint-y\n");
        // Build a checkpoint manually with the typed envelope but
        // a payload that the plugin's validator will reject (the
        // fixture checks `"pre_name":"<metadata.name>"` and we
        // ship a name that won't match).
        let cp_value = serde_json::json!({
            "wit_checkpoint": r#"{"plugin":"test.plugin","pre_name":"DIFFERENT","pre_spec_len":42}"#,
        });
        let checkpoint = iac_core::operation::Checkpoint::new(
            iac_core::ResourceId::new("test.plugin", "test", "checkpoint-y"),
            ulid::Ulid::new(),
            cp_value,
        );
        let err = p
            .rollback(&res, &checkpoint, std::path::Path::new("/tmp"))
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("rollback") && msg.contains("pre_name"),
            "expected plugin's rollback error, got: {msg}"
        );
    }
}
