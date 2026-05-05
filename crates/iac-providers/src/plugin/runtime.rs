//! Transport-layer trait for dynamic plugins.
//!
//! Implementors hide everything about how the plugin is reached — fork
//! a shell script, ship NDJSON to a long-running daemon, instantiate a
//! WASM module — and present a uniform `call(method, params) -> Json`
//! surface. The shared [`super::PluginProvider`] does the rest.

use iac_core::Result;
use serde_json::Value as Json;

/// How the host should derive a resource's capability keys for a
/// given runtime.
///
/// Most plugin authors are happy with template-based keys: declare
/// `["my-kind:{{ name }}"]` in the spec or in the `hello` message and
/// the host renders it against the resource. A handful of plugins
/// (currently the WASM core runtime, where computed keys are
/// idiomatic and the WIT/host boundary makes templates clumsy) want
/// to compute the keys themselves; they signal that with [`Plugin`].
///
/// [`Plugin`]: CapabilityKeysStrategy::Plugin
#[derive(Debug, Clone)]
pub enum CapabilityKeysStrategy {
    /// Host renders these templates against the resource's top-level
    /// scalar fields via [`iac_core::template::render_yaml_top_scalars`].
    /// Empty list = "no capability keys advertised".
    Templates(Vec<String>),
    /// Host calls the plugin's `"capability_keys"` method (same JSON
    /// envelope as `observe`); plugin returns a JSON array of strings.
    /// If the plugin doesn't implement that method, the host treats
    /// it as "no keys" rather than erroring (matches the pre-7di.1
    /// wasm-core behaviour where the export is optional).
    Plugin,
}

/// Transport layer for a dynamic plugin runtime.
///
/// All required methods MUST be infallible to "just call". Errors
/// propagate as `Err(iac_core::Error::Provider)` from the underlying
/// transport (timeout, malformed reply, plugin crash) — they don't
/// silently degrade.
pub trait PluginRuntime: Send + Sync + std::fmt::Debug {
    /// Resource-kind this runtime serves (e.g. `"file"`, `"my-app"`).
    /// Returned verbatim from `Provider::kind`; baked into envelopes
    /// the plugin sees.
    fn kind(&self) -> &str;

    /// Invoke `method` on the plugin with the JSON `params` envelope.
    /// Returns the plugin's JSON reply. Used for every
    /// pluggable operation: `"observe"`, `"apply"`, `"diff"`,
    /// `"verify"`, `"rollback"`, `"pre_apply"`, and (when the
    /// runtime's [`capability_keys_strategy`] is `Plugin`) the
    /// `"capability_keys"` method.
    ///
    /// The provider only calls this for methods the runtime claims
    /// to support — see [`Self::supports`]. Calls for unsupported
    /// methods may either error or work (test-only paths sometimes
    /// pass through), but the contract is "the host won't ask".
    ///
    /// [`capability_keys_strategy`]: Self::capability_keys_strategy
    fn call(&self, method: &str, params: Json) -> Result<Json>;

    /// Whether the plugin opted into handling `method` beyond the
    /// required minimum (`observe` + `apply`). Plugins that return
    /// `false` here get the host's built-in fallback (spec-equality
    /// diff, observe-snapshot pre_apply, re-observe verify, apply-
    /// against-prior rollback).
    fn supports(&self, method: &str) -> bool;

    /// Where capability keys come from for this runtime. See
    /// [`CapabilityKeysStrategy`] for the variants. Default
    /// implementation is `Templates(vec![])` — "no keys" — so
    /// runtimes that don't care can skip this method.
    fn capability_keys_strategy(&self) -> CapabilityKeysStrategy {
        CapabilityKeysStrategy::Templates(vec![])
    }
}
