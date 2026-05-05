//! Phase 7di.1: shared dynamic-plugin runtime.
//!
//! Three of the four plugin runtimes (shellout, external-process,
//! wasm-core) used to carry their own `impl Provider for X` block —
//! ~300 LOC each, structurally identical. They all:
//!
//!   * Build the same `{ kind, metadata, spec }` envelope from the
//!     resource.
//!   * Call a method by string name (`"observe"`, `"apply"`, etc.) and
//!     parse the response as JSON.
//!   * Fall back to spec-equality diffing when the plugin doesn't
//!     opt into `"diff"`.
//!   * Synthesise one Step per non-trivial diff in `plan()`.
//!   * Snapshot prior observed state in `pre_apply` when the plugin
//!     doesn't opt into a custom snapshot.
//!   * Re-observe + diff in `verify` when the plugin doesn't opt in.
//!   * Synthesise an apply against the prior snapshot in `rollback`
//!     when the plugin doesn't opt in.
//!   * Render `{{ field }}` templates against the resource spec in
//!     `capability_keys`.
//!
//! Every difference between the three was in the *transport layer*:
//! how does invoking `"observe"` actually reach the plugin? They
//! share everything else. This module isolates the transport behind
//! [`PluginRuntime`] and provides a single [`PluginProvider`] that
//! carries the rest.
//!
//! The fourth runtime — wasm-component — uses typed WIT bindings and
//! does **not** fit this abstraction. It keeps its own Provider impl
//! and is intentionally out of scope here.

mod provider;
mod runtime;

pub use provider::PluginProvider;
pub use runtime::{CapabilityKeysStrategy, PluginRuntime};
