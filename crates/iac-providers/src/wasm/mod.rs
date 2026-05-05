//! Phase 7dc: sandboxed WebAssembly plugin providers.
//!
//! ```toml
//! # agent.toml
//! [[wasm_providers]]
//! kind = "ufw.rule"
//! module = "/usr/local/share/iac/plugins/ufw.wasm"
//! max_memory_bytes = 16777216    # 16 MiB
//! fuel_per_call = 100_000_000    # ~100M instructions
//! ```
//!
//! Same JSON envelope as shellout / external-process providers, but
//! the plugin runs inside wasmtime — no filesystem access, no
//! network, no environment, hard-capped memory, fuel-bounded CPU.
//! Right tool for less-trusted plugins (community marketplace,
//! third-party vendors) and CI-shaped reproducible builds (a
//! `.wasm` byte-for-byte identical across linux / macos / windows).
//!
//! See [`runtime`] for the host-side wire format and ABI; see
//! [`provider`] for the agent-facing `Provider` trait wrapper.

mod component;
mod provider;
mod runtime;
pub(crate) mod spec;

pub use component::WasmComponentProvider;
pub use provider::{WasmProvider, WasmRuntimeAdapter};
pub use runtime::WasmRuntime;
pub use spec::{WasiConfig, WasiPreopen, WasmProviderSpec, WasmRuntimeKind};
