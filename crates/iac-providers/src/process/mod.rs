//! Phase 7db.2: external-process plugin providers.
//!
//! ```toml
//! # agent.toml
//! [[external_providers]]
//! kind = "k8s.deployment"
//! binary = "/usr/local/bin/iac-k8s-plugin"
//! ```
//!
//! Each plugin is a long-running binary that speaks NDJSON-RPC over
//! stdin/stdout. See [`proto`] for the wire format and [`provider`]
//! for the agent-side driver.
//!
//! Tradeoff vs. [`crate::shellout`]: external plugins keep state
//! across calls (caches, connection pools) — better fit for chatty
//! upstream APIs (Kubernetes, AWS) where per-call spawn would dominate
//! latency. Cost: more involved plugin author bar (read/write loop,
//! id matching) and one persistent process per kind.

mod handle;
pub mod proto;
mod provider;
mod spec;

pub use handle::PluginHandle;
pub use provider::{ExternalProvider, ExternalRuntime};
pub use spec::ExternalProviderSpec;
