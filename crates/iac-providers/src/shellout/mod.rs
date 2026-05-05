//! Phase 7db.1: declarative shell-out providers.
//!
//! Operators add custom resource kinds without writing Rust:
//!
//! ```toml
//! # agent.toml
//! [[shellout_providers]]
//! kind = "ufw.rule"
//! observe = "/usr/local/bin/iac-ufw observe"
//! apply = "/usr/local/bin/iac-ufw apply"
//! capability_keys = ["{{ name }}"]
//! ```
//!
//! Each command speaks JSON over stdin/stdout. See
//! [`provider`] for the wire protocol and lifecycle.
//!
//! Tradeoff vs. Rust providers: shell-out gives up structured rollback
//! and rich diff output (only top-level field changes are surfaced),
//! but adds zero compile-time coupling. Use it when wrapping an
//! existing CLI; promote to a real provider when you need typed spec
//! validation or per-step checkpoints.

mod provider;
mod spec;

pub use provider::{ShellOutProvider, ShellOutRuntime};
pub use spec::{split_argv, ShellOutSpec};
