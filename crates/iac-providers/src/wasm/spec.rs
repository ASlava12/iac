//! Phase 7dc: WebAssembly plugin provider config.
//!
//! ```toml
//! [[wasm_providers]]
//! kind = "ufw.rule"                     # required
//! module = "/usr/local/share/iac/plugins/ufw.wasm"
//! max_memory_bytes = 16777216           # 16 MiB, default 16 MiB
//! fuel_per_call = 100_000_000           # 100M instructions, default 100M
//! ```
//!
//! `kind` must match the kind the module reports via its `iac_kind`
//! export (defence-in-depth: catches binary/config drift the same
//! way external-process providers do).
//!
//! ### Why fuel + memory limits
//!
//! WASM is a CPU-shaped abstraction; without limits a buggy or
//! malicious plugin could spin a hot loop or grow memory until the
//! agent OOMs. Wasmtime's fuel mechanism decrements a counter on
//! every instruction, trapping the guest at 0. Memory growth is
//! capped via the `ResourceLimiter` API. Both knobs are config
//! defaults — operators raise them for legitimate workloads.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasmProviderSpec {
    /// Resource kind handled by this plugin.
    pub kind: String,

    /// Absolute path to the `.wasm` module on disk.
    pub module: PathBuf,

    /// Hard cap on the linear-memory pages the plugin may grow into,
    /// in bytes. Default 16 MiB. Plugins that exceed this trap.
    #[serde(default = "default_max_memory")]
    pub max_memory_bytes: u64,

    /// Wasmtime fuel allocated per top-level method call. Each WASM
    /// instruction burns roughly one unit; 100M is plenty for typical
    /// observe/apply work but bounds runaway loops to ≤ a few seconds
    /// of wall time on slow CPUs. Default 100_000_000.
    #[serde(default = "default_fuel")]
    pub fuel_per_call: u64,

    /// Phase 7dd: which runtime drives this `.wasm`. `core` (the
    /// default) is the manual `iac_alloc` / `iac_observe` ABI from
    /// Phase 7dc. `component` switches to the WIT-typed component-
    /// model runtime — the plugin must be a `.component.wasm` (built
    /// with `cargo-component` or `wasm-tools component new`).
    #[serde(default)]
    pub runtime: WasmRuntimeKind,

    /// Phase 7de: WASI preview2 capabilities. Only honoured when
    /// `runtime = "component"`. Empty (default) → plugin sees no
    /// filesystem, no env, no stdio — same as the historical 7dc
    /// sandbox. Each opt-in expands the surface in a controlled
    /// way: preopens are bind-style (host path mapped to guest
    /// path), env entries are explicit, stdio is binary on/off.
    #[serde(default)]
    pub wasi: WasiConfig,

    /// Phase 7dh.4: optional content-hash pin on the `.wasm` file.
    /// When set (lowercase 64-char hex), the agent verifies the
    /// SHA-256 of the on-disk module against this value at load
    /// time and refuses to instantiate on mismatch. Operators
    /// pinning hashes via their config-management of choice get
    /// integrity protection against an attacker who can write to
    /// the binary's path on the agent host.
    ///
    /// `None` (default) means "trust the path" — same behaviour
    /// as pre-7dh.4. Recommended for production deployments.
    #[serde(default)]
    pub module_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasiConfig {
    /// Filesystem preopens. Each entry is a `host -> guest` mapping
    /// — the plugin sees `guest` as a root and reads/writes route
    /// to `host`. Operators get directory-level granularity (no
    /// per-file allowlist) which matches WASI preview2's preopen
    /// semantics. Mounting `/etc` is a footgun; mounting
    /// `/var/lib/iac/<plugin>/state` is the recommended pattern.
    #[serde(default)]
    pub preopens: Vec<WasiPreopen>,
    /// Environment variables passed to the plugin. Listed
    /// explicitly — the plugin does NOT inherit the agent's env.
    /// Each entry is `KEY=VALUE`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Inherit the agent's stdout. Default: false (plugin output
    /// is dropped). Useful when porting a CLI-shaped plugin and
    /// you want operator-visible diagnostics — but the agent's
    /// `tracing` pipeline via `iac.log` is the structured path.
    #[serde(default)]
    pub inherit_stdout: bool,
    /// Inherit the agent's stderr. Same caveat as stdout.
    #[serde(default)]
    pub inherit_stderr: bool,
    /// Allow networking imports (sockets, dns lookups). Default:
    /// false. Plugins that genuinely need outbound network are
    /// almost always better served by external-process providers
    /// — but operators with vendor-shipped components occasionally
    /// need the WASI sockets surface.
    #[serde(default)]
    pub allow_network: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WasiPreopen {
    /// Absolute host path the plugin gets access to.
    pub host: PathBuf,
    /// What the plugin sees the directory as. Typically "/" or
    /// "/state". Doesn't have to be an absolute host path on
    /// the agent — it's a guest-side label.
    pub guest: String,
    /// `false` (default) → read-only. `true` → plugin can write.
    /// Read-only is the right default; bump only when you
    /// know the plugin needs to persist state.
    #[serde(default)]
    pub writable: bool,
    /// Phase 7dh.3: explicit opt-in to map host paths the standard
    /// validator otherwise rejects (`/etc`, `/root`, `/proc`, etc.).
    /// Plugins legitimately reading `/etc/os-release` for distro
    /// detection set this; the field exists so that decision is
    /// audit-visible in the operator's `agent.toml`.
    #[serde(default)]
    pub unsafe_host: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WasmRuntimeKind {
    /// Manual ABI: plugin exports `iac_alloc`, `iac_observe`, etc.
    /// Compatible with hand-written WAT and any language that can
    /// produce raw wasm32 + memory. The original Phase 7dc runtime.
    #[default]
    Core,
    /// WIT-typed component-model. Plugin author works with strongly-
    /// typed `Metadata` / `Observed` / `Phase` records via
    /// wit-bindgen. Requires a `.component.wasm` artifact.
    Component,
}

fn default_max_memory() -> u64 {
    16 * 1024 * 1024
}

fn default_fuel() -> u64 {
    100_000_000
}

/// Phase 7dh.4: shared SHA-256-hex format check used by every
/// plugin spec that pins a binary hash. Lowercase, exactly 64
/// hex chars. Reject mixed-case / leading "sha256:" prefixes /
/// whitespace upfront.
// Phase 10: helpers moved to crate-level `sha256_pin` so the
// `process` provider (and any future ones) can share without
// pulling in wasmtime.
pub(crate) use crate::sha256_pin::{validate_sha256_hex, verify_sha256};

/// Phase 7dh.3: host paths the validator refuses to map into a
/// guest unless the operator opts in via `unsafe_host = true` on
/// the preopen entry. The list isn't exhaustive — it's a
/// "common-mistake" filter, not a sandbox boundary. Real OS-level
/// isolation belongs in systemd / namespaces, not config validation.
fn is_sensitive_host_path(p: &std::path::Path) -> bool {
    const SENSITIVE_PREFIXES: &[&str] = &[
        "/etc",
        "/root",
        "/proc",
        "/sys",
        "/dev",
        "/boot",
        "/var/lib/iac-agent",       // agent's own state dir
        "/var/lib/iac-controlplane", // control-plane's state dir
    ];
    let s = p.to_string_lossy();
    for prefix in SENSITIVE_PREFIXES {
        if s == *prefix || s.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }
    false
}

impl WasmProviderSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.kind.is_empty() {
            return Err("kind must not be empty".into());
        }
        if self.kind.chars().any(|c| c.is_whitespace()) {
            return Err(format!("kind {:?} contains whitespace", self.kind));
        }
        if !self.module.is_absolute() {
            return Err(format!(
                "module path {} must be absolute",
                self.module.display()
            ));
        }
        // Lower bound: 64 KiB is one WASM page. Below that the guest
        // can't even allocate its scratch buffer for arguments.
        if self.max_memory_bytes < 64 * 1024 {
            return Err(format!(
                "max_memory_bytes {} below 64 KiB minimum",
                self.max_memory_bytes
            ));
        }
        // Upper bound: 1 GiB. Anything more should be a real provider.
        if self.max_memory_bytes > 1024 * 1024 * 1024 {
            return Err(format!(
                "max_memory_bytes {} above 1 GiB ceiling",
                self.max_memory_bytes
            ));
        }
        if self.fuel_per_call == 0 {
            return Err("fuel_per_call must be > 0".into());
        }
        // Phase 7dh.4: validate hash format upfront so a typo (extra
        // space, mixed case) gets caught at config load, not at
        // first plugin instantiation.
        if let Some(h) = &self.module_sha256 {
            validate_sha256_hex(h, "module_sha256")?;
        }
        // WASI options only make sense for the component runtime —
        // the core ABI doesn't carry preview2 imports. Reject the
        // mismatch loudly so operators don't misconfigure silently.
        if matches!(self.runtime, WasmRuntimeKind::Core) && !self.wasi.is_empty() {
            return Err(
                "wasi.* options require runtime = \"component\"; the core runtime has no WASI imports"
                    .into(),
            );
        }
        for p in &self.wasi.preopens {
            if !p.host.is_absolute() {
                return Err(format!(
                    "wasi.preopens host {} must be absolute",
                    p.host.display()
                ));
            }
            // Phase 7dh.3: reject preopens at sensitive host roots.
            // Operators can override case-by-case with
            // `unsafe_host = true`, which makes the choice visible
            // in `agent.toml` (rather than silently leaving an
            // RCE-shaped misconfig possible).
            if !p.unsafe_host && is_sensitive_host_path(&p.host) {
                return Err(format!(
                    "wasi.preopens host {} maps a sensitive system path; \
                     set `unsafe_host = true` in this preopen to opt in",
                    p.host.display()
                ));
            }
            if p.guest.is_empty() {
                return Err("wasi.preopens guest must not be empty".into());
            }
            // Reject `..` segments in guest path. wasmtime's preopen
            // resolution shouldn't follow them, but defence in
            // depth: a leading `..` collides with a sibling
            // preopen's namespace and is almost never intended.
            if p.guest.split(['/', '\\']).any(|seg| seg == "..") {
                return Err(format!(
                    "wasi.preopens guest {:?} contains '..' segment; \
                     pick a clean root-relative path",
                    p.guest
                ));
            }
        }
        for kv in &self.wasi.env {
            if !kv.contains('=') {
                return Err(format!(
                    "wasi.env entry {kv:?} missing '=' (expected KEY=VALUE)"
                ));
            }
        }
        Ok(())
    }
}

impl WasiConfig {
    /// True iff every field is at default — used to short-circuit
    /// the "no WASI imports needed" path.
    pub fn is_empty(&self) -> bool {
        self.preopens.is_empty()
            && self.env.is_empty()
            && !self.inherit_stdout
            && !self.inherit_stderr
            && !self.allow_network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_spec() -> WasmProviderSpec {
        WasmProviderSpec {
            kind: "k".into(),
            module: "/srv/p.wasm".into(),
            max_memory_bytes: default_max_memory(),
            fuel_per_call: default_fuel(),
            runtime: WasmRuntimeKind::default(),
            wasi: WasiConfig::default(),
            module_sha256: None,
        }
    }

    #[test]
    fn parses_runtime_component() {
        let toml = r#"
kind = "ufw.rule"
module = "/srv/iac/ufw.component.wasm"
runtime = "component"
"#;
        let s: WasmProviderSpec = toml::from_str(toml).unwrap();
        s.validate().unwrap();
        assert_eq!(s.runtime, WasmRuntimeKind::Component);
    }

    #[test]
    fn defaults_to_core_runtime() {
        let toml = r#"
kind = "ufw.rule"
module = "/srv/iac/ufw.wasm"
"#;
        let s: WasmProviderSpec = toml::from_str(toml).unwrap();
        assert_eq!(s.runtime, WasmRuntimeKind::Core);
    }

    #[test]
    fn rejects_empty_kind() {
        let mut s = ok_spec();
        s.kind = String::new();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_relative_module_path() {
        let mut s = ok_spec();
        s.module = "p.wasm".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_too_small_memory() {
        let mut s = ok_spec();
        s.max_memory_bytes = 1024;
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_too_large_memory() {
        let mut s = ok_spec();
        s.max_memory_bytes = 4 * 1024 * 1024 * 1024;
        assert!(s.validate().is_err());
    }

    #[test]
    fn parses_minimal_toml() {
        let toml = r#"
kind = "ufw.rule"
module = "/srv/iac/ufw.wasm"
"#;
        let s: WasmProviderSpec = toml::from_str(toml).unwrap();
        s.validate().unwrap();
        assert_eq!(s.max_memory_bytes, default_max_memory());
        assert_eq!(s.fuel_per_call, default_fuel());
    }

    #[test]
    fn parses_full_wasi_block() {
        let toml = r#"
kind = "policy.engine"
module = "/srv/iac/policy.component.wasm"
runtime = "component"

[wasi]
env = ["LOG_LEVEL=debug"]
inherit_stdout = true
allow_network = false

[[wasi.preopens]]
host = "/var/lib/iac/policy/state"
guest = "/state"
writable = true

[[wasi.preopens]]
host = "/etc/iac/policy.d"
guest = "/policies"
# Phase 7dh.3: /etc/* is in the sensitive prefix list. Operator
# explicitly opts in here because the plugin needs to read its
# read-only config from /etc.
unsafe_host = true
"#;
        let s: WasmProviderSpec = toml::from_str(toml).unwrap();
        s.validate().unwrap();
        assert_eq!(s.wasi.preopens.len(), 2);
        assert_eq!(s.wasi.preopens[0].guest, "/state");
        assert!(s.wasi.preopens[0].writable);
        assert!(!s.wasi.preopens[1].writable, "default writable = false");
        assert_eq!(s.wasi.env, vec!["LOG_LEVEL=debug"]);
        assert!(s.wasi.inherit_stdout);
        assert!(!s.wasi.allow_network);
    }

    #[test]
    fn rejects_wasi_options_with_core_runtime() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Core;
        s.wasi.preopens.push(WasiPreopen {
            host: "/tmp".into(),
            guest: "/data".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains("component"), "{err}");
    }

    #[test]
    fn rejects_relative_preopen_host() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "relative".into(),
            guest: "/x".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn rejects_env_entry_without_equals() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.env.push("BARE".into());
        let err = s.validate().unwrap_err();
        assert!(err.contains("="), "{err}");
    }

    #[test]
    fn empty_wasi_is_default() {
        let cfg = WasiConfig::default();
        assert!(cfg.is_empty());
    }

    #[test]
    fn rejects_sensitive_preopen_etc() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/etc".into(),
            guest: "/system".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains("sensitive"), "{err}");
    }

    #[test]
    fn rejects_sensitive_preopen_under_etc() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/etc/iac".into(),
            guest: "/conf".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains("sensitive"), "{err}");
    }

    #[test]
    fn accepts_unsafe_host_opt_in() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/etc/os-release".into(),
            guest: "/os-release".into(),
            writable: false,
            unsafe_host: true,
        });
        s.validate().unwrap();
    }

    #[test]
    fn rejects_dotdot_in_guest_path() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/var/lib/foo".into(),
            guest: "/state/../escape".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains(".."), "{err}");
    }

    #[test]
    fn rejects_sensitive_preopen_under_agent_state_dir() {
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/var/lib/iac-agent/identity.json".into(),
            guest: "/secret".into(),
            writable: false,
            unsafe_host: false,
        });
        let err = s.validate().unwrap_err();
        assert!(err.contains("sensitive"), "{err}");
    }

    #[test]
    fn doesnt_match_random_paths_starting_with_e() {
        // /etc/foo is sensitive; /etc-other is not.
        let mut s = ok_spec();
        s.runtime = WasmRuntimeKind::Component;
        s.wasi.preopens.push(WasiPreopen {
            host: "/etc-other/foo".into(),
            guest: "/x".into(),
            writable: false,
            unsafe_host: false,
        });
        s.validate().unwrap();
    }
}
