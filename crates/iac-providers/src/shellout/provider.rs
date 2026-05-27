//! Phase 7db.1: declarative shell-out plugin runtime.
//!
//! ### Wire protocol (stdin → stdout)
//!
//! All commands receive one JSON object on stdin and must print one
//! JSON object to stdout. Stderr is captured for error messages.
//! Exit code 0 = success.
//!
//! **`observe`** input:
//! ```json
//! { "kind": "...", "metadata": { "name": "...", "environment": "..." }, "spec": { ... desired ... } }
//! ```
//! **`observe`** output:
//! ```json
//! { "present": true|false, "spec": { ... actual ... } }
//! ```
//! When `present == false`, `spec` may be omitted or `null`.
//!
//! **`apply`** input:
//! ```json
//! { "kind": "...", "metadata": { ... }, "spec": { ... }, "phase": "create"|"update"|"delete" }
//! ```
//! **`apply`** output:
//! ```json
//! { "status": "ok"|"failed", "message": "..." }
//! ```
//!
//! **`verify`** input/output: same as `observe`. Provider treats
//! `present && observed.spec == spec` as match.
//!
//! **`rollback`** input:
//! ```json
//! { "kind": "...", "metadata": { ... }, "checkpoint": { ... } }
//! ```
//!
//! ### Phase 7di.1
//!
//! The 200+ LOC `impl Provider for ShellOutProvider` block was lifted
//! out of this file; what remains is the *transport* — argv parsing,
//! env-var injection, subprocess spawn — and the [`PluginRuntime`]
//! impl that maps method names to the four configurable scripts.
//! All Provider semantics now live in [`crate::plugin::PluginProvider`].

use super::spec::{ShellOutSpec, split_argv};
use crate::plugin::{CapabilityKeysStrategy, PluginProvider, PluginRuntime};
use iac_core::{Error, Result};
use serde_json::Value as Json;
use std::process::{Command, Stdio};

/// Transport-only struct for the shellout runtime. Holds the parsed
/// spec; every subprocess invocation goes through [`Self::run`].
#[derive(Debug, Clone)]
pub struct ShellOutRuntime {
    spec: ShellOutSpec,
}

/// Public-facing alias kept for backward source compatibility with
/// agent / CLI / tests that constructed `ShellOutProvider`. The trait
/// surface is identical (still `impl Provider`); only the inherent
/// `new(spec)` constructor moved one layer deeper — callers now go
/// `ShellOutRuntime::new(spec)?.into_provider()`.
pub type ShellOutProvider = PluginProvider<ShellOutRuntime>;

impl ShellOutRuntime {
    /// Build a runtime from its declarative config. The config's
    /// `validate()` is called eagerly so misconfigurations don't
    /// lurk until the first observe.
    pub fn new(spec: ShellOutSpec) -> std::result::Result<Self, String> {
        spec.validate()?;
        Ok(Self { spec })
    }

    /// Wrap into the shared `PluginProvider`. Equivalent to the old
    /// `ShellOutProvider::new(spec)` two-step.
    pub fn into_provider(self) -> ShellOutProvider {
        PluginProvider::new(self)
    }

    fn run(&self, cmd_str: &str, stdin_bytes: &[u8]) -> Result<Vec<u8>> {
        // Phase 7di.5: spawn + write stdin + bounded wait + reap
        // logic moved to `iac_core::subprocess::run_with_timeout`.
        // What's left here is the shellout-specific argv-parse,
        // env-pass, and error-shape mapping.
        let argv = split_argv(cmd_str);
        let (head, tail) = argv
            .split_first()
            .ok_or_else(|| Error::provider(&self.spec.kind, "empty command"))?;
        let mut cmd = Command::new(head);
        cmd.args(tail);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        for kv in &self.spec.env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        match iac_core::subprocess::run_with_timeout(cmd, stdin_bytes, self.spec.timeout()) {
            Ok(out) => {
                if !out.status.success() {
                    return Err(Error::provider(
                        &self.spec.kind,
                        format!(
                            "{} exit={:?} stderr={}",
                            argv.join(" "),
                            out.status.code(),
                            String::from_utf8_lossy(&out.stderr)
                        ),
                    ));
                }
                Ok(out.stdout)
            }
            Err(iac_core::subprocess::SubprocessError::Timeout { elapsed, .. }) => {
                Err(Error::provider(
                    &self.spec.kind,
                    format!("{} timed out after {}s", argv.join(" "), elapsed.as_secs()),
                ))
            }
            Err(iac_core::subprocess::SubprocessError::Spawn(e)) => Err(Error::provider(
                &self.spec.kind,
                format!("spawn {}: {e}", argv.join(" ")),
            )),
            Err(iac_core::subprocess::SubprocessError::Wait(e)) => {
                Err(Error::provider(&self.spec.kind, format!("wait: {e}")))
            }
        }
    }

    /// Pick the configured script path for a wire method name. Returns
    /// `None` for methods the spec doesn't configure (verify/rollback
    /// are optional; everything else is either required or not
    /// supported by shellout at all — see [`Self::supports`]).
    fn cmd_for(&self, method: &str) -> Option<&str> {
        match method {
            "observe" => Some(self.spec.observe.as_str()),
            "apply" => Some(self.spec.apply.as_str()),
            "verify" => self.spec.verify.as_deref(),
            "rollback" => self.spec.rollback.as_deref(),
            _ => None,
        }
    }
}

impl PluginRuntime for ShellOutRuntime {
    fn kind(&self) -> &str {
        &self.spec.kind
    }

    fn call(&self, method: &str, params: Json) -> Result<Json> {
        let cmd = self.cmd_for(method).ok_or_else(|| {
            Error::provider(
                &self.spec.kind,
                format!("shellout does not implement method {method:?}"),
            )
        })?;
        let stdin = params.to_string();
        let stdout = self.run(cmd, stdin.as_bytes())?;
        // Empty stdout is a legal "I succeeded, no payload" signal for
        // methods like rollback. Surface it as JSON null so the host's
        // decode step doesn't trip on "EOF while parsing".
        if stdout.is_empty() {
            return Ok(Json::Null);
        }
        serde_json::from_slice(&stdout).map_err(|e| {
            Error::provider(
                &self.spec.kind,
                format!(
                    "decode {method}: {e}: {:?}",
                    String::from_utf8_lossy(&stdout)
                ),
            )
        })
    }

    fn supports(&self, method: &str) -> bool {
        match method {
            // Required pair — every shellout spec configures both.
            "observe" | "apply" => true,
            // Optional — only "supported" if the operator wired it up.
            "verify" => self.spec.verify.is_some(),
            "rollback" => self.spec.rollback.is_some(),
            // Shellout never opts into the host's typed-fallback paths;
            // the host always synthesises diff/pre_apply for it.
            _ => false,
        }
    }

    fn capability_keys_strategy(&self) -> CapabilityKeysStrategy {
        CapabilityKeysStrategy::Templates(self.spec.capability_keys.clone())
    }
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::operation::Step;
    use iac_core::provider::Provider;
    use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
    use indexmap::IndexMap;
    use serde_yaml_ng::Value as YamlValue;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::TempDir;

    fn mk_script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    fn mk_provider(observe: &Path, apply: &Path) -> ShellOutProvider {
        let spec = ShellOutSpec {
            kind: "test.k".into(),
            observe: observe.display().to_string(),
            apply: apply.display().to_string(),
            verify: None,
            rollback: None,
            capability_keys: vec![],
            env: vec![],
            timeout_secs: 30,
        };
        ShellOutRuntime::new(spec).unwrap().into_provider()
    }

    fn mk_resource() -> Resource {
        let mut spec = serde_yaml_ng::Mapping::new();
        spec.insert(
            YamlValue::String("name".into()),
            YamlValue::String("alpha".into()),
        );
        Resource {
            api_version: API_VERSION.into(),
            kind: "test.k".into(),
            metadata: Metadata {
                name: "alpha".into(),
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

    #[test]
    fn capability_keys_render_from_spec() {
        let spec = ShellOutSpec {
            kind: "test.k".into(),
            observe: "/bin/true".into(),
            apply: "/bin/true".into(),
            verify: None,
            rollback: None,
            capability_keys: vec!["k:{{ name }}".into()],
            env: vec![],
            timeout_secs: 30,
        };
        let provider = ShellOutRuntime::new(spec).unwrap().into_provider();
        let res = mk_resource();
        let keys = provider.capability_keys(&res).unwrap();
        assert_eq!(keys, vec!["k:alpha"]);
    }

    #[test]
    fn apply_propagates_failure_status() {
        let dir = TempDir::new().unwrap();
        let observe = mk_script(
            dir.path(),
            "observe",
            "#!/bin/sh\nprintf '{\"present\":false}\\n'\n",
        );
        let apply = mk_script(
            dir.path(),
            "apply",
            "#!/bin/sh\nprintf '{\"status\":\"failed\",\"message\":\"nope\"}\\n'\n",
        );
        let provider = mk_provider(&observe, &apply);
        let res = mk_resource();
        let step = Step::new("plugin-create", "create via test.k", Json::Null);
        let ctx = iac_core::provider::ApplyContext {
            operation_id: ulid::Ulid::new(),
            workspace: dir.path().to_path_buf(),
        };
        let r = provider.apply(&res, &step, &ctx).unwrap();
        assert!(matches!(r.status, iac_core::operation::StepStatus::Failed));
        assert!(r.message.contains("nope"));
    }

    #[test]
    fn run_times_out_long_running_command() {
        let dir = TempDir::new().unwrap();
        let observe = mk_script(dir.path(), "observe", "#!/bin/sh\nsleep 10\n");
        let apply = mk_script(
            dir.path(),
            "apply",
            "#!/bin/sh\nprintf '{\"status\":\"ok\"}\\n'\n",
        );
        let spec = ShellOutSpec {
            kind: "test.k".into(),
            observe: observe.display().to_string(),
            apply: apply.display().to_string(),
            verify: None,
            rollback: None,
            capability_keys: vec![],
            env: vec![],
            timeout_secs: 1,
        };
        let provider = ShellOutRuntime::new(spec).unwrap().into_provider();
        let res = mk_resource();
        let err = provider.observe(&res).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("timed out"),
            "expected timeout error, got {msg:?}"
        );
    }
}
