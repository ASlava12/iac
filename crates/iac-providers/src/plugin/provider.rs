//! Shared `Provider` impl on top of a [`PluginRuntime`].
//!
//! All Provider methods are implemented exactly once here. Each of the
//! 3 runtimes used to repeat ~300 LOC of nearly-identical glue; this
//! module replaces those copies. See `mod.rs` for the design.

use super::runtime::{CapabilityKeysStrategy, PluginRuntime};
use iac_core::convert::{
    collect_top_level_changes, json_to_yaml, resource_metadata_to_json, yaml_to_json,
};
use iac_core::diff::{Diff, DiffKind};
use iac_core::operation::{Checkpoint, Step, StepResult, StepStatus};
use iac_core::provider::{ApplyContext, Provider, VerifyOutcome};
use iac_core::resource::Resource;
use iac_core::state::ObservedState;
use iac_core::{Error, Result};
use serde::Deserialize;
use serde_json::{Value as Json, json};
use serde_yaml_ng::Value as YamlValue;
use std::path::Path;

/// Method-name constants. Lifted out of `process::proto::methods` so
/// every runtime speaks the same vocabulary. The strings are wire
/// literals — operators see them in plugin-side logs and error
/// messages, so they're stable on purpose.
const OBSERVE: &str = "observe";
const APPLY: &str = "apply";
const VERIFY: &str = "verify";
const ROLLBACK: &str = "rollback";
const PRE_APPLY: &str = "pre_apply";
const DIFF: &str = "diff";

/// Step-action prefix the synthesised `plan()` output uses. Was
/// per-runtime ("shellout-create", "external-create", "wasm-create")
/// pre-7di.1; unified here. Pre-prod, no migration concerns — operators
/// don't have persistent ops with the old action names.
const ACTION_CREATE: &str = "plugin-create";
const ACTION_UPDATE: &str = "plugin-update";
const ACTION_DELETE: &str = "plugin-delete";

/// Generic Provider on top of a [`PluginRuntime`]. Construct via
/// [`PluginProvider::new`]; the runtime owns all transport state.
pub struct PluginProvider<R: PluginRuntime> {
    runtime: R,
}

impl<R: PluginRuntime> std::fmt::Debug for PluginProvider<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginProvider")
            .field("kind", &self.runtime.kind())
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl<R: PluginRuntime> PluginProvider<R> {
    pub fn new(runtime: R) -> Self {
        Self { runtime }
    }

    /// Access the underlying runtime — useful for tests that want to
    /// poke transport-level state without going through Provider.
    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    /// `{ kind, metadata, spec }` envelope every plugin method
    /// receives. Same shape that shellout / external / wasm-core all
    /// independently produced before the unification.
    fn envelope(&self, resource: &Resource) -> Json {
        json!({
            "kind": self.runtime.kind(),
            "metadata": resource_metadata_to_json(resource),
            "spec": yaml_to_json(&resource.spec),
        })
    }

    /// Decode a typed response. `method` is only used for the error
    /// message (operators see "decode observe: ..." etc.).
    fn decode<T: for<'de> Deserialize<'de>>(&self, method: &str, raw: Json) -> Result<T> {
        serde_json::from_value(raw)
            .map_err(|e| Error::provider(self.runtime.kind(), format!("decode {method}: {e}")))
    }

    fn observe_inner(&self, resource: &Resource) -> Result<ObserveResp> {
        let raw = self.runtime.call(OBSERVE, self.envelope(resource))?;
        self.decode(OBSERVE, raw)
    }
}

/// Wire shape every plugin produces from `observe` (and from `verify`
/// when the plugin opts into a custom verify). `present` defaults to
/// `false` if the plugin omits it; `spec` defaults to JSON null.
#[derive(Debug, Deserialize)]
struct ObserveResp {
    #[serde(default)]
    present: bool,
    #[serde(default)]
    spec: Json,
}

/// Wire shape every plugin produces from `apply` (and rollback's
/// fallback re-apply). `status` is `"ok"` or `"failed"`; `message`
/// goes into the operator-facing step result.
#[derive(Debug, Deserialize)]
struct ApplyResp {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
}

impl<R: PluginRuntime> Provider for PluginProvider<R> {
    fn kind(&self) -> &str {
        self.runtime.kind()
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let resp = self.observe_inner(resource)?;
        if resp.present {
            Ok(ObservedState::present(json_to_yaml(&resp.spec)))
        } else {
            Ok(ObservedState::absent())
        }
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        if self.runtime.supports(DIFF) {
            // Plugin opted in — let it speak.
            let raw = self.runtime.call(
                DIFF,
                json!({
                    "metadata": resource_metadata_to_json(resource),
                    "desired_spec": yaml_to_json(&resource.spec),
                    "observed": {
                        "present": observed.present,
                        "spec": yaml_to_json(&observed.spec),
                    },
                }),
            )?;
            return self.decode(DIFF, raw);
        }
        // Built-in fallback: spec-equality diff. Identical to what
        // shellout / external / wasm-core all did separately before
        // the unification.
        let desired_absent = matches!(spec_state_field(&resource.spec).as_deref(), Some("absent"));
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
            DiffKind::Create => ACTION_CREATE,
            DiffKind::Update => ACTION_UPDATE,
            DiffKind::Delete => ACTION_DELETE,
            DiffKind::NoChange => unreachable!("filtered above"),
        };
        Ok(vec![Step::new(
            action,
            format!("{action} via {}", self.runtime.kind()),
            Json::Null,
        )])
    }

    fn pre_apply(&self, resource: &Resource, _step: &Step, _ctx: &ApplyContext) -> Result<Json> {
        if self.runtime.supports(PRE_APPLY) {
            return self.runtime.call(PRE_APPLY, self.envelope(resource));
        }
        // Fallback: snapshot the prior observed state so rollback can
        // synthesise an apply that restores it. If observe fails here,
        // surface the error rather than silently skipping the snapshot —
        // better to fail closed before we mutate.
        let prior = self.observe_inner(resource)?;
        Ok(json!({
            "prior_present": prior.present,
            "prior_spec": prior.spec,
        }))
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let phase = phase_of_action(&step.action).ok_or_else(|| {
            Error::provider(
                self.runtime.kind(),
                format!("unknown step action {:?}", step.action),
            )
        })?;
        let raw = self.runtime.call(
            APPLY,
            json!({
                "kind": self.runtime.kind(),
                "metadata": resource_metadata_to_json(resource),
                "spec": yaml_to_json(&resource.spec),
                "phase": phase,
            }),
        )?;
        let resp: ApplyResp = self.decode(APPLY, raw)?;
        if resp.status == "ok" {
            Ok(StepResult::ok(if resp.message.is_empty() {
                format!("{phase} via {}", self.runtime.kind())
            } else {
                resp.message
            }))
        } else {
            Ok(StepResult {
                status: StepStatus::Failed,
                message: if resp.message.is_empty() {
                    format!("{phase} via {} reported failure", self.runtime.kind())
                } else {
                    resp.message.clone()
                },
                data: Json::Null,
                error: Some(if resp.message.is_empty() {
                    format!("{phase} via {} reported failure", self.runtime.kind())
                } else {
                    resp.message
                }),
            })
        }
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        if self.runtime.supports(VERIFY) {
            let raw = self.runtime.call(VERIFY, self.envelope(resource))?;
            let resp: ObserveResp = self.decode(VERIFY, raw)?;
            if resp.present && yaml_to_json(&resource.spec) == resp.spec {
                return Ok(VerifyOutcome::Match);
            }
            return Ok(VerifyOutcome::Mismatch(vec![]));
        }
        // Fallback: re-observe + spec-equality diff.
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
        if self.runtime.supports(ROLLBACK) {
            self.runtime.call(
                ROLLBACK,
                json!({
                    "kind": self.runtime.kind(),
                    "metadata": resource_metadata_to_json(resource),
                    "checkpoint": checkpoint.data,
                }),
            )?;
            return Ok(());
        }
        // Fallback: re-apply against the prior observed state captured
        // by pre_apply's fallback. `prior_present=false` means the
        // resource didn't exist before, so rollback = delete.
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
        let phase = if prior_present { "update" } else { "delete" };
        let raw = self.runtime.call(
            APPLY,
            json!({
                "kind": self.runtime.kind(),
                "metadata": resource_metadata_to_json(resource),
                "spec": prior_spec,
                "phase": phase,
            }),
        )?;
        let resp: ApplyResp = self.decode("rollback-apply", raw)?;
        if resp.status != "ok" {
            return Err(Error::provider(
                self.runtime.kind(),
                format!(
                    "rollback failed: {}",
                    if resp.message.is_empty() {
                        "no message"
                    } else {
                        &resp.message
                    }
                ),
            ));
        }
        Ok(())
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        match self.runtime.capability_keys_strategy() {
            CapabilityKeysStrategy::Templates(templates) => {
                let mut out = Vec::with_capacity(templates.len());
                for tmpl in &templates {
                    out.push(
                        iac_core::template::render_yaml_top_scalars(tmpl, &resource.spec).map_err(
                            |e| {
                                Error::provider(
                                    self.runtime.kind(),
                                    format!("capability_keys[{tmpl:?}]: {e}"),
                                )
                            },
                        )?,
                    );
                }
                Ok(out)
            }
            CapabilityKeysStrategy::Plugin => {
                // Plugin-computed keys: same envelope as observe.
                // If the plugin doesn't implement the method,
                // surface that as "no keys" rather than erroring —
                // matches the pre-7di.1 behaviour where wasm modules
                // could legitimately omit the optional export.
                match self
                    .runtime
                    .call("capability_keys", self.envelope(resource))
                {
                    Ok(raw) => self.decode("capability_keys", raw),
                    // Distinguish "plugin doesn't implement this optional
                    // method" (→ no keys, fine) from a transport/runtime
                    // failure (→ propagate, fail-closed). Swallowing a
                    // transport error as "no keys" would silently widen
                    // authorization whenever a plugin is merely flaky.
                    Err(e) => {
                        let msg = e.to_string();
                        let transport = msg.contains("EOF")
                            || msg.contains("read:")
                            || msg.contains("write:")
                            || msg.contains("not running")
                            || msg.contains("timed out")
                            || msg.contains("deadline")
                            || msg.contains("ndjson line exceeded");
                        if transport { Err(e) } else { Ok(Vec::new()) }
                    }
                }
            }
        }
    }
}

/// Map `step.action` back to the `phase` literal a plugin's
/// `apply()` expects. Returns `None` for actions that didn't come
/// from this provider (e.g. a step generated by another provider
/// got routed here by mistake — better to error than execute it).
fn phase_of_action(action: &str) -> Option<&'static str> {
    match action {
        ACTION_CREATE => Some("create"),
        ACTION_UPDATE => Some("update"),
        ACTION_DELETE => Some("delete"),
        _ => None,
    }
}

/// Look up `state` in the top level of a YAML mapping — used by the
/// fallback diff to detect explicit `state: absent`. Mirrors the
/// per-runtime helper that shellout / wasm previously carried.
fn spec_state_field(spec: &YamlValue) -> Option<String> {
    let map = spec.as_mapping()?;
    let v = map.get(YamlValue::String("state".into()))?;
    if let YamlValue::String(s) = v {
        Some(s.clone())
    } else {
        None
    }
}
