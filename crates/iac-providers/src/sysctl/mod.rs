//! Phase 7cb: `sysctl.setting` provider — declarative kernel parameters.
//!
//! Critical primitive for network gear and tuning servers. Operators
//! declare runtime kernel parameters; the provider reads `/proc/sys`
//! directly (no `sysctl(8)` shell-out, no third-party deps), tracks
//! drift per-key, and rolls back to the captured pre-apply value.
//!
//! Persistence vs. runtime:
//!   * This provider sets the *runtime* value only. Reboot loses it.
//!   * To persist, pair with a `file` resource writing
//!     `/etc/sysctl.d/iac-<name>.conf` containing `key = value`.
//!   * Operators wanting both: declare both resources with a
//!     `dependsOn` from the file → the runtime sysctl. (The file
//!     write doesn't actually need to come before the runtime set
//!     for correctness, but having both in one operation makes the
//!     audit clear.)

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(SysctlAction {
    Set => "sysctl.set",
});

pub use backend::{MockSysctl, ProcfsBackend, SysctlBackend};
pub use spec::{SysctlSettingSpec, SysctlState};

use iac_core::{
    Error, Result,
    diff::Diff,
    operation::{Checkpoint, Step, StepResult},
    provider::{ApplyContext, Provider, VerifyOutcome},
    resource::Resource,
    state::ObservedState,
};
use serde_json::Value as Json;
use std::path::Path;

#[derive(Debug)]
pub struct SysctlProvider {
    backend: Box<dyn SysctlBackend>,
}

impl Default for SysctlProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SysctlProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(ProcfsBackend),
        }
    }

    pub fn with_backend(backend: Box<dyn SysctlBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<SysctlSettingSpec> {
        SysctlSettingSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid sysctl.setting spec: {e}"),
            )
        })
    }
}

impl Provider for SysctlProvider {
    fn kind(&self) -> &str {
        "sysctl.setting"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(self.backend.as_ref(), &spec)
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let spec = self.parse_spec(resource)?;
        Ok(ops::diff(&spec, observed))
    }

    fn plan(&self, resource: &Resource, diff: &Diff) -> Result<Vec<Step>> {
        let spec = self.parse_spec(resource)?;
        Ok(ops::plan(&spec, diff))
    }

    fn pre_apply(&self, resource: &Resource, _step: &Step, _ctx: &ApplyContext) -> Result<Json> {
        let spec = self.parse_spec(resource)?;
        ops::pre_apply(self.backend.as_ref(), &spec)
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        ops::apply(self.backend.as_ref(), &spec, step)
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let observed = ops::observe(self.backend.as_ref(), &spec)?;
        let diff = ops::diff(&spec, &observed);
        if diff.is_change() {
            Ok(VerifyOutcome::Mismatch(diff.changes))
        } else {
            Ok(VerifyOutcome::Match)
        }
    }

    fn rollback(
        &self,
        resource: &Resource,
        checkpoint: &Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        let spec = self.parse_spec(resource)?;
        ops::rollback(self.backend.as_ref(), &spec, &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        // Capability key = the sysctl key. Operators can authorize
        // `sysctl.setting:net.ipv4.*` via glob to allow tuning a whole
        // namespace.
        Ok(vec![spec.key])
    }
}
