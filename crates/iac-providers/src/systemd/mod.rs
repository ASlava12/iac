//! `systemd.unit` provider: manages systemd unit `enabled` and `active` state.
//!
//! Spec:
//! ```yaml
//! kind: systemd.unit
//! spec:
//!   name: nginx          # without suffix; or "nginx.service"
//!   type: service        # service|socket|timer|target|path|mount
//!   enabled: true
//!   active: true
//! ```
//!
//! This provider does NOT manage the unit file itself — pair it with a `file`
//! resource pointing at `/etc/systemd/system/<name>.service` and a (future)
//! `systemd.daemon-reload` hook.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(SystemdAction {
    Enable  => "systemd.enable",
    Disable => "systemd.disable",
    Start   => "systemd.start",
    Stop    => "systemd.stop",
    Restart => "systemd.restart",
    Reload  => "systemd.reload",
});

pub use backend::{MockSystemctl, RealSystemctl, Systemctl, UnitInfo};
pub use spec::{SystemdUnitSpec, UnitType};

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
pub struct SystemdProvider {
    backend: Box<dyn Systemctl>,
}

impl Default for SystemdProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemdProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(RealSystemctl),
        }
    }

    pub fn with_backend(backend: Box<dyn Systemctl>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<SystemdUnitSpec> {
        SystemdUnitSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid systemd.unit spec: {e}"),
            )
        })
    }
}

impl Provider for SystemdProvider {
    fn kind(&self) -> &str {
        "systemd.unit"
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

    fn apply(&self, _resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        ops::apply(self.backend.as_ref(), step)
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
        _resource: &Resource,
        checkpoint: &Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        ops::rollback(self.backend.as_ref(), &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        Ok(vec![spec.unit_name()])
    }
}
