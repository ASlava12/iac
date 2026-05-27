//! Phase 7ca: `monitoring.check` provider — active health checks
//! as asserted invariants.
//!
//! Replaces the shell+curl pattern shipped in the Phase 7k
//! `web-with-monitoring` composite. Operators declare a check;
//! observe runs it; apply re-runs it and succeeds iff healthy. Phased
//! apply (Phase 7by) gates dependent layers on the check result —
//! deploy app, then verify, then deploy whatever depends on app.
//!
//! Pure-std implementation (no third-party HTTP client) keeps the
//! agent binary small, important for network gear / embedded boxes.
//! HTTPS deferred to v2 (would require rustls + cert chain config).

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(MonitoringAction {
    Verify => "monitoring.verify",
});

pub use backend::{CheckBackend, CheckOutcome, MockCheck, StdNetBackend};
pub use spec::{CheckState, CheckType, MonitoringCheckSpec};

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
pub struct MonitoringCheckProvider {
    backend: Box<dyn CheckBackend>,
}

impl Default for MonitoringCheckProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitoringCheckProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(StdNetBackend),
        }
    }

    pub fn with_backend(backend: Box<dyn CheckBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<MonitoringCheckSpec> {
        MonitoringCheckSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid monitoring.check spec: {e}"),
            )
        })
    }
}

impl Provider for MonitoringCheckProvider {
    fn kind(&self) -> &str {
        "monitoring.check"
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
        _checkpoint: &Checkpoint,
        _workspace: &Path,
    ) -> Result<()> {
        let spec = self.parse_spec(resource)?;
        ops::rollback(self.backend.as_ref(), &spec)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        // Capability key = check name, so operators authorize
        // `monitoring.check:web-healthz` (or `monitoring.check:*`).
        Ok(vec![spec.name])
    }
}
