//! `package` provider: manages OS packages via apt (Phase 0).
//!
//! Spec:
//! ```yaml
//! kind: package
//! spec:
//!   name: nginx
//!   state: present | absent      # default: present
//!   version: "1.18.0-6.1"        # optional pin
//!   backend: apt                 # default; only apt in Phase 0
//! ```

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(PackageAction {
    Install => "package.install",
    Remove  => "package.remove",
});

pub use backend::{AptBackend, InstallStatus, MockPackageBackend, PackageBackend};
pub use spec::{PackageSpec, PackageState};

use iac_core::{
    diff::Diff,
    operation::{Checkpoint, Step, StepResult},
    provider::{ApplyContext, Provider, VerifyOutcome},
    resource::Resource,
    state::ObservedState,
    Error, Result,
};
use serde_json::Value as Json;
use std::path::Path;

#[derive(Debug)]
pub struct PackageProvider {
    backend: Box<dyn PackageBackend>,
}

impl Default for PackageProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageProvider {
    pub fn new() -> Self {
        Self { backend: Box::new(AptBackend) }
    }

    pub fn with_backend(backend: Box<dyn PackageBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<PackageSpec> {
        PackageSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(resource.id().to_string(), format!("invalid package spec: {e}"))
        })
    }
}

impl Provider for PackageProvider {
    fn kind(&self) -> &str {
        "package"
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
        Ok(vec![spec.name.clone()])
    }
}
