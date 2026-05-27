//! `docker.compose` provider — manages a Compose stack as a single resource.
//!
//! Spec:
//! ```yaml
//! kind: docker.compose
//! spec:
//!   project: web-stack
//!   state: present | absent      # default: present
//!   source: |                    # inline compose YAML
//!     services:
//!       app:
//!         image: nginx:1.27
//!         ports: ["8080:80"]
//!   env_file: /etc/iac/web.env   # optional
//! ```
//!
//! Phase 7cw is intentionally minimal: no per-service drift, no scale, no
//! profiles. Operators wanting per-container control reach for
//! `docker.container` directly. `docker.compose` is for the case where
//! the operator already maintains a compose YAML and just wants a
//! managed stack.
//!
//! Implementation: shells out to `docker compose` (V2 plugin). The
//! compose YAML is materialised under `/var/lib/iac/compose/<project>/`
//! at apply time so operators can poke at it directly with
//! `docker compose ps -p <project>` for debugging.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(ComposeAction {
    Up   => "compose-up",
    Down => "compose-down",
});

pub use backend::{ComposeBackend, ComposeCli, ComposeService, MockCompose};
pub use spec::{ComposeState, DockerComposeSpec};

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
pub struct DockerComposeProvider {
    backend: Box<dyn ComposeBackend>,
}

impl Default for DockerComposeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerComposeProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(ComposeCli),
        }
    }

    pub fn with_backend(backend: Box<dyn ComposeBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<DockerComposeSpec> {
        DockerComposeSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid docker.compose spec: {e}"),
            )
        })
    }
}

impl Provider for DockerComposeProvider {
    fn kind(&self) -> &str {
        "docker.compose"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(self.backend.as_ref(), &spec)
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let spec = self.parse_spec(resource)?;
        ops::diff(&spec, observed)
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
        let diff = ops::diff(&spec, &observed)?;
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
        Ok(vec![spec.project.clone()])
    }
}
