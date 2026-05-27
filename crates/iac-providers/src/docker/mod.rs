//! `docker.container` provider: manages a single Docker container by name.
//!
//! Spec:
//! ```yaml
//! kind: docker.container
//! spec:
//!   name: web
//!   image: nginx:1.27-alpine        # required when state=present
//!   state: present | absent         # default: present
//!   env:                            # optional map
//!     PORT: "8080"
//!   ports:                          # optional list of host:container[/proto]
//!     - "8080:80"
//!   restart_policy: unless-stopped  # default
//! ```
//!
//! Phase 5a is intentionally minimal — no volumes, networks, healthchecks, or
//! command overrides. Image identity is compared by content digest (the local
//! `docker inspect`'s `.Image` field) so a tag repointed upstream triggers a
//! recreate after `docker pull`.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(DockerAction {
    Pull     => "docker.pull",
    Recreate => "docker.recreate",
    Remove   => "docker.remove",
});

pub use backend::{ContainerInfo, DockerBackend, DockerCli, MockDocker};
pub use spec::{DockerContainerSpec, DockerState, RestartPolicy};

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
pub struct DockerProvider {
    backend: Box<dyn DockerBackend>,
}

impl Default for DockerProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerProvider {
    pub fn new() -> Self {
        Self {
            backend: Box::new(DockerCli),
        }
    }

    pub fn with_backend(backend: Box<dyn DockerBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<DockerContainerSpec> {
        DockerContainerSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid docker.container spec: {e}"),
            )
        })
    }
}

impl Provider for DockerProvider {
    fn kind(&self) -> &str {
        "docker.container"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(self.backend.as_ref(), &spec)
    }

    fn diff(&self, resource: &Resource, observed: &ObservedState) -> Result<Diff> {
        let spec = self.parse_spec(resource)?;
        ops::diff(self.backend.as_ref(), &spec, observed)
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
        let diff = ops::diff(self.backend.as_ref(), &spec, &observed)?;
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
        Ok(vec![spec.name.clone()])
    }
}
