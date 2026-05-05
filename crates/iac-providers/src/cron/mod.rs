//! `cron.job` provider: writes a single `/etc/cron.d/<name>` file with a
//! validated schedule + command. The cron daemon picks up changes
//! automatically; we don't need to reload anything.
//!
//! Spec:
//! ```yaml
//! kind: cron.job
//! spec:
//!   name: backup-db                  # filename under /etc/cron.d/
//!   schedule: "0 3 * * *"            # 5 fields or @-shorthand
//!   command: /usr/local/bin/backup.sh
//!   user: root                       # default
//!   env:                             # optional KEY=VALUE prelude
//!     PATH: /usr/local/bin:/usr/bin
//!   state: present                   # or absent
//! ```

mod ops;
mod render;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(CronAction {
    Write  => "cron.write",
    Remove => "cron.remove",
});

pub use spec::{CronJobSpec, CronState};

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

#[derive(Debug, Default)]
pub struct CronProvider;

impl CronProvider {
    pub fn new() -> Self {
        Self
    }

    fn parse_spec(&self, resource: &Resource) -> Result<CronJobSpec> {
        CronJobSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(resource.id().to_string(), format!("invalid cron.job spec: {e}"))
        })
    }
}

impl Provider for CronProvider {
    fn kind(&self) -> &str {
        "cron.job"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(&spec)
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
        ops::pre_apply(&spec)
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        ops::apply(&spec, step)
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let observed = ops::observe(&spec)?;
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
        ops::rollback(&spec, &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        Ok(vec![spec.name.clone()])
    }
}
