//! Phase 7bz: `firewall.rule` provider — declarative iptables / ip6tables.
//!
//! The first dedicated network-equipment primitive in the catalog.
//! Spec is intentionally narrower than iptables's full surface area
//! (filter table only by default; tcp/udp/icmp/all protocols; basic
//! ACCEPT/DROP/REJECT actions). Operators with esoteric needs can
//! still drop in raw iptables-restore via the `file` provider — this
//! resource is for the 90% of "open this port from this CIDR" rules.
//!
//! Identity: each rule carries an `iac:<resource_name>` iptables
//! comment so observe / diff / rollback can find it unambiguously.
//! Resources are matched by spec.name; renaming a resource creates
//! a new rule and orphans the old one (manual cleanup needed).
//!
//! Cross-platform: works wherever iptables is on PATH (mainline
//! Linux, OpenWrt with the iptables package, most network gear).
//! Pure-nftables systems (recent Debian / Fedora) need
//! `iptables-nft` shim — this still uses the `iptables` CLI.
//! Embedded gear with only nftables: future Phase 5d+ provider.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(FirewallAction {
    Upsert => "firewall.upsert",
    Delete => "firewall.delete",
});

pub use backend::{FirewallBackend, IptablesBackend, MockFirewall, ObservedRule};
pub use spec::{Family, FirewallRuleSpec, FirewallState};

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
pub struct FirewallProvider {
    backend: Box<dyn FirewallBackend>,
}

impl Default for FirewallProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallProvider {
    pub fn new() -> Self {
        Self { backend: Box::new(IptablesBackend) }
    }

    pub fn with_backend(backend: Box<dyn FirewallBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<FirewallRuleSpec> {
        FirewallRuleSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(resource.id().to_string(), format!("invalid firewall.rule spec: {e}"))
        })
    }
}

impl Provider for FirewallProvider {
    fn kind(&self) -> &str {
        "firewall.rule"
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
        // Capability gating: operators authorize firewall.rule by
        // resource name. A capability `firewall.rule:allow-ssh`
        // permits exactly that rule; `firewall.rule:*` (glob) all of
        // them.
        Ok(vec![spec.name])
    }
}
