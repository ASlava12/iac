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
//! Pure-nftables systems (recent Debian / Fedora / RHEL 9+) get a
//! native `nft`-shelling backend selected via the
//! `IAC_FIREWALL_BACKEND=nft` env var; see `nft.rs`. Default
//! remains the iptables backend so unset / legacy operators
//! keep pre-Phase-9 behaviour.

mod backend;
mod nft;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(FirewallAction {
    Upsert => "firewall.upsert",
    Delete => "firewall.delete",
});

pub use backend::{FirewallBackend, IptablesBackend, MockFirewall, ObservedRule};
pub use nft::NftablesBackend;
pub use spec::{Family, FirewallRuleSpec, FirewallState};

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
pub struct FirewallProvider {
    backend: Box<dyn FirewallBackend>,
}

impl Default for FirewallProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallProvider {
    /// Phase 9 follow-up: pick the backend at construct-time via
    /// the `IAC_FIREWALL_BACKEND` env var.
    ///
    /// - unset / `"iptables"` → [`IptablesBackend`] (default; same
    ///   behaviour as pre-Phase-9 builds).
    /// - `"nft"` / `"nftables"` → [`NftablesBackend`], for distros
    ///   that no longer ship iptables (RHEL 9+, recent Fedora) or
    ///   operators preferring native nftables semantics.
    ///
    /// Unknown values fall back to iptables with a `warn!` — a typo
    /// shouldn't silently swap the firewall provider out from under
    /// the operator.
    pub fn new() -> Self {
        let raw = std::env::var("IAC_FIREWALL_BACKEND").ok();
        let normalised = raw.as_deref().map(|s| s.trim().to_ascii_lowercase());
        let backend: Box<dyn FirewallBackend> = match normalised.as_deref() {
            None | Some("") | Some("iptables") => Box::new(IptablesBackend),
            Some("nft") | Some("nftables") => {
                tracing::info!("firewall provider: nft backend selected via IAC_FIREWALL_BACKEND");
                Box::new(NftablesBackend)
            }
            Some(other) => {
                tracing::warn!(
                    requested = other,
                    "unknown IAC_FIREWALL_BACKEND value; falling back to iptables"
                );
                Box::new(IptablesBackend)
            }
        };
        Self { backend }
    }

    pub fn with_backend(backend: Box<dyn FirewallBackend>) -> Self {
        Self { backend }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<FirewallRuleSpec> {
        FirewallRuleSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid firewall.rule spec: {e}"),
            )
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
