//! `dns.record` provider — pluggable DNS-record management.
//!
//! Phase 7cx ships the trait + a Cloudflare backend that shells out to
//! `curl` against the Cloudflare v4 API. Other backends (Route53,
//! BIND zones, DigitalOcean) plug in via the same trait without a
//! breaking spec change — operators add a new `provider:` enum
//! variant and a corresponding credentials block.
//!
//! Spec:
//! ```yaml
//! kind: dns.record
//! spec:
//!   zone: example.com
//!   name: app
//!   type: A
//!   value: "${secret://env/APP_IP}"
//!   ttl: 300
//!   state: present
//!   provider: cloudflare
//!   cloudflare:
//!     api_token: "${secret://env/CF_API_TOKEN}"
//! ```
//!
//! Identity for upserts is `(zone, fqdn, type)`. A record's value
//! changes; the trio identifies which record to mutate. Multiple
//! records sharing name+type (round-robin A, multiple TXT) are out of
//! scope for Phase 7cx.
//!
//! Why curl: same shell-out pattern we already use for `git`, `ssh`,
//! `docker`, `sops`. Operators have curl on every Linux host. Adding
//! reqwest to iac-providers would balloon the static binary and
//! double the TLS surface. Tradeoff: agent host needs curl on PATH.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(DnsAction {
    Create => "dns-create",
    Update => "dns-update",
    Delete => "dns-delete",
});

pub use backend::{CloudflareCli, DnsBackend, DnsRecord, MockDns, pick_backend};
pub use spec::{CloudflareCreds, DnsBackendKind, DnsRecordSpec, RecordState, RecordType};

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
pub struct DnsRecordProvider {
    /// Optional injected backend for tests. When `None`, every
    /// observe/apply/rollback call constructs a backend from the
    /// resource's spec via [`pick_backend`].
    test_backend: Option<Box<dyn DnsBackend>>,
}

impl Default for DnsRecordProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsRecordProvider {
    pub fn new() -> Self {
        Self { test_backend: None }
    }

    pub fn with_backend(backend: Box<dyn DnsBackend>) -> Self {
        Self {
            test_backend: Some(backend),
        }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<DnsRecordSpec> {
        DnsRecordSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid dns.record spec: {e}"),
            )
        })
    }

    fn backend_for<'a>(
        &'a self,
        spec: &DnsRecordSpec,
        owned: &'a mut Option<Box<dyn DnsBackend>>,
    ) -> Result<&'a dyn DnsBackend> {
        if let Some(b) = self.test_backend.as_deref() {
            return Ok(b);
        }
        *owned = Some(pick_backend(spec)?);
        // Phase 7cz.16: just-set above; tag for clippy.
        #[allow(clippy::unwrap_used)]
        Ok(owned.as_deref().unwrap())
    }
}

impl Provider for DnsRecordProvider {
    fn kind(&self) -> &str {
        "dns.record"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        let mut owned: Option<Box<dyn DnsBackend>> = None;
        let backend = self.backend_for(&spec, &mut owned)?;
        ops::observe(backend, &spec)
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
        let mut owned: Option<Box<dyn DnsBackend>> = None;
        let backend = self.backend_for(&spec, &mut owned)?;
        ops::pre_apply(backend, &spec)
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        let mut owned: Option<Box<dyn DnsBackend>> = None;
        let backend = self.backend_for(&spec, &mut owned)?;
        ops::apply(backend, &spec, step)
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let mut owned: Option<Box<dyn DnsBackend>> = None;
        let backend = self.backend_for(&spec, &mut owned)?;
        let observed = ops::observe(backend, &spec)?;
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
        let mut owned: Option<Box<dyn DnsBackend>> = None;
        let backend = self.backend_for(&spec, &mut owned)?;
        ops::rollback(backend, &spec, &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        // Capability key is `<fqdn>:<type>` — gives operators a way to
        // restrict per-record without exposing zone secrets in the
        // allowlist string.
        Ok(vec![format!(
            "{}:{}",
            spec.fqdn(),
            spec.record_type.as_str()
        )])
    }
}
