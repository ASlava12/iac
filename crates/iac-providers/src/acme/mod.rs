//! `acme.certificate` provider — Let's Encrypt / ACMEv2 certificates.
//!
//! Phase 7cy ships:
//!   * Spec with HTTP-01 webroot mode and DNS-01 via Cloudflare.
//!   * Backend trait + `lego` shell-out implementation.
//!   * Auto-renew when cert expires within `renew_window_days`.
//!   * Mock backend for tests.
//!
//! Identity is the primary domain (first entry in `domains`). On-disk
//! layout matches `lego`:
//!   * `<cert_dir>/<primary>.crt` — full chain
//!   * `<cert_dir>/<primary>.key` — private key
//!
//! Operators chain this with `nginx.vhost` (or any TLS-consuming
//! resource) by referencing the `<cert_dir>/<primary>.crt` path.
//!
//! Why lego: single static Go binary, zero-config DNS-01 with
//! Cloudflare. Future: `CertbotBackend`, `Acme.shBackend` plug in
//! against the same trait.

mod backend;
mod ops;
mod spec;

// Phase 7cz.20: typed action namespace.
crate::step_actions!(AcmeAction {
    Issue  => "acme-issue",
    Renew  => "acme-renew",
    Revoke => "acme-revoke",
});

pub use backend::{
    AcmeBackend, LegoCli, MockAcme, pick_backend, read_cert_expiry_unix, read_expiry_with_fallback,
};
pub use spec::{AcmeCertSpec, AcmeState, ChallengeKind};

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
pub struct AcmeCertProvider {
    test_backend: Option<Box<dyn AcmeBackend>>,
}

impl Default for AcmeCertProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AcmeCertProvider {
    pub fn new() -> Self {
        Self { test_backend: None }
    }

    pub fn with_backend(backend: Box<dyn AcmeBackend>) -> Self {
        Self {
            test_backend: Some(backend),
        }
    }

    fn parse_spec(&self, resource: &Resource) -> Result<AcmeCertSpec> {
        AcmeCertSpec::from_value(&resource.spec).map_err(|e| {
            Error::validation(
                resource.id().to_string(),
                format!("invalid acme.certificate spec: {e}"),
            )
        })
    }

    fn backend_for<'a>(
        &'a self,
        owned: &'a mut Option<Box<dyn AcmeBackend>>,
    ) -> &'a dyn AcmeBackend {
        if let Some(b) = self.test_backend.as_deref() {
            return b;
        }
        *owned = Some(pick_backend());
        // Phase 7cz.16: just-set above; tag for clippy.
        #[allow(clippy::unwrap_used)]
        owned.as_deref().unwrap()
    }
}

impl Provider for AcmeCertProvider {
    fn kind(&self) -> &str {
        "acme.certificate"
    }

    fn observe(&self, resource: &Resource) -> Result<ObservedState> {
        let spec = self.parse_spec(resource)?;
        ops::observe(&spec)
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
        ops::pre_apply(&spec)
    }

    fn apply(&self, resource: &Resource, step: &Step, _ctx: &ApplyContext) -> Result<StepResult> {
        let spec = self.parse_spec(resource)?;
        let mut owned: Option<Box<dyn AcmeBackend>> = None;
        let backend = self.backend_for(&mut owned);
        ops::apply(backend, &spec, step)
    }

    fn verify(&self, resource: &Resource) -> Result<VerifyOutcome> {
        let spec = self.parse_spec(resource)?;
        let observed = ops::observe(&spec)?;
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
        ops::rollback(&spec, &checkpoint.data)
    }

    fn capability_keys(&self, resource: &Resource) -> Result<Vec<String>> {
        let spec = self.parse_spec(resource)?;
        Ok(vec![spec.primary_domain().to_string()])
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use std::path::Path;

    /// Construct a minimal http-01 spec rooted at `dir`. Used by tests
    /// in both `backend.rs` and `ops.rs`.
    pub fn cf_spec(dir: &Path, state: &str) -> AcmeCertSpec {
        let body = format!(
            r#"
domains: ["test.example.com"]
email: ops@example.com
cert_dir: {}
state: {state}
challenge: http-01
webroot: /var/www/html
"#,
            dir.display(),
        );
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&body).unwrap();
        AcmeCertSpec::from_value(&v).unwrap()
    }
}
