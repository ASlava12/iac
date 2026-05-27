//! Phase 7cy: lifecycle for `acme.certificate`.
//!
//! Drift sources:
//!   * cert file missing → issue
//!   * cert exists but expires within `renew_window_days` → renew
//!   * spec says absent and cert files exist → revoke

use super::backend::{AcmeBackend, read_expiry_with_fallback};
use super::spec::{AcmeCertSpec, AcmeState};
use iac_core::{
    Error, Result,
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
};
use indexmap::IndexMap;
use serde_json::{Value as Json, json};
use serde_yaml_ng::Value as YamlValue;

pub fn observe(spec: &AcmeCertSpec) -> Result<ObservedState> {
    let cert_present = spec.cert_file().exists();
    let key_present = spec.key_file().exists();
    let expiry_unix = read_expiry_with_fallback(spec);
    let now = jiff::Timestamp::now().as_second();
    let days_left = expiry_unix.map(|e| (e - now) / 86400);
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    facts.insert("cert_present".into(), YamlValue::Bool(cert_present));
    facts.insert("key_present".into(), YamlValue::Bool(key_present));
    facts.insert(
        "expiry_unix".into(),
        match expiry_unix {
            Some(e) => YamlValue::Number(e.into()),
            None => YamlValue::Null,
        },
    );
    facts.insert(
        "days_left".into(),
        match days_left {
            Some(d) => YamlValue::Number(d.into()),
            None => YamlValue::Null,
        },
    );
    let mut spec_value = serde_yaml_ng::Mapping::new();
    spec_value.insert(
        "primary_domain".into(),
        YamlValue::String(spec.primary_domain().into()),
    );
    spec_value.insert(
        "cert_path".into(),
        YamlValue::String(spec.cert_file().to_string_lossy().into_owned()),
    );
    Ok(ObservedState {
        present: cert_present && key_present,
        spec: YamlValue::Mapping(spec_value),
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

pub fn diff(spec: &AcmeCertSpec, observed: &ObservedState) -> Result<Diff> {
    let cert_present = observed
        .facts
        .get("cert_present")
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);
    let days_left = observed.facts.get("days_left").and_then(YamlValue::as_i64);
    match spec.state {
        AcmeState::Absent => {
            if !cert_present {
                Ok(Diff::no_change())
            } else {
                Ok(Diff {
                    kind: DiffKind::Delete,
                    changes: vec![FieldChange {
                        field: "state".into(),
                        from: Some(YamlValue::String("present".into())),
                        to: Some(YamlValue::String("absent".into())),
                        sensitive: false,
                    }],
                    reasons: vec![format!(
                        "revoke + delete certificate for {}",
                        spec.primary_domain()
                    )],
                    reversible: false,
                })
            }
        }
        AcmeState::Present => {
            if !cert_present {
                return Ok(Diff {
                    kind: DiffKind::Create,
                    changes: vec![FieldChange {
                        field: "cert".into(),
                        from: None,
                        to: Some(YamlValue::String(format!(
                            "issue {} domains",
                            spec.domains.len()
                        ))),
                        sensitive: false,
                    }],
                    reasons: vec![format!("issue certificate for {}", spec.primary_domain())],
                    reversible: true,
                });
            }
            // Cert present — check expiry vs renew window.
            match days_left {
                Some(d) if d < spec.renew_window_days as i64 => Ok(Diff {
                    kind: DiffKind::Update,
                    changes: vec![FieldChange {
                        field: "expiry".into(),
                        from: Some(YamlValue::Number(d.into())),
                        to: Some(YamlValue::Number(
                            (spec.renew_window_days as i64 + 60).into(),
                        )),
                        sensitive: false,
                    }],
                    reasons: vec![format!(
                        "renew {} (expires in {d} days; window={})",
                        spec.primary_domain(),
                        spec.renew_window_days
                    )],
                    reversible: true,
                }),
                Some(_) => Ok(Diff::no_change()),
                None => {
                    // Cert exists but we can't read its expiry. Treat
                    // as drift — re-issue rather than risk an outage.
                    Ok(Diff {
                        kind: DiffKind::Update,
                        changes: vec![FieldChange {
                            field: "expiry".into(),
                            from: Some(YamlValue::String("unreadable".into())),
                            to: Some(YamlValue::String("re-issued".into())),
                            sensitive: false,
                        }],
                        reasons: vec![format!(
                            "cert for {} exists but expiry unreadable; re-issuing",
                            spec.primary_domain()
                        )],
                        reversible: true,
                    })
                }
            }
        }
    }
}

pub fn plan(spec: &AcmeCertSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    let action = match diff.kind {
        DiffKind::Create => super::AcmeAction::Issue,
        DiffKind::Update => super::AcmeAction::Renew,
        DiffKind::Delete => super::AcmeAction::Revoke,
        DiffKind::NoChange => return Vec::new(),
    };
    vec![Step::new(
        action.as_str(),
        format!("{action} {}", spec.primary_domain()),
        Json::Null,
    )]
}

pub fn pre_apply(spec: &AcmeCertSpec) -> Result<Json> {
    // Snapshot the prior cert+key files so rollback can restore.
    let prior_cert = std::fs::read(spec.cert_file()).ok();
    let prior_key = std::fs::read(spec.key_file()).ok();
    Ok(json!({
        "prior_cert_present": prior_cert.is_some(),
        "prior_cert_b64": prior_cert.map(|b| base64_encode(&b)),
        "prior_key_b64": prior_key.map(|b| base64_encode(&b)),
    }))
}

pub fn apply(backend: &dyn AcmeBackend, spec: &AcmeCertSpec, step: &Step) -> Result<StepResult> {
    match super::AcmeAction::parse(&step.action)? {
        super::AcmeAction::Issue => {
            backend.issue(spec)?;
            Ok(StepResult::ok(format!(
                "issued certificate for {}",
                spec.primary_domain()
            )))
        }
        super::AcmeAction::Renew => {
            backend.renew(spec)?;
            Ok(StepResult::ok(format!(
                "renewed certificate for {}",
                spec.primary_domain()
            )))
        }
        super::AcmeAction::Revoke => {
            backend.revoke(spec)?;
            Ok(StepResult::ok(format!(
                "revoked certificate for {}",
                spec.primary_domain()
            )))
        }
    }
}

pub fn rollback(spec: &AcmeCertSpec, checkpoint: &Json) -> Result<()> {
    let prior_present = checkpoint
        .get("prior_cert_present")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if prior_present {
        // Restore the prior cert+key files.
        std::fs::create_dir_all(&spec.cert_dir).map_err(|e| {
            Error::provider("acme.certificate", format!("rollback create_dir_all: {e}"))
        })?;
        if let Some(b64) = checkpoint.get("prior_cert_b64").and_then(|v| v.as_str()) {
            let bytes = base64_decode(b64)?;
            std::fs::write(spec.cert_file(), bytes).map_err(|e| {
                Error::provider("acme.certificate", format!("rollback write cert: {e}"))
            })?;
        }
        if let Some(b64) = checkpoint.get("prior_key_b64").and_then(|v| v.as_str()) {
            let bytes = base64_decode(b64)?;
            std::fs::write(spec.key_file(), bytes).map_err(|e| {
                Error::provider("acme.certificate", format!("rollback write key: {e}"))
            })?;
        }
    } else {
        // Prior absent — remove what we just issued.
        let _ = std::fs::remove_file(spec.cert_file());
        let _ = std::fs::remove_file(spec.key_file());
    }
    Ok(())
}

// Phase 7cz.10: dropped 70 lines of inline base64 in favour of the
// `base64` crate already in the workspace. The original "defence
// against deps" comment was misguided — the crate was already a
// transitive dep via reqwest/sqlx.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

fn base64_encode(input: &[u8]) -> String {
    B64.encode(input)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| Error::provider("acme.certificate", format!("base64 decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockAcme;
    use super::*;

    #[test]
    fn diff_create_when_no_cert() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Create));
    }

    #[test]
    fn diff_no_change_when_fresh_cert() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        let now = jiff::Timestamp::now().as_second();
        m.set_next_not_after(now + 60 * 86400); // 60 days out
        m.issue(&spec).unwrap();
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::NoChange), "{d:?}");
    }

    #[test]
    fn diff_renew_when_within_window() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        let now = jiff::Timestamp::now().as_second();
        m.set_next_not_after(now + 10 * 86400); // 10 days out
        m.issue(&spec).unwrap();
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Update), "{d:?}");
        assert!(d.reasons[0].contains("renew"));
    }

    #[test]
    fn diff_delete_when_absent_but_present_observed() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec_p = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.issue(&spec_p).unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "absent");
        let observed = observe(&spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Delete));
    }

    #[test]
    fn apply_issue_calls_backend() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        let step = Step::new("acme-issue", "issue", Json::Null);
        apply(&m, &spec, &step).unwrap();
        assert_eq!(m.calls().len(), 1);
        assert!(m.calls()[0].starts_with("issue domains="));
    }

    #[test]
    fn apply_renew_calls_backend() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        let step = Step::new("acme-renew", "renew", Json::Null);
        apply(&m, &spec, &step).unwrap();
        assert!(m.calls()[0].starts_with("renew domains="));
    }

    #[test]
    fn pre_apply_then_rollback_restores_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.issue(&spec).unwrap();
        let original = std::fs::read(spec.cert_file()).unwrap();
        let cp = pre_apply(&spec).unwrap();
        // Now overwrite as if a renew happened.
        std::fs::write(spec.cert_file(), b"new").unwrap();
        rollback(&spec, &cp).unwrap();
        let restored = std::fs::read(spec.cert_file()).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn rollback_with_no_prior_removes_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let spec = super::super::test_helpers::cf_spec(dir.path(), "present");
        let m = MockAcme::new();
        m.issue(&spec).unwrap();
        let cp = json!({"prior_cert_present": false});
        rollback(&spec, &cp).unwrap();
        assert!(!spec.cert_file().exists());
    }

    #[test]
    fn b64_round_trip() {
        for sample in &[
            b"".as_slice(),
            b"x".as_slice(),
            b"hi".as_slice(),
            b"hello".as_slice(),
            &[0u8, 1, 2, 3, 4, 5, 254, 255][..],
        ] {
            let enc = base64_encode(sample);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec.as_slice(), *sample, "input={sample:?} enc={enc}");
        }
    }
}
