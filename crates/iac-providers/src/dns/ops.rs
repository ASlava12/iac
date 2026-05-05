//! Phase 7cx: lifecycle implementation for `dns.record`.
//!
//! Per record:
//!   * observe: `find_record(zone, fqdn, type)`
//!   * diff: present + observed value matches → no_change. Else update / create.
//!     absent + no observed → no_change. absent + observed → delete.
//!   * apply: create / update / delete via backend
//!   * rollback: re-apply the prior observed value (captured in pre_apply)

use super::backend::DnsBackend;
use super::spec::{DnsRecordSpec, RecordState};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn DnsBackend, spec: &DnsRecordSpec) -> Result<ObservedState> {
    let fqdn = spec.fqdn();
    let rec = backend.find_record(&spec.zone, &fqdn, spec.record_type)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    facts.insert("fqdn".into(), YamlValue::String(fqdn.clone()));
    facts.insert(
        "type".into(),
        YamlValue::String(spec.record_type.as_str().into()),
    );
    facts.insert("present".into(), YamlValue::Bool(rec.is_some()));
    let spec_value = match rec.as_ref() {
        Some(r) => {
            let mut m = Mapping::new();
            m.insert("id".into(), YamlValue::String(r.id.clone()));
            m.insert("value".into(), YamlValue::String(r.value.clone()));
            m.insert("ttl".into(), YamlValue::Number((r.ttl as u64).into()));
            YamlValue::Mapping(m)
        }
        None => YamlValue::Null,
    };
    Ok(ObservedState {
        present: rec.is_some(),
        spec: spec_value,
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

pub fn diff(spec: &DnsRecordSpec, observed: &ObservedState) -> Result<Diff> {
    let observed_value = observed
        .spec
        .as_mapping()
        .and_then(|m| m.get(YamlValue::String("value".into())))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let observed_ttl = observed
        .spec
        .as_mapping()
        .and_then(|m| m.get(YamlValue::String("ttl".into())))
        .and_then(|v| v.as_u64())
        .map(|t| t as u32);
    let present = observed.present;
    match spec.state {
        RecordState::Absent => {
            if !present {
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
                        "delete {} record {}",
                        spec.record_type.as_str(),
                        spec.fqdn()
                    )],
                    reversible: true,
                })
            }
        }
        RecordState::Present => {
            let desired_value = spec.value.as_deref().unwrap_or_default();
            if !present {
                return Ok(Diff {
                    kind: DiffKind::Create,
                    changes: vec![FieldChange {
                        field: "value".into(),
                        from: None,
                        to: Some(YamlValue::String(desired_value.into())),
                        sensitive: false,
                    }],
                    reasons: vec![format!(
                        "create {} record {} -> {}",
                        spec.record_type.as_str(),
                        spec.fqdn(),
                        desired_value
                    )],
                    reversible: true,
                });
            }
            let mut changes = Vec::new();
            if observed_value.as_deref() != Some(desired_value) {
                changes.push(FieldChange {
                    field: "value".into(),
                    from: observed_value.clone().map(YamlValue::String),
                    to: Some(YamlValue::String(desired_value.into())),
                    sensitive: false,
                });
            }
            if observed_ttl != Some(spec.ttl) {
                changes.push(FieldChange {
                    field: "ttl".into(),
                    from: observed_ttl.map(|t| YamlValue::Number((t as u64).into())),
                    to: Some(YamlValue::Number((spec.ttl as u64).into())),
                    sensitive: false,
                });
            }
            if changes.is_empty() {
                Ok(Diff::no_change())
            } else {
                Ok(Diff {
                    kind: DiffKind::Update,
                    changes,
                    reasons: vec![format!(
                        "update {} record {}",
                        spec.record_type.as_str(),
                        spec.fqdn()
                    )],
                    reversible: true,
                })
            }
        }
    }
}

pub fn plan(spec: &DnsRecordSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    let action = match diff.kind {
        DiffKind::Create => super::DnsAction::Create,
        DiffKind::Update => super::DnsAction::Update,
        DiffKind::Delete => super::DnsAction::Delete,
        DiffKind::NoChange => return Vec::new(),
    };
    vec![Step::new(
        action.as_str(),
        format!(
            "{action} {} record {}",
            spec.record_type.as_str(),
            spec.fqdn()
        ),
        Json::Null,
    )]
}

pub fn pre_apply(backend: &dyn DnsBackend, spec: &DnsRecordSpec) -> Result<Json> {
    // Snapshot for rollback.
    let rec = backend.find_record(&spec.zone, &spec.fqdn(), spec.record_type)?;
    Ok(match rec {
        Some(r) => json!({
            "prior_id": r.id,
            "prior_value": r.value,
            "prior_ttl": r.ttl,
            "prior_present": true,
        }),
        None => json!({
            "prior_present": false,
        }),
    })
}

pub fn apply(
    backend: &dyn DnsBackend,
    spec: &DnsRecordSpec,
    step: &Step,
) -> Result<StepResult> {
    let fqdn = spec.fqdn();
    match super::DnsAction::parse(&step.action)? {
        super::DnsAction::Create => {
            let value = spec.value.as_deref().ok_or_else(|| {
                Error::provider("dns.record", "dns-create requires value")
            })?;
            let id =
                backend.create_record(&spec.zone, &fqdn, spec.record_type, value, spec.ttl)?;
            Ok(StepResult::ok(format!(
                "created {} record {fqdn} (id={id})",
                spec.record_type.as_str()
            )))
        }
        super::DnsAction::Update => {
            let value = spec.value.as_deref().ok_or_else(|| {
                Error::provider("dns.record", "dns-update requires value")
            })?;
            let existing =
                backend.find_record(&spec.zone, &fqdn, spec.record_type)?.ok_or_else(|| {
                    Error::provider(
                        "dns.record",
                        format!("dns-update: record {fqdn} unexpectedly missing"),
                    )
                })?;
            backend.update_record(
                &spec.zone,
                &existing.id,
                &fqdn,
                spec.record_type,
                value,
                spec.ttl,
            )?;
            Ok(StepResult::ok(format!(
                "updated {} record {fqdn}",
                spec.record_type.as_str()
            )))
        }
        super::DnsAction::Delete => {
            let existing =
                backend.find_record(&spec.zone, &fqdn, spec.record_type)?.ok_or_else(|| {
                    Error::provider(
                        "dns.record",
                        format!("dns-delete: record {fqdn} already gone"),
                    )
                })?;
            backend.delete_record(&spec.zone, &existing.id)?;
            Ok(StepResult::ok(format!(
                "deleted {} record {fqdn}",
                spec.record_type.as_str()
            )))
        }
    }
}

pub fn rollback(
    backend: &dyn DnsBackend,
    spec: &DnsRecordSpec,
    checkpoint: &Json,
) -> Result<()> {
    let prior_present = checkpoint
        .get("prior_present")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let fqdn = spec.fqdn();
    if prior_present {
        let value = checkpoint
            .get("prior_value")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ttl = checkpoint
            .get("prior_ttl")
            .and_then(|v| v.as_u64())
            .unwrap_or(300) as u32;
        // The record may or may not exist now (depending on what was
        // applied). Try update; on miss, fall back to create.
        if let Some(existing) =
            backend.find_record(&spec.zone, &fqdn, spec.record_type)?
        {
            backend.update_record(
                &spec.zone,
                &existing.id,
                &fqdn,
                spec.record_type,
                value,
                ttl,
            )
        } else {
            backend
                .create_record(&spec.zone, &fqdn, spec.record_type, value, ttl)
                .map(|_| ())
        }
    } else {
        // Prior absent; remove the record we created.
        if let Some(existing) =
            backend.find_record(&spec.zone, &fqdn, spec.record_type)?
        {
            backend.delete_record(&spec.zone, &existing.id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::{DnsRecord, MockDns};
    use super::super::spec::RecordType;
    use super::*;

    fn cf_spec(state: &str, value: Option<&str>, ttl: u32) -> DnsRecordSpec {
        let body = format!(
            r#"
zone: example.com
name: app
type: A
ttl: {ttl}
state: {state}
{value_line}
provider: cloudflare
cloudflare:
  api_token: t
"#,
            value_line = value
                .map(|v| format!("value: \"{v}\""))
                .unwrap_or_default(),
        );
        let v: YamlValue = serde_yaml_ng::from_str(&body).unwrap();
        DnsRecordSpec::from_value(&v).unwrap()
    }

    #[test]
    fn diff_no_change_when_present_and_match() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("present", Some("1.2.3.4"), 300);
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::NoChange), "{d:?}");
    }

    #[test]
    fn diff_create_when_absent_observed_but_present_desired() {
        let backend = MockDns::new();
        let spec = cf_spec("present", Some("1.2.3.4"), 300);
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Create));
    }

    #[test]
    fn diff_update_when_value_changed() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("present", Some("9.9.9.9"), 300);
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Update));
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].field, "value");
    }

    #[test]
    fn diff_update_when_ttl_changed() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("present", Some("1.2.3.4"), 60);
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Update));
        assert_eq!(d.changes[0].field, "ttl");
    }

    #[test]
    fn diff_delete_when_absent_desired_but_present_observed() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("absent", None, 300);
        let observed = observe(&backend, &spec).unwrap();
        let d = diff(&spec, &observed).unwrap();
        assert!(matches!(d.kind, DiffKind::Delete));
    }

    #[test]
    fn apply_create_calls_backend() {
        let backend = MockDns::new();
        let spec = cf_spec("present", Some("1.2.3.4"), 300);
        let step = Step::new("dns-create", "create", Json::Null);
        apply(&backend, &spec, &step).unwrap();
        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("create zone=example.com"));
    }

    #[test]
    fn apply_update_finds_record_then_updates() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("present", Some("9.9.9.9"), 60);
        let step = Step::new("dns-update", "update", Json::Null);
        apply(&backend, &spec, &step).unwrap();
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("update zone=example.com id=id1")));
    }

    #[test]
    fn apply_delete_finds_then_deletes() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "1.2.3.4".into(),
                ttl: 300,
            },
        );
        let spec = cf_spec("absent", None, 300);
        let step = Step::new("dns-delete", "delete", Json::Null);
        apply(&backend, &spec, &step).unwrap();
        let calls = backend.calls();
        assert!(calls.iter().any(|c| c.starts_with("delete zone=example.com id=id1")));
    }

    #[test]
    fn rollback_restores_prior_value() {
        let backend = MockDns::new();
        // Simulate: we've changed the record; prior_value=1.2.3.4
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "9.9.9.9".into(),
                ttl: 60,
            },
        );
        let spec = cf_spec("present", Some("9.9.9.9"), 60);
        let cp = json!({
            "prior_present": true,
            "prior_id": "id1",
            "prior_value": "1.2.3.4",
            "prior_ttl": 300,
        });
        rollback(&backend, &spec, &cp).unwrap();
        let r = backend
            .find_record("example.com", "app.example.com", RecordType::A)
            .unwrap()
            .unwrap();
        assert_eq!(r.value, "1.2.3.4");
        assert_eq!(r.ttl, 300);
    }

    #[test]
    fn rollback_deletes_when_prior_absent() {
        let backend = MockDns::new();
        backend.pre_insert(
            "example.com",
            DnsRecord {
                id: "id1".into(),
                fqdn: "app.example.com".into(),
                record_type: "A".into(),
                value: "9.9.9.9".into(),
                ttl: 60,
            },
        );
        let spec = cf_spec("present", Some("9.9.9.9"), 60);
        let cp = json!({"prior_present": false});
        rollback(&backend, &spec, &cp).unwrap();
        assert!(backend
            .find_record("example.com", "app.example.com", RecordType::A)
            .unwrap()
            .is_none());
    }
}
