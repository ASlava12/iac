//! Phase 7bz: firewall ops — observe / diff / plan / apply / rollback.

use super::backend::FirewallBackend;
use super::spec::{Family, FirewallRuleSpec, FirewallState};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn FirewallBackend, spec: &FirewallRuleSpec) -> Result<ObservedState> {
    let observed = backend.query(&spec.name, spec.family)?;
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    match observed {
        None => {
            facts.insert("present".into(), YamlValue::Bool(false));
            Ok(ObservedState {
                present: false,
                spec: YamlValue::Null,
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
        Some(rule) => {
            facts.insert("present".into(), YamlValue::Bool(true));
            let mut spec_value = Mapping::new();
            spec_value.insert("name".into(), YamlValue::String(rule.name.clone()));
            spec_value.insert("chain".into(), YamlValue::String(rule.chain.clone()));
            spec_value.insert("protocol".into(), YamlValue::String(rule.protocol.clone()));
            if let Some(p) = rule.port {
                spec_value.insert(
                    "port".into(),
                    YamlValue::Number(serde_yaml_ng::Number::from(p as u64)),
                );
            }
            if let Some(s) = &rule.source {
                spec_value.insert("source".into(), YamlValue::String(s.clone()));
            }
            if let Some(d) = &rule.destination {
                spec_value.insert("destination".into(), YamlValue::String(d.clone()));
            }
            spec_value.insert("action".into(), YamlValue::String(rule.action.clone()));
            spec_value.insert(
                "family".into(),
                YamlValue::String(
                    match rule.family {
                        Family::Ipv4 => "ipv4",
                        Family::Ipv6 => "ipv6",
                    }
                    .into(),
                ),
            );
            Ok(ObservedState {
                present: true,
                spec: YamlValue::Mapping(spec_value),
                facts,
                observed_at: jiff::Timestamp::now(),
            })
        }
    }
}

pub fn diff(spec: &FirewallRuleSpec, observed: &ObservedState) -> Diff {
    let present = observed
        .facts
        .get("present")
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);

    match (&spec.state, present) {
        (FirewallState::Absent, false) => Diff::no_change(),
        (FirewallState::Absent, true) => Diff {
            kind: DiffKind::Update,
            changes: vec![FieldChange {
                field: "present".into(),
                from: Some(YamlValue::Bool(true)),
                to: Some(YamlValue::Bool(false)),
                sensitive: false,
            }],
            reasons: vec![format!("delete firewall rule {}", spec.name)],
            reversible: true,
        },
        (FirewallState::Present, false) => Diff {
            kind: DiffKind::Create,
            changes: vec![FieldChange {
                field: "present".into(),
                from: Some(YamlValue::Bool(false)),
                to: Some(YamlValue::Bool(true)),
                sensitive: false,
            }],
            reasons: vec![format!("create firewall rule {}", spec.name)],
            reversible: true,
        },
        (FirewallState::Present, true) => {
            // Compare each managed field. Unmanaged fields (e.g. an
            // operator-specified mark) live outside this resource's
            // ownership and aren't checked.
            let mut changes: Vec<FieldChange> = Vec::new();
            let mut reasons: Vec<String> = Vec::new();
            let observed_spec = observed.spec.as_mapping();
            let get_str = |k: &str| -> Option<String> {
                observed_spec
                    .and_then(|m| m.get(YamlValue::String(k.into())))
                    .and_then(YamlValue::as_str)
                    .map(str::to_string)
            };
            let get_num = |k: &str| -> Option<u64> {
                observed_spec
                    .and_then(|m| m.get(YamlValue::String(k.into())))
                    .and_then(YamlValue::as_u64)
            };
            macro_rules! cmp_str {
                ($field:literal, $observed:expr, $desired:expr) => {{
                    let obs = $observed;
                    let des = $desired;
                    if obs.as_deref() != des.as_deref() {
                        changes.push(FieldChange {
                            field: $field.into(),
                            from: obs.clone().map(YamlValue::String),
                            to: des.clone().map(YamlValue::String),
                            sensitive: false,
                        });
                        reasons.push(format!(
                            "{} {:?} -> {:?}",
                            $field,
                            obs.as_deref().unwrap_or(""),
                            des.as_deref().unwrap_or("")
                        ));
                    }
                }};
            }
            cmp_str!("chain", get_str("chain"), Some(spec.chain.clone()));
            cmp_str!("protocol", get_str("protocol"), Some(spec.protocol.clone()));
            cmp_str!("source", get_str("source"), spec.source.clone());
            cmp_str!("destination", get_str("destination"), spec.destination.clone());
            cmp_str!("action", get_str("action"), Some(spec.action.clone()));

            let observed_port = get_num("port").map(|p| p as u16);
            if observed_port != spec.port {
                changes.push(FieldChange {
                    field: "port".into(),
                    from: observed_port.map(|p| YamlValue::Number(p.into())),
                    to: spec.port.map(|p| YamlValue::Number(p.into())),
                    sensitive: false,
                });
                reasons.push(format!(
                    "port {:?} -> {:?}",
                    observed_port,
                    spec.port
                ));
            }

            if changes.is_empty() {
                Diff::no_change()
            } else {
                Diff {
                    kind: DiffKind::Update,
                    changes,
                    reasons,
                    reversible: true,
                }
            }
        }
    }
}

pub fn plan(spec: &FirewallRuleSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    let action = match spec.state {
        FirewallState::Present => super::FirewallAction::Upsert,
        FirewallState::Absent => super::FirewallAction::Delete,
    };
    vec![Step::new(
        action.as_str(),
        format!("firewall.rule/{}", spec.name),
        serde_json::json!({ "name": spec.name }),
    )]
}

pub fn pre_apply(backend: &dyn FirewallBackend, spec: &FirewallRuleSpec) -> Result<Json> {
    // Snapshot the existing rule so rollback can restore it. None means
    // "rule didn't exist before this apply" — rollback then deletes.
    let observed = backend.query(&spec.name, spec.family)?;
    Ok(json!({
        "previous": observed.map(|r| json!({
            "name": r.name,
            "table": r.table,
            "chain": r.chain,
            "protocol": r.protocol,
            "port": r.port,
            "source": r.source,
            "destination": r.destination,
            "action": r.action,
            "family": match r.family {
                Family::Ipv4 => "ipv4",
                Family::Ipv6 => "ipv6",
            },
        })),
    }))
}

pub fn apply(
    backend: &dyn FirewallBackend,
    spec: &FirewallRuleSpec,
    step: &Step,
) -> Result<StepResult> {
    match super::FirewallAction::parse(&step.action)? {
        super::FirewallAction::Upsert => {
            backend.ensure_present(spec)?;
            Ok(StepResult::ok(format!("upserted firewall rule {}", spec.name)))
        }
        super::FirewallAction::Delete => {
            backend.ensure_absent(&spec.name, &spec.table, &spec.chain, spec.family)?;
            Ok(StepResult::ok(format!("deleted firewall rule {}", spec.name)))
        }
    }
}

pub fn rollback(backend: &dyn FirewallBackend, spec: &FirewallRuleSpec, checkpoint: &Json) -> Result<()> {
    let prev = checkpoint.get("previous");
    match prev {
        Some(Json::Null) | None => {
            // The rule didn't exist before — rollback removes the
            // post-apply rule.
            backend.ensure_absent(&spec.name, &spec.table, &spec.chain, spec.family)?;
            Ok(())
        }
        Some(p) => {
            // Reconstruct the prior spec and re-apply it.
            let prev_family = match p.get("family").and_then(Json::as_str) {
                Some("ipv6") => Family::Ipv6,
                _ => Family::Ipv4,
            };
            let prev_spec = FirewallRuleSpec {
                name: p
                    .get("name")
                    .and_then(Json::as_str)
                    .unwrap_or(&spec.name)
                    .to_string(),
                table: p
                    .get("table")
                    .and_then(Json::as_str)
                    .unwrap_or("filter")
                    .to_string(),
                chain: p
                    .get("chain")
                    .and_then(Json::as_str)
                    .unwrap_or("INPUT")
                    .to_string(),
                protocol: p
                    .get("protocol")
                    .and_then(Json::as_str)
                    .unwrap_or("all")
                    .to_string(),
                port: p
                    .get("port")
                    .and_then(Json::as_u64)
                    .and_then(|n| u16::try_from(n).ok()),
                source: p
                    .get("source")
                    .and_then(Json::as_str)
                    .map(str::to_string),
                destination: p
                    .get("destination")
                    .and_then(Json::as_str)
                    .map(str::to_string),
                action: p
                    .get("action")
                    .and_then(Json::as_str)
                    .unwrap_or("ACCEPT")
                    .to_string(),
                family: prev_family,
                state: FirewallState::Present,
            };
            backend.ensure_present(&prev_spec)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockFirewall;
    use super::*;

    fn spec(name: &str) -> FirewallRuleSpec {
        FirewallRuleSpec {
            name: name.into(),
            table: "filter".into(),
            chain: "INPUT".into(),
            protocol: "tcp".into(),
            port: Some(22),
            source: Some("10.0.0.0/8".into()),
            destination: None,
            action: "ACCEPT".into(),
            family: Family::Ipv4,
            state: FirewallState::Present,
        }
    }

    #[test]
    fn observe_absent_when_rule_missing() {
        let backend = MockFirewall::new();
        let s = spec("test");
        let obs = observe(&backend, &s).unwrap();
        assert!(!obs.present);
    }

    #[test]
    fn observe_present_after_apply() {
        let backend = MockFirewall::new();
        let s = spec("test");
        backend.ensure_present(&s).unwrap();
        let obs = observe(&backend, &s).unwrap();
        assert!(obs.present);
    }

    #[test]
    fn diff_create_when_present_desired_and_absent_observed() {
        let backend = MockFirewall::new();
        let s = spec("test");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert_eq!(d.kind, DiffKind::Create);
    }

    #[test]
    fn diff_no_change_after_round_trip() {
        let backend = MockFirewall::new();
        let s = spec("test");
        backend.ensure_present(&s).unwrap();
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert!(!d.is_change(), "round-trip should not drift; got {d:?}");
    }

    #[test]
    fn diff_update_when_action_changes() {
        let backend = MockFirewall::new();
        let mut existing = spec("test");
        backend.ensure_present(&existing).unwrap();
        // Change action from ACCEPT to DROP.
        existing.action = "DROP".into();
        let obs = observe(&backend, &existing).unwrap();
        let d = diff(&existing, &obs);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.changes.iter().any(|c| c.field == "action"));
    }

    #[test]
    fn diff_update_when_port_changes() {
        let backend = MockFirewall::new();
        let mut s = spec("test");
        backend.ensure_present(&s).unwrap();
        s.port = Some(2222);
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert!(d.changes.iter().any(|c| c.field == "port"));
    }

    #[test]
    fn diff_delete_when_absent_desired_and_present_observed() {
        let backend = MockFirewall::new();
        let mut s = spec("test");
        backend.ensure_present(&s).unwrap();
        s.state = FirewallState::Absent;
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.reasons[0].contains("delete"));
    }

    #[test]
    fn plan_emits_upsert_for_present() {
        let s = spec("test");
        let diff = Diff {
            kind: DiffKind::Create,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        };
        let steps = plan(&s, &diff);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "firewall.upsert");
    }

    #[test]
    fn plan_emits_delete_for_absent() {
        let mut s = spec("test");
        s.state = FirewallState::Absent;
        let diff = Diff {
            kind: DiffKind::Update,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        };
        let steps = plan(&s, &diff);
        assert_eq!(steps[0].action, "firewall.delete");
    }

    #[test]
    fn apply_upsert_creates_rule_via_backend() {
        let backend = MockFirewall::new();
        let s = spec("test");
        let step = Step::new(
            "firewall.upsert",
            format!("firewall.rule/{}", s.name),
            serde_json::json!({ "name": s.name }),
        );
        apply(&backend, &s, &step).unwrap();
        let rules = backend.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "test");
    }

    #[test]
    fn apply_delete_removes_rule_via_backend() {
        let backend = MockFirewall::new();
        let mut s = spec("test");
        backend.ensure_present(&s).unwrap();
        s.state = FirewallState::Absent;
        let step = Step::new(
            "firewall.delete",
            format!("firewall.rule/{}", s.name),
            serde_json::json!({ "name": s.name }),
        );
        apply(&backend, &s, &step).unwrap();
        assert!(backend.rules().is_empty());
    }

    #[test]
    fn rollback_to_no_previous_deletes_rule() {
        let backend = MockFirewall::new();
        let s = spec("test");
        backend.ensure_present(&s).unwrap();
        let cp = json!({ "previous": null });
        rollback(&backend, &s, &cp).unwrap();
        assert!(backend.rules().is_empty());
    }

    #[test]
    fn rollback_to_previous_restores_prior_spec() {
        let backend = MockFirewall::new();
        // Pre-existing rule with action ACCEPT.
        let mut prior = spec("test");
        backend.ensure_present(&prior).unwrap();
        let prior_cp = pre_apply(&backend, &prior).unwrap();

        // Apply a change to DROP.
        prior.action = "DROP".into();
        backend.ensure_present(&prior).unwrap();
        let after = backend.rules();
        assert_eq!(after[0].action, "DROP");

        // Roll back — should restore ACCEPT.
        rollback(&backend, &prior, &prior_cp).unwrap();
        let restored = backend.rules();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].action, "ACCEPT");
    }
}
