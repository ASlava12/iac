//! Phase 7ca: monitoring.check ops — the lifecycle for an asserted
//! invariant.
//!
//! Unusual for the IaC model: most providers WRITE state (file/docker/
//! firewall). monitoring.check OBSERVES state — runs an active check
//! and reports whether the world matches the desired invariant.
//!
//! Mapping to the standard lifecycle:
//!   * observe: run the check, encode result in `present` field
//!   * diff: present (healthy) ↔ Update if absent state desired,
//!     or NoChange if Present desired and currently healthy
//!     - Unhealthy + Present desired = Create-style "needs apply"
//!   * apply: re-run the check; succeed iff healthy
//!   * rollback: no-op (this resource doesn't write state to undo)

use super::backend::{CheckBackend, CheckOutcome};
use super::spec::{CheckState, MonitoringCheckSpec};
use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    operation::{Step, StepResult},
    state::ObservedState,
    Error, Result,
};
use indexmap::IndexMap;
use serde_json::{json, Value as Json};
use serde_yaml_ng::{Mapping, Value as YamlValue};

pub fn observe(backend: &dyn CheckBackend, spec: &MonitoringCheckSpec) -> Result<ObservedState> {
    let mut facts: IndexMap<String, YamlValue> = IndexMap::new();
    let mut spec_value = Mapping::new();
    spec_value.insert("name".into(), YamlValue::String(spec.name.clone()));
    spec_value.insert("target".into(), YamlValue::String(spec.target.clone()));

    if matches!(spec.state, CheckState::Absent) {
        // Absent state means "skip this check". Observed = converged
        // by definition; no probe runs.
        facts.insert("active".into(), YamlValue::Bool(false));
        facts.insert("healthy".into(), YamlValue::Bool(true));
        return Ok(ObservedState {
            present: true,
            spec: YamlValue::Mapping(spec_value),
            facts,
            observed_at: jiff::Timestamp::now(),
        });
    }

    let outcome = backend.run(spec)?;
    let healthy = outcome.is_healthy();
    facts.insert("active".into(), YamlValue::Bool(true));
    facts.insert("healthy".into(), YamlValue::Bool(healthy));
    facts.insert(
        "message".into(),
        YamlValue::String(outcome.message().to_string()),
    );
    Ok(ObservedState {
        present: healthy,
        spec: YamlValue::Mapping(spec_value),
        facts,
        observed_at: jiff::Timestamp::now(),
    })
}

pub fn diff(spec: &MonitoringCheckSpec, observed: &ObservedState) -> Diff {
    let healthy = observed
        .facts
        .get("healthy")
        .and_then(YamlValue::as_bool)
        .unwrap_or(false);

    match (&spec.state, healthy) {
        (CheckState::Absent, _) => Diff::no_change(),
        (CheckState::Present, true) => Diff::no_change(),
        (CheckState::Present, false) => {
            let message = observed
                .facts
                .get("message")
                .and_then(YamlValue::as_str)
                .unwrap_or("unhealthy")
                .to_string();
            Diff {
                kind: DiffKind::Update,
                changes: vec![FieldChange {
                    field: "healthy".into(),
                    from: Some(YamlValue::Bool(false)),
                    to: Some(YamlValue::Bool(true)),
                    sensitive: false,
                }],
                reasons: vec![format!("check {} unhealthy: {}", spec.name, message)],
                // Reversibility flag is misleading here — this resource
                // doesn't change state, it ASSERTS it. Marking
                // reversible=true so phased-apply rollback machinery
                // doesn't refuse rollback at the operation level.
                reversible: true,
            }
        }
    }
}

pub fn plan(spec: &MonitoringCheckSpec, diff: &Diff) -> Vec<Step> {
    if !diff.is_change() {
        return Vec::new();
    }
    vec![Step::new(
        super::MonitoringAction::Verify.as_str(),
        format!("monitoring.check/{}", spec.name),
        json!({ "name": spec.name }),
    )]
}

pub fn pre_apply(_backend: &dyn CheckBackend, _spec: &MonitoringCheckSpec) -> Result<Json> {
    // This resource doesn't write state, so there's nothing to
    // checkpoint for rollback. Return empty payload.
    Ok(json!({}))
}

pub fn apply(
    backend: &dyn CheckBackend,
    spec: &MonitoringCheckSpec,
    step: &Step,
) -> Result<StepResult> {
    let _ = super::MonitoringAction::parse(&step.action)?;
    // Phase 7cj: retry-on-failure. Total attempts = 1 + retries.
    // Each loop iteration runs one probe. First success short-circuits.
    // Sleep happens BETWEEN attempts so we never sleep after the
    // last failed probe (would just delay error reporting).
    let total_attempts = 1u32.saturating_add(spec.retries);
    let mut last_reason: Option<String> = None;
    for attempt in 0..total_attempts {
        let outcome = backend.run(spec)?;
        match outcome {
            CheckOutcome::Healthy => {
                let msg = if attempt == 0 {
                    format!("check {} passed", spec.name)
                } else {
                    format!(
                        "check {} passed on attempt {}/{}",
                        spec.name,
                        attempt + 1,
                        total_attempts
                    )
                };
                return Ok(StepResult::ok(msg));
            }
            CheckOutcome::Unhealthy(reason) => {
                last_reason = Some(reason);
                let attempts_remaining = total_attempts - attempt - 1;
                if attempts_remaining > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(
                        spec.retry_interval_secs,
                    ));
                }
            }
        }
    }
    Err(Error::provider(
        "monitoring.check",
        format!(
            "check {} failed after {} attempt(s): {}",
            spec.name,
            total_attempts,
            last_reason.unwrap_or_else(|| "unknown".into())
        ),
    ))
}

pub fn rollback(_backend: &dyn CheckBackend, _spec: &MonitoringCheckSpec) -> Result<()> {
    // No-op. monitoring.check doesn't mutate external state, so
    // rollback has nothing to undo. Operators rolling back a failed
    // operation that included a check just see the check skipped.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockCheck;
    use super::super::spec::CheckType;
    use super::*;

    fn spec(name: &str) -> MonitoringCheckSpec {
        MonitoringCheckSpec {
            name: name.into(),
            check_type: CheckType::Http,
            target: "http://localhost/".into(),
            expected_status: None,
            timeout_secs: 5,
            state: CheckState::Present,
            retries: 0,
            retry_interval_secs: 1,
        }
    }

    #[test]
    fn observe_present_when_healthy() {
        let backend = MockCheck::always_healthy();
        let s = spec("t");
        let obs = observe(&backend, &s).unwrap();
        assert!(obs.present);
        assert_eq!(
            obs.facts.get("healthy").and_then(YamlValue::as_bool),
            Some(true)
        );
    }

    #[test]
    fn observe_absent_when_unhealthy() {
        let backend = MockCheck::always_unhealthy("connection refused");
        let s = spec("t");
        let obs = observe(&backend, &s).unwrap();
        assert!(!obs.present);
        assert_eq!(
            obs.facts.get("healthy").and_then(YamlValue::as_bool),
            Some(false)
        );
        assert_eq!(
            obs.facts.get("message").and_then(YamlValue::as_str),
            Some("connection refused")
        );
    }

    #[test]
    fn observe_absent_state_skips_probe_and_reports_converged() {
        let backend = MockCheck::always_unhealthy("would fail if run");
        let mut s = spec("t");
        s.state = CheckState::Absent;
        let obs = observe(&backend, &s).unwrap();
        assert!(obs.present);
        assert_eq!(
            obs.facts.get("active").and_then(YamlValue::as_bool),
            Some(false)
        );
        // Backend should NOT have been called.
        assert_eq!(backend.call_count(), 0);
    }

    #[test]
    fn diff_no_change_when_healthy() {
        let backend = MockCheck::always_healthy();
        let s = spec("t");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert!(!d.is_change());
    }

    #[test]
    fn diff_update_when_unhealthy() {
        let backend = MockCheck::always_unhealthy("timeout");
        let s = spec("t");
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert_eq!(d.kind, DiffKind::Update);
        assert!(d.reasons[0].contains("unhealthy"));
        assert!(d.reasons[0].contains("timeout"));
    }

    #[test]
    fn diff_no_change_when_state_absent() {
        let backend = MockCheck::always_unhealthy("would fail");
        let mut s = spec("t");
        s.state = CheckState::Absent;
        let obs = observe(&backend, &s).unwrap();
        let d = diff(&s, &obs);
        assert!(!d.is_change(), "absent state must always be converged");
    }

    #[test]
    fn plan_emits_verify_step_on_change() {
        let s = spec("t");
        let d = Diff {
            kind: DiffKind::Update,
            changes: vec![],
            reasons: vec![],
            reversible: true,
        };
        let steps = plan(&s, &d);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].action, "monitoring.verify");
    }

    #[test]
    fn apply_succeeds_when_check_passes() {
        use iac_core::operation::StepStatus;
        let backend = MockCheck::always_healthy();
        let s = spec("t");
        let step = Step::new(
            "monitoring.verify",
            format!("monitoring.check/{}", s.name),
            json!({}),
        );
        let res = apply(&backend, &s, &step).unwrap();
        assert!(matches!(res.status, StepStatus::Succeeded));
    }

    #[test]
    fn apply_fails_when_check_fails() {
        let backend = MockCheck::always_unhealthy("connection refused");
        let s = spec("t");
        let step = Step::new(
            "monitoring.verify",
            format!("monitoring.check/{}", s.name),
            json!({}),
        );
        let err = apply(&backend, &s, &step).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("connection refused"), "msg: {msg}");
    }

    #[test]
    fn pre_apply_returns_empty_checkpoint() {
        let backend = MockCheck::always_healthy();
        let s = spec("t");
        let cp = pre_apply(&backend, &s).unwrap();
        assert_eq!(cp, json!({}));
    }

    #[test]
    fn rollback_is_noop() {
        let backend = MockCheck::always_unhealthy("anything");
        let s = spec("t");
        rollback(&backend, &s).unwrap();
        // No-op completes without error.
    }

    // -------- Phase 7cj: retry-on-failure tests ---------

    #[test]
    fn apply_retries_until_healthy_then_succeeds() {
        // Backend reports unhealthy first 2 attempts, then healthy.
        // Spec sets retries=3 → up to 4 total attempts. Expect
        // success on attempt 3, mock called exactly 3 times.
        use iac_core::operation::StepStatus;
        let backend = MockCheck::always_unhealthy("not yet");
        backend.queue_outcome(CheckOutcome::Unhealthy("warming up".into()));
        backend.queue_outcome(CheckOutcome::Unhealthy("almost there".into()));
        backend.queue_outcome(CheckOutcome::Healthy);
        let mut s = spec("t");
        s.retries = 3;
        s.retry_interval_secs = 0; // no sleep in tests
        let step = Step::new(
            "monitoring.verify",
            format!("monitoring.check/{}", s.name),
            json!({}),
        );
        let res = apply(&backend, &s, &step).unwrap();
        assert!(matches!(res.status, StepStatus::Succeeded));
        // 2 unhealthy from queue + 1 healthy from queue (3 total).
        // queue insert(0) means earliest-queued pops first, so order
        // is: unhealthy, unhealthy, healthy.
        assert_eq!(backend.call_count(), 3);
    }

    #[test]
    fn apply_fails_after_exhausting_retries() {
        let backend = MockCheck::always_unhealthy("never recovers");
        let mut s = spec("t");
        s.retries = 4;
        s.retry_interval_secs = 0;
        let step = Step::new(
            "monitoring.verify",
            format!("monitoring.check/{}", s.name),
            json!({}),
        );
        let err = apply(&backend, &s, &step).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("after 5 attempt") && msg.contains("never recovers"),
            "msg: {msg}"
        );
        assert_eq!(backend.call_count(), 5, "1 + retries");
    }

    #[test]
    fn apply_passes_first_try_skips_retries() {
        use iac_core::operation::StepStatus;
        let backend = MockCheck::always_healthy();
        let mut s = spec("t");
        s.retries = 10;
        s.retry_interval_secs = 0;
        let step = Step::new(
            "monitoring.verify",
            format!("monitoring.check/{}", s.name),
            json!({}),
        );
        let res = apply(&backend, &s, &step).unwrap();
        assert!(matches!(res.status, StepStatus::Succeeded));
        assert_eq!(
            backend.call_count(),
            1,
            "first probe passed; no retries needed"
        );
    }
}
