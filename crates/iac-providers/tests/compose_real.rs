// Phase 7da.6: real `docker compose` integration test.
//
// Skipped unless `IAC_COMPOSE_INTEGRATION=1` AND the local Docker
// daemon + compose plugin are reachable. Exercises the full
// `DockerComposeProvider` lifecycle against a real daemon: observe
// (empty) → diff (Create) → apply (compose up) → observe (services
// running) → idempotent re-diff → state: absent → apply (compose
// down) → observe (empty).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_core::diff::DiffKind;
use iac_core::operation::{Step, StepStatus};
use iac_core::provider::{ApplyContext, Provider};
use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
use iac_providers::compose::DockerComposeProvider;
use indexmap::IndexMap;
use serde_yaml_ng::Value as YamlValue;
use std::process::Command;

const TEST_PROJECT: &str = "iac-compose-test";

fn integration_enabled() -> bool {
    std::env::var("IAC_COMPOSE_INTEGRATION").as_deref() == Ok("1")
}

fn compose_reachable() -> bool {
    Command::new("docker")
        .args(["compose", "version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cleanup() {
    let _ = Command::new("docker")
        .args([
            "compose",
            "-p",
            TEST_PROJECT,
            "down",
            "--remove-orphans",
            "-v",
        ])
        .output();
}

fn mk_resource(workdir: &std::path::Path, source: &str, state: &str) -> Resource {
    let mut spec = serde_yaml_ng::Mapping::new();
    spec.insert("project".into(), YamlValue::String(TEST_PROJECT.into()));
    spec.insert("source".into(), YamlValue::String(source.into()));
    spec.insert(
        "workdir".into(),
        YamlValue::String(workdir.display().to_string()),
    );
    spec.insert("state".into(), YamlValue::String(state.into()));
    Resource {
        api_version: API_VERSION.into(),
        kind: "docker.compose".into(),
        metadata: Metadata {
            name: TEST_PROJECT.into(),
            environment: "test".into(),
            owner: None,
            labels: IndexMap::new(),
            annotations: IndexMap::new(),
        },
        spec: YamlValue::Mapping(spec),
        policy: YamlValue::Null,
        source: SourceLocation::default(),
    }
}

#[test]
fn compose_full_lifecycle_against_real_daemon() {
    if !integration_enabled() {
        eprintln!("skipping: set IAC_COMPOSE_INTEGRATION=1 to run");
        return;
    }
    if !compose_reachable() {
        eprintln!("skipping: docker compose plugin unreachable");
        return;
    }
    cleanup();

    let tmp = tempfile::TempDir::new().unwrap();
    let ws = tempfile::TempDir::new().unwrap();
    let ctx = ApplyContext {
        operation_id: ulid::Ulid::new(),
        workspace: ws.path().to_path_buf(),
    };

    // Minimal stack: one alpine container that sleeps. Image is small
    // (~5 MiB) so even a slow CI cold-pull finishes in seconds.
    let source = r#"services:
  sleeper:
    image: alpine:3.20
    command: ["sleep", "120"]
"#;

    let provider = DockerComposeProvider::new();

    // 1. Initial state: nothing exists.
    let res = mk_resource(tmp.path(), source, "present");
    let observed = provider.observe(&res).expect("observe initial");
    let d = provider.diff(&res, &observed).expect("diff initial");
    assert_eq!(d.kind, DiffKind::Create, "expected Create, got {d:?}");

    // 2. Apply: compose up.
    let steps: Vec<Step> = provider.plan(&res, &d).expect("plan");
    assert!(!steps.is_empty(), "plan produced no steps");
    let _cp = provider
        .pre_apply(&res, &steps[0], &ctx)
        .expect("pre_apply");
    for s in &steps {
        let r = provider.apply(&res, s, &ctx).expect("apply");
        assert_eq!(r.status, StepStatus::Succeeded, "{}: {r:?}", s.action);
    }

    // 3. Observe-after-apply: service is running.
    let observed = provider.observe(&res).expect("observe after apply");
    let observed_json = serde_json::to_string(&observed.spec).unwrap();
    assert!(
        observed_json.contains("sleeper"),
        "expected sleeper service: {observed_json}"
    );

    // 4. Idempotent re-diff: NoChange.
    let d2 = provider.diff(&res, &observed).expect("re-diff");
    assert_eq!(
        d2.kind,
        DiffKind::NoChange,
        "second apply should be idempotent: {d2:?}"
    );

    // 5. Switch to state=absent.
    let res_absent = mk_resource(tmp.path(), source, "absent");
    let observed = provider.observe(&res_absent).expect("observe pre-absent");
    let d = provider.diff(&res_absent, &observed).expect("diff absent");
    assert!(
        d.is_change(),
        "absent + services present should diff as a change: {d:?}"
    );

    let steps = provider.plan(&res_absent, &d).expect("plan absent");
    let _cp = provider
        .pre_apply(&res_absent, &steps[0], &ctx)
        .expect("pre_apply absent");
    for s in &steps {
        let r = provider.apply(&res_absent, s, &ctx).expect("apply absent");
        assert_eq!(r.status, StepStatus::Succeeded, "absent: {r:?}");
    }

    // 6. Final observe: empty.
    let observed = provider.observe(&res_absent).expect("observe final");
    let observed_json = serde_json::to_string(&observed.spec).unwrap();
    assert!(
        !observed_json.contains("sleeper"),
        "stack should be torn down: {observed_json}"
    );

    cleanup();
}
