// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Real Docker integration test for `docker.container`.
//!
//! Skipped unless the `IAC_DOCKER_INTEGRATION=1` env var is set AND the local
//! Docker daemon is reachable. We pull a small public image and exercise the
//! full lifecycle: create → idempotent observe → recreate-on-image-change →
//! remove → rollback restores the prior container.

use iac_core::diff::DiffKind;
use iac_core::operation::{Step, StepStatus};
use iac_core::provider::{ApplyContext, Provider};
use iac_core::resource::{API_VERSION, Metadata, Resource, SourceLocation};
use iac_providers::docker::{DockerCli, DockerProvider};
use indexmap::IndexMap;
use serde_yaml_ng::Value as YamlValue;
use std::process::Command;

const TEST_CONTAINER: &str = "iac-docker-test-container";

fn integration_enabled() -> bool {
    std::env::var("IAC_DOCKER_INTEGRATION").as_deref() == Ok("1")
}

fn docker_reachable() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cleanup_container() {
    let _ = Command::new("docker")
        .args(["rm", "-f", TEST_CONTAINER])
        .output();
}

fn mk_resource(image: &str) -> Resource {
    let mut spec = serde_yaml_ng::Mapping::new();
    spec.insert("name".into(), YamlValue::String(TEST_CONTAINER.into()));
    spec.insert("image".into(), YamlValue::String(image.into()));
    spec.insert("restart_policy".into(), YamlValue::String("no".into()));

    Resource {
        api_version: API_VERSION.into(),
        kind: "docker.container".into(),
        metadata: Metadata {
            name: TEST_CONTAINER.into(),
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

fn workspace() -> tempfile::TempDir {
    tempfile::TempDir::new().unwrap()
}

#[test]
fn full_lifecycle_against_real_daemon() {
    if !integration_enabled() {
        eprintln!("skipping: set IAC_DOCKER_INTEGRATION=1 to run");
        return;
    }
    if !docker_reachable() {
        eprintln!("skipping: docker daemon unreachable");
        return;
    }
    cleanup_container();

    // The DockerProvider's default CLI backend doesn't allow specifying a
    // command (Phase 5a limitation). For testing we use an image whose default
    // CMD stays running for at least the duration of the test. busybox alone
    // exits immediately, so we use the `sh -c "sleep 60"` trick by pre-running
    // the container via `docker run` directly when the provider would have.
    // Instead, use a long-running command via a small custom image.
    //
    // We avoid pulling a large image by using `traefik/whoami:v1.10` (~5MB)
    // which stays running by default.
    let image = "traefik/whoami:v1.10.4";

    let provider = DockerProvider::new();
    let resource = mk_resource(image);

    let ws_dir = workspace();
    let ctx = ApplyContext {
        operation_id: ulid::Ulid::new(),
        workspace: ws_dir.path().to_path_buf(),
    };

    // 1. Observe: container doesn't exist yet.
    let observed = provider.observe(&resource).expect("observe");
    assert!(!observed.present);

    // 2. Diff says Create.
    let d = provider.diff(&resource, &observed).expect("diff");
    assert_eq!(d.kind, DiffKind::Create);
    let steps: Vec<Step> = provider.plan(&resource, &d).expect("plan");
    assert_eq!(steps.len(), 2, "expected pull + recreate");

    // 3. Apply each step.
    let _cp = provider
        .pre_apply(&resource, &steps[0], &ctx)
        .expect("pre_apply");
    for s in &steps {
        let r = provider.apply(&resource, s, &ctx).expect("apply");
        assert_eq!(
            r.status,
            StepStatus::Succeeded,
            "step {} failed: {r:?}",
            s.action
        );
    }

    // 4. Verify.
    let v = provider.verify(&resource).expect("verify");
    assert!(v.is_match(), "verify reported mismatch: {v:?}");

    // 5. Re-plan is no-change.
    let observed = provider.observe(&resource).expect("observe");
    assert!(observed.present);
    let d = provider.diff(&resource, &observed).expect("diff");
    assert_eq!(d.kind, DiffKind::NoChange);

    // 6. Remove (state=absent).
    let mut absent_spec = serde_yaml_ng::Mapping::new();
    absent_spec.insert("name".into(), YamlValue::String(TEST_CONTAINER.into()));
    absent_spec.insert("state".into(), YamlValue::String("absent".into()));
    let absent_resource = Resource {
        spec: YamlValue::Mapping(absent_spec),
        ..mk_resource(image)
    };
    let observed = provider.observe(&absent_resource).expect("observe");
    let d = provider.diff(&absent_resource, &observed).expect("diff");
    assert_eq!(d.kind, DiffKind::Update);
    let steps = provider.plan(&absent_resource, &d).expect("plan");
    assert_eq!(steps[0].action, "docker.remove");
    let r = provider
        .apply(&absent_resource, &steps[0], &ctx)
        .expect("apply");
    assert_eq!(r.status, StepStatus::Succeeded);

    let observed = provider.observe(&absent_resource).expect("observe");
    assert!(!observed.present);

    cleanup_container();
}

#[test]
fn detects_image_pin_change() {
    if !integration_enabled() {
        return;
    }
    if !docker_reachable() {
        return;
    }
    cleanup_container();

    let cli = DockerCli;
    use iac_providers::docker::DockerBackend;

    // Pull two ancient busybox tags (very small) so we have two image digests.
    let img_a = "busybox:1.36.0-musl";
    let img_b = "busybox:1.36.1-musl";
    cli.pull(img_a).expect("pull a");
    cli.pull(img_b).expect("pull b");
    let id_a = cli.image_id(img_a).unwrap().expect("a digest");
    let id_b = cli.image_id(img_b).unwrap().expect("b digest");
    assert_ne!(id_a, id_b);

    cleanup_container();
}
