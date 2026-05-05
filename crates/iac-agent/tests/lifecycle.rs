// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end agent tests against the real file provider.
//! Each test gets its own tempdir so they parallelize safely.

use iac_agent::{Agent, Config, ConfigOverrides};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::Notify;

fn build_agent(workdir: &Path) -> Agent {
    let state_dir = workdir.join("state");
    let manifests_dir = workdir.join("manifests.d");
    std::fs::create_dir_all(&manifests_dir).unwrap();

    let overrides = ConfigOverrides {
        state_dir: Some(state_dir),
        manifests_dir: Some(manifests_dir),
        observe_interval_secs: Some(1),
        environment: Some("test".into()),
        actor: Some("test".into()),
        server_url: None,
        agent_name: Some("test".into()),
        capabilities_file: None,
    };
    let cfg = Config::load(None, overrides).unwrap();
    Agent::new(cfg).unwrap()
}

fn write_manifest(manifests_dir: &Path, name: &str, target: &Path, content: &str) {
    let path = manifests_dir.join(format!("{name}.yaml"));
    std::fs::write(
        &path,
        format!(
            r#"apiVersion: iac.example/v1
kind: file
metadata:
  name: {name}
  environment: test
spec:
  path: {}
  mode: "0644"
  content: |
    {}
"#,
            target.display(),
            content,
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn observe_records_drift_for_missing_file() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());
    let target = dir.path().join("target.txt");
    write_manifest(&agent.config().manifests_dir, "x", &target, "hello");

    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.observed, 1);
    assert_eq!(summary.drift_detected, 1);
    assert!(summary.errors.is_empty(), "errors: {:?}", summary.errors);

    // Drift event was opened in the store.
    let store = agent.store();
    let drifts = tokio::task::spawn_blocking(move || store.list_open_drifts())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(drifts.len(), 1);
    assert!(drifts[0].resource_id.starts_with("file/"));
}

#[tokio::test]
async fn apply_converges_and_closes_drift() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());
    let target = dir.path().join("hello.txt");
    write_manifest(&agent.config().manifests_dir, "h", &target, "hello");

    // Observe → drift opens.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.drift_detected, 1);

    // Apply → file gets created.
    let r = agent.apply_once().await.unwrap();
    use iac_core::operation::OperationStatus;
    assert!(
        matches!(r.operation.status, OperationStatus::Succeeded),
        "operation: {r:?}"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello\n");

    // Observe again → no drift; the open event should have been closed during apply.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.drift_detected, 0);

    let store = agent.store();
    let n = tokio::task::spawn_blocking(move || store.open_drift_count())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn observe_clears_drift_on_its_own_when_world_converges_externally() {
    // If something else fixes the world (e.g. a human), the agent's drift
    // bookkeeping should auto-resolve on the next observe.
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());
    let target = dir.path().join("present.txt");
    write_manifest(&agent.config().manifests_dir, "p", &target, "hi");

    // First observe: drift.
    agent.observe_once().await.unwrap();
    let store = agent.store();
    let count = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.open_drift_count()
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(count, 1);

    // External fix.
    std::fs::write(&target, "hi\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Observe again: drift auto-closed.
    agent.observe_once().await.unwrap();
    let count = tokio::task::spawn_blocking(move || store.open_drift_count())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn run_loop_writes_status_and_exits_on_shutdown() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());
    let target = dir.path().join("loop.txt");
    write_manifest(&agent.config().manifests_dir, "loop", &target, "world");

    let shutdown = Arc::new(Notify::new());
    let agent_clone = agent.clone();
    let signaler = shutdown.clone();
    let handle = tokio::spawn(async move { agent_clone.run(signaler).await });

    // Wait for the status file to appear (initial cycle).
    let status_path = agent.config().status_file.clone();
    for _ in 0..50 {
        if status_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(status_path.exists(), "status file never appeared");

    // Read it.
    let status = iac_agent::status::read_status(&status_path).unwrap();
    assert_eq!(status.managed_resource_count, 1);
    assert!(status.last_observe_summary.is_some());

    // Shutdown; the loop should return promptly.
    shutdown.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), handle).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn observe_with_no_manifests_is_clean() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.observed, 0);
    assert_eq!(summary.drift_detected, 0);
    assert!(summary.errors.is_empty());
}

#[tokio::test]
async fn agent_runs_recorded_for_each_cycle() {
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path());

    agent.observe_once().await.unwrap();
    agent.observe_once().await.unwrap();
    agent.observe_once().await.unwrap();

    let store = agent.store();
    let runs = tokio::task::spawn_blocking(move || store.recent_runs(10))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runs.len(), 3);
    for r in &runs {
        assert!(r.finished_at.is_some());
        assert!(r.error.is_none());
    }
}
