// F3 (Phase 9 deferred → done locally): cold-reboot resilience.
//
// If an `iac-agent` process dies between observe and apply (or
// mid-apply), the next start must detect drift and converge. This
// test file exercises that contract without requiring a real OS
// process kill: it builds two `Agent` instances over the same
// `state_dir` (the on-disk identity / DB / manifests survive
// `Drop`, so a fresh `Agent` is the closest in-process analogue
// of "agent restarted after sudden death"). The interesting
// failure modes — half-applied host state, drifted host state
// while the agent was down — are simulated by tampering with the
// host between the two runs.
//
// What this DOESN'T cover (would need a real SIGKILL'd subprocess):
// open-FD flush ordering, SQLite WAL checkpoint mid-write, half-
// written audit rows. The DB layer's own atomicity (sqlx + WAL +
// the rename-tempfile pattern in `persist_identity`) covers most
// of that — the F4 atomic-write tests in `remote::tests` pin the
// identity-file invariant directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iac_agent::{Agent, Config, ConfigOverrides};
use iac_core::operation::OperationStatus;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Build an `Agent` config rooted at `state` + `manifests`. The
/// observe interval is set short so the test doesn't wait on the
/// real-world default (10 s).
fn cfg(state: &Path, manifests: &Path, agent_toml: &Path) -> Config {
    Config::load(
        Some(agent_toml),
        ConfigOverrides {
            state_dir: Some(state.to_path_buf()),
            manifests_dir: Some(manifests.to_path_buf()),
            observe_interval_secs: Some(1),
            environment: Some("test".into()),
            actor: Some("test".into()),
            server_url: None,
            agent_name: Some("test".into()),
            capabilities_file: None,
        },
    )
    .unwrap()
}

/// Drop a `file`-kind manifest under `manifests_dir/<name>.yaml`.
fn write_file_manifest(manifests_dir: &Path, name: &str, target: &Path, content: &str) {
    std::fs::write(
        manifests_dir.join(format!("{name}.yaml")),
        format!(
            "apiVersion: iac.example/v1\n\
             kind: file\n\
             metadata:\n  \
                 name: {name}\n  \
                 environment: test\n\
             spec:\n  \
                 path: {target}\n  \
                 mode: \"0644\"\n  \
                 content: |\n    {content}\n",
            target = target.display(),
        ),
    )
    .unwrap();
}

fn empty_agent_toml(dir: &Path) -> PathBuf {
    let p = dir.join("agent.toml");
    // Empty TOML is valid — all overrides come from `ConfigOverrides`.
    std::fs::write(&p, "").unwrap();
    p
}

/// F3 main case. The agent applies a manifest cleanly. The process
/// dies (we drop the `Agent`). Something on the host drifts the file
/// while the agent is down — this could be a SIGKILL'd half-apply, an
/// admin's hand-edit, or a misbehaving cron. After restart the agent
/// must observe the drift and reconverge to the desired state.
#[tokio::test]
async fn cold_reboot_observes_drift_and_reconverges() {
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state");
    let manifests = dir.path().join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let agent_toml = empty_agent_toml(dir.path());

    let target = dir.path().join("hello.txt");
    write_file_manifest(&manifests, "hello", &target, "hello-iac");

    // Run #1: clean apply of the manifest.
    let a1 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    let s1 = a1.observe_once().await.unwrap();
    assert_eq!(s1.drift_detected, 1, "first observe sees the absent file");
    let r1 = a1.apply_once().await.unwrap();
    assert!(matches!(r1.operation.status, OperationStatus::Succeeded));
    assert!(target.exists(), "first apply created the file");
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("hello-iac"),
        "first apply wrote the right content"
    );
    drop(a1);

    // Tamper between runs: the world drifts while the agent is down.
    std::fs::write(&target, "tampered-by-someone-else\n").unwrap();

    // Run #2: fresh agent against the *same* `state_dir`. The on-disk
    // applied-state survives the drop, so the agent's diff against
    // the desired manifest finds the host-side tamper.
    let a2 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    let s2 = a2.observe_once().await.unwrap();
    assert_eq!(
        s2.drift_detected, 1,
        "post-restart observe must detect the host-side tamper"
    );
    let r2 = a2.apply_once().await.unwrap();
    assert!(matches!(r2.operation.status, OperationStatus::Succeeded));

    let after = std::fs::read_to_string(&target).unwrap();
    assert!(
        after.contains("hello-iac"),
        "post-restart apply must reconverge the file (got: {after:?})"
    );
    assert!(
        !after.contains("tampered"),
        "tamper string must be gone after reconverge"
    );

    // Final observe sees no drift — the loop is fixed-point.
    let s3 = a2.observe_once().await.unwrap();
    assert_eq!(s3.drift_detected, 0, "post-reconverge state is steady");
}

/// F3 supplementary: a fresh agent against the SAME state_dir reuses
/// the prior identity / store. This invariant is what makes the
/// recovery story above non-trivial — if every restart wiped the
/// state, drift detection wouldn't have anything to compare against.
#[tokio::test]
async fn cold_reboot_preserves_state_dir_artifacts() {
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state");
    let manifests = dir.path().join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let agent_toml = empty_agent_toml(dir.path());

    let target = dir.path().join("touch.txt");
    write_file_manifest(&manifests, "t", &target, "x");

    let a1 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    a1.observe_once().await.unwrap();
    a1.apply_once().await.unwrap();

    // The agent's local store + status file must be there for run #2.
    let agent_db = state.join("agent.db");
    let status = state.join("status.json");
    assert!(agent_db.exists(), "agent.db missing after run 1");
    assert!(status.exists(), "status.json missing after run 1");
    let db_size_before = std::fs::metadata(&agent_db).unwrap().len();
    drop(a1);

    let a2 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    a2.observe_once().await.unwrap();
    let db_size_after = std::fs::metadata(&agent_db).unwrap().len();

    // SQLite WAL may grow slightly on the second open; we assert the
    // DB wasn't truncated to zero (which would be a real recovery
    // bug).
    assert!(
        db_size_after >= db_size_before / 2,
        "agent.db looks truncated across restart: {db_size_before} → {db_size_after}"
    );
}

/// F3 corner case: the manifest changes WHILE the agent is down.
/// Operator commits a new manifest (or the GitOps pull lands a newer
/// revision) between two agent invocations. The post-restart observe
/// must pick up the new desired state, not the cached one from the
/// applied-state DB.
#[tokio::test]
async fn cold_reboot_picks_up_manifest_change_made_while_down() {
    let dir = TempDir::new().unwrap();
    let state = dir.path().join("state");
    let manifests = dir.path().join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let agent_toml = empty_agent_toml(dir.path());

    let target = dir.path().join("conf.txt");
    write_file_manifest(&manifests, "c", &target, "v1");

    let a1 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    a1.observe_once().await.unwrap();
    a1.apply_once().await.unwrap();
    assert!(std::fs::read_to_string(&target).unwrap().contains("v1"));
    drop(a1);

    // Operator updates the manifest while the agent is offline.
    write_file_manifest(&manifests, "c", &target, "v2");

    let a2 = Agent::new(cfg(&state, &manifests, &agent_toml)).unwrap();
    let s = a2.observe_once().await.unwrap();
    assert_eq!(s.drift_detected, 1, "manifest change must surface as drift");
    a2.apply_once().await.unwrap();
    let after = std::fs::read_to_string(&target).unwrap();
    assert!(
        after.contains("v2") && !after.contains("v1"),
        "agent must converge to the new manifest after restart (got: {after:?})"
    );
}
