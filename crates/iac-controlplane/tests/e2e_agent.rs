// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Agent ↔ control-plane end-to-end test. Drives a real `iac-agent` against a
//! live axum server bound to 127.0.0.1:0. Covers: register, push observations,
//! push drift, heartbeat, drift auto-close on convergence.

mod common;

use common::TestServer;

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{AgentSummary, DriftSummary};
use std::path::Path;
use tempfile::TempDir;

fn build_agent(workdir: &Path, server_url: &str) -> Agent {
    let manifests = workdir.join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let cfg = AgentConfig::load(
        None,
        ConfigOverrides {
            state_dir: Some(workdir.join("state")),
            manifests_dir: Some(manifests),
            observe_interval_secs: Some(1),
            environment: Some("test".into()),
            actor: Some("test".into()),
            server_url: Some(server_url.to_string()),
            agent_name: Some(format!("agent-{}", ulid::Ulid::new())),
            capabilities_file: None,
        },
    )
    .unwrap();
    Agent::new(cfg).unwrap()
}

fn write_file_manifest(manifests_dir: &Path, name: &str, target: &Path, content: &str) {
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
async fn agent_registers_then_pushes_observations_and_drift() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("hello.txt");
    let agent = build_agent(dir.path(), &server.url_base());

    write_file_manifest(&agent.config().manifests_dir, "hello", &target, "hi");

    // First connect should register and store identity.
    assert!(agent.connect_remote().await, "expected agent to register");
    let id_path = agent.config().identity_file.clone();
    assert!(id_path.exists(), "identity file should be persisted");

    // First observe — file is missing, so drift gets recorded and pushed.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.observed, 1);
    assert_eq!(summary.drift_detected, 1);

    // Server side should now know about the agent.
    let client = reqwest::Client::new();
    let agents: Vec<AgentSummary> = client
        .get(format!("{}/v1/agents", server.url_base()))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].environment, "test");
    assert_eq!(agents[0].open_drifts, 1);
    assert!(agents[0].last_heartbeat_at.is_some());
    assert!(agents[0].last_observation_at.is_some());

    let drifts: Vec<DriftSummary> = client
        .get(format!("{}/v1/drift", server.url_base()))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drifts.len(), 1);
    assert!(drifts[0].resource_id.contains("hello"));

    // Apply locally → file created, drift cleared on agent side.
    let r = agent.apply_once().await.unwrap();
    use iac_core::operation::OperationStatus;
    assert!(matches!(r.operation.status, OperationStatus::Succeeded));

    // Next observe pushes empty drift batch → server auto-closes.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.drift_detected, 0);

    let drifts: Vec<DriftSummary> = client
        .get(format!("{}/v1/drift", server.url_base()))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drifts.len(), 0, "server-side drift should be auto-closed");

    server.shutdown().await;
}

#[tokio::test]
async fn agent_with_unreachable_server_falls_back_to_standalone() {
    let dir = TempDir::new().unwrap();
    // Bind to an address nothing is listening on.
    let agent = build_agent(dir.path(), "http://127.0.0.1:1");

    // Should NOT panic / abort even though the server isn't there.
    assert!(!agent.connect_remote().await);

    // Local observe still works.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.observed, 0);
}

#[tokio::test]
async fn agent_persists_identity_across_runs() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();

    // First "boot": registers fresh.
    let a1 = build_agent(dir.path(), &server.url_base());
    assert!(a1.connect_remote().await);
    let identity_text = std::fs::read_to_string(&a1.config().identity_file).unwrap();
    let id1: serde_json::Value = serde_json::from_str(&identity_text).unwrap();
    let agent_id_1 = id1["agent_id"].as_str().unwrap().to_string();
    drop(a1);

    // Second "boot": picks up the stored identity, no re-registration.
    let a2 = build_agent(dir.path(), &server.url_base());
    assert!(a2.connect_remote().await);
    let identity_text = std::fs::read_to_string(&a2.config().identity_file).unwrap();
    let id2: serde_json::Value = serde_json::from_str(&identity_text).unwrap();
    let agent_id_2 = id2["agent_id"].as_str().unwrap();
    assert_eq!(
        agent_id_1, agent_id_2,
        "identity should be reused across runs"
    );

    // The server should still see exactly ONE agent registered.
    let client = reqwest::Client::new();
    let agents: Vec<AgentSummary> = client
        .get(format!("{}/v1/agents", server.url_base()))
        .bearer_auth("test-admin")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agents.len(), 1);

    server.shutdown().await;
}
