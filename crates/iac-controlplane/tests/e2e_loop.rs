// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 2c: closing the loop. After an operator submits desired state, the
//! agent should keep observing those resources on every cycle — even when
//! they aren't in the agent's local manifests dir — and push drift events
//! that reach the server.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{
    DesiredStateBatch, DriftSummary, OperationStatus, OperationView, SubmitOperationRequest,
    SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;


fn build_agent(workdir: &Path, server_url: &str, name: &str, env: &str) -> Agent {
    let manifests = workdir.join("manifests.d");
    std::fs::create_dir_all(&manifests).unwrap();
    let cfg = AgentConfig::load(
        None,
        ConfigOverrides {
            state_dir: Some(workdir.join("state")),
            manifests_dir: Some(manifests),
            observe_interval_secs: Some(1),
            environment: Some(env.into()),
            actor: Some("test".into()),
            server_url: Some(server_url.into()),
            agent_name: Some(name.into()),
            capabilities_file: None,
        },
    )
    .unwrap();
    Agent::new(cfg).unwrap()
}

fn file_resource_json(name: &str, env: &str, target: &Path, content: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": target.display().to_string(),
            "mode": "0644",
            "content": format!("{content}\n"),
        }
    })
}

async fn submit(
    server_url: &str,
    environment: &str,
    resources: Vec<serde_json::Value>,
) -> SubmitOperationResponse {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{server_url}/v1/operations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: environment.into(),
            requested_by: "op".into(),
            source_commit: None,
            summary: None,
            resources, canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn agent_observes_server_submitted_resource_with_no_local_manifest() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("watched.txt");
    let agent = build_agent(dir.path(), &server.url(), "loop-agent", "loop");
    assert!(agent.connect_remote().await);

    // Local manifests dir is intentionally EMPTY.
    assert!(agent.load_manifests().await.unwrap().is_empty());

    // Operator submits the resource.
    let resp = submit(
        &server.url(),
        "loop",
        vec![file_resource_json("watched", "loop", &target, "hello")],
    )
    .await;
    assert_eq!(resp.assignment_count, 1);

    // Agent observe → drains assignment → applies → pushes back.
    agent.observe_once().await.unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello\n");

    // Drift the file out-of-band.
    std::fs::write(&target, "tampered\n").unwrap();

    // The desired-state endpoint should still surface the resource for this agent.
    let client = reqwest::Client::new();
    let identity_path = dir.path().join("state/identity.json");
    let identity_text = std::fs::read_to_string(&identity_path).unwrap();
    let id_val: serde_json::Value = serde_json::from_str(&identity_text).unwrap();
    let agent_id = id_val["agent_id"].as_str().unwrap().to_string();
    let token = id_val["token"].as_str().unwrap().to_string();

    let ds: DesiredStateBatch = client
        .get(format!("{}/v1/agents/{}/desired-state", server.url(), agent_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ds.items.len(), 1);
    assert!(ds.items[0].resource_id.contains("watched"));

    // Next observe — local manifests still empty, but server desired state
    // should drive the cycle. Drift should be detected and pushed.
    let summary = agent.observe_once().await.unwrap();
    assert_eq!(summary.observed, 1, "agent should have observed the server-managed resource");
    assert_eq!(summary.drift_detected, 1);

    // Server-side drift list should reflect it.
    let drifts: Vec<DriftSummary> = client
        .get(format!("{}/v1/drift", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(drifts.len(), 1);
    assert!(drifts[0].resource_id.contains("watched"));

    server.shutdown().await;
}

#[tokio::test]
async fn newer_operation_supersedes_older_desired_state_per_resource() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("greet.txt");
    let agent = build_agent(dir.path(), &server.url(), "supersede-agent", "loop");
    assert!(agent.connect_remote().await);

    // First operation: content "v1".
    let r1 = submit(
        &server.url(),
        "loop",
        vec![file_resource_json("greet", "loop", &target, "v1")],
    )
    .await;
    assert_eq!(r1.assignment_count, 1);
    agent.observe_once().await.unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "v1\n");

    // Second operation: same resource, content "v2".
    let r2 = submit(
        &server.url(),
        "loop",
        vec![file_resource_json("greet", "loop", &target, "v2")],
    )
    .await;
    assert_eq!(r2.assignment_count, 1);
    agent.observe_once().await.unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "v2\n");

    // Desired-state endpoint should show only ONE entry for `greet`, with v2.
    let client = reqwest::Client::new();
    let agent_id = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(dir.path().join("state/identity.json")).unwrap(),
    )
    .unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let token = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(dir.path().join("state/identity.json")).unwrap(),
    )
    .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let ds: DesiredStateBatch = client
        .get(format!("{}/v1/agents/{}/desired-state", server.url(), agent_id))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ds.items.len(), 1, "expected dedup to one entry per resource");
    let content = ds.items[0].resource["spec"]["content"].as_str().unwrap();
    assert_eq!(content, "v2\n");
    assert_eq!(ds.items[0].operation_id, r2.operation_id);

    server.shutdown().await;
}

#[tokio::test]
async fn second_op_routes_to_same_agent_when_only_one_exists_in_env() {
    // Sanity test for the "only one agent in env" routing branch interacting
    // with the new desired-state pipeline.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "lone-agent", "lone");
    assert!(agent.connect_remote().await);

    let target = dir.path().join("once.txt");
    let resp = submit(
        &server.url(),
        "lone",
        vec![file_resource_json("once", "lone", &target, "yes")],
    )
    .await;
    assert_eq!(resp.assignment_count, 1);

    agent.observe_once().await.unwrap();
    assert!(target.exists());

    // Operation should be succeeded.
    let client = reqwest::Client::new();
    let view: OperationView = client
        .get(format!("{}/v1/operations/{}", server.url(), resp.operation_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(view.status, OperationStatus::Succeeded));

    server.shutdown().await;
}
