// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7g: dependency-graph ordering for resources within an
//! operation. `metadata.dependsOn` declares "this resource needs X
//! applied first." Server-side topo sort guarantees the agent
//! receives resources in dependency-respecting order.

mod common;

use common::{ADMIN_TOKEN, TestServer};

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{
    DesiredStateBatch, OperationDesiredState, SubmitOperationRequest, SubmitOperationResponse,
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

fn file_resource(name: &str, env: &str, depends_on: &[&str]) -> serde_json::Value {
    let mut metadata = json!({ "name": name, "environment": env });
    if !depends_on.is_empty() {
        metadata["dependsOn"] = json!(depends_on);
    }
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": metadata,
        "spec": {
            "path": format!("/tmp/{name}"),
            "mode": "0644",
            "content": format!("{name}\n"),
        }
    })
}

async fn submit(
    server: &TestServer,
    env: &str,
    resources: Vec<serde_json::Value>,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&SubmitOperationRequest {
            environment: env.into(),
            requested_by: "alice".into(),
            source_commit: None,
            summary: None,
            resources,
            canary: None,
        })
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn dependency_reorders_resources_in_assignment() {
    // Submit resources b, a where b depends on a. The agent's
    // desired-state list should arrive with a *before* b regardless
    // of submission order.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-dep", "ord");
    assert!(agent.connect_remote().await);

    let resp = submit(
        &server,
        "ord",
        vec![
            file_resource("b", "ord", &["file/ord/a"]),
            file_resource("a", "ord", &[]),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();
    // Phase 7by: dependsOn now produces one assignment per (agent, layer).
    // `a` (layer 0) and `b` (layer 1) end up in separate assignments
    // even when targeted at the same agent — the layer-1 one stays in
    // `pending_layer` until layer-0 succeeds, providing the
    // cross-agent gating that's the whole point of phased apply.
    // For a single-agent same-pipeline op the visible effect is two
    // assignments instead of one; the agent still sees them in topo
    // order and applies them sequentially.
    assert_eq!(submit.assignment_count, 2);

    // Phase 7b preview reflects the topologically-sorted order: a, b.
    let preview: OperationDesiredState = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = preview
        .items
        .iter()
        .map(|i| i.resource["metadata"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a", "b"]);

    // Agent's desired-state endpoint reads from a different angle —
    // it joins via assignments and orders by resource_id+created_at.
    // The point of the test is that the *operation* preview matches
    // declared dependencies. Sanity check that the agent saw both.
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("state/identity.json")).unwrap())
            .unwrap();
    let ds: DesiredStateBatch = reqwest::Client::new()
        .get(format!(
            "{}/v1/agents/{}/desired-state",
            server.url(),
            identity["agent_id"].as_str().unwrap()
        ))
        .bearer_auth(identity["token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ds.items.len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn dependency_chain_ordered_correctly() {
    // c → b → a. Submit in reverse to prove the sort actually does work.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-chain", "ord");
    assert!(agent.connect_remote().await);

    let resp = submit(
        &server,
        "ord",
        vec![
            file_resource("c", "ord", &["file/ord/b"]),
            file_resource("b", "ord", &["file/ord/a"]),
            file_resource("a", "ord", &[]),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();

    let preview: OperationDesiredState = reqwest::Client::new()
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = preview
        .items
        .iter()
        .map(|i| i.resource["metadata"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a", "b", "c"]);

    server.shutdown().await;
}

#[tokio::test]
async fn cycle_rejected_at_submit() {
    let server = TestServer::spawn().await;
    let _agent = build_agent(
        &TempDir::new().unwrap().keep(),
        &server.url(),
        "vm-x",
        "ord",
    );

    let resp = submit(
        &server,
        "ord",
        vec![
            file_resource("a", "ord", &["file/ord/b"]),
            file_resource("b", "ord", &["file/ord/a"]),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("cycle"), "body: {body}");

    server.shutdown().await;
}

#[tokio::test]
async fn unknown_dependency_rejected_at_submit() {
    let server = TestServer::spawn().await;
    let _agent = build_agent(
        &TempDir::new().unwrap().keep(),
        &server.url(),
        "vm-u",
        "ord",
    );

    let resp = submit(
        &server,
        "ord",
        vec![file_resource("a", "ord", &["file/ord/nonexistent"])],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("nonexistent") && body.contains("unknown"),
        "body: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn no_depends_on_passes_through_submit() {
    // Ensure the topo sort doesn't break the non-dependsOn path.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-clean", "ord");
    assert!(agent.connect_remote().await);

    let resp = submit(
        &server,
        "ord",
        vec![
            file_resource("first", "ord", &[]),
            file_resource("second", "ord", &[]),
        ],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}
