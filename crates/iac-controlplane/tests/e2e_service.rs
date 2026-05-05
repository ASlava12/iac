// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7a: composite `kind: service` expansion + blast radius preview.
//! Operator submits one resource, server expands to two primitives, agents
//! receive both via assignments, blast radius is reported back at submit.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{
    DesiredStateBatch, OperationStatus, OperationView, SubmitOperationRequest,
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

#[tokio::test]
async fn service_expands_and_blast_radius_reported() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-svc", "svc");
    assert!(agent.connect_remote().await);

    // Operator submits ONE service resource.
    let req = SubmitOperationRequest {
        environment: "svc".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": "web", "environment": "svc" },
            "spec": {
                "image": "nginx:1.27-alpine",
                "port": 8080,
                "domain": "app.example.com",
            }
        })], canary: None,
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();

    // Server expanded service → docker.container + nginx.vhost. Both went
    // to the lone agent in the env, so we got 1 assignment carrying 2
    // resources.
    assert_eq!(submit.assignment_count, 1);
    assert_eq!(submit.blast_radius.resource_count, 2);
    assert_eq!(submit.blast_radius.agent_count, 1);
    assert_eq!(
        submit.blast_radius.kinds,
        vec!["docker.container".to_string(), "nginx.vhost".to_string()]
    );

    // The agent's desired-state endpoint shows BOTH expanded primitives.
    let identity: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("state/identity.json")).unwrap())
            .unwrap();
    let agent_id = identity["agent_id"].as_str().unwrap();
    let token = identity["token"].as_str().unwrap();
    let ds: DesiredStateBatch = reqwest::Client::new()
        .get(format!("{}/v1/agents/{}/desired-state", server.url(), agent_id))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ds.items.len(), 2);
    let kinds: Vec<&str> = ds
        .items
        .iter()
        .map(|i| i.resource["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"docker.container"));
    assert!(kinds.contains(&"nginx.vhost"));

    // OperationView lists both primitives via the assignment's payload.
    let view: OperationView = reqwest::Client::new()
        .get(format!("{}/v1/operations/{}", server.url(), submit.operation_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(view.assignments.len(), 1);
    // No agent has applied yet, so status is pending or running.
    assert!(matches!(
        view.status,
        OperationStatus::Pending | OperationStatus::Running
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn service_with_host_selector_routes_to_named_agent() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    // Two agents in the same env — the host selector picks one.
    let a = build_agent(&dir.path().join("a"), &server.url(), "host-A", "svc");
    assert!(a.connect_remote().await);
    let b = build_agent(&dir.path().join("b"), &server.url(), "host-B", "svc");
    assert!(b.connect_remote().await);

    let req = SubmitOperationRequest {
        environment: "svc".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": "api", "environment": "svc" },
            "spec": {
                "image": "ghcr.io/me/api:v1",
                "port": 9090,
                "domain": "api.example.com",
                "hostSelector": { "name": "host-A" },
            }
        })], canary: None,
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();

    // Both expanded primitives carry the same host selector → both go to
    // host-A. So 2 resources, 1 assignment.
    assert_eq!(submit.blast_radius.resource_count, 2);
    assert_eq!(submit.blast_radius.agent_count, 1);
    assert_eq!(submit.assignment_count, 1);

    server.shutdown().await;
}

#[tokio::test]
async fn malformed_service_spec_returns_400() {
    let server = TestServer::spawn().await;
    let _agent = build_agent(&TempDir::new().unwrap().keep(), &server.url(), "vm-svc", "svc");

    let req = SubmitOperationRequest {
        environment: "svc".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "service",
            "metadata": { "name": "broken", "environment": "svc" },
            "spec": {
                "image": "nginx",
                // missing required `port` and `domain`
            }
        })], canary: None,
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    server.shutdown().await;
}

#[tokio::test]
async fn primitive_resources_passthrough_with_blast_radius() {
    // Plain `file` resource — no expansion, blast radius shows kind=file.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let _agent = build_agent(dir.path(), &server.url(), "vm-prim", "prim");
    assert!(_agent.connect_remote().await);

    let target = dir.path().join("file.txt");
    let req = SubmitOperationRequest {
        environment: "prim".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "x", "environment": "prim" },
            "spec": { "path": target.display().to_string(), "mode": "0644", "content": "y\n" }
        })], canary: None,
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submit: SubmitOperationResponse = resp.json().await.unwrap();
    assert_eq!(submit.blast_radius.resource_count, 1);
    assert_eq!(submit.blast_radius.kinds, vec!["file".to_string()]);

    server.shutdown().await;
}
