// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7c: composite `kind: cron-job-bundle` expansion. Operator submits
//! one resource, server expands to `file` (the script) + `cron.job` (the
//! schedule). Same pattern as Phase 7a's `service` — agents stay primitive.

mod common;

use common::{TestServer, ADMIN_TOKEN};

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

#[tokio::test]
async fn cron_bundle_expands_and_blast_radius_reported() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-cron", "ops");
    assert!(agent.connect_remote().await);

    let req = SubmitOperationRequest {
        environment: "ops".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": "nightly-backup", "environment": "ops" },
            "spec": {
                "schedule": "0 3 * * *",
                "script": "#!/bin/bash\necho hello\n",
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

    // Bundle expanded → file + cron.job. Both go to vm-cron, so 1 assignment
    // carrying 2 resources.
    assert_eq!(submit.assignment_count, 1);
    assert_eq!(submit.blast_radius.resource_count, 2);
    assert_eq!(submit.blast_radius.agent_count, 1);
    assert_eq!(
        submit.blast_radius.kinds,
        vec!["cron.job".to_string(), "file".to_string()]
    );

    // Agent's desired-state endpoint shows BOTH expanded primitives.
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
    assert!(kinds.contains(&"file"));
    assert!(kinds.contains(&"cron.job"));

    // Cross-check the file path in the cron.job spec matches the file's path.
    let file = ds.items.iter().find(|i| i.resource["kind"] == "file").unwrap();
    let cron = ds.items.iter().find(|i| i.resource["kind"] == "cron.job").unwrap();
    assert_eq!(
        file.resource["spec"]["path"].as_str().unwrap(),
        cron.resource["spec"]["command"].as_str().unwrap()
    );
    // Default script path is /usr/local/bin/<name>.
    assert_eq!(
        cron.resource["spec"]["command"].as_str().unwrap(),
        "/usr/local/bin/nightly-backup"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn cron_bundle_with_host_selector_routes_to_named_agent() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let a = build_agent(&dir.path().join("a"), &server.url(), "cron-A", "ops");
    assert!(a.connect_remote().await);
    let b = build_agent(&dir.path().join("b"), &server.url(), "cron-B", "ops");
    assert!(b.connect_remote().await);

    let req = SubmitOperationRequest {
        environment: "ops".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": "rotate-logs", "environment": "ops" },
            "spec": {
                "schedule": "*/30 * * * *",
                "script": "echo rotating",
                "scriptPath": "/opt/scripts/rotate.sh",
                "user": "logger",
                "hostSelector": { "name": "cron-A" },
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
    assert_eq!(submit.blast_radius.resource_count, 2);
    assert_eq!(submit.blast_radius.agent_count, 1);
    assert_eq!(submit.assignment_count, 1);

    // Phase 7b preview shows both children, both routed to cron-A.
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
    assert_eq!(preview.items.len(), 2);
    let agents: std::collections::BTreeSet<&str> =
        preview.items.iter().map(|i| i.agent_id.as_str()).collect();
    assert_eq!(agents.len(), 1);
    // Both children point at the custom path.
    let cron = preview
        .items
        .iter()
        .find(|i| i.kind == "cron.job")
        .unwrap();
    assert_eq!(
        cron.resource["spec"]["command"].as_str().unwrap(),
        "/opt/scripts/rotate.sh"
    );
    assert_eq!(cron.resource["spec"]["user"].as_str().unwrap(), "logger");

    server.shutdown().await;
}

#[tokio::test]
async fn malformed_cron_bundle_spec_returns_400() {
    let server = TestServer::spawn().await;
    let _agent = build_agent(&TempDir::new().unwrap().keep(), &server.url(), "vm-cron", "ops");

    // Missing required `script`.
    let req = SubmitOperationRequest {
        environment: "ops".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "cron-job-bundle",
            "metadata": { "name": "broken", "environment": "ops" },
            "spec": { "schedule": "* * * * *" }
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
