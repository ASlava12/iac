// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7k: composite `web-with-monitoring` expansion. One submission
//! becomes four primitives — docker.container + nginx.vhost + file
//! (healthcheck script) + cron.job — co-located on the same agent.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{
    OperationDesiredState, SubmitOperationRequest, SubmitOperationResponse,
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
async fn web_with_monitoring_expands_and_lands_on_one_agent() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    let agent = build_agent(dir.path(), &server.url(), "vm-web", "prod");
    assert!(agent.connect_remote().await);

    let req = SubmitOperationRequest {
        environment: "prod".into(),
        requested_by: "alice".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "web-with-monitoring",
            "metadata": { "name": "api", "environment": "prod" },
            "spec": {
                "image": "ghcr.io/me/api:v1",
                "port": 8080,
                "domain": "api.example.com",
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

    // 4 primitives, all routed to the lone agent → 1 assignment.
    assert_eq!(submit.assignment_count, 1);
    assert_eq!(submit.blast_radius.resource_count, 4);
    assert_eq!(submit.blast_radius.agent_count, 1);
    let kinds = submit.blast_radius.kinds.clone();
    assert!(kinds.contains(&"docker.container".to_string()));
    assert!(kinds.contains(&"nginx.vhost".to_string()));
    assert!(kinds.contains(&"file".to_string()));
    assert!(kinds.contains(&"cron.job".to_string()));

    // Phase 7b preview shows all four routed to the same agent.
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
    assert_eq!(preview.items.len(), 4);
    let agents: std::collections::BTreeSet<&str> =
        preview.items.iter().map(|i| i.agent_id.as_str()).collect();
    assert_eq!(agents.len(), 1, "all four must route to the same agent");
    // Every primitive carries the composite annotation.
    for item in &preview.items {
        assert_eq!(
            item.resource["metadata"]["annotations"]["iac.example/composite-of"],
            "web-with-monitoring"
        );
    }

    server.shutdown().await;
}
