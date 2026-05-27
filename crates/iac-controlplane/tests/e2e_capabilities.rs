// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6a: agent enforces a capability allowlist before applying any
//! assignment from the control-plane. Resources outside the rules cause the
//! whole assignment to fail with `capability_denied` items so the operator
//! sees exactly what was rejected.

mod common;

use common::{ADMIN_TOKEN, TestServer};

use iac_agent::{Agent, Config as AgentConfig, ConfigOverrides};
use iac_core::protocol::v1::{
    OperationStatus, OperationView, SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;

fn build_agent(
    workdir: &Path,
    server_url: &str,
    name: &str,
    env: &str,
    caps: Option<&Path>,
) -> Agent {
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
            capabilities_file: caps.map(|p| p.to_path_buf()),
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
            resources,
            canary: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn capability_denied_resource_fails_whole_assignment() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();

    // Capability allowlist: only /tmp/<this test>/allowed/** for files.
    let allowed_dir = dir.path().join("allowed");
    let forbidden_dir = dir.path().join("forbidden");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&forbidden_dir).unwrap();

    let caps_path = dir.path().join("capabilities.yaml");
    std::fs::write(
        &caps_path,
        format!(
            r#"
files:
  allow:
    - "{}/**"
"#,
            allowed_dir.display()
        ),
    )
    .unwrap();

    let agent = build_agent(
        dir.path(),
        &server.url(),
        "caps-agent",
        "caps",
        Some(&caps_path),
    );
    assert!(agent.connect_remote().await);

    // Two resources: one inside allowed/, one inside forbidden/.
    let target_ok = allowed_dir.join("ok.txt");
    let target_bad = forbidden_dir.join("bad.txt");

    let resp = submit(
        &server.url(),
        "caps",
        vec![
            file_resource_json("ok", "caps", &target_ok, "fine"),
            file_resource_json("bad", "caps", &target_bad, "denied"),
        ],
    )
    .await;
    assert_eq!(resp.assignment_count, 1);

    // Drive one observe cycle. The agent fetches the assignment, sees one
    // resource fails the capability check, and returns Failed for the whole
    // assignment without applying anything.
    agent.observe_once().await.unwrap();

    // Neither file should have been written — assignments are atomic w.r.t.
    // capability denial.
    assert!(
        !target_ok.exists(),
        "allowed file should NOT exist when assignment was rejected"
    );
    assert!(!target_bad.exists(), "forbidden file should NOT exist");

    // Server should reflect the failure.
    let client = reqwest::Client::new();
    let view: OperationView = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(view.status, OperationStatus::Failed));
    let assignment = &view.assignments[0];
    assert_eq!(assignment.status, "failed");
    let result = assignment.result.as_ref().expect("result present");
    let items = result["items"].as_array().expect("items array");
    let denied: Vec<&str> = items
        .iter()
        .filter_map(|i| {
            if i["status"].as_str() == Some("capability_denied") {
                Some(i["resource_id"].as_str().unwrap())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(denied.len(), 1);
    assert!(denied[0].contains("bad"));

    server.shutdown().await;
}

#[tokio::test]
async fn capability_allowlist_lets_clean_assignment_through() {
    // Same setup but EVERY resource is in the allowlist — should apply normally.
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();

    let allowed_dir = dir.path().join("allowed");
    std::fs::create_dir_all(&allowed_dir).unwrap();

    let caps_path = dir.path().join("capabilities.yaml");
    std::fs::write(
        &caps_path,
        format!(
            r#"
files:
  allow:
    - "{}/**"
"#,
            allowed_dir.display()
        ),
    )
    .unwrap();

    let agent = build_agent(
        dir.path(),
        &server.url(),
        "caps-clean",
        "caps",
        Some(&caps_path),
    );
    assert!(agent.connect_remote().await);

    let target = allowed_dir.join("ok.txt");
    let resp = submit(
        &server.url(),
        "caps",
        vec![file_resource_json("ok", "caps", &target, "fine")],
    )
    .await;
    assert_eq!(resp.assignment_count, 1);

    agent.observe_once().await.unwrap();
    assert!(target.exists());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "fine\n");

    let client = reqwest::Client::new();
    let view: OperationView = client
        .get(format!(
            "{}/v1/operations/{}",
            server.url(),
            resp.operation_id
        ))
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

#[tokio::test]
async fn missing_capabilities_file_is_unrestricted() {
    let server = TestServer::spawn().await;
    let dir = TempDir::new().unwrap();
    // capabilities_file points at a path that doesn't exist → soft-start mode.
    let caps_path = dir.path().join("capabilities.yaml");
    assert!(!caps_path.exists());

    let agent = build_agent(
        dir.path(),
        &server.url(),
        "caps-soft",
        "caps",
        Some(&caps_path),
    );
    assert!(agent.connect_remote().await);

    let target = dir.path().join("anywhere.txt");
    let resp = submit(
        &server.url(),
        "caps",
        vec![file_resource_json("any", "caps", &target, "ok")],
    )
    .await;
    assert_eq!(resp.assignment_count, 1);

    agent.observe_once().await.unwrap();
    assert!(target.exists(), "no capabilities file → unrestricted");

    server.shutdown().await;
}
