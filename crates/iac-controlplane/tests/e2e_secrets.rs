// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7am + 7co: end-to-end secret resolution.
//!
//! 7am introduced server-side substitution of `${secret://...}` tokens.
//! 7co (security fix) MOVED that substitution from submit-time to
//! agent-fetch time so resolved values never enter the DB. Tests here
//! enforce both:
//!
//!   1. After submit, `desired_states.spec_json` contains the
//!      reference verbatim — no plaintext leak via DB dumps.
//!   2. When an agent fetches assignments, the served payload has
//!      the resolved value.
//!   3. Fail-closed: a server with NO registry rejects a submission
//!      containing a secret ref.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_controlplane::secrets::{EnvResolver, Resolver, SecretRegistry};
use iac_core::protocol::v1::{
    AssignmentList, OperationDesiredState, OperationDesiredStateItem, RegisterRequest,
    SubmitOperationRequest, SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;

async fn spawn(registry: Option<SecretRegistry>) -> TestServer {
    let mut b = TestServer::builder();
    if let Some(r) = registry {
        b = b.secret_registry(Arc::new(r));
    }
    b.build().await
}

fn registry_with_env() -> SecretRegistry {
    let mut r = SecretRegistry::new();
    r.register(Resolver::Env(EnvResolver));
    r
}

/// Build a resource with a `${secret://...}` token in its content field.
/// The `file` provider's `content` field is a plain string — perfect for
/// asserting that substitution happened.
fn file_resource_with_secret(name: &str, env: &str, target: &str) -> serde_json::Value {
    json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": { "name": name, "environment": env },
        "spec": {
            "path": target,
            "mode": "0644",
            // Embed the env-var read inside a longer string so we exercise
            // the multi-segment substitution path, not just whole-string replace.
            "content": "PATH=${secret://env/PATH}\n",
        }
    })
}

#[tokio::test]
async fn secret_refs_persist_unresolved_in_desired_state() {
    // Phase 7co: secret values must NEVER hit the database.
    // After submit, `desired_states.spec_json` still contains the
    // `${secret://...}` reference verbatim. Resolution happens on the
    // way out (in `list_assignments` for agents). A DB dump / read-
    // only replica leaks references, not credentials.
    let server = spawn(Some(registry_with_env())).await;

    let req = SubmitOperationRequest {
        environment: "secrets-test".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: Some("env secret stays as ref".into()),
        resources: vec![file_resource_with_secret(
            "greet",
            "secrets-test",
            "/tmp/iac-secret-test.txt",
        )], canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "submit failed: {}",
        resp.text().await.unwrap()
    );
    let submit: SubmitOperationResponse = resp.json().await.unwrap();

    // Persisted desired-state must contain the REFERENCE — not the
    // resolved value. This is the core security invariant of Phase 7co.
    let resp = client
        .get(format!(
            "{}/v1/operations/{}/desired-state",
            server.url(),
            submit.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: OperationDesiredState = resp.json().await.unwrap();
    assert_eq!(body.items.len(), 1, "exactly one desired-state row");
    let item: &OperationDesiredStateItem = &body.items[0];
    let content = item.resource["spec"]["content"]
        .as_str()
        .expect("spec.content must be a string");
    assert_eq!(
        content, "PATH=${secret://env/PATH}\n",
        "DB must store the reference, not the resolved value"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn agent_fetch_receives_resolved_secret_value() {
    // Phase 7co: complement to the previous test. The DB stores
    // refs; the agent's `GET /v1/agents/{id}/assignments` resolves
    // them on the fly before signing. The agent applies the
    // resolved value, but the resolved value never persists.
    let server = spawn(Some(registry_with_env())).await;
    let real_path = std::env::var("PATH").expect("PATH must be set");

    // Register an agent so the operation can be routed.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/agents/register", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&RegisterRequest {
            name: "vm-secret".into(),
            environment: "secrets-test".into(),
            metadata: serde_json::Value::Null,
        })
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();
    let agent_token = body["token"].as_str().unwrap().to_string();

    // Submit manifest with a secret ref. The submit clones the
    // resource, smoke-tests resolution, but persists the original.
    let req = SubmitOperationRequest {
        environment: "secrets-test".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![file_resource_with_secret(
            "greet",
            "secrets-test",
            "/tmp/iac-secret-fetch-test.txt",
        )],
        canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Agent fetch: the served payload must have the RESOLVED value.
    let resp = client
        .get(format!("{}/v1/agents/{agent_id}/assignments", server.url()))
        .bearer_auth(&agent_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list: AssignmentList = resp.json().await.unwrap();
    assert_eq!(list.items.len(), 1, "exactly one assignment");
    let env = &list.items[0];
    let resource = &env.payload.resources[0];
    let content = resource["spec"]["content"].as_str().unwrap();
    assert_eq!(
        content,
        format!("PATH={real_path}\n"),
        "agent gets resolved value"
    );
    assert!(
        !content.contains("${secret://"),
        "no unresolved tokens in agent payload"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn submit_without_registry_rejects_secret_refs() {
    // Server has no registry → any secret ref is fail-closed.
    let server = spawn(None).await;

    let req = SubmitOperationRequest {
        environment: "secrets-test".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![file_resource_with_secret(
            "greet",
            "secrets-test",
            "/tmp/iac-secret-test.txt",
        )], canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("no resolver"),
        "error should explain that no resolver is configured: {body}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn submit_without_secrets_in_request_works_under_registry() {
    // Registry present but the manifest has no `${secret://...}` tokens —
    // the resolver should be a no-op and submission should succeed normally.
    let server = spawn(Some(registry_with_env())).await;

    let req = SubmitOperationRequest {
        environment: "secrets-test".into(),
        requested_by: "op".into(),
        source_commit: None,
        summary: None,
        resources: vec![json!({
            "apiVersion": "iac.example/v1",
            "kind": "file",
            "metadata": { "name": "plain", "environment": "secrets-test" },
            "spec": {
                "path": "/tmp/plain.txt",
                "mode": "0644",
                "content": "no secrets here\n",
            }
        })], canary: None,
    };
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}
