// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6f: `Policy.approvers` enforcement at the approve endpoint.
//! When a matched policy declares an approvers list, only callers whose
//! display name is in the list (or who hold the Admin role) can approve.

mod common;

use common::{ADMIN_TOKEN, TestServer};

use iac_controlplane::identity::Role;
use iac_controlplane::policy::{Policy, PolicyMatch};
use iac_controlplane::store::CreateUser;
use iac_core::protocol::v1::{
    LoginRequest, LoginResponse, OperationApproveRequest, SubmitOperationRequest,
    SubmitOperationResponse,
};
use reqwest::StatusCode;
use serde_json::json;
use tempfile::TempDir;

async fn spawn(policies: Vec<Policy>) -> TestServer {
    TestServer::builder().policies(policies).build().await
}

async fn login(server: &TestServer, name: &str, password: &str) -> String {
    let resp: LoginResponse = reqwest::Client::new()
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: name.into(),
            password: password.into(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp.token
}

async fn submit(server: &TestServer, bearer: &str) -> SubmitOperationResponse {
    let dir = TempDir::new().unwrap();
    reqwest::Client::new()
        .post(format!("{}/v1/operations", server.url()))
        .bearer_auth(bearer)
        .json(&SubmitOperationRequest {
            environment: "prod".into(),
            requested_by: "any".into(),
            source_commit: None,
            summary: None,
            resources: vec![json!({
                "apiVersion": "iac.example/v1",
                "kind": "file",
                "metadata": { "name": "x", "environment": "prod" },
                "spec": { "path": dir.path().join("x").display().to_string(), "mode": "0644", "content": "y\n" }
            })], canary: None,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn prod_policy_with_approvers(approvers: Vec<&str>) -> Policy {
    Policy {
        name: "prod-needs-named-approver".into(),
        r#match: PolicyMatch {
            environment: Some("prod".into()),
            kind: None,
            resource_count_min: None,
        },
        requires_approval: true,
        approvers: approvers.iter().map(|s| s.to_string()).collect(),
        rate_limit_per_minute: None,
    }
}

#[tokio::test]
async fn approver_in_list_can_approve() {
    let server = spawn(vec![prod_policy_with_approvers(vec!["alice"])]).await;
    server
        .store
        .create_user(CreateUser {
            username: "alice",
            password: "p",
            roles: vec![Role::Approver],
        })
        .await
        .unwrap();
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    let alice = login(&server, "alice", "p").await;
    let op = login(&server, "op", "p").await;

    let resp = submit(&server, &op).await;
    assert_eq!(resp.assignment_count, 0);

    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(&alice)
        .json(&OperationApproveRequest {
            reason: Some("LGTM".into()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn approver_not_in_list_is_forbidden() {
    let server = spawn(vec![prod_policy_with_approvers(vec!["alice"])]).await;
    server
        .store
        .create_user(CreateUser {
            username: "bob",
            password: "p",
            roles: vec![Role::Approver],
        })
        .await
        .unwrap();
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    let bob = login(&server, "bob", "p").await;
    let op = login(&server, "op", "p").await;

    let resp = submit(&server, &op).await;

    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(&bob)
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    server.shutdown().await;
}

#[tokio::test]
async fn admin_role_bypasses_approvers_list() {
    let server = spawn(vec![prod_policy_with_approvers(vec!["alice"])]).await;
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    server
        .store
        .create_user(CreateUser {
            username: "carol",
            password: "p",
            roles: vec![Role::Admin],
        })
        .await
        .unwrap();
    let op = login(&server, "op", "p").await;
    let carol = login(&server, "carol", "p").await;

    let resp = submit(&server, &op).await;

    // Carol has Admin → bypasses the list even though her name isn't in it.
    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(&carol)
        .json(&OperationApproveRequest {
            reason: Some("break glass".into()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // Static legacy admin token — also Admin.
    server.shutdown().await;
}

#[tokio::test]
async fn empty_approvers_list_means_any_approver_role() {
    let server = spawn(vec![prod_policy_with_approvers(vec![])]).await;
    server
        .store
        .create_user(CreateUser {
            username: "bob",
            password: "p",
            roles: vec![Role::Approver],
        })
        .await
        .unwrap();
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    let bob = login(&server, "bob", "p").await;
    let op = login(&server, "op", "p").await;

    let resp = submit(&server, &op).await;

    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(&bob)
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn legacy_admin_token_bypasses_approvers_list() {
    // Legacy admin path should always succeed for break-glass.
    let server = spawn(vec![prod_policy_with_approvers(vec!["alice"])]).await;
    server
        .store
        .create_user(CreateUser {
            username: "op",
            password: "p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();
    let op = login(&server, "op", "p").await;
    let resp = submit(&server, &op).await;

    let r = reqwest::Client::new()
        .post(format!(
            "{}/v1/operations/{}/approve",
            server.url(),
            resp.operation_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&OperationApproveRequest { reason: None })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    server.shutdown().await;
}
