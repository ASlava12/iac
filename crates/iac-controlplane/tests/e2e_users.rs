// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 6h: user CRUD endpoints. Admin-only operator workflow:
//! provision new users, list them, update roles / disabled / password,
//! soft-delete via DELETE.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_controlplane::identity::Role;
use iac_controlplane::store::CreateUser;
use iac_core::protocol::v1::{
    AuditEvent, CreateUserRequest, CreateUserResponse, LoginRequest, LoginResponse,
    UpdateUserRequest, UserView,
};
use reqwest::StatusCode;
use serde_json::json;


#[tokio::test]
async fn admin_creates_lists_and_disables_users() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // Create alice via API.
    let resp = client
        .post(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&CreateUserRequest {
            username: "alice".into(),
            password: "hunter2".into(),
            roles: vec!["operator".into()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let created: CreateUserResponse = resp.json().await.unwrap();
    assert!(!created.user_id.is_empty());

    // alice can log in.
    let login: LoginResponse = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "alice".into(),
            password: "hunter2".into(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(login.roles, vec!["operator"]);

    // List shows alice.
    let users: Vec<UserView> = client
        .get(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    assert!(users[0].disabled_at.is_none());

    // Disable alice (DELETE = soft delete).
    let resp = client
        .delete(format!("{}/v1/users/{}", server.url(), created.user_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Login fails after disable.
    let resp = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "alice".into(),
            password: "hunter2".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // List still shows alice with disabled_at populated.
    let users: Vec<UserView> = client
        .get(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(users[0].disabled_at.is_some());

    // Login attempt is recorded as 401 even before — re-enable and confirm.
    let resp = client
        .patch(format!("{}/v1/users/{}", server.url(), created.user_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest { disabled: Some(false), ..Default::default() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "alice".into(),
            password: "hunter2".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn admin_can_change_user_roles() {
    let server = TestServer::spawn().await;
    let id = server
        .store
        .create_user(CreateUser {
            username: "bob",
            password: "p",
            roles: vec![Role::Viewer],
        })
        .await
        .unwrap();

    // Bob can login as viewer.
    let client = reqwest::Client::new();
    let login: LoginResponse = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "bob".into(),
            password: "p".into(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(login.roles, vec!["viewer"]);

    // Promote Bob to approver.
    let resp = client
        .patch(format!("{}/v1/users/{id}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["approver".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Existing token didn't refresh roles in real-time — verify by fresh login.
    let login: LoginResponse = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest {
            username: "bob".into(),
            password: "p".into(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(login.roles, vec!["approver"]);

    server.shutdown().await;
}

#[tokio::test]
async fn admin_resets_password_revokes_existing_tokens() {
    let server = TestServer::spawn().await;
    let id = server
        .store
        .create_user(CreateUser {
            username: "carol",
            password: "old-p",
            roles: vec![Role::Operator],
        })
        .await
        .unwrap();

    let client = reqwest::Client::new();
    // Carol logs in with old password.
    let login: LoginResponse = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest { username: "carol".into(), password: "old-p".into() })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let old_token = login.token;

    // Admin resets password.
    let resp = client
        .patch(format!("{}/v1/users/{id}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest { password: Some("new-p".into()), ..Default::default() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Old token is revoked — using it on a protected endpoint is 401.
    // (Logout is intentionally idempotent and returns 200 even when the token
    // is already gone.)
    let resp = client
        .get(format!("{}/v1/audit", server.url()))
        .bearer_auth(&old_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Old password fails.
    let resp = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest { username: "carol".into(), password: "old-p".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // New password works.
    let resp = client
        .post(format!("{}/v1/auth/login", server.url()))
        .json(&LoginRequest { username: "carol".into(), password: "new-p".into() })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn non_admin_cannot_use_user_endpoints() {
    let server = TestServer::spawn().await;
    server
        .store
        .create_user(CreateUser {
            username: "viewer",
            password: "p",
            roles: vec![Role::Viewer],
        })
        .await
        .unwrap();
    server
        .store
        .create_user(CreateUser {
            username: "approver",
            password: "p",
            roles: vec![Role::Approver],
        })
        .await
        .unwrap();

    let client = reqwest::Client::new();
    for username in ["viewer", "approver"] {
        let login: LoginResponse = client
            .post(format!("{}/v1/auth/login", server.url()))
            .json(&LoginRequest { username: username.into(), password: "p".into() })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // GET and POST both denied.
        let resp = client
            .get(format!("{}/v1/users", server.url()))
            .bearer_auth(&login.token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = client
            .post(format!("{}/v1/users", server.url()))
            .bearer_auth(&login.token)
            .json(&CreateUserRequest {
                username: "intruder".into(),
                password: "x".into(),
                roles: vec!["admin".into()],
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    server.shutdown().await;
}

#[tokio::test]
async fn unknown_role_string_returns_400() {
    let server = TestServer::spawn().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&CreateUserRequest {
            username: "x".into(),
            password: "p".into(),
            roles: vec!["wizard".into()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    server.shutdown().await;
}

#[tokio::test]
async fn duplicate_username_returns_409() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&CreateUserRequest {
            username: "alice".into(),
            password: "p".into(),
            roles: vec!["viewer".into()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = client
        .post(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&CreateUserRequest {
            username: "alice".into(),
            password: "different".into(),
            roles: vec!["operator".into()],
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    server.shutdown().await;
}

#[tokio::test]
async fn user_audit_events_recorded() {
    let server = TestServer::spawn().await;
    let client = reqwest::Client::new();
    let created: CreateUserResponse = client
        .post(format!("{}/v1/users", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&CreateUserRequest {
            username: "diana".into(),
            password: "p".into(),
            roles: vec!["viewer".into()],
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let _ = client
        .patch(format!("{}/v1/users/{}", server.url(), created.user_id))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest {
            roles: Some(vec!["operator".into()]),
            ..Default::default()
        })
        .send()
        .await
        .unwrap();

    let _ = client
        .delete(format!("{}/v1/users/{}", server.url(), created.user_id))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();

    // Audit log: created → updated → disabled.
    let events: Vec<AuditEvent> = client
        .get(format!("{}/v1/audit", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"user.created"));
    assert!(kinds.contains(&"user.updated"));
    assert!(kinds.contains(&"user.disabled"));
    // Created event payload has username and roles.
    let created_event = events.iter().find(|e| e.kind == "user.created").unwrap();
    assert_eq!(created_event.payload["username"], "diana");
    assert_eq!(created_event.payload["roles"], json!(["viewer"]));

    server.shutdown().await;
}

#[tokio::test]
async fn empty_update_returns_400() {
    let server = TestServer::spawn().await;
    let id = server
        .store
        .create_user(CreateUser {
            username: "x",
            password: "p",
            roles: vec![Role::Viewer],
        })
        .await
        .unwrap();
    let resp = reqwest::Client::new()
        .patch(format!("{}/v1/users/{id}", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .json(&UpdateUserRequest::default())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    server.shutdown().await;
}
