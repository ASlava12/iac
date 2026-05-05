// Phase 7cz.16: integration tests are compiled as their own crates, so the
// crate-root #[cfg_attr(test, allow(...))] does not reach here. Add it locally.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Phase 7ce: server signing-key rotation. End-to-end coverage of the
//! admin endpoints `/v1/admin/signing-keys/rotate` and `/retire`, plus
//! the public bundle endpoint `/v1/signing-keys`.
//!
//! Why these tests matter:
//!   * Rotation must produce a fresh key_id without losing the old
//!     one — concurrent in-flight assignments signed under the old
//!     key still need to verify until they're picked up.
//!   * Retire must refuse the active key (operator must rotate first).
//!   * Bundle endpoint must reflect on-disk state.
//!   * Admin gate must reject non-admin callers.
//!   * Audit log must record both rotate + retire with the actor.

mod common;

use common::{TestServer, ADMIN_TOKEN};

use iac_core::protocol::v1::{SigningPubkey, SigningPubkeyBundle};
use reqwest::StatusCode;
use tempfile::TempDir;


#[tokio::test]
async fn signing_keys_bundle_returns_active_alone_initially() {
    let server = TestServer::spawn().await;
    let bundle: SigningPubkeyBundle = reqwest::Client::new()
        .get(format!("{}/v1/signing-keys", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bundle.keys.len(), 1, "fresh server has only the active key");
    assert_eq!(bundle.keys[0].key_id, bundle.active_key_id);
    server.shutdown().await;
}

#[tokio::test]
async fn rotate_changes_active_keeps_old_in_bundle() {
    let server = TestServer::spawn().await;

    // Capture initial state via /v1/signing-pubkey (legacy single-key).
    let initial: SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let initial_id = initial.key_id.clone();
    let initial_pub = initial.public_key.clone();

    // Rotate.
    let rotated: SigningPubkeyBundle = reqwest::Client::new()
        .post(format!("{}/v1/admin/signing-keys/rotate", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(rotated.active_key_id, initial_id, "active changed");
    assert_eq!(rotated.keys.len(), 2, "old key retained in verification set");
    let ids: Vec<&str> = rotated.keys.iter().map(|k| k.key_id.as_str()).collect();
    assert!(ids.contains(&initial_id.as_str()));
    assert!(ids.contains(&rotated.active_key_id.as_str()));

    // /v1/signing-pubkey now returns the NEW active.
    let new_active: SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(new_active.key_id, rotated.active_key_id);
    assert_ne!(new_active.public_key, initial_pub);

    // /v1/signing-keys also reflects the change.
    let bundle: SigningPubkeyBundle = reqwest::Client::new()
        .get(format!("{}/v1/signing-keys", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(bundle.active_key_id, rotated.active_key_id);
    assert_eq!(bundle.keys.len(), 2);

    server.shutdown().await;
}

#[tokio::test]
async fn retire_removes_old_key_after_rotate() {
    let server = TestServer::spawn().await;

    let initial: SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Rotate so we have an old key to retire.
    reqwest::Client::new()
        .post(format!("{}/v1/admin/signing-keys/rotate", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Retire the original.
    let retired: SigningPubkeyBundle = reqwest::Client::new()
        .post(format!(
            "{}/v1/admin/signing-keys/{}/retire",
            server.url(),
            initial.key_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retired.keys.len(), 1, "only active remains after retire");
    assert_eq!(retired.keys[0].key_id, retired.active_key_id);
    assert_ne!(retired.active_key_id, initial.key_id);

    server.shutdown().await;
}

#[tokio::test]
async fn retire_active_key_rejected_with_409() {
    let server = TestServer::spawn().await;
    let initial: SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/admin/signing-keys/{}/retire",
            server.url(),
            initial.key_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "operator must rotate before retiring active"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn retire_unknown_key_returns_404() {
    let server = TestServer::spawn().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/v1/admin/signing-keys/{}/retire",
            server.url(),
            "01NEVER_EXISTED"
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    server.shutdown().await;
}

#[tokio::test]
async fn rotate_requires_admin_token() {
    let server = TestServer::spawn().await;
    // No bearer at all.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/admin/signing-keys/rotate", server.url()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong bearer.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/admin/signing-keys/rotate", server.url()))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    server.shutdown().await;
}

#[tokio::test]
async fn rotate_and_retire_appear_in_audit_log() {
    let server = TestServer::spawn().await;

    let initial: SigningPubkey = reqwest::Client::new()
        .get(format!("{}/v1/signing-pubkey", server.url()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    reqwest::Client::new()
        .post(format!("{}/v1/admin/signing-keys/rotate", server.url()))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    reqwest::Client::new()
        .post(format!(
            "{}/v1/admin/signing-keys/{}/retire",
            server.url(),
            initial.key_id
        ))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    use sqlx::Row;
    let rotated_rows = sqlx::query(
        "SELECT actor, payload_json FROM audit_events WHERE kind = 'signing.key_rotated'",
    )
    .fetch_all(server.store.pool())
    .await
    .unwrap();
    assert_eq!(rotated_rows.len(), 1);
    let actor: String = rotated_rows[0].try_get("actor").unwrap();
    assert_eq!(actor, "admin");

    let retired_rows = sqlx::query(
        "SELECT actor, payload_json FROM audit_events WHERE kind = 'signing.key_retired'",
    )
    .fetch_all(server.store.pool())
    .await
    .unwrap();
    assert_eq!(retired_rows.len(), 1);

    server.shutdown().await;
}

#[tokio::test]
async fn rotated_keyset_persists_across_restart() {
    // Rotate, then re-load the signer from the same state_dir; the
    // multi-key set must come back exactly as it was.
    let dir = TempDir::new().unwrap();
    let signer = iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap();
    let initial = signer.key_id();
    let rotated = signer.rotate().unwrap();
    drop(signer);

    let reloaded = iac_controlplane::signing::ServerSigner::load_or_create(dir.path()).unwrap();
    assert_eq!(reloaded.key_id(), rotated, "active persists");
    let pubkeys = reloaded.pubkeys();
    let ids: Vec<&str> = pubkeys.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&initial.as_str()), "old key still in set after reload");
    assert!(ids.contains(&rotated.as_str()));
}
