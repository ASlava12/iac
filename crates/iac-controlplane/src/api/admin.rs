//! Phase 7aj: admin-only diagnostics. Currently exposes
//! `/v1/admin/config-issues` — the per-entry structured form of the
//! `iac_maintenance_misconfigured_windows` gauge.
//!
//! Routed under `/v1/admin/` so future "operators want to know what
//! the server thinks about its own state" endpoints have a home.
//!
//! Phase 7ce: also routes the signing-key rotation endpoints —
//! `POST /v1/admin/signing-keys/rotate` and
//! `POST /v1/admin/signing-keys/{key_id}/retire`.

use crate::api::{BearerToken, require_role};
use crate::error::{ApiError, ApiResult};
use crate::identity::Role;
use crate::maintenance::ConfigIssue;
use crate::server::AppState;
use crate::store::AuditRecord;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use iac_core::protocol::v1::{SigningPubkey, SigningPubkeyBundle};
use serde::Serialize;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/config-issues", get(get_config_issues))
        .route("/v1/admin/signing-keys/rotate", post(rotate_signing_key))
        .route(
            "/v1/admin/signing-keys/{key_id}/retire",
            post(retire_signing_key),
        )
}

#[derive(Debug, Serialize)]
struct ConfigIssuesResponse<'a> {
    /// One entry per misconfigured maintenance window. Empty list →
    /// config is clean. Order: absolute entries first (in config
    /// order), then recurring (in config order).
    maintenance: &'a [ConfigIssue],
}

async fn get_config_issues(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<serde_json::Value>> {
    require_role(&state, &token, Role::Admin).await?;
    // Phase 7aq: serve the cached snapshot — no re-parsing per request.
    // Phase 7bx: pull from the live state — issues are recomputed on
    // every SIGHUP reload so the response reflects the latest config.
    let issues = state.config_issues();
    let resp = ConfigIssuesResponse {
        maintenance: issues.as_ref(),
    };
    Ok(Json(serde_json::to_value(&resp)?))
}

/// Phase 7ce: rotate the active signing key. Generates a fresh
/// keypair, makes it the new active, and keeps the previous active
/// in the verification set so in-flight assignments signed with it
/// still verify. Returns the new bundle (active + accepted) so the
/// caller can sanity-check before propagating.
async fn rotate_signing_key(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<SigningPubkeyBundle>> {
    let identity = require_role(&state, &token, Role::Admin).await?;
    let previous = state.signer.key_id();
    let new_id = state
        .signer
        .rotate()
        .map_err(|e| ApiError::Internal(format!("rotate signing key: {e}")))?;
    state
        .store
        .record_audit(
            AuditRecord::new(&identity.audit_actor(), "signing.key_rotated").payload(
                serde_json::json!({
                    "previous_active": previous,
                    "new_active": new_id,
                }),
            ),
        )
        .await?;
    Ok(Json(bundle(&state)))
}

/// Phase 7ce: retire a previously-rotated key. Removes it from the
/// verification set + deletes the secret on disk. Refuses to retire
/// the active key (operator must rotate first to elect a new active).
/// Returns the post-retire bundle. 404 when the key wasn't in the
/// set — easier debugging than silent idempotent success.
async fn retire_signing_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<SigningPubkeyBundle>> {
    let identity = require_role(&state, &token, Role::Admin).await?;
    let removed = state
        .signer
        .retire(&key_id)
        .map_err(|e| ApiError::Conflict(format!("retire: {e}")))?;
    if !removed {
        return Err(ApiError::NotFound);
    }
    state
        .store
        .record_audit(
            AuditRecord::new(&identity.audit_actor(), "signing.key_retired")
                .payload(serde_json::json!({ "retired_key_id": key_id })),
        )
        .await?;
    Ok(Json(bundle(&state)))
}

fn bundle(state: &AppState) -> SigningPubkeyBundle {
    SigningPubkeyBundle {
        active_key_id: state.signer.key_id(),
        keys: state
            .signer
            .pubkeys()
            .into_iter()
            .map(|(key_id, public_key)| SigningPubkey { key_id, public_key })
            .collect(),
    }
}
