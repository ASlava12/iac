//! Public key endpoints. No auth required — these are meant for
//! first-contact agent bootstrap and ongoing pubkey-set refresh.
//!
//! * `GET /v1/signing-pubkey` — Phase 6b. Returns *just* the active
//!   key. Pre-7cf agents pin this on first contact (TOFU) and reject
//!   anything else. Kept for backwards compatibility.
//! * `GET /v1/signing-keys` — Phase 7ce. Returns the full accepted
//!   set (active + recently-rotated still in the verification window).
//!   Multi-key-aware agents (Phase 7cf) consume this so they accept
//!   signatures from any key in the set, lookup by `key_id`.

use crate::error::{ApiError, ApiResult};
use crate::server::AppState;
use axum::{Json, Router, extract::State, routing::get};
use iac_core::protocol::v1::{SigningPubkey, SigningPubkeyBundle};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/signing-pubkey", get(pubkey))
        .route("/v1/signing-keys", get(pubkey_bundle))
}

async fn pubkey(State(state): State<AppState>) -> ApiResult<Json<SigningPubkey>> {
    let public_key = state
        .signer
        .public_key_b64()
        .map_err(|e| ApiError::Internal(format!("signer state inconsistent: {e}")))?;
    Ok(Json(SigningPubkey {
        key_id: state.signer.key_id(),
        public_key,
    }))
}

async fn pubkey_bundle(State(state): State<AppState>) -> ApiResult<Json<SigningPubkeyBundle>> {
    let active_key_id = state.signer.key_id();
    let keys = state
        .signer
        .pubkeys()
        .into_iter()
        .map(|(key_id, public_key)| SigningPubkey { key_id, public_key })
        .collect();
    Ok(Json(SigningPubkeyBundle {
        active_key_id,
        keys,
    }))
}
