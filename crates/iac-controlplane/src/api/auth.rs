//! Phase 6e: human-user login. Issues a bearer token tied to the user's
//! roles. Logout revokes the current token.

use crate::api::BearerToken;
use crate::error::{ApiError, ApiResult};
use crate::server::AppState;
use axum::{extract::State, routing::post, Json, Router};
use iac_core::protocol::v1::{LoginRequest, LoginResponse};

/// 24-hour token lifetime. Refresh by re-logging-in until Phase 6f introduces
/// a refresh-token endpoint.
const TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/refresh", post(refresh))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(ApiError::BadRequest(
            "username and password must be non-empty".into(),
        ));
    }
    // Phase 7co (security fix #4.2): rate-limit BEFORE Argon2 verify.
    // Online brute-force gets blocked at the cap; Argon2-CPU-DoS
    // (thousands of parallel logins exhausting CPU) is also bounded
    // because the limiter rejects the flood before any password
    // hashing happens.
    state
        .rate_limiter
        .check_and_record_login(&req.username, "")
        .await?;
    let outcome = state
        .store
        .login(&req.username, &req.password, TOKEN_TTL_SECS)
        .await;
    // Audit success AND failure. Compromised-account use is now
    // detectable post-hoc; failed-attempt spikes are visible to a
    // SOC. We deliberately don't put the password (or even its
    // length) into the payload.
    match &outcome {
        Ok(_) => {
            let _ = state
                .store
                .record_audit(
                    crate::store::AuditRecord::new(
                        &format!("user:{}", req.username),
                        "auth.login_succeeded",
                    )
                    .severity("info"),
                )
                .await;
        }
        Err(e) => {
            // Don't try to look up role on failure — we don't know
            // who they are. The actor "anonymous" + the attempted
            // username gets the SOC enough to investigate.
            let kind = if matches!(e, ApiError::Unauthorized) {
                "auth.login_failed"
            } else {
                "auth.login_errored"
            };
            let _ = state
                .store
                .record_audit(
                    crate::store::AuditRecord::new("anonymous", kind)
                        .severity("warning")
                        .payload(serde_json::json!({
                            "attempted_username": req.username,
                        })),
                )
                .await;
        }
    }
    let (token, expires_at, user) = outcome?;
    let roles = user
        .roles
        .iter()
        .map(|r| serde_json::to_value(r).ok())
        .filter_map(|v| v.and_then(|x| x.as_str().map(str::to_string)))
        .collect();
    Ok(Json(LoginResponse { token, expires_at, roles }))
}

async fn logout(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<serde_json::Value>> {
    // Phase 7co (security fix #4.11): audit logout. Without this,
    // a compromised account that rotates / logs out leaves no trace
    // that the legitimate session was terminated.
    let identity = crate::identity::resolve_identity(&state, &token).await.ok();
    state.store.revoke_user_token(&token).await?;
    if let Some(id) = identity {
        let _ = state
            .store
            .record_audit(
                crate::store::AuditRecord::new(&id.audit_actor(), "auth.logout")
                    .severity("info"),
            )
            .await;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Phase 7e: rotate the bearer token without re-asking for the password.
/// The new token also picks up any role changes that landed since login —
/// that's the whole point: an admin promotes Bob, Bob runs `iac whoami` /
/// any next call, and the CLI silently refreshes to get the new roles.
///
/// Legacy admin tokens and agent tokens can't refresh (this is human-user
/// only); they reject as `Unauthorized`. Agents use long-lived bearer
/// tokens by design, and the legacy admin token is a static config value.
async fn refresh(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<LoginResponse>> {
    let (new_token, expires_at, user) =
        state.store.refresh_user_token(&token, TOKEN_TTL_SECS).await?;
    // Phase 7co (security fix #4.11): audit token refreshes — a
    // compromised account using `refresh` to extend access without
    // reauthentication is otherwise invisible.
    let _ = state
        .store
        .record_audit(
            crate::store::AuditRecord::new(
                &format!("user:{}", user.username),
                "auth.token_refreshed",
            )
            .severity("info")
            .payload(serde_json::json!({ "user_id": user.id })),
        )
        .await;
    let roles = user
        .roles
        .iter()
        .map(|r| serde_json::to_value(r).ok())
        .filter_map(|v| v.and_then(|x| x.as_str().map(str::to_string)))
        .collect();
    Ok(Json(LoginResponse {
        token: new_token,
        expires_at,
        roles,
    }))
}
