//! Phase 6h: user CRUD endpoints (admin-only).
//!
//! Unlike Phase 6e's bootstrap-via-env path, this lets a running operator
//! provision teammates on the fly. Every mutation records an audit event so
//! "who created `bob`" / "who removed `alice`'s approver role" is answerable.

use crate::api::{require_role, BearerToken};
use crate::error::{ApiError, ApiResult};
use crate::identity::{Identity, Role};
use crate::server::AppState;
use crate::store::{AuditRecord, CreateUser};
use axum::{
    extract::{Path, State},
    routing::{delete, patch, post},
    Json, Router,
};
use iac_core::protocol::v1::{
    CreateUserRequest, CreateUserResponse, UpdateUserRequest, UserView,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/users", post(create_user).get(list_users))
        .route("/v1/users/{user_id}", patch(update_user))
        .route("/v1/users/{user_id}", delete(disable_user))
}

async fn create_user(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<Json<CreateUserResponse>> {
    let identity = require_role(&state, &token, Role::Admin).await?;
    let roles = parse_roles(&req.roles)?;
    let user_id = state
        .store
        .create_user(CreateUser {
            username: &req.username,
            password: &req.password,
            roles: roles.clone(),
        })
        .await?;
    record_user_audit(&state, &identity, "user.created", &user_id, &req.username, &roles).await?;
    Ok(Json(CreateUserResponse { user_id }))
}

async fn list_users(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<Vec<UserView>>> {
    require_role(&state, &token, Role::Admin).await?;
    let rows = state.store.list_users().await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| UserView {
                id: r.id,
                username: r.username,
                roles: r.roles.iter().filter_map(role_to_str).collect(),
                created_at: r.created_at,
                disabled_at: r.disabled_at,
            })
            .collect(),
    ))
}

async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    BearerToken(token): BearerToken,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Admin).await?;
    let mut applied: Vec<&'static str> = Vec::new();

    if let Some(roles_strs) = &req.roles {
        let roles = parse_roles(roles_strs)?;
        state.store.update_user_roles(&user_id, &roles).await?;
        applied.push("roles");
    }
    if let Some(disabled) = req.disabled {
        if disabled {
            state.store.disable_user(&user_id).await?;
            applied.push("disabled");
        } else {
            state.store.enable_user(&user_id).await?;
            applied.push("enabled");
        }
    }
    if let Some(new_password) = &req.password {
        state.store.set_user_password(&user_id, new_password).await?;
        applied.push("password");
    }
    if applied.is_empty() {
        return Err(ApiError::BadRequest(
            "request must set at least one of: roles, disabled, password".into(),
        ));
    }

    state
        .store
        .record_audit(
            AuditRecord::new(&identity.audit_actor(), "user.updated").payload(serde_json::json!({
                "user_id": user_id,
                "fields": applied,
                // Don't surface the new password value; just note it changed.
                "roles": req.roles,
                "disabled": req.disabled,
                "password_changed": req.password.is_some(),
            })),
        )
        .await?;

    Ok(Json(serde_json::json!({ "ok": true, "applied": applied })))
}

async fn disable_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    BearerToken(token): BearerToken,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_role(&state, &token, Role::Admin).await?;
    state.store.disable_user(&user_id).await?;
    state
        .store
        .record_audit(
            AuditRecord::new(&identity.audit_actor(), "user.disabled")
                .payload(serde_json::json!({ "user_id": user_id })),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn record_user_audit(
    state: &AppState,
    identity: &Identity,
    kind: &str,
    user_id: &str,
    username: &str,
    roles: &[Role],
) -> ApiResult<()> {
    let actor = identity.audit_actor();
    state
        .store
        .record_audit(AuditRecord::new(&actor, kind).payload(serde_json::json!({
            "user_id": user_id,
            "username": username,
            "roles": roles.iter().filter_map(role_to_str).collect::<Vec<_>>(),
        })))
        .await?;
    Ok(())
}

fn parse_roles(roles: &[String]) -> ApiResult<Vec<Role>> {
    roles
        .iter()
        .map(|r| match r.as_str() {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "approver" => Ok(Role::Approver),
            "admin" => Ok(Role::Admin),
            other => Err(ApiError::BadRequest(format!(
                "unknown role {other:?}; valid: viewer | operator | approver | admin"
            ))),
        })
        .collect()
}

fn role_to_str(r: &Role) -> Option<String> {
    Some(
        match r {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Approver => "approver",
            Role::Admin => "admin",
        }
        .to_string(),
    )
}
