pub mod admin;
pub mod agents;
pub mod audit;
pub mod auth;
pub mod drift;
pub mod expanders;
pub mod health;
pub mod metrics;
pub mod operations;
pub mod signing;
pub mod users;

use crate::error::ApiError;
use axum::{
    extract::{FromRequestParts, Request, State},
    http::request::Parts,
    middleware::Next,
    response::Response,
};

use crate::server::AppState;

/// Extracts the bearer token from `Authorization: Bearer <token>`.
pub struct BearerToken(pub String);

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(ApiError::Unauthorized)?
            .to_str()
            .map_err(|_| ApiError::Unauthorized)?;
        let prefix = "Bearer ";
        if !header.starts_with(prefix) {
            return Err(ApiError::Unauthorized);
        }
        let token = header[prefix.len()..].trim().to_string();
        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self(token))
    }
}

/// Authenticates the bearer token against the agent_id in `parts.extensions`.
/// Used by the per-agent endpoints; the agent_id comes from the URL path.
pub async fn require_agent_auth(
    State(state): State<AppState>,
    BearerToken(token): BearerToken,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let agent_id = req
        .extensions()
        .get::<AgentIdParam>()
        .cloned()
        .ok_or_else(|| ApiError::Internal("agent_id missing from request extensions".into()))?;
    let record = state.store.authenticate(&agent_id.0, &token).await?;
    req.extensions_mut().insert(record);
    Ok(next.run(req).await)
}

#[derive(Clone, Debug)]
pub struct AgentIdParam(pub String);

/// Phase 6e: replaces the old admin-only check with a role-aware resolver.
/// The legacy admin token still works (it resolves to `Identity::LegacyAdmin`,
/// which holds every role) so existing deployments don't break overnight.
/// Returns the resolved identity so handlers can record an audit-friendly
/// actor name.
pub async fn require_admin(
    state: &crate::server::AppState,
    token: &str,
) -> Result<crate::identity::Identity, ApiError> {
    crate::identity::require_role(state, token, crate::identity::Role::Admin).await
}

/// Most endpoints want a finer-grained role gate. Wraps
/// [`crate::identity::require_role`] for ergonomics — handlers `use` this
/// alongside `BearerToken`.
pub async fn require_role(
    state: &crate::server::AppState,
    token: &str,
    role: crate::identity::Role,
) -> Result<crate::identity::Identity, ApiError> {
    crate::identity::require_role(state, token, role).await
}
