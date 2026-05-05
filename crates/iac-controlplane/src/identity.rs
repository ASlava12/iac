//! Phase 6e: role-based identity model.
//!
//! Three identity classes share one bearer-token surface:
//!   * `User` — human operator authenticated via `POST /v1/auth/login`.
//!     Carries a list of roles loaded from the `users` table.
//!   * `Agent` — programmatic caller, registered via `POST /v1/agents/register`.
//!   * `LegacyAdmin` — the static `admin_token` from server config. Always
//!     grants the `Admin` role. Will be removed in Phase 7+ once user-based
//!     auth is fully rolled out.
//!
//! Endpoint handlers call [`require_role`] which walks the resolution chain
//! (admin_token → user_tokens → agents) and returns an [`Identity`] the
//! handler can use to record audit-friendly actor names.

use crate::auth::{ct_eq, hash_token};
use crate::error::{ApiError, ApiResult};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

/// User-facing roles. The order encodes the inclusion lattice — a higher
/// role implicitly grants every lower role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Operator,
    Approver,
    Admin,
}

impl Role {
    /// `self` includes (i.e. is at least as privileged as) `required`.
    pub fn includes(self, required: Role) -> bool {
        self >= required
    }
}

/// What the bearer-token chain resolved a request to. Handlers use the
/// `audit_actor` and `display_name` for audit + UI purposes.
#[derive(Debug, Clone)]
pub enum Identity {
    /// Static admin token from server config.
    LegacyAdmin,
    /// Authenticated user.
    User { id: String, username: String, roles: Vec<Role> },
    /// Agent caller (per-agent bearer token from `register`).
    Agent { id: String, name: String },
}

impl Identity {
    pub fn audit_actor(&self) -> String {
        match self {
            Self::LegacyAdmin => "admin".to_string(),
            Self::User { username, .. } => format!("user:{username}"),
            Self::Agent { id, .. } => format!("agent:{id}"),
        }
    }

    pub fn display_name(&self) -> String {
        match self {
            Self::LegacyAdmin => "admin".to_string(),
            Self::User { username, .. } => username.clone(),
            Self::Agent { name, .. } => name.clone(),
        }
    }

    pub fn has_role(&self, role: Role) -> bool {
        match self {
            Self::LegacyAdmin => true,
            Self::User { roles, .. } => roles.iter().any(|r| r.includes(role)),
            Self::Agent { .. } => false,
        }
    }
}

/// Argon2id-hash a plaintext password. Returns a PHC-format string ready to
/// store. Uses default Argon2 parameters; revisit if benchmarks show login
/// CPU is a bottleneck.
pub fn hash_password(plaintext: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    argon
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError::Internal(format!("argon2 hash: {e}")))
}

/// Returns Ok(()) iff the plaintext matches the stored Argon2 PHC string.
/// Constant-time inside argon2's verifier.
pub fn verify_password(plaintext: &str, stored_phc: &str) -> ApiResult<bool> {
    let parsed = match PasswordHash::new(stored_phc) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let argon = Argon2::default();
    Ok(argon.verify_password(plaintext.as_bytes(), &parsed).is_ok())
}

/// Phase 6e auth chain. Resolves a raw bearer token into one of the
/// `Identity` variants and returns 401 if it doesn't match anything.
/// Then checks the resolved identity has at least `required` role.
pub async fn require_role(
    state: &crate::server::AppState,
    token: &str,
    required: Role,
) -> ApiResult<Identity> {
    let identity = resolve(state, token).await?;
    if identity.has_role(required) {
        Ok(identity)
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Same as `require_role` but doesn't enforce a minimum — callers that need
/// the identity for naming purposes only.
pub async fn resolve_identity(
    state: &crate::server::AppState,
    token: &str,
) -> ApiResult<Identity> {
    resolve(state, token).await
}

async fn resolve(
    state: &crate::server::AppState,
    token: &str,
) -> ApiResult<Identity> {
    // 1. Legacy static admin_token.
    // Phase 7bx: admin_token is NOT hot-reloadable — it's the bootstrap
    // credential. We still snapshot for consistency.
    let cfg = state.config();
    if let Some(expected) = cfg.admin_token.as_deref() {
        let lhs = hash_token(token);
        let rhs = hash_token(expected);
        if ct_eq(lhs.as_bytes(), rhs.as_bytes()) {
            return Ok(Identity::LegacyAdmin);
        }
    }
    // 2. User token.
    if let Some(user) = state.store.find_user_by_token(token).await? {
        return Ok(Identity::User {
            id: user.id,
            username: user.username,
            roles: user.roles,
        });
    }
    // 3. Agent token. We don't know which agent without scanning, but the
    // existing per-agent endpoints use a path-bound `agent_id` and call
    // `Store::authenticate(agent_id, token)` directly. So at this layer we
    // don't try to resolve agent tokens — endpoints that need the agent
    // identity look it up by id explicitly.
    Err(ApiError::Unauthorized)
}

/// Snapshot of a user row plus parsed roles. Used by the resolver and store.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub roles: Vec<Role>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_inclusion_lattice() {
        assert!(Role::Admin.includes(Role::Approver));
        assert!(Role::Admin.includes(Role::Viewer));
        assert!(Role::Approver.includes(Role::Operator));
        assert!(Role::Operator.includes(Role::Viewer));
        assert!(!Role::Viewer.includes(Role::Operator));
        assert!(!Role::Operator.includes(Role::Approver));
    }

    #[test]
    fn argon2_hash_then_verify_true() {
        let phc = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &phc).unwrap());
        assert!(!verify_password("wrong", &phc).unwrap());
    }

    #[test]
    fn corrupt_phc_string_returns_false() {
        assert!(!verify_password("anything", "not-a-real-phc").unwrap());
    }

    #[test]
    fn legacy_admin_has_every_role() {
        let id = Identity::LegacyAdmin;
        assert!(id.has_role(Role::Viewer));
        assert!(id.has_role(Role::Operator));
        assert!(id.has_role(Role::Approver));
        assert!(id.has_role(Role::Admin));
    }

    #[test]
    fn user_role_membership() {
        let id = Identity::User {
            id: "u1".into(),
            username: "alice".into(),
            roles: vec![Role::Operator],
        };
        assert!(id.has_role(Role::Viewer));
        assert!(id.has_role(Role::Operator));
        assert!(!id.has_role(Role::Approver));
    }

    #[test]
    fn agent_holds_no_human_roles() {
        let id = Identity::Agent { id: "a1".into(), name: "vm14".into() };
        assert!(!id.has_role(Role::Viewer));
        assert!(!id.has_role(Role::Operator));
    }

    #[test]
    fn audit_actor_strings() {
        assert_eq!(Identity::LegacyAdmin.audit_actor(), "admin");
        assert_eq!(
            Identity::User {
                id: "u1".into(),
                username: "alice".into(),
                roles: vec![]
            }
            .audit_actor(),
            "user:alice"
        );
        assert_eq!(
            Identity::Agent { id: "01H".into(), name: "vm14".into() }.audit_actor(),
            "agent:01H"
        );
    }
}
