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

/// Pick the IP that the per-IP rate-limit buckets should key by.
///
/// If the socket peer is NOT in `trusted_proxies`, the header is ignored
/// and we bucket by the socket IP — an untrusted client can't spoof
/// `X-Forwarded-For` to dodge a bucket.
///
/// If the peer IS a trusted proxy, we take the **rightmost entry that is
/// not itself a trusted proxy**: we peel trusted-proxy hops off the
/// right of the chain and return the address the nearest trusted proxy
/// actually observed. Taking the *leftmost* entry (the old behaviour) is
/// exploitable — a client behind the proxy sends
/// `X-Forwarded-For: <spoofed>` and the proxy *appends* the real peer,
/// so leftmost is fully attacker-chosen, defeating the per-IP register /
/// login caps. Rightmost-after-peeling is what the trusted proxy
/// vouches for. (OWASP "X-Forwarded-For" guidance.)
///
/// Malformed / all-trusted header falls back to the socket IP with a
/// debug log — better to bucket the proxy itself than skip the check.
pub fn effective_client_ip(
    headers: &axum::http::HeaderMap,
    socket_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) -> std::net::IpAddr {
    let socket_ip = socket_addr.ip();
    if trusted_proxies.is_empty() || !trusted_proxies.contains(&socket_ip) {
        return socket_ip;
    }
    let Some(hv) = headers.get("x-forwarded-for") else {
        return socket_ip;
    };
    let Ok(s) = hv.to_str() else { return socket_ip };
    // Walk right-to-left: skip entries that are themselves trusted
    // proxies, return the first remaining (the real client as seen by
    // the nearest trusted hop). All-trusted / none-parseable → socket.
    for entry in s.split(',').rev() {
        let Some(ip) = parse_xff_entry(entry.trim()) else {
            continue;
        };
        if trusted_proxies.contains(&ip) {
            continue;
        }
        return ip;
    }
    tracing::debug!(
        header = %s,
        "X-Forwarded-For from trusted proxy had no non-proxy IP — falling back to socket IP"
    );
    socket_ip
}

/// Parse one `X-Forwarded-For` entry into an [`IpAddr`], tolerating the
/// `[v6]:port`, `v4:port` and bare-IP shapes proxies emit.
fn parse_xff_entry(entry: &str) -> Option<std::net::IpAddr> {
    let bare = if entry.starts_with('[') {
        let after_close = entry.trim_start_matches('[');
        after_close.split(']').next().unwrap_or(after_close)
    } else if entry.parse::<std::net::IpAddr>().is_ok() {
        entry
    } else if entry.matches(':').count() == 1 {
        entry.split(':').next().unwrap_or(entry)
    } else {
        entry
    };
    bare.parse::<std::net::IpAddr>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn h(v: &str) -> HeaderMap {
        let mut hm = HeaderMap::new();
        hm.insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        hm
    }

    fn proxy() -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
    }

    #[test]
    fn untrusted_peer_returns_socket_ip_even_with_header() {
        // Header is set but socket peer isn't in trusted_proxies →
        // ignore the header (the canonical anti-spoof behaviour).
        let hm = h("1.2.3.4");
        let socket = "192.168.1.5:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "192.168.1.5");
    }

    #[test]
    fn trusted_proxy_returns_rightmost_non_proxy() {
        // Socket is the trusted proxy, which appended itself on the
        // right; the real client is the rightmost non-proxy entry.
        let hm = h("1.2.3.4, 10.0.0.1");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn trusted_proxy_ignores_client_spoofed_leftmost() {
        // Attacker behind the proxy sets "X-F-F: 9.9.9.9"; the proxy
        // APPENDS the attacker's real IP (1.2.3.4). Old leftmost logic
        // returned the attacker-chosen 9.9.9.9 (bucket evasion). We must
        // return the appended real IP instead.
        let hm = h("9.9.9.9, 1.2.3.4");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn multiple_trusted_proxies_peeled_from_right() {
        let trusted = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let hm = h("1.2.3.4, 10.0.0.2, 10.0.0.1");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &trusted);
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn all_trusted_chain_falls_back_to_socket() {
        // Degenerate: every hop is a trusted proxy → no client IP to
        // trust, bucket the socket peer.
        let hm = h("10.0.0.1, 10.0.0.1");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn empty_trusted_list_keeps_socket_semantics() {
        let hm = h("1.2.3.4");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &[]);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn missing_header_from_trusted_proxy_falls_back() {
        let hm = HeaderMap::new();
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn malformed_header_falls_back_to_socket() {
        let hm = h("not-an-ip");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn header_with_port_strips_to_bare_ip() {
        // Some proxies set "1.2.3.4:5678" entries; we want the IP.
        let hm = h("1.2.3.4:5678");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn ipv6_xff_unbracketed() {
        let hm = h("2001:db8::1");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "2001:db8::1");
    }
}
