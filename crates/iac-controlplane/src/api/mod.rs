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

/// Phase 9 follow-up: pick the IP that the per-IP rate-limit buckets
/// should key by. If the raw socket peer is in `trusted_proxies`,
/// read the leftmost entry in `X-Forwarded-For` instead (that's
/// the canonical "originating client" position in RFC 7239). Any
/// other peer keeps using the socket IP, so a non-proxied client
/// can't spoof the header to dodge a bucket.
///
/// Malformed header (no parseable IP) falls back to the socket IP
/// with a debug-level log — better to bucket the proxy itself than
/// to skip the check entirely.
pub fn effective_client_ip(
    headers: &axum::http::HeaderMap,
    socket_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) -> std::net::IpAddr {
    let socket_ip = socket_addr.ip();
    if trusted_proxies.is_empty() || !trusted_proxies.iter().any(|p| *p == socket_ip) {
        return socket_ip;
    }
    let Some(hv) = headers.get("x-forwarded-for") else {
        return socket_ip;
    };
    let Ok(s) = hv.to_str() else { return socket_ip };
    // X-Forwarded-For: client, proxy1, proxy2  → leftmost is the
    // originating client. Strip whitespace.
    let leftmost = s.split(',').next().unwrap_or("").trim();
    // Three shapes to handle:
    //   `[2001:db8::1]:443`  bracketed v6 with port
    //   `1.2.3.4:5678`        v4 with port (some proxies)
    //   `2001:db8::1` / `1.2.3.4`  bare IP
    // Try bare-IP-parse first to keep IPv6-without-port working
    // (multi-colon string that's a valid v6 → use as-is).
    let bare = if leftmost.starts_with('[') {
        // Bracketed v6: trim `[...]` and optional `:port` suffix.
        let after_close = leftmost.trim_start_matches('[');
        after_close.split(']').next().unwrap_or(after_close)
    } else if leftmost.parse::<std::net::IpAddr>().is_ok() {
        leftmost
    } else if leftmost.matches(':').count() == 1 {
        // v4-with-port shape.
        leftmost.split(':').next().unwrap_or(leftmost)
    } else {
        leftmost
    };
    match bare.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            tracing::debug!(
                header = %s,
                "X-Forwarded-For from trusted proxy not parseable as IP — falling back to socket IP"
            );
            socket_ip
        }
    }
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
    fn trusted_proxy_returns_xff_leftmost() {
        // Socket is the trusted proxy; X-F-F leftmost is the real
        // originating client.
        let hm = h("1.2.3.4, 10.0.0.1");
        let socket = "10.0.0.1:5000".parse::<SocketAddr>().unwrap();
        let ip = effective_client_ip(&hm, socket, &proxy());
        assert_eq!(ip.to_string(), "1.2.3.4");
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
