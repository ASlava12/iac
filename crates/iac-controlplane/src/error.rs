use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Phase 7q: structured identity of the rate-limit bucket that
/// rejected. Replaces the Phase 7o magic-prefix string (`env:prod` /
/// `policy:foo`) with a typed pair so clients don't have to parse.
#[derive(Debug, Clone, Serialize)]
pub struct RateLimitBucket {
    /// `"env"` for environment-level caps, `"policy"` for per-policy caps.
    /// Future bucket types (per-user, per-IP) extend this enum-as-string.
    pub r#type: String,
    /// Identifier within that type (the env name or policy name).
    pub name: String,
}

impl RateLimitBucket {
    pub fn env(name: impl Into<String>) -> Self {
        Self { r#type: "env".into(), name: name.into() }
    }
    pub fn policy(name: impl Into<String>) -> Self {
        Self { r#type: "policy".into(), name: name.into() }
    }
    /// Phase 7bh: per-agent bucket. Limits how many `heartbeat` /
    /// `observations` / `drift` requests a single agent can make per
    /// 60-second window — protection against a misbehaving agent
    /// flooding the server.
    pub fn agent(name: impl Into<String>) -> Self {
        Self { r#type: "agent".into(), name: name.into() }
    }
    /// Phase 7co (security fix #4.2): per-username bucket on
    /// `POST /v1/auth/login`. Caps online password-guess attempts and
    /// blunts Argon2-CPU-DoS. Combined with `client` bucket (per-IP)
    /// makes brute-force across-many-accounts also infeasible.
    pub fn login_user(name: impl Into<String>) -> Self {
        Self { r#type: "login_user".into(), name: name.into() }
    }
    /// Phase 7co: per-client bucket. Today, "client" is the
    /// authenticated identity for normal endpoints, but for unauth
    /// endpoints (login!) we use the source IP. Future: extract from
    /// `X-Forwarded-For` when behind a trusted proxy.
    pub fn client(name: impl Into<String>) -> Self {
        Self { r#type: "client".into(), name: name.into() }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("payload too large")]
    PayloadTooLarge,
    /// Phase 7h: rate limit exceeded. `retry_after_secs` populates the
    /// header. Phase 7o named the bucket; Phase 7q makes it structured.
    #[error("too many requests on bucket {}:{}; retry after {retry_after_secs}s", bucket.r#type, bucket.name)]
    TooManyRequests {
        bucket: RateLimitBucket,
        retry_after_secs: u64,
    },
    /// Phase 7i: maintenance window in effect. `reason` is shown to the
    /// caller; `retry_after_secs` populates the response header so
    /// pipelines can pause without polling.
    #[error("service unavailable: {reason}")]
    ServiceUnavailable { reason: String, retry_after_secs: u64 },
    #[error("internal error: {0}")]
    Internal(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// Phase 7q: structured bucket info, populated only for
    /// `TooManyRequests`. Clients should match on this rather than
    /// parsing `detail`. (Phase 7av: the `bucket=<type>:<name>` prefix
    /// in `detail` was dropped — `detail` is now a plain
    /// human-readable string.)
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket: Option<RateLimitBucket>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut bucket_field: Option<RateLimitBucket> = None;
        let (status, code, detail, retry_after) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None, None),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None, None),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None, None),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "conflict", Some(msg.clone()), None),
            Self::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, "bad_request", Some(msg.clone()), None)
            }
            Self::PayloadTooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", None, None)
            }
            Self::TooManyRequests { bucket, retry_after_secs } => {
                bucket_field = Some(bucket.clone());
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_requests",
                    // Phase 7av: plain human-readable detail. The
                    // structured `bucket` field has carried machine-
                    // readable bucket info since Phase 7q, so the
                    // legacy `bucket=<type>:<name>` prefix is gone.
                    // Operators see a clean message; programmatic
                    // clients use `body.bucket`.
                    Some(format!("retry after {retry_after_secs}s")),
                    Some(*retry_after_secs),
                )
            }
            Self::ServiceUnavailable { reason, retry_after_secs } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                Some(reason.clone()),
                Some(*retry_after_secs),
            ),
            Self::Internal(msg) => {
                tracing::error!(error = %msg, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", None, None)
            }
            Self::Sqlx(e) => {
                // Phase 8.7 (real-hardware finding): SQLite returns
                // SQLITE_BUSY (extended code 5) when busy_timeout is
                // exhausted under sustained write contention — common
                // on slow flash storage (Pi SD card, embedded MMC,
                // network-equipment NOR/NAND). It's transient by
                // definition: the caller can retry and likely succeed.
                // Mapping it to 500 was misleading — clients treated
                // it as a server bug rather than backpressure. Map to
                // 503 with Retry-After=1 so well-behaved clients (our
                // own agent has retry-on-5xx-with-backoff) recover.
                if is_sqlite_busy(e) {
                    tracing::warn!(error = %e, "sqlite write contention — returning 503");
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                        Some("database busy; retry".to_string()),
                        Some(1),
                    )
                } else {
                    tracing::error!(error = %e, "sqlx error");
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal", None, None)
                }
            }
            Self::Json(e) => {
                tracing::error!(error = %e, "json error");
                (StatusCode::BAD_REQUEST, "bad_json", Some(e.to_string()), None)
            }
        };
        let body = Json(ErrorBody {
            error: code.to_string(),
            detail,
            bucket: bucket_field,
        });
        let mut response = (status, body).into_response();
        if let Some(secs) = retry_after
            && let Ok(value) = HeaderValue::from_str(&secs.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// Phase 8.7 (real-hardware finding): detect SQLITE_BUSY and friends
/// inside an `sqlx::Error::Database`. SQLite returns code 5 (BUSY) or
/// 6 (LOCKED); both indicate transient write contention that the caller
/// should retry. We don't depend on `libsqlite3-sys` here — string
/// matching on the error message is enough and keeps this crate's
/// dependency surface narrow.
fn is_sqlite_busy(e: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db) = e {
        let msg = db.message();
        // Covers `(code: 5) database is locked` and
        // `(code: 6) database table is locked` from the sqlx-sqlite
        // adapter.
        if msg.contains("database is locked") || msg.contains("database table is locked") {
            return true;
        }
        if let Some(code) = db.code() {
            // SQLITE_BUSY=5, SQLITE_LOCKED=6.
            return code == "5" || code == "6";
        }
    }
    false
}
