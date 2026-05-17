//! Phase 7h: per-environment rate limit on operation submissions.
//!
//! Submitting many operations against the same environment in a short
//! window is almost always either a runaway pipeline or an attacker
//! abusing the assignment fan-out. The limiter caps the number of
//! `POST /v1/operations` calls a single environment can complete per
//! 60-second sliding window. Exceeded → 429 with a `Retry-After`
//! header so well-behaved CI scripts back off without polling.
//!
//! Per-environment isolation matters because operators routinely run
//! `prod` deploys at one cadence and `staging` smoke tests at a much
//! higher cadence; one global bucket would force the limit to the
//! noisier env.
//!
//! Implementation: in-process `tokio::sync::Mutex` over a
//! `HashMap<env, VecDeque<Instant>>`. We expire timestamps lazily on
//! each check so the queue stays bounded by the configured cap. A
//! distributed implementation (Redis token bucket) is out of scope
//! until horizontal scale is needed.

use crate::error::{ApiError, ApiResult, RateLimitBucket};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Operator-tunable rate limit. `None` (or zero) disables the limiter
/// entirely — the dev-loop default so test fixtures don't have to
/// think about it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Cap on `POST /v1/operations` per environment per 60 seconds.
    /// `None` disables. Above zero enforces.
    #[serde(default)]
    pub operations_per_minute: Option<u32>,
    /// Phase 7bh: cap on agent requests per agent_id per 60 seconds.
    /// Applies across the agent endpoints (`heartbeat`, `observations`,
    /// `drift`). `None` / `0` disables. Defaults to `None` so existing
    /// deployments aren't affected; operators turn it on for fleets
    /// where a single misbehaving agent could swamp the server.
    #[serde(default)]
    pub agent_requests_per_minute: Option<u32>,
    /// Phase 7co (security fix #4.2): cap on `POST /v1/auth/login`
    /// per username per 60 seconds. The default is 10 — generous for
    /// mistyped passwords, restrictive enough that online brute-
    /// force is infeasible. `None`/`0` disables (not recommended).
    #[serde(default = "default_login_per_minute")]
    pub login_per_minute_per_user: Option<u32>,
    /// Phase 7co: same cap, but per source IP. Stops the "rotate the
    /// username, keep guessing" spread-out attack. Default 30.
    #[serde(default = "default_login_per_minute_ip")]
    pub login_per_minute_per_ip: Option<u32>,
    /// Phase 9-F8 (security fix): cap on `POST /v1/agents/register`
    /// per source IP per 60 seconds. Default 20 — covers a normal
    /// fleet rollout (where ~10 agents come up roughly together) with
    /// headroom, but stops storm/DDoS attempts dead. The endpoint is
    /// unauthenticated by design (agents need it to bootstrap), so a
    /// per-IP cap is the only line of defence; without it, a single
    /// host can flood the agents table + audit chain at line rate.
    /// `None` / `0` disables (not recommended for any fleet larger
    /// than dev).
    #[serde(default = "default_register_per_minute_ip")]
    pub register_per_minute_per_ip: Option<u32>,
}

fn default_login_per_minute() -> Option<u32> {
    Some(10)
}
fn default_login_per_minute_ip() -> Option<u32> {
    Some(30)
}
fn default_register_per_minute_ip() -> Option<u32> {
    Some(20)
}

/// Phase 9 follow-up: caps are stored as `AtomicU32` (0 = disabled —
/// matches the historical `.filter(|n| *n > 0)` semantics) so SIGHUP
/// can hot-swap them without rebuilding the limiter. The per-bucket
/// `state` map keeps its `Instant` history across reloads — only
/// the *thresholds* change. That preserves the original observation
/// that mid-flight buckets shouldn't be reset on a config edit
/// while still allowing operators to tune caps without a restart.
#[derive(Debug)]
pub struct RateLimiter {
    max_per_minute: std::sync::atomic::AtomicU32,
    /// Phase 7bh: per-agent cap (0 = disabled).
    agent_max_per_minute: std::sync::atomic::AtomicU32,
    /// Phase 7co (security fix #4.2): per-username login cap.
    login_user_max_per_minute: std::sync::atomic::AtomicU32,
    /// Phase 7co: per-client-IP login cap.
    login_ip_max_per_minute: std::sync::atomic::AtomicU32,
    /// Phase 9-F8: per-client-IP register cap.
    register_ip_max_per_minute: std::sync::atomic::AtomicU32,
    state: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Phase 7ae: lock-free counters for the metrics endpoint.
    metrics: RateLimitMetrics,
}

#[derive(Debug, Default)]
pub struct RateLimitMetrics {
    /// Total `check_and_record_*` calls that ran a real check
    /// (limiter enabled). Excludes calls short-circuited by a
    /// missing cap (the `None` config + `0` cap paths).
    pub checks_total: std::sync::atomic::AtomicU64,
    /// Of those, the count that returned `TooManyRequests`. The
    /// difference (`checks_total - rejected_total`) is the count
    /// of admitted requests.
    pub rejected_total: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RateLimitMetricsSnapshot {
    pub checks_total: u64,
    pub rejected_total: u64,
    pub admitted_total: u64,
}

impl RateLimiter {
    pub fn from_config(cfg: &RateLimitConfig) -> Self {
        use std::sync::atomic::AtomicU32;
        let norm = |o: Option<u32>| AtomicU32::new(o.filter(|n| *n > 0).unwrap_or(0));
        Self {
            max_per_minute: norm(cfg.operations_per_minute),
            agent_max_per_minute: norm(cfg.agent_requests_per_minute),
            login_user_max_per_minute: norm(cfg.login_per_minute_per_user),
            login_ip_max_per_minute: norm(cfg.login_per_minute_per_ip),
            register_ip_max_per_minute: norm(cfg.register_per_minute_per_ip),
            state: Mutex::new(HashMap::new()),
            metrics: RateLimitMetrics::default(),
        }
    }

    /// Phase 9 follow-up: hot-swap caps without touching per-bucket
    /// state. SIGHUP calls this after `reload_config()` succeeds; the
    /// existing in-flight buckets keep their `Instant` history so
    /// operators can tune thresholds mid-flight without spurious
    /// rejection-bursts (every existing client suddenly seeing their
    /// bucket reset) or unfair freebies (clients in over-budget
    /// buckets getting their slate wiped).
    pub fn apply_config(&self, cfg: &RateLimitConfig) {
        use std::sync::atomic::Ordering::Relaxed;
        let norm = |o: Option<u32>| o.filter(|n| *n > 0).unwrap_or(0);
        self.max_per_minute.store(norm(cfg.operations_per_minute), Relaxed);
        self.agent_max_per_minute.store(norm(cfg.agent_requests_per_minute), Relaxed);
        self.login_user_max_per_minute.store(norm(cfg.login_per_minute_per_user), Relaxed);
        self.login_ip_max_per_minute.store(norm(cfg.login_per_minute_per_ip), Relaxed);
        self.register_ip_max_per_minute.store(norm(cfg.register_per_minute_per_ip), Relaxed);
    }

    /// Phase 7co (security fix #4.2): rate-limit a login attempt
    /// BEFORE the Argon2 verify. Both the per-username and per-IP
    /// buckets are checked; the more-restrictive of the two limits
    /// wins. Both `None`/`0` short-circuit to `Ok(())`.
    pub async fn check_and_record_login(
        &self,
        username: &str,
        client_ip: &str,
    ) -> ApiResult<()> {
        use std::sync::atomic::Ordering::Relaxed;
        let user_max = self.login_user_max_per_minute.load(Relaxed);
        if user_max > 0 {
            self.check_and_record_keyed_at(
                RateLimitBucket::login_user(username),
                user_max,
                Instant::now(),
            )
            .await?;
        }
        let ip_max = self.login_ip_max_per_minute.load(Relaxed);
        if ip_max > 0 {
            self.check_and_record_keyed_at(
                RateLimitBucket::client(client_ip),
                ip_max,
                Instant::now(),
            )
            .await?;
        }
        Ok(())
    }

    /// Phase 9-F8: rate-limit a register attempt by source IP. The
    /// endpoint is unauthenticated by design (agents must be able to
    /// bootstrap before they have credentials), so the only useful
    /// throttle is per-IP. `None` / `0` short-circuits to `Ok(())`
    /// (limit disabled).
    ///
    /// Whitespace / empty client IP is treated as the bucket name
    /// `unknown` rather than panicking — it should not happen in
    /// practice (axum's `ConnectInfo<SocketAddr>` always populates),
    /// but a misconfigured proxy header could conceivably yield it,
    /// and we'd rather rate-limit unknowns together than skip the
    /// check.
    pub async fn check_and_record_register(&self, client_ip: &str) -> ApiResult<()> {
        let max = self.register_ip_max_per_minute.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 { return Ok(()); }
        let key = if client_ip.trim().is_empty() { "unknown" } else { client_ip };
        self.check_and_record_keyed_at(
            RateLimitBucket::register_ip(key),
            max,
            Instant::now(),
        )
        .await
    }

    pub fn metrics(&self) -> RateLimitMetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let checks = self.metrics.checks_total.load(Relaxed);
        let rejected = self.metrics.rejected_total.load(Relaxed);
        RateLimitMetricsSnapshot {
            checks_total: checks,
            rejected_total: rejected,
            admitted_total: checks.saturating_sub(rejected),
        }
    }

    /// Returns `Ok(())` if the call is within budget (and records the
    /// timestamp), `Err(ApiError::TooManyRequests { bucket, .. })` otherwise.
    pub async fn check_and_record(&self, environment: &str) -> ApiResult<()> {
        let max = self.max_per_minute.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 { return Ok(()); }
        self.check_and_record_at(environment, max, Instant::now()).await
    }

    /// Phase 7bh: per-agent bucket. Caps how many requests a single
    /// agent can make per 60-second sliding window across the agent
    /// endpoints (heartbeat / observations / drift). `None` / `0`
    /// from config short-circuits to `Ok(())` so this is free when
    /// disabled. Returns the same `TooManyRequests { bucket: agent }`
    /// shape the env / policy paths use, so the existing 429 handling
    /// (Retry-After header, structured `bucket` body field) carries
    /// through.
    pub async fn check_and_record_agent(&self, agent_id: &str) -> ApiResult<()> {
        let max = self.agent_max_per_minute.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 { return Ok(()); }
        self.check_and_record_keyed_at(
            RateLimitBucket::agent(agent_id),
            max,
            Instant::now(),
        )
        .await
    }

    /// Phase 7n: per-policy bucket. Enforces a cap keyed by policy name
    /// independently of the env-level bucket. Each policy gets its own
    /// 60-second sliding window so multiple policies matching the same
    /// submission can each contribute a constraint.
    pub async fn check_and_record_policy(
        &self,
        policy_name: &str,
        max_per_minute: u32,
    ) -> ApiResult<()> {
        if max_per_minute == 0 {
            return Ok(());
        }
        self.check_and_record_keyed_at(
            RateLimitBucket::policy(policy_name),
            max_per_minute,
            Instant::now(),
        )
        .await
    }

    /// Env-level variant with explicit `Instant` for tests.
    pub async fn check_and_record_at(
        &self,
        environment: &str,
        max: u32,
        now: Instant,
    ) -> ApiResult<()> {
        self.check_and_record_keyed_at(RateLimitBucket::env(environment), max, now)
            .await
    }

    async fn check_and_record_keyed_at(
        &self,
        bucket: RateLimitBucket,
        max: u32,
        now: Instant,
    ) -> ApiResult<()> {
        use std::sync::atomic::Ordering::Relaxed;
        // Phase 7ae: count every real check (skipping no-op short-
        // circuits in `check_and_record` / `check_and_record_policy`
        // when the cap is `None` / 0 — those are config-disabled).
        self.metrics.checks_total.fetch_add(1, Relaxed);

        let key = format!("{}:{}", bucket.r#type, bucket.name);
        let mut state = self.state.lock().await;
        let q = state.entry(key).or_default();
        let cutoff = now.checked_sub(Duration::from_secs(60));
        // Drop entries older than the 60-second window. `checked_sub`
        // returns None only on monotonic-clock overflow (essentially
        // never); skip pruning if it does.
        if let Some(cutoff) = cutoff {
            while let Some(&t) = q.front() {
                if t < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
        }
        if q.len() >= max as usize {
            // The oldest entry tells us when the next slot frees up.
            let retry_secs = q
                .front()
                .map(|&t| 60u64.saturating_sub(now.duration_since(t).as_secs()))
                .unwrap_or(60)
                .max(1);
            self.metrics.rejected_total.fetch_add(1, Relaxed);
            return Err(ApiError::TooManyRequests {
                bucket,
                retry_after_secs: retry_secs,
            });
        }
        q.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_limiter_passes_everything() {
        let lim = RateLimiter::from_config(&RateLimitConfig::default());
        for _ in 0..100 {
            assert!(lim.check_and_record("any").await.is_ok());
        }
    }

    #[tokio::test]
    async fn zero_limit_treated_as_disabled() {
        let lim = RateLimiter::from_config(&RateLimitConfig {
            operations_per_minute: Some(0),
            agent_requests_per_minute: None, ..Default::default()
        });
        for _ in 0..100 {
            assert!(lim.check_and_record("any").await.is_ok());
        }
    }

    #[tokio::test]
    async fn enforces_cap_within_window() {
        let lim = RateLimiter::from_config(&RateLimitConfig {
            operations_per_minute: Some(3),
            agent_requests_per_minute: None, ..Default::default()
        });
        let t0 = Instant::now();
        // 3 calls inside the same window are fine.
        for _ in 0..3 {
            assert!(lim.check_and_record_at("prod", 3, t0).await.is_ok());
        }
        // 4th is rejected.
        let err = lim.check_and_record_at("prod", 3, t0).await.unwrap_err();
        match err {
            ApiError::TooManyRequests { retry_after_secs, bucket } => {
                assert!((1..=60).contains(&retry_after_secs));
                assert_eq!(bucket.r#type, "env");
                assert_eq!(bucket.name, "prod");
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn separate_environments_have_separate_buckets() {
        let lim = RateLimiter::from_config(&RateLimitConfig {
            operations_per_minute: Some(2),
            agent_requests_per_minute: None, ..Default::default()
        });
        let t0 = Instant::now();
        // Fill prod bucket.
        for _ in 0..2 {
            assert!(lim.check_and_record_at("prod", 2, t0).await.is_ok());
        }
        // staging is untouched.
        for _ in 0..2 {
            assert!(lim.check_and_record_at("staging", 2, t0).await.is_ok());
        }
        // prod still rejected.
        assert!(lim.check_and_record_at("prod", 2, t0).await.is_err());
    }

    #[tokio::test]
    async fn entries_expire_after_window() {
        let lim = RateLimiter::from_config(&RateLimitConfig {
            operations_per_minute: Some(1),
            agent_requests_per_minute: None, ..Default::default()
        });
        let t0 = Instant::now();
        assert!(lim.check_and_record_at("env", 1, t0).await.is_ok());
        // 30s later: still capped.
        assert!(lim
            .check_and_record_at("env", 1, t0 + Duration::from_secs(30))
            .await
            .is_err());
        // 61s later: bucket cleared, allowed again.
        assert!(lim
            .check_and_record_at("env", 1, t0 + Duration::from_secs(61))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn agent_cap_disabled_when_unset() {
        // Phase 7bh: with `agent_requests_per_minute = None`, the
        // method short-circuits to `Ok(())` regardless of how many
        // calls.
        let lim = RateLimiter::from_config(&RateLimitConfig::default());
        for _ in 0..100 {
            assert!(lim.check_and_record_agent("agent-x").await.is_ok());
        }
    }

    #[tokio::test]
    async fn agent_cap_isolates_per_agent_id() {
        // Each agent_id gets its own 60-second window — one chatty
        // agent doesn't impact a quiet one's budget.
        let lim = RateLimiter::from_config(&RateLimitConfig {
            operations_per_minute: None,
            agent_requests_per_minute: Some(2), ..Default::default()
        });
        // Fill agent-a's bucket via the public path.
        assert!(lim.check_and_record_agent("agent-a").await.is_ok());
        assert!(lim.check_and_record_agent("agent-a").await.is_ok());
        // Third request from agent-a is rejected.
        let err = lim
            .check_and_record_agent("agent-a")
            .await
            .unwrap_err();
        match err {
            ApiError::TooManyRequests { bucket, .. } => {
                assert_eq!(bucket.r#type, "agent");
                assert_eq!(bucket.name, "agent-a");
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
        // agent-b is independent — its bucket is fresh.
        assert!(lim.check_and_record_agent("agent-b").await.is_ok());
        assert!(lim.check_and_record_agent("agent-b").await.is_ok());
        assert!(lim.check_and_record_agent("agent-b").await.is_err());
    }

    #[test]
    fn rate_limit_bucket_agent_constructor() {
        let b = RateLimitBucket::agent("foo");
        assert_eq!(b.r#type, "agent");
        assert_eq!(b.name, "foo");
    }

    #[tokio::test]
    async fn register_cap_disabled_when_unset() {
        let cfg = RateLimitConfig {
            register_per_minute_per_ip: None,
            ..Default::default()
        };
        let lim = RateLimiter::from_config(&cfg);
        for _ in 0..100 {
            assert!(lim.check_and_record_register("1.2.3.4").await.is_ok());
        }
    }

    #[tokio::test]
    async fn register_cap_zero_disabled() {
        let cfg = RateLimitConfig {
            register_per_minute_per_ip: Some(0),
            ..Default::default()
        };
        let lim = RateLimiter::from_config(&cfg);
        for _ in 0..100 {
            assert!(lim.check_and_record_register("1.2.3.4").await.is_ok());
        }
    }

    #[tokio::test]
    async fn register_cap_isolates_per_ip() {
        let cfg = RateLimitConfig {
            register_per_minute_per_ip: Some(2),
            ..Default::default()
        };
        let lim = RateLimiter::from_config(&cfg);
        // Two storm IPs spamming, one legit IP should still get through.
        assert!(lim.check_and_record_register("10.0.0.1").await.is_ok());
        assert!(lim.check_and_record_register("10.0.0.1").await.is_ok());
        let err = lim.check_and_record_register("10.0.0.1").await.unwrap_err();
        match err {
            ApiError::TooManyRequests { bucket, .. } => {
                assert_eq!(bucket.r#type, "register_ip");
                assert_eq!(bucket.name, "10.0.0.1");
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
        // Different IP gets a fresh budget — fleet bootstrap from
        // multiple hosts is unaffected.
        assert!(lim.check_and_record_register("10.0.0.2").await.is_ok());
        assert!(lim.check_and_record_register("10.0.0.2").await.is_ok());
        assert!(lim.check_and_record_register("10.0.0.2").await.is_err());
    }

    #[tokio::test]
    async fn register_cap_empty_ip_falls_back_to_unknown() {
        let cfg = RateLimitConfig {
            register_per_minute_per_ip: Some(1),
            ..Default::default()
        };
        let lim = RateLimiter::from_config(&cfg);
        assert!(lim.check_and_record_register("").await.is_ok());
        let err = lim.check_and_record_register("   ").await.unwrap_err();
        match err {
            ApiError::TooManyRequests { bucket, .. } => {
                assert_eq!(bucket.name, "unknown");
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_config_swaps_caps_preserves_bucket_state() {
        // Phase 9 follow-up: SIGHUP hot-reload of rate-limit config.
        // Start with cap=2/min on register, fill the bucket from one
        // IP, then raise the cap to 5. Existing Instants survive
        // (no slate wipe), but the new cap should let two more
        // requests in before re-rejecting at the (new) limit.
        let lim = RateLimiter::from_config(&RateLimitConfig {
            register_per_minute_per_ip: Some(2),
            ..Default::default()
        });
        assert!(lim.check_and_record_register("1.2.3.4").await.is_ok());
        assert!(lim.check_and_record_register("1.2.3.4").await.is_ok());
        assert!(
            lim.check_and_record_register("1.2.3.4").await.is_err(),
            "third call should hit the cap=2 limit"
        );

        // Hot-reload to cap=5; existing 2 hits are preserved, so 3
        // more should pass and then we hit the new cap.
        lim.apply_config(&RateLimitConfig {
            register_per_minute_per_ip: Some(5),
            ..Default::default()
        });
        for i in 0..3 {
            assert!(
                lim.check_and_record_register("1.2.3.4").await.is_ok(),
                "post-reload call {i} should pass under raised cap=5"
            );
        }
        assert!(
            lim.check_and_record_register("1.2.3.4").await.is_err(),
            "sixth call total should hit new cap=5 — proves Instants survived swap"
        );

        // Disabling the cap entirely on reload (None → 0) lets
        // everything through.
        lim.apply_config(&RateLimitConfig::default());
        for _ in 0..50 {
            assert!(lim.check_and_record_register("1.2.3.4").await.is_ok());
        }
    }

    #[tokio::test]
    async fn register_and_login_buckets_dont_share_counter() {
        // Same source IP hitting register and login should have two
        // independent budgets — register storms shouldn't lock out
        // legitimate login attempts and vice versa.
        let cfg = RateLimitConfig {
            register_per_minute_per_ip: Some(1),
            login_per_minute_per_user: None,
            login_per_minute_per_ip: Some(1),
            ..Default::default()
        };
        let lim = RateLimiter::from_config(&cfg);
        assert!(lim.check_and_record_register("9.9.9.9").await.is_ok());
        // Same IP has a separate login budget.
        assert!(lim.check_and_record_login("alice", "9.9.9.9").await.is_ok());
        // Both are now exhausted independently.
        assert!(lim.check_and_record_register("9.9.9.9").await.is_err());
        assert!(lim.check_and_record_login("alice", "9.9.9.9").await.is_err());
    }
}
