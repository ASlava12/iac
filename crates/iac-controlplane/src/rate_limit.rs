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
}

fn default_login_per_minute() -> Option<u32> {
    Some(10)
}
fn default_login_per_minute_ip() -> Option<u32> {
    Some(30)
}

#[derive(Debug)]
pub struct RateLimiter {
    max_per_minute: Option<u32>,
    /// Phase 7bh: per-agent cap (`None` / `0` disables).
    agent_max_per_minute: Option<u32>,
    /// Phase 7co (security fix #4.2): per-username login cap.
    login_user_max_per_minute: Option<u32>,
    /// Phase 7co: per-client-IP login cap.
    login_ip_max_per_minute: Option<u32>,
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
        Self {
            max_per_minute: cfg.operations_per_minute.filter(|n| *n > 0),
            agent_max_per_minute: cfg.agent_requests_per_minute.filter(|n| *n > 0),
            login_user_max_per_minute: cfg.login_per_minute_per_user.filter(|n| *n > 0),
            login_ip_max_per_minute: cfg.login_per_minute_per_ip.filter(|n| *n > 0),
            state: Mutex::new(HashMap::new()),
            metrics: RateLimitMetrics::default(),
        }
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
        if let Some(max) = self.login_user_max_per_minute {
            self.check_and_record_keyed_at(
                RateLimitBucket::login_user(username),
                max,
                Instant::now(),
            )
            .await?;
        }
        if let Some(max) = self.login_ip_max_per_minute {
            self.check_and_record_keyed_at(
                RateLimitBucket::client(client_ip),
                max,
                Instant::now(),
            )
            .await?;
        }
        Ok(())
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
        let Some(max) = self.max_per_minute else { return Ok(()); };
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
        let Some(max) = self.agent_max_per_minute else { return Ok(()); };
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
}
