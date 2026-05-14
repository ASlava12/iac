//! Phase 8: trial workload generator + scenario runner.
//!
//! Drives a control-plane in the docker-compose stack with
//! synthetic operations and reports throughput / error / latency
//! distributions. Three subcommands:
//!
//!   * `submit-burst` — fire N submit-operation requests at a target
//!     RPS, against a generated set of `file` resources. Stresses
//!     the operation-creation path + agent assignment.
//!   * `drift-cascade` — flips host-side state on a fraction of
//!     agents to provoke drift recording. Stresses the drift
//!     accept/ignore pipeline.
//!   * `longevity` — runs `submit-burst` at a low rate forever
//!     and tracks per-cycle agent count, RSS-via-metrics, and
//!     audit-chain growth. The "leave it running overnight" one.
//!
//! Each subcommand prints a final summary + non-zero exits if
//! pass/fail thresholds were violated. Operators wire that into
//! CI for trial regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "iac-trial", version, about = "Trial harness workload generator")]
struct Cli {
    /// Control-plane base URL.
    #[arg(long, default_value = "http://127.0.0.1:8443")]
    server_url: String,

    /// Admin token. Default matches `trial/compose/server.toml`.
    #[arg(long, default_value = "trial-admin-token")]
    admin_token: String,

    /// Environment label for submitted operations.
    #[arg(long, default_value = "trial")]
    environment: String,

    /// Phase 9: comma-separated list of agent names to round-robin
    /// `spec.hostSelector.name` through. The single-host docker-compose
    /// trial got away without this because the controlplane routes
    /// no-selector resources to the only agent in the env. A real
    /// fleet has N>1 agents and the routing rule rejects ambiguous
    /// resources as unrouted (see `route_resource` in
    /// `iac-controlplane::store`). Empty = no hostSelector (legacy
    /// single-agent behaviour).
    #[arg(long, default_value = "", value_delimiter = ',')]
    targets: Vec<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Fire a burst of operation submissions and report throughput.
    SubmitBurst {
        /// Total number of submissions to make.
        #[arg(long, default_value_t = 1000)]
        count: u64,
        /// Target submissions per second. The actual rate
        /// depends on server-side latency; we pace a token
        /// bucket but won't stall under timeouts.
        #[arg(long, default_value_t = 50.0)]
        rps: f64,
        /// Concurrent client futures. Higher = more pipeline
        /// depth, more chance to saturate the server's HTTP
        /// pool.
        #[arg(long, default_value_t = 16)]
        concurrency: usize,
    },
    /// Long-running low-rate workload — for soak / longevity runs.
    Longevity {
        /// Duration to run for (e.g. `30m`, `2h`, `24h`). Parsed
        /// as seconds for simplicity in the trial harness.
        #[arg(long, default_value_t = 1800)]
        duration_secs: u64,
        /// Operations per second.
        #[arg(long, default_value_t = 1.0)]
        rps: f64,
    },
    /// Probe `/v1/health` and `/v1/agents` until the fleet
    /// reaches `expected` registered agents. Used to gate
    /// scenario starts.
    WaitFleet {
        /// Number of agents to wait for.
        #[arg(long)]
        expected: usize,
        /// Timeout in seconds. Returns non-zero if not reached.
        #[arg(long, default_value_t = 180)]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();

    let cli = Cli::parse();
    let client = build_client(&cli.admin_token)?;

    match cli.cmd {
        Cmd::SubmitBurst { count, rps, concurrency } => {
            submit_burst(&cli, &client, count, rps, concurrency).await
        }
        Cmd::Longevity { duration_secs, rps } => {
            longevity(&cli, &client, duration_secs, rps).await
        }
        Cmd::WaitFleet { expected, timeout_secs } => {
            wait_fleet(&cli, &client, expected, timeout_secs).await
        }
    }
}

fn build_client(_token: &str) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(64)
        .build()
        .context("building reqwest client")
}

/// One synthetic file-resource manifest. Each call generates a
/// fresh ResourceId so submissions never collide on dedup. When
/// `host_selector` is `Some`, the resource pins to that agent name —
/// required when the controlplane has more than one agent in the
/// target environment (the routing rule rejects ambiguous resources;
/// see `route_resource` in `iac-controlplane::store`).
/// Phase 9-F1-fix-9: bound resource path namespace so long-running
/// soaks don't accumulate unbounded unique resources on the CP
/// (which makes the per-resource cap subquery slow even though the
/// cap itself works correctly per-resource). F1 #6-#9 all saw
/// `observations` table grow to 1.7-2 M rows because each submission
/// produced a fresh ULID-derived path → resource_id, so cap=10
/// still allowed thousands of distinct (agent, resource) pairs to
/// accumulate over a 24h trial.
///
/// Fix: counter modulo POOL. Path = `/tmp/trial-{host}-{idx%POOL}.txt`,
/// so each (host, slot) pair is re-used across submissions. POOL
/// defaults to 200; for fleet-7-agent trial that bounds fleet-wide
/// resource count to 7 × 200 = 1400, well within SQLite's comfort
/// zone at all observation cap levels.
///
/// Tunable via `TRIAL_RESOURCE_POOL_SIZE` env var so stress variants
/// (F1-density, F1-burst) can exercise larger working sets without
/// recompiling.
const DEFAULT_TRIAL_RESOURCE_POOL: u64 = 200;
static TRIAL_RESOURCE_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn make_file_manifest(env: &str, host_selector: Option<&str>) -> serde_json::Value {
    let pool = std::env::var("TRIAL_RESOURCE_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_TRIAL_RESOURCE_POOL);
    let iter = TRIAL_RESOURCE_COUNTER
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let slot = iter % pool;
    let host_tag = host_selector.unwrap_or("any");
    let path = format!("/tmp/trial-{host_tag}-{slot:04}.txt");
    let mut spec = serde_json::json!({
        "path": path,
        "mode": "0644",
        // Include `iter` so successive submissions to the same slot
        // produce different content (an actual write happens each
        // time, not a no-op no-change apply).
        "content": format!("trial iter={iter} slot={slot}\n"),
    });
    if let Some(host) = host_selector
        && let Some(map) = spec.as_object_mut()
    {
        map.insert(
            "hostSelector".into(),
            serde_json::json!({ "name": host }),
        );
    }
    serde_json::json!({
        "apiVersion": "iac.example/v1",
        "kind": "file",
        "metadata": {
            "name": format!("trial-{host_tag}-{slot:04}"),
            "environment": env,
        },
        "spec": spec,
    })
}

async fn submit_one(
    client: &reqwest::Client,
    server_url: &str,
    admin_token: &str,
    environment: &str,
    target: Option<&str>,
) -> Result<Duration> {
    let body = serde_json::json!({
        "environment": environment,
        "requested_by": "iac-trial",
        "source_commit": null,
        "summary": "trial submit-burst",
        "resources": [make_file_manifest(environment, target)],
        "canary": null,
    });
    let started = Instant::now();
    let resp = client
        .post(format!("{server_url}/v1/operations"))
        .bearer_auth(admin_token)
        .json(&body)
        .send()
        .await
        .context("submit /v1/operations")?;
    let elapsed = started.elapsed();
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("submit failed: {status}: {text}");
    }
    Ok(elapsed)
}

/// Latency-bucket aggregator. Lock-free: each worker bumps the
/// bucket counter directly; we read the atomic snapshot at the
/// end. Simple histogram is enough for trial-shape signal.
struct Stats {
    submitted: AtomicU64,
    failures: AtomicU64,
    /// Latency buckets in milliseconds: <5, <10, <25, <50, <100,
    /// <250, <500, <1000, <2500, ≥2500.
    buckets: [AtomicU64; 10],
}

impl Stats {
    fn new() -> Self {
        Self {
            submitted: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn record(&self, latency: Duration) {
        self.submitted.fetch_add(1, Ordering::Relaxed);
        let ms = latency.as_millis() as u64;
        let idx = match ms {
            0..=4 => 0,
            5..=9 => 1,
            10..=24 => 2,
            25..=49 => 3,
            50..=99 => 4,
            100..=249 => 5,
            250..=499 => 6,
            500..=999 => 7,
            1000..=2499 => 8,
            _ => 9,
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    fn fail(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn print_summary(&self, total_elapsed: Duration) {
        let n = self.submitted.load(Ordering::Relaxed);
        let f = self.failures.load(Ordering::Relaxed);
        let rps = if total_elapsed.as_secs_f64() > 0.0 {
            n as f64 / total_elapsed.as_secs_f64()
        } else {
            0.0
        };
        let bucket_labels = [
            "<5ms",
            "<10ms",
            "<25ms",
            "<50ms",
            "<100ms",
            "<250ms",
            "<500ms",
            "<1s",
            "<2.5s",
            "≥2.5s",
        ];
        println!("---");
        println!("submitted:  {n}");
        println!("failed:     {f}");
        println!("elapsed:    {:.2}s", total_elapsed.as_secs_f64());
        println!("throughput: {rps:.1} ops/s");
        println!("latency histogram:");
        for (label, b) in bucket_labels.iter().zip(self.buckets.iter()) {
            let c = b.load(Ordering::Relaxed);
            if c > 0 {
                println!("  {label:>8}: {c}");
            }
        }
    }

    /// Pass criteria for trial CI:
    ///   * < 1% failures
    ///   * < 5% of submissions in the worst bucket (≥ 2.5 s)
    fn passed(&self) -> bool {
        let n = self.submitted.load(Ordering::Relaxed).max(1);
        let f = self.failures.load(Ordering::Relaxed);
        let slow = self.buckets[9].load(Ordering::Relaxed);
        (f * 100) < n && (slow * 20) < n
    }
}

async fn submit_burst(
    cli: &Cli,
    client: &reqwest::Client,
    count: u64,
    rps: f64,
    concurrency: usize,
) -> Result<()> {
    tracing::info!(
        count,
        rps,
        concurrency,
        url = %cli.server_url,
        targets = ?cli.targets,
        "submit-burst starting"
    );
    let stats = Arc::new(Stats::new());
    let started = Instant::now();
    let permits = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(count as usize);
    let interval = if rps > 0.0 {
        Duration::from_secs_f64(1.0 / rps)
    } else {
        Duration::ZERO
    };
    let mut next_dispatch = Instant::now();
    // Filter empty entries from `--targets ""` (clap value-delimiter
    // splits even empty strings into a single empty element).
    let targets: Vec<String> = cli
        .targets
        .iter()
        .filter(|t| !t.is_empty())
        .cloned()
        .collect();
    let target_idx = Arc::new(AtomicU64::new(0));

    for _ in 0..count {
        let now = Instant::now();
        if now < next_dispatch {
            tokio::time::sleep(next_dispatch - now).await;
        }
        next_dispatch += interval;
        let permit = permits.clone().acquire_owned().await.unwrap();
        let stats = stats.clone();
        let client = client.clone();
        let server_url = cli.server_url.clone();
        let token = cli.admin_token.clone();
        let env = cli.environment.clone();
        // Pre-pick the target so each submit binds to a deterministic
        // agent name rather than letting concurrent tasks race on the
        // index. Round-robin via fetch-and-increment.
        let target = if targets.is_empty() {
            None
        } else {
            let i = target_idx.fetch_add(1, Ordering::Relaxed) as usize;
            Some(targets[i % targets.len()].clone())
        };
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match submit_one(&client, &server_url, &token, &env, target.as_deref()).await {
                Ok(d) => stats.record(d),
                Err(e) => {
                    stats.fail();
                    tracing::warn!("submit failed: {e}");
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed();
    stats.print_summary(elapsed);
    if !stats.passed() {
        anyhow::bail!("submit-burst FAILED pass thresholds (>1% errors or >5% slow)");
    }
    println!("PASS");
    Ok(())
}

async fn longevity(
    cli: &Cli,
    client: &reqwest::Client,
    duration_secs: u64,
    rps: f64,
) -> Result<()> {
    tracing::info!(duration_secs, rps, "longevity scenario starting");
    let stats = Arc::new(Stats::new());
    let started = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / rps);
    let deadline = started + Duration::from_secs(duration_secs);

    let targets: Vec<String> = cli
        .targets
        .iter()
        .filter(|t| !t.is_empty())
        .cloned()
        .collect();
    let mut idx: u64 = 0;
    while Instant::now() < deadline {
        let begin = Instant::now();
        let target = if targets.is_empty() {
            None
        } else {
            let t = &targets[(idx as usize) % targets.len()];
            idx = idx.wrapping_add(1);
            Some(t.as_str())
        };
        match submit_one(
            client,
            &cli.server_url,
            &cli.admin_token,
            &cli.environment,
            target,
        )
        .await
        {
            Ok(d) => stats.record(d),
            Err(e) => {
                stats.fail();
                tracing::warn!("longevity submit failed: {e}");
            }
        }
        let next = begin + interval;
        let now = Instant::now();
        if now < next {
            tokio::time::sleep(next - now).await;
        }
        // Periodic status line every ~100 ops so operators see
        // progress on long runs.
        let n = stats.submitted.load(Ordering::Relaxed);
        if n > 0 && n.is_multiple_of(100) {
            tracing::info!(
                submitted = n,
                failures = stats.failures.load(Ordering::Relaxed),
                "longevity progress"
            );
        }
    }

    let elapsed = started.elapsed();
    stats.print_summary(elapsed);
    if !stats.passed() {
        anyhow::bail!("longevity FAILED pass thresholds");
    }
    println!("PASS");
    Ok(())
}

async fn wait_fleet(
    cli: &Cli,
    client: &reqwest::Client,
    expected: usize,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last_seen = 0;
    while Instant::now() < deadline {
        let resp = client
            .get(format!("{}/v1/agents", cli.server_url))
            .bearer_auth(&cli.admin_token)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                let agents: Vec<serde_json::Value> =
                    r.json().await.unwrap_or_default();
                let n = agents.len();
                if n != last_seen {
                    last_seen = n;
                    tracing::info!(registered = n, expected, "fleet poll");
                }
                if n >= expected {
                    println!("PASS — fleet reached {n} agents");
                    return Ok(());
                }
            }
            Ok(r) => tracing::debug!(status = %r.status(), "agents poll non-2xx"),
            Err(e) => tracing::debug!("agents poll error: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    anyhow::bail!(
        "wait-fleet TIMEOUT — only {last_seen} of {expected} agents registered in {timeout_secs}s"
    );
}
