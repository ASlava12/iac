//! Long-running agent: drives observe cycles, records drift, applies on demand.
//!
//! Phase 1 contract:
//!
//!   * The observe loop is read-only. It records observations and drift events,
//!     never mutates the host.
//!   * `apply()` is one-shot and explicit; the loop never auto-applies.
//!   * After each cycle, `Agent` writes a fresh status snapshot to disk so
//!     `iac-agent status` and external monitors can read it without touching SQL.

use crate::capabilities::{Capabilities, DenyReason};
use crate::config::Config;
use crate::remote::Client;
use crate::status::{self, AgentStatus, ObserveCycleSummary};
use crate::store::Store;
use anyhow::{Context, Result};
use iac_core::diff::Diff;
use iac_core::executor::{ApplyResult, Executor, PlanResult};
use iac_core::manifest;
use iac_core::protocol::v1::{
    AgentHealth, AssignmentEnvelope, AssignmentItemResult, AssignmentResultRequest,
    AssignmentResultStatus, ObservationItem, RegisterRequest,
};
use iac_core::{ProviderRegistry, Resource};
use iac_providers::process::ExternalRuntime;
use iac_providers::register_builtins;
use iac_providers::shellout::ShellOutRuntime;
#[cfg(feature = "wasm")]
use iac_providers::wasm::{WasmComponentProvider, WasmRuntimeAdapter, WasmRuntimeKind};
use jiff::Timestamp;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, RwLock};
use tokio::task;
use tokio::time::Instant as TokioInstant;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct Agent {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: Config,
    registry: ProviderRegistry,
    store: Arc<Store>,
    status: RwLock<AgentStatus>,
    /// Lazily resolved control-plane client. `None` means standalone mode.
    /// Built at startup if `config.server_url` is set. Failure to register at
    /// startup is logged but does not abort the agent — it operates standalone
    /// and retries each observe cycle.
    remote: RwLock<Option<Client>>,
    /// Capability allowlist loaded from `config.capabilities_file`. `None`
    /// means the file was absent and the agent runs unrestricted; `Some`
    /// means rules are enforced before every apply.
    capabilities: Option<Capabilities>,
}

impl Agent {
    /// Build a new agent. Creates state dirs and opens the SQLite db.
    /// Does NOT attempt to talk to the control-plane — call
    /// [`Agent::connect_remote`] for that.
    pub fn new(config: Config) -> Result<Self> {
        config.ensure_dirs()?;
        let mut registry = ProviderRegistry::new();
        register_builtins(&mut registry);

        // Phase 7db: dynamic providers. Built-ins register first so a
        // shellout/external entry that declares an existing kind
        // overrides it — operators can replace a built-in with a
        // local fork without rebuilding the agent. We log the
        // override loudly so it's easy to spot in `iac-agent status`
        // logs.
        for p in &config.shellout_providers {
            let kind = p.kind.clone();
            if registry.get(&kind).is_some() {
                warn!(kind = %kind, "shellout provider overrides built-in or earlier registration");
            }
            let runtime = ShellOutRuntime::new(p.clone()).map_err(|e| {
                anyhow::anyhow!("shellout_providers[{}]: {e}", kind)
            })?;
            registry.register(Box::new(runtime.into_provider()));
            info!(kind = %kind, "registered shellout provider");
        }
        for p in &config.external_providers {
            let kind = p.kind.clone();
            if registry.get(&kind).is_some() {
                warn!(kind = %kind, "external provider overrides built-in or earlier registration");
            }
            let runtime = ExternalRuntime::new(p.clone()).map_err(|e| {
                anyhow::anyhow!("external_providers[{}]: {e}", kind)
            })?;
            registry.register(Box::new(runtime.into_provider()));
            info!(kind = %kind, binary = %p.binary.display(), "registered external provider");
        }
        #[cfg(feature = "wasm")]
        for p in &config.wasm_providers {
            let kind = p.kind.clone();
            if registry.get(&kind).is_some() {
                warn!(kind = %kind, "wasm provider overrides built-in or earlier registration");
            }
            // Phase 7dd: dispatch on the runtime discriminator. Both
            // variants implement the same `Provider` trait, so the
            // executor doesn't care which one is registered.
            match p.runtime {
                WasmRuntimeKind::Core => {
                    let runtime = WasmRuntimeAdapter::new(p.clone()).map_err(|e| {
                        anyhow::anyhow!("wasm_providers[{}] (core): {e}", kind)
                    })?;
                    registry.register(Box::new(runtime.into_provider()));
                    info!(kind = %kind, module = %p.module.display(), runtime = "core", "registered wasm provider");
                }
                WasmRuntimeKind::Component => {
                    let provider = WasmComponentProvider::new(p.clone()).map_err(|e| {
                        anyhow::anyhow!("wasm_providers[{}] (component): {e}", kind)
                    })?;
                    registry.register(Box::new(provider));
                    info!(kind = %kind, module = %p.module.display(), runtime = "component", "registered wasm provider");
                }
            }
        }
        let store = Arc::new(Store::open(&config.db_path)?);
        let status = AgentStatus::initial(&config);

        // Load capabilities. Absent file → unrestricted (logged once).
        // Malformed file → fail closed: refuse to construct the agent.
        let capabilities = Capabilities::load(&config.capabilities_file)?;
        if capabilities.is_some() {
            info!(
                file = %config.capabilities_file.display(),
                "capability allowlist loaded; agent will reject resources outside rules"
            );
        } else {
            warn!(
                file = %config.capabilities_file.display(),
                "no capability allowlist found; agent runs unrestricted"
            );
        }

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                registry,
                store,
                status: RwLock::new(status),
                remote: RwLock::new(None),
                capabilities,
            }),
        })
    }

    /// Filter `resources` against the loaded capability allowlist. Returns
    /// `(allowed, denied)`. With no rules loaded, everything is allowed.
    fn enforce_capabilities(
        &self,
        resources: Vec<Resource>,
    ) -> (Vec<Resource>, Vec<(Resource, DenyReason)>) {
        let Some(caps) = self.inner.capabilities.as_ref() else {
            return (resources, Vec::new());
        };
        let mut allowed = Vec::with_capacity(resources.len());
        let mut denied = Vec::new();
        for r in resources {
            match caps.check(&self.inner.registry, &r) {
                Ok(()) => allowed.push(r),
                Err(reason) => {
                    warn!(
                        resource = %reason.resource_id,
                        identifier = %reason.identifier,
                        reason = %reason.reason,
                        "capability denied"
                    );
                    denied.push((r, reason));
                }
            }
        }
        (allowed, denied)
    }

    /// If `config.server_url` is set, register (or load identity) and cache
    /// a [`Client`]. Failure is logged and the agent stays in standalone mode;
    /// each observe cycle retries.
    pub async fn connect_remote(&self) -> bool {
        let Some(url) = self.inner.config.server_url.clone() else {
            return false;
        };
        let req = RegisterRequest {
            name: self.inner.config.agent_name.clone(),
            environment: self.inner.config.environment.clone(),
            metadata: serde_json::json!({
                "actor": self.inner.config.actor,
                "version": env!("CARGO_PKG_VERSION"),
            }),
        };
        match Client::connect_with_tls(
            &url,
            &self.inner.config.identity_file,
            req,
            &self.inner.config.tls,
        )
        .await
        {
            Ok(c) => {
                info!(url = %url, agent_id = %c.identity().agent_id, "remote configured");
                *self.inner.remote.write().await = Some(c);
                true
            }
            Err(e) => {
                warn!(error = %e, url = %url, "control-plane unavailable; running standalone");
                false
            }
        }
    }

    pub async fn has_remote(&self) -> bool {
        self.inner.remote.read().await.is_some()
    }

    /// Fetch any pending assignments from the control-plane and apply them.
    /// Each assignment is applied via the same local [`Executor`] used for
    /// `apply_once`, then the per-resource result is reported back. Best
    /// effort: errors are logged and the next cycle retries.
    pub async fn drain_assignments(&self) -> Result<usize> {
        let remote = self.inner.remote.read().await;
        let Some(client) = remote.as_ref() else {
            return Ok(0);
        };
        let client = client.clone();
        drop(remote);

        let assignments = match client.fetch_assignments().await {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "fetching assignments failed");
                return Ok(0);
            }
        };
        let mut handled = 0;
        for env in assignments {
            // Phase 7cz.8: replay protection. Even though envelopes
            // are signed and time-bound (Phase 7cs.2 added a 24h
            // freshness check), an attacker who captures one inside
            // that window and replays it would otherwise re-execute
            // the assignment. We persist every assignment_id we've
            // seen and silently no-op on a repeat.
            match self.inner.store.assignment_already_processed(&env.assignment_id) {
                Ok(Some(prior_status)) => {
                    warn!(
                        assignment = %env.assignment_id,
                        prior_status = %prior_status,
                        "replay rejected: assignment already processed",
                    );
                    // Re-report the prior status so the server sees a
                    // fresh ack — without this the operation could sit
                    // pending if the original report was lost on the
                    // wire and the server retried us.
                    let status = match prior_status.as_str() {
                        "succeeded" => AssignmentResultStatus::Succeeded,
                        "partially_applied" => AssignmentResultStatus::PartiallyApplied,
                        _ => AssignmentResultStatus::Failed,
                    };
                    let report = AssignmentResultRequest {
                        status,
                        summary: Some(format!(
                            "replay-of-already-processed assignment ({prior_status})"
                        )),
                        items: vec![],
                    };
                    let _ = client.report_assignment(&env.assignment_id, report).await;
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    // DB failure shouldn't kill the worker — log and
                    // proceed without the dedup guarantee for this
                    // tick. The envelope-freshness window still
                    // protects against long-tail replay.
                    warn!(error = %e, "replay-dedup lookup failed; proceeding");
                }
            }
            match self.execute_assignment(&env).await {
                Ok(report) => {
                    let processed_status = match report.status {
                        AssignmentResultStatus::Succeeded => "succeeded",
                        AssignmentResultStatus::PartiallyApplied => "partially_applied",
                        AssignmentResultStatus::Failed => "failed",
                    };
                    if let Err(e) = self
                        .inner
                        .store
                        .mark_assignment_processed(&env.assignment_id, processed_status)
                    {
                        warn!(error = %e, "recording processed assignment failed");
                    }
                    if let Err(e) = client.report_assignment(&env.assignment_id, report).await {
                        warn!(error = %e, assignment = %env.assignment_id, "reporting assignment failed");
                    }
                    handled += 1;
                }
                Err(e) => {
                    error!(error = %e, assignment = %env.assignment_id, "executing assignment failed");
                    // Mark as failed so the dedup table sees this id
                    // even on errors — a replay attempt of a known-
                    // failed envelope shouldn't get a retry.
                    let _ = self
                        .inner
                        .store
                        .mark_assignment_processed(&env.assignment_id, "failed");
                    // Best-effort: still notify the server so the operation
                    // doesn't sit pending forever.
                    let report = AssignmentResultRequest {
                        status: AssignmentResultStatus::Failed,
                        summary: Some(format!("execution error: {e}")),
                        items: vec![],
                    };
                    let _ = client.report_assignment(&env.assignment_id, report).await;
                }
            }
        }
        Ok(handled)
    }

    async fn execute_assignment(
        &self,
        env: &AssignmentEnvelope,
    ) -> Result<AssignmentResultRequest> {
        if env.kind != "apply" {
            anyhow::bail!("unsupported assignment kind {:?}", env.kind);
        }
        // Deserialize the resources payload back into proper Resource values.
        let resources: Vec<Resource> = env
            .payload
            .resources
            .iter()
            .map(|v| serde_json::from_value::<Resource>(v.clone()))
            .collect::<Result<Vec<_>, _>>()
            .context("decoding assignment resources")?;

        // Capability check happens BEFORE we hand anything to the executor —
        // even a partially-trusted server can't drive the agent past its
        // local policy. Any rejection causes the entire assignment to fail
        // (operator-visible via the result endpoint).
        let (resources, denied) = self.enforce_capabilities(resources);
        if !denied.is_empty() {
            let items: Vec<AssignmentItemResult> = denied
                .iter()
                .map(|(_, reason)| AssignmentItemResult {
                    resource_id: reason.resource_id.clone(),
                    status: "capability_denied".into(),
                    error: Some(reason.to_string()),
                })
                .collect();
            warn!(
                assignment = %env.assignment_id,
                denied_count = items.len(),
                "assignment contains resources outside capability allowlist; refusing"
            );
            return Ok(AssignmentResultRequest {
                status: AssignmentResultStatus::Failed,
                summary: Some(format!(
                    "{} resource(s) denied by agent capability policy",
                    items.len()
                )),
                items,
            });
        }

        let inner = self.inner.clone();
        let result = task::spawn_blocking(move || -> Result<iac_core::executor::ApplyResult> {
            let exec = Executor::new(
                &inner.registry,
                executor_state_dir(&inner.config),
                inner.config.actor.clone(),
            );
            exec.apply(&resources).map_err(anyhow::Error::from)
        })
        .await
        .context("assignment apply task")??;

        use iac_core::executor::ItemStatus;
        use iac_core::operation::OperationStatus as OpStatus;
        let status = match result.operation.status {
            OpStatus::Succeeded => AssignmentResultStatus::Succeeded,
            OpStatus::PartiallyApplied => AssignmentResultStatus::PartiallyApplied,
            _ => AssignmentResultStatus::Failed,
        };
        let items = result
            .items
            .iter()
            .map(|item| AssignmentItemResult {
                resource_id: item.resource_id.to_string(),
                status: match item.status {
                    ItemStatus::NoChange => "no_change",
                    ItemStatus::Succeeded => "succeeded",
                    ItemStatus::Failed => "failed",
                    ItemStatus::Skipped => "skipped",
                }
                .into(),
                error: item.error.clone(),
            })
            .collect();
        Ok(AssignmentResultRequest {
            status,
            summary: Some(format!("operation {}", result.operation.id)),
            items,
        })
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Cloneable handle to the agent's store. Use this from `spawn_blocking`
    /// closures that need to query SQLite without holding `&Agent`.
    pub fn store(&self) -> Arc<Store> {
        self.inner.store.clone()
    }

    /// Snapshot the current status for the CLI.
    pub async fn status(&self) -> AgentStatus {
        self.inner.status.read().await.clone()
    }

    /// Read all manifests from `config.manifests_dir`. Missing or empty dir
    /// returns an empty vec (the agent stays running but observes nothing).
    pub async fn load_manifests(&self) -> Result<Vec<Resource>> {
        let dir = self.inner.config.manifests_dir.clone();
        task::spawn_blocking(move || -> Result<Vec<Resource>> {
            if !dir.exists() {
                return Ok(Vec::new());
            }
            manifest::load_directory(&dir)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading manifests from {}", dir.display()))
        })
        .await
        .context("manifest loader task panicked")?
    }

    /// Effective resource list for one observe cycle: local manifests merged
    /// with whatever the control-plane has scoped to this agent. Server entries
    /// override local ones with the same `ResourceId`, so an `iac apply --server`
    /// supersedes a stale on-disk manifest.
    async fn observation_resources(&self) -> Result<Vec<Resource>> {
        let mut resources = self.load_manifests().await?;

        // Server-side desired state. Best-effort: if the server is down,
        // fall back to local-only.
        let remote = self.inner.remote.read().await;
        let server_resources: Vec<Resource> = if let Some(client) = remote.as_ref() {
            match client.fetch_desired_state().await {
                Ok(items) => items
                    .into_iter()
                    .filter_map(|it| match serde_json::from_value::<Resource>(it.resource) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            warn!(error = %e, "skipping malformed desired-state entry");
                            None
                        }
                    })
                    .collect(),
                Err(e) => {
                    warn!(error = %e, "fetching desired-state failed");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        drop(remote);

        // Merge by ResourceId — server wins on collision.
        use std::collections::HashMap;
        let mut by_id: HashMap<String, Resource> = HashMap::new();
        for r in resources.drain(..) {
            by_id.insert(r.id().to_string(), r);
        }
        for r in server_resources {
            by_id.insert(r.id().to_string(), r);
        }
        let mut merged: Vec<Resource> = by_id.into_values().collect();
        // Stable order so observation/drift dedup keys are deterministic.
        merged.sort_by_key(|a| a.id().to_string());
        Ok(merged)
    }

    /// Run a single observe cycle: load manifests, observe each, record drift.
    /// Returns the summary of what happened.
    pub async fn observe_once(&self) -> Result<ObserveCycleSummary> {
        let started_at = Timestamp::now();
        let started_instant = Instant::now();
        let resources = self.observation_resources().await?;

        let inner = self.inner.clone();
        let summary = task::spawn_blocking(move || -> Result<ObserveCycleSummary> {
            observe_resources_blocking(&inner, &resources, started_at, started_instant)
        })
        .await
        .context("observe task panicked")??;

        // Update in-memory status.
        let open = self.inner.store.open_drift_count()?;
        let managed = summary.observed;
        {
            let mut s = self.inner.status.write().await;
            s.record_cycle(summary.clone(), usize::try_from(open).unwrap_or(0), managed);
        }
        // Persist status snapshot to disk.
        let snapshot = self.inner.status.read().await.clone();
        let status_path = self.inner.config.status_file.clone();
        task::spawn_blocking(move || status::write_status(&status_path, &snapshot))
            .await
            .context("status writer panicked")??;

        // Best-effort push to control-plane.
        if let Err(e) = self.push_to_remote(&summary).await {
            warn!(error = %e, "remote push failed");
        }

        // Best-effort: drain any assignments waiting for us. Done after the
        // observation push so the server has fresh state when planning.
        if self.has_remote().await
            && let Err(e) = self.drain_assignments().await {
                warn!(error = %e, "draining assignments failed");
            }

        // Phase 7da.4: auto-rotate the bearer token before it expires.
        // Server returns `expires_at` in `RegisterResponse`; the
        // `rotate_if_needed()` method has been on `Client` since 7cd
        // but nothing called it. We invoke it once per observe cycle
        // with a generous safety margin (TTL/3 ≈ 8h on a 24h TTL).
        // Rotation failures are logged but don't fail the cycle —
        // the agent keeps using its current token until it actually
        // expires, by which point a fresh `connect_remote()` will
        // re-register.
        if let Err(e) = self.maybe_rotate_token().await {
            warn!(error = %e, "auto-rotation attempt failed");
        }

        Ok(summary)
    }

    /// Phase 7da.4: rotate the agent's bearer token when within
    /// 1/3 of its TTL of expiry. Caller is the observe-cycle loop;
    /// see also [`Client::rotate_if_needed`].
    async fn maybe_rotate_token(&self) -> Result<()> {
        let mut remote_guard = self.inner.remote.write().await;
        let Some(client) = remote_guard.as_mut() else {
            return Ok(());
        };
        let Some(remaining) = client.token_seconds_until_expiry() else {
            // No expiry configured — nothing to rotate.
            return Ok(());
        };
        // Rotate when within max(1h, TTL/3) of expiry. Picking the
        // larger of the two means short TTLs (rare; testing-only)
        // still get a sensible safety window without ping-ponging.
        // The agent's expires_at is recorded on registration; we
        // can't recover the original TTL exactly, so estimate from
        // 3× the current remaining time-to-expiry.
        let safety_secs = (remaining / 2).max(3600);
        let identity_path = &self.inner.config.identity_file;
        if client.rotate_if_needed(identity_path, safety_secs).await?.is_some() {
            tracing::info!(
                remaining_secs_before = remaining,
                "auto-rotated agent token"
            );
        }
        Ok(())
    }

    async fn push_to_remote(&self, summary: &ObserveCycleSummary) -> Result<()> {
        // Lazy reconnect if we haven't attached yet.
        if !self.has_remote().await && self.inner.config.server_url.is_some() {
            self.connect_remote().await;
        }
        let remote = self.inner.remote.read().await;
        let Some(client) = remote.as_ref() else {
            return Ok(());
        };

        // Build the observation batch: one entry per managed resource
        // re-derived from the merged resource list + last observation in the
        // local store.
        let resources = self.observation_resources().await?;
        let store = self.inner.store.clone();
        let observation_items = task::spawn_blocking(move || -> Result<Vec<ObservationItem>> {
            let mut items: Vec<ObservationItem> = Vec::with_capacity(resources.len());
            for r in &resources {
                let id = r.id();
                let row = store.last_observation(&id.to_string())?;
                if let Some(row) = row {
                    items.push(ObservationItem {
                        resource_id: id,
                        observed_at: row.observed_at,
                        present: row.present,
                        spec: row.spec,
                        facts: row.facts,
                    });
                }
            }
            Ok(items)
        })
        .await
        .context("observation batch task")??;

        // Drift items.
        let store = self.inner.store.clone();
        let drift_items = task::spawn_blocking(move || -> Result<Vec<_>> {
            let rows = store.list_open_drifts()?;
            Ok(rows
                .iter()
                .filter_map(crate::remote::drift_row_to_item)
                .collect::<Vec<_>>())
        })
        .await
        .context("drift batch task")??;

        client.push_observations(observation_items).await?;
        client.push_drift(drift_items).await?;

        let open_drifts = u32::try_from(self.inner.store.open_drift_count()?).unwrap_or(u32::MAX);
        let health = if summary.errors.is_empty() {
            AgentHealth::Healthy
        } else {
            AgentHealth::Degraded
        };
        client
            .heartbeat(
                health,
                u32::try_from(summary.observed).unwrap_or(u32::MAX),
                open_drifts,
                Some(summary.at.to_string()),
            )
            .await?;
        Ok(())
    }

    /// One-shot apply via the local executor. Resolves drift in `drift_events`
    /// for any resource that successfully converged. Resources rejected by
    /// the capability allowlist are filtered out before they reach the
    /// executor; the caller sees `ApplyResult` only for the resources that
    /// were actually applied.
    pub async fn apply_once(&self) -> Result<ApplyResult> {
        let resources = self.load_manifests().await?;
        let (resources, denied) = self.enforce_capabilities(resources);
        if !denied.is_empty() {
            warn!(
                count = denied.len(),
                "skipping resources rejected by capability allowlist"
            );
        }
        let inner = self.inner.clone();
        let result = task::spawn_blocking(move || -> Result<ApplyResult> {
            let exec = Executor::new(
                &inner.registry,
                executor_state_dir(&inner.config),
                inner.config.actor.clone(),
            );
            let result = exec.apply(&resources)?;
            // Close drift for resources that ended in NoChange or Succeeded.
            for item in &result.items {
                use iac_core::executor::ItemStatus;
                if matches!(item.status, ItemStatus::NoChange | ItemStatus::Succeeded) {
                    inner
                        .store
                        .close_open_drift_for(&item.resource_id, "apply converged")?;
                }
            }
            Ok(result)
        })
        .await
        .context("apply task panicked")??;

        Ok(result)
    }

    /// One-shot plan, no side effects.
    pub async fn plan_once(&self) -> Result<PlanResult> {
        let resources = self.load_manifests().await?;
        let inner = self.inner.clone();
        let result = task::spawn_blocking(move || -> Result<PlanResult> {
            let exec = Executor::new(
                &inner.registry,
                executor_state_dir(&inner.config),
                inner.config.actor.clone(),
            );
            exec.plan(&resources).map_err(anyhow::Error::from)
        })
        .await
        .context("plan task panicked")??;
        Ok(result)
    }

    /// Roll back a previously-applied operation.
    pub async fn rollback(&self, operation_id: ulid::Ulid) -> Result<()> {
        let inner = self.inner.clone();
        task::spawn_blocking(move || -> Result<()> {
            let exec = Executor::new(
                &inner.registry,
                executor_state_dir(&inner.config),
                inner.config.actor.clone(),
            );
            exec.rollback(operation_id).map_err(anyhow::Error::from)
        })
        .await
        .context("rollback task panicked")??;
        Ok(())
    }

    /// Long-running observe loop. Returns when `shutdown` fires.
    /// The first cycle runs immediately so external monitors see status quickly.
    pub async fn run(&self, shutdown: Arc<Notify>) -> Result<()> {
        info!(
            interval_secs = self.inner.config.observe_interval.as_secs(),
            manifests_dir = %self.inner.config.manifests_dir.display(),
            "agent loop starting"
        );

        // Immediate first cycle.
        if let Err(e) = self.observe_once().await {
            error!(error = %e, "initial observe cycle failed");
        }

        let mut ticker = tokio::time::interval_at(
            TokioInstant::now() + self.inner.config.observe_interval,
            self.inner.config.observe_interval,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    info!("shutdown signal received");
                    break;
                }
                _ = ticker.tick() => {
                    debug!("observe tick");
                    match self.observe_once().await {
                        Ok(s) => debug!(observed = s.observed, drift = s.drift_detected, "cycle ok"),
                        Err(e) => warn!(error = %e, "observe cycle failed"),
                    }
                }
            }
        }
        Ok(())
    }
}

fn executor_state_dir(config: &Config) -> PathBuf {
    config.state_dir.join("executor")
}

fn observe_resources_blocking(
    inner: &Inner,
    resources: &[Resource],
    started_at: Timestamp,
    started_instant: Instant,
) -> Result<ObserveCycleSummary> {
    let mut errors: Vec<String> = Vec::new();
    let mut drift_count = 0usize;

    for resource in resources {
        let id = resource.id();
        let provider = match inner.registry.require(&resource.kind) {
            Ok(p) => p,
            Err(e) => {
                errors.push(format!("{id}: unknown kind: {e}"));
                continue;
            }
        };
        let observed = match provider.observe(resource) {
            Ok(o) => o,
            Err(e) => {
                errors.push(format!("{id}: observe failed: {e}"));
                continue;
            }
        };
        if let Err(e) = inner.store.record_observation(&id, &observed) {
            errors.push(format!("{id}: record observation: {e}"));
            // continue: failure to record shouldn't block drift detection on other resources
        }
        let diff = match provider.diff(resource, &observed) {
            Ok(d) => d,
            Err(e) => {
                errors.push(format!("{id}: diff failed: {e}"));
                continue;
            }
        };
        if diff.is_change() {
            drift_count += 1;
            let severity = severity_for(&diff);
            if let Err(e) = inner.store.open_drift(&id, &severity, &diff) {
                errors.push(format!("{id}: open drift: {e}"));
            }
        } else if let Err(e) = inner.store.close_open_drift_for(&id, "drift cleared") {
            errors.push(format!("{id}: close drift: {e}"));
        }
    }

    let finished_at = Timestamp::now();
    let duration_ms = u64::try_from(started_instant.elapsed().as_millis()).unwrap_or(u64::MAX);

    let error_summary = if errors.is_empty() { None } else { Some(errors.join("; ")) };
    inner.store.record_run(
        started_at,
        Some(finished_at),
        i64::try_from(resources.len()).unwrap_or(i64::MAX),
        i64::try_from(drift_count).unwrap_or(i64::MAX),
        error_summary.as_deref(),
    )?;

    Ok(ObserveCycleSummary {
        at: started_at,
        duration_ms,
        observed: resources.len(),
        drift_detected: drift_count,
        errors,
    })
}

fn severity_for(diff: &Diff) -> String {
    if !diff.reversible {
        "critical".into()
    } else {
        "warning".into()
    }
}
