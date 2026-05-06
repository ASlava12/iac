// Phase 7cz.16: tests-only exemption for unwrap/expect/panic.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{Context, Result};
use clap::Parser;
use iac_controlplane::{
    identity::Role,
    server::AppState,
    signing::ServerSigner,
    store::CreateUser,
    Config, Store,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;

#[derive(Parser, Debug)]
#[command(name = "iac-controlplane", version, about = "IaC control-plane API server (Phase 2a)")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long)]
    bind: Option<String>,

    #[arg(long)]
    state_dir: Option<PathBuf>,

    #[arg(long)]
    database_url: Option<String>,

    /// Admin token for operator endpoints. Falls back to `IAC_ADMIN_TOKEN` env.
    #[arg(long)]
    admin_token: Option<String>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot build tokio runtime: {e}");
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::from(2)
        }
    }
}

async fn bootstrap_admin_from_env(store: &Store) -> Result<()> {
    let username = match std::env::var("IAC_BOOTSTRAP_USER") {
        Ok(u) if !u.is_empty() => u,
        _ => return Ok(()),
    };
    let password = match std::env::var("IAC_BOOTSTRAP_PASS") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            tracing::warn!(
                "IAC_BOOTSTRAP_USER set but IAC_BOOTSTRAP_PASS missing; \
                 skipping admin bootstrap"
            );
            return Ok(());
        }
    };
    let count = store.user_count().await?;
    if count > 0 {
        return Ok(());
    }
    match store
        .create_user(CreateUser {
            username: &username,
            password: &password,
            roles: vec![Role::Admin],
        })
        .await
    {
        Ok(_) => {
            tracing::info!(username = %username, "bootstrapped admin user");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to bootstrap admin user");
        }
    }
    Ok(())
}

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = match verbosity {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        1 => EnvFilter::new("info,iac_controlplane=debug"),
        _ => EnvFilter::new("debug"),
    };
    let _ = fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let overrides = iac_controlplane::config::Overrides {
        bind: cli.bind,
        database_url: cli.database_url,
        state_dir: cli.state_dir,
        admin_token: cli.admin_token,
    };
    let config = Config::load(cli.config.as_deref(), overrides)?;
    config.ensure_dirs()?;

    tracing::info!(bind = %config.bind, db = %config.database_url, "starting control-plane");

    let store = Store::connect(&config.database_url)
        .await
        .context("connecting to database")?;

    // Phase 6e: bootstrap admin user from env vars on first start. We only
    // create the user if the `users` table is empty AND both vars are set —
    // re-runs with the same env are idempotent (will hit the "user already
    // exists" branch and proceed without complaint).
    bootstrap_admin_from_env(&store)
        .await
        .context("bootstrapping admin user")?;

    let signer =
        ServerSigner::load_or_create(&config.state_dir).context("initializing signer")?;
    let rate_limiter = Arc::new(iac_controlplane::rate_limit::RateLimiter::from_config(
        &config.rate_limit,
    ));

    // Phase 7t / 7ad: build the webhook dispatcher BEFORE AppState so
    // we can share the Arc with both the polling loop and the
    // /v1/metrics handler.
    let webhook_dispatcher = Arc::new(
        iac_controlplane::webhook::WebhookDispatcher::new(config.webhooks.clone()),
    );
    // Phase 7bg: pre-build the per-window counter map from configured
    // window names. `from_config` also runs the Phase 7ai
    // misconfigured-windows count internally.
    let maintenance_metrics =
        Arc::new(iac_controlplane::maintenance::MaintenanceMetrics::from_config(
            &config.maintenance_windows,
            &config.recurring_maintenance_windows,
        ));
    // Phase 7am: assemble the secret-resolver registry from config. `env`
    // is always available; `vault` opts in via `[secrets.vault]`.
    let secret_registry = build_secret_registry(&config.secrets)?;

    // Phase 7aq: snapshot misconfigured-window issues once so the admin
    // endpoint doesn't re-parse on every request.
    // Phase 7bx: hosted inside ReloadableState — recomputed on SIGHUP.
    let config_arc = Arc::new(config.clone());
    let live = Arc::new(arc_swap::ArcSwap::from_pointee(
        iac_controlplane::server::ReloadableState::new(config_arc),
    ));

    let state = AppState {
        store: store.clone(),
        live,
        config_path: cli.config.clone(),
        signer: Arc::new(signer),
        rate_limiter,
        webhook_dispatcher: Some(webhook_dispatcher.clone()),
        maintenance_metrics,
        secret_registry: secret_registry.map(Arc::new),
    };

    // Phase 6g: spawn the retention loop. The shutdown Notify is shared so
    // the loop exits cleanly on SIGTERM alongside the HTTP server.
    let retention_shutdown = Arc::new(Notify::new());
    let retention_handle = iac_controlplane::retention::spawn_loop(
        store.clone(),
        config.retention,
        retention_shutdown.clone(),
    );

    // Phase 7t: spawn the webhook loop. Polls audit_events for new rows
    // and POSTs matching events to configured receivers.
    let webhook_shutdown = Arc::new(Notify::new());
    let webhook_handle = iac_controlplane::webhook::spawn_loop(
        store.clone(),
        webhook_dispatcher,
        webhook_shutdown.clone(),
    );

    // Phase 7ck: register SSH targets in the agents table + spawn
    // one push worker per target. Each worker pops pending
    // assignments addressed to its target and dispatches via
    // `ssh user@host -- iac apply --assignment-stdin`.
    let ssh_shutdown = Arc::new(Notify::new());
    let mut ssh_target_ids = Vec::with_capacity(config.ssh_targets.len());
    for target in &config.ssh_targets {
        let id = store
            .upsert_ssh_target(&target.name, &target.environment)
            .await?;
        ssh_target_ids.push(id);
    }
    let ssh_handles = iac_controlplane::ssh_push::spawn_ssh_workers(
        store,
        config.ssh_targets.clone(),
        ssh_target_ids,
        ssh_shutdown.clone(),
    );
    if !ssh_handles.is_empty() {
        tracing::info!(
            target_count = ssh_handles.len(),
            "spawned SSH push workers"
        );
    }

    let app = iac_controlplane::server::router(state.clone());

    let addr: SocketAddr = config.bind;
    tracing::info!(addr = %addr, mode = %config.tls.mode, "listening");

    let shutdown = Arc::new(Notify::new());
    let signaler = shutdown.clone();
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM"),
            _ = sigint.recv() => tracing::info!("SIGINT"),
        }
        signaler.notify_waiters();
    });

    // Phase 9-F1: periodic WAL truncate. SQLite's auto-checkpoint
    // pages back to the main DB but doesn't shrink the WAL file —
    // only TRUNCATE-mode does. Without this task, sustained mixed
    // read/write traffic grows the WAL unboundedly (the F1 24-h soak
    // hit disk-full on an 8.5 GB VPS at ~3 h with a 4 GB WAL).
    // Disabled by setting `wal_checkpoint_interval_secs = 0`. No-op
    // on Postgres; see `Store::wal_checkpoint_truncate`.
    let wal_interval = state.config().wal_checkpoint_interval_secs;
    if wal_interval > 0 {
        let wal_state = state.clone();
        let wal_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(wal_interval));
            // First tick fires immediately; skip it so we let the
            // server warm up before the first checkpoint runs.
            tick.tick().await;
            // Phase 9-F1-fix-3: most cycles run a non-blocking
            // PASSIVE checkpoint; every TRUNCATE_EVERY_N-th cycle
            // runs a TRUNCATE to actually reclaim WAL file size.
            // PASSIVE alone would let the WAL grow up to
            // `journal_size_limit` over time, so we still need
            // periodic TRUNCATE — just not on every tick.
            const TRUNCATE_EVERY_N: u64 = 10;
            let mut cycle: u64 = 0;
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        cycle = cycle.wrapping_add(1);
                        let force = cycle % TRUNCATE_EVERY_N == 0;
                        match wal_state.store.wal_checkpoint(force).await {
                            Ok(()) => tracing::debug!(force_truncate = force, "wal_checkpoint ok"),
                            Err(e) => tracing::warn!(error = %e, "wal_checkpoint failed; will retry next tick"),
                        }
                    }
                    _ = wal_shutdown.notified() => {
                        tracing::info!("WAL checkpoint task shutting down");
                        break;
                    }
                }
            }
        });
        tracing::info!(interval_secs = wal_interval, "WAL checkpoint task scheduled (PASSIVE most ticks, TRUNCATE every 10th)");
    } else {
        tracing::info!("WAL checkpoint task disabled (interval = 0)");
    }

    // Phase 7bx: separate task for SIGHUP — re-reads the config file
    // and atomically swaps the live state. Failures (parse error,
    // validation error) log and leave the running config unchanged
    // so a misedit doesn't kill the server.
    let reload_state = state.clone();
    tokio::spawn(async move {
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGHUP handler; hot-reload disabled");
                return;
            }
        };
        loop {
            sighup.recv().await;
            tracing::info!("SIGHUP received — reloading config");
            match reload_state.reload_config() {
                Ok(outcome) => {
                    tracing::info!(
                        path = %outcome.path.display(),
                        config_issues = outcome.config_issues,
                        "config reloaded"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "config reload failed; running config unchanged"
                    );
                }
            }
        }
    });

    let shutdown_signal = shutdown.clone();
    if config.tls.is_enabled() {
        // Phase 7ak: TLS / mTLS path. axum-server handles the
        // tokio-rustls glue. Graceful shutdown via the shared Notify.
        use axum_server::tls_rustls::RustlsConfig;
        let rustls_cfg = iac_controlplane::tls::build_rustls_config(&config.tls)
            .context("loading TLS config")?;
        let server_cfg = RustlsConfig::from_config(rustls_cfg);
        let handle = axum_server::Handle::new();
        let handle_for_shutdown = handle.clone();
        tokio::spawn(async move {
            shutdown_signal.notified().await;
            handle_for_shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });
        // Phase 9-F8: `with_connect_info` plumbs the source SocketAddr
        // through to handlers via `ConnectInfo<SocketAddr>`. Required
        // for the per-IP register / login rate limits.
        axum_server::bind_rustls(addr, server_cfg)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .context("tls server error")?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await.context("binding")?;
        let actual = listener.local_addr().context("local_addr")?;
        tracing::info!(addr = %actual, "plain HTTP listener bound");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { shutdown_signal.notified().await })
        .await
        .context("server error")?;
    }

    // Stop the retention + webhook loops and wait for them to drain.
    retention_shutdown.notify_waiters();
    let _ = retention_handle.await;
    webhook_shutdown.notify_waiters();
    let _ = webhook_handle.await;
    // Phase 7ck: stop SSH push workers. Each worker will drain its
    // current iteration and then exit on the next loop check.
    ssh_shutdown.notify_waiters();
    for handle in ssh_handles {
        let _ = handle.await;
    }

    tracing::info!("shutdown complete");
    Ok(ExitCode::SUCCESS)
}

/// Build a `SecretRegistry` from the configured backends. Returns `None`
/// when nothing is configured beyond defaults — saves an Arc allocation
/// in the common test path. In production we always at least register
/// `EnvResolver` so manifest authors can reach process-scope env vars.
fn build_secret_registry(
    cfg: &iac_controlplane::config::SecretsConfig,
) -> Result<Option<iac_controlplane::secrets::SecretRegistry>> {
    use iac_controlplane::secrets::{
        EnvResolver, Resolver, SecretRegistry, SopsResolver, VaultResolver,
    };
    let mut registry = SecretRegistry::new();
    registry.register(Resolver::Env(EnvResolver));

    if let Some(v) = &cfg.vault {
        if v.addr.is_empty() {
            anyhow::bail!("[secrets.vault].addr must be set when vault block is present");
        }
        let token = v.resolve_token().ok_or_else(|| {
            anyhow::anyhow!(
                "[secrets.vault]: must set `token` or `token_env` (and the env var must be set)"
            )
        })?;
        let resolver = VaultResolver::new(&v.addr, token)
            .map_err(|e| anyhow::anyhow!("building vault resolver: {e}"))?;
        registry.register(Resolver::Vault(resolver));
        tracing::info!(addr = %v.addr, "vault secret resolver registered");
    }

    if let Some(s) = &cfg.sops {
        if s.base_dir.as_os_str().is_empty() {
            anyhow::bail!(
                "[secrets.sops].base_dir must be set when sops block is present"
            );
        }
        let binary = s.resolve_binary();
        let resolver = SopsResolver::new(&s.base_dir, &binary)
            .map_err(|e| anyhow::anyhow!("building sops resolver: {e}"))?;
        registry.register(Resolver::Sops(resolver));
        tracing::info!(
            base_dir = %s.base_dir.display(),
            binary = %binary,
            "sops secret resolver registered"
        );
    }

    Ok(Some(registry))
}
