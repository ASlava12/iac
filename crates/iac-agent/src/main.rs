// Phase 7cz.16: tests-only exemption for unwrap/expect/panic.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use iac_agent::{Agent, Config, ConfigOverrides};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;

const APP: &str = "iac-agent";

#[derive(Parser, Debug)]
#[command(name = APP, version, about = "Long-running local IaC agent (Phase 1)")]
struct Cli {
    /// Path to a TOML config file. If absent, defaults are used.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Override `state_dir`.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,

    /// Override `manifests_dir`.
    #[arg(long, global = true)]
    manifests_dir: Option<PathBuf>,

    /// Observe loop period in seconds (overrides config file).
    #[arg(long, global = true)]
    interval: Option<u64>,

    /// Override `environment`.
    #[arg(long, global = true)]
    environment: Option<String>,

    /// Override `actor`.
    #[arg(long, global = true)]
    actor: Option<String>,

    /// Control-plane URL. When set, the agent registers and pushes after each cycle.
    #[arg(long, global = true)]
    server_url: Option<String>,

    /// Agent name used at first registration (defaults to hostname).
    #[arg(long, global = true)]
    agent_name: Option<String>,

    /// Path to the capability allowlist YAML (default `<state_dir>/capabilities.yaml`).
    /// When the file is absent the agent runs unrestricted; when present, the
    /// declared rules are enforced before every apply.
    #[arg(long, global = true)]
    capabilities_file: Option<PathBuf>,

    /// Output format for status / drift / runs commands.
    #[arg(long, short = 'f', global = true, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Verbosity. Repeat for more.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human => f.write_str("human"),
            Self::Json => f.write_str("json"),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the agent daemon. Blocks until SIGTERM/SIGINT.
    Run,
    /// Print the current agent status (reads the status file).
    Status,
    /// Run a single observe cycle and exit.
    Observe,
    /// Compute a plan against the configured manifests and print it.
    Plan,
    /// Apply the configured manifests once.
    Apply {
        #[arg(long)]
        yes: bool,
    },
    /// Roll back a previously-applied operation.
    Rollback { operation_id: String },
    /// List or resolve open drift events.
    Drift {
        #[command(subcommand)]
        action: DriftAction,
    },
    /// Show recent agent runs.
    Runs {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Print version and exit.
    Version,
}

#[derive(Subcommand, Debug)]
enum DriftAction {
    /// List open (unresolved) drift events.
    List,
    /// Mark an open drift event resolved with an explanation.
    Resolve {
        id: i64,
        #[arg(long, default_value = "manual")]
        reason: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
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

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = match verbosity {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        1 => EnvFilter::new("info,iac_agent=debug"),
        _ => EnvFilter::new("debug"),
    };
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run(cli: Cli) -> Result<ExitCode> {
    // `Version` is the one command that doesn't need a fully-loaded
    // agent. Phase 7cz.11: previously a match-arm `unreachable!()`
    // guarded the post-load path; explicit early return is clearer
    // and removes a panic site that was nominally unreachable but
    // would crash the binary if the matches!() guard above ever
    // drifted.
    if let Command::Version = cli.command {
        println!("{APP} {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }

    let overrides = ConfigOverrides {
        state_dir: cli.state_dir.clone(),
        manifests_dir: cli.manifests_dir.clone(),
        observe_interval_secs: cli.interval,
        environment: cli.environment.clone(),
        actor: cli.actor.clone(),
        server_url: cli.server_url.clone(),
        agent_name: cli.agent_name.clone(),
        capabilities_file: cli.capabilities_file.clone(),
    };
    let config = Config::load(cli.config.as_deref(), overrides)?;
    config.ensure_dirs()?;

    let agent = Agent::new(config.clone()).context("building agent")?;

    match cli.command {
        // Already handled above — kept here for an exhaustive match
        // so future Command additions are caught at compile time.
        Command::Version => Ok(ExitCode::SUCCESS),
        Command::Run => cmd_run(agent).await,
        Command::Status => cmd_status(&config, cli.format),
        Command::Observe => cmd_observe(agent, cli.format).await,
        Command::Plan => cmd_plan(agent, cli.format).await,
        Command::Apply { yes } => cmd_apply(agent, cli.format, yes).await,
        Command::Rollback { operation_id } => cmd_rollback(agent, &operation_id).await,
        Command::Drift { action } => cmd_drift(agent, action, cli.format).await,
        Command::Runs { limit } => cmd_runs(agent, limit, cli.format).await,
    }
}

async fn cmd_run(agent: Agent) -> Result<ExitCode> {
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

    agent.run(shutdown).await?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_status(config: &Config, format: OutputFormat) -> Result<ExitCode> {
    let status = match iac_agent::status::read_status(&config.status_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: status file unavailable ({}): {e}",
                config.status_file.display()
            );
            return Ok(ExitCode::from(1));
        }
    };
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Human => print_status_human(&status),
    }
    Ok(if status.healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

fn print_status_human(s: &iac_agent::AgentStatus) {
    println!("started_at:   {}", s.started_at);
    println!("manifests:    {}", s.manifests_dir);
    println!("state_dir:    {}", s.state_dir);
    println!("healthy:      {}", s.healthy);
    println!("managed:      {}", s.managed_resource_count);
    println!("open drifts:  {}", s.open_drift_count);
    if let Some(at) = s.last_observe_at {
        println!("last observe: {at}");
    } else {
        println!("last observe: <none>");
    }
    if let Some(c) = &s.last_observe_summary {
        println!(
            "last cycle:   {} resource(s), {} drift(s), {} ms",
            c.observed, c.drift_detected, c.duration_ms
        );
        for e in &c.errors {
            println!("  ! {e}");
        }
    }
}

async fn cmd_observe(agent: Agent, format: OutputFormat) -> Result<ExitCode> {
    let summary = agent.observe_once().await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&summary)?),
        OutputFormat::Human => {
            println!(
                "observed {} resource(s), {} drift(s), {} ms",
                summary.observed, summary.drift_detected, summary.duration_ms
            );
            for e in &summary.errors {
                eprintln!("  ! {e}");
            }
        }
    }
    Ok(if summary.errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

async fn cmd_plan(agent: Agent, format: OutputFormat) -> Result<ExitCode> {
    let plan = agent.plan_once().await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&plan)?),
        OutputFormat::Human => {
            println!(
                "Plan: {} change(s), {} unchanged",
                plan.change_count(),
                plan.items.len() - plan.change_count()
            );
            for item in &plan.items {
                if !item.diff.is_change() {
                    continue;
                }
                println!("  ~ {} ({:?})", item.resource_id, item.diff.kind);
                for r in &item.diff.reasons {
                    println!("      # {r}");
                }
            }
        }
    }
    Ok(if plan.has_changes() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

async fn cmd_apply(agent: Agent, format: OutputFormat, yes: bool) -> Result<ExitCode> {
    if !yes {
        anyhow::bail!("`iac-agent apply` requires --yes (no interactive prompt in agent CLI)");
    }
    let result = agent.apply_once().await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Human => {
            println!("Operation: {}", result.operation.id);
            println!("Status:    {:?}", result.operation.status);
            for item in &result.items {
                println!("  {:?}: {}", item.status, item.resource_id);
                if let Some(err) = &item.error {
                    println!("    error: {err}");
                }
            }
        }
    }
    use iac_core::operation::OperationStatus;
    Ok(match result.operation.status {
        OperationStatus::Succeeded => ExitCode::SUCCESS,
        OperationStatus::PartiallyApplied => ExitCode::from(4),
        _ => ExitCode::from(5),
    })
}

async fn cmd_rollback(agent: Agent, operation_id: &str) -> Result<ExitCode> {
    let id = ulid::Ulid::from_string(operation_id)
        .map_err(|e| anyhow::anyhow!("invalid operation id: {e}"))?;
    agent.rollback(id).await?;
    println!("rolled back {id}");
    Ok(ExitCode::SUCCESS)
}

async fn cmd_drift(agent: Agent, action: DriftAction, format: OutputFormat) -> Result<ExitCode> {
    match action {
        DriftAction::List => {
            let store = agent.store();
            let drifts = tokio::task::spawn_blocking(move || store.list_open_drifts())
                .await
                .context("drift list task")??;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&drifts)?),
                OutputFormat::Human => {
                    if drifts.is_empty() {
                        println!("(no open drift)");
                    } else {
                        for d in &drifts {
                            println!(
                                "[{}] {} ({}) — {} reason(s)",
                                d.id,
                                d.resource_id,
                                d.severity,
                                d.diff.reasons.len()
                            );
                            for r in &d.diff.reasons {
                                println!("    {r}");
                            }
                        }
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::Resolve { id, reason } => {
            let store = agent.store();
            let n = tokio::task::spawn_blocking(move || store.resolve_drift(id, &reason))
                .await
                .context("drift resolve task")??;
            if n == 0 {
                eprintln!("no open drift with id {id}");
                Ok(ExitCode::from(1))
            } else {
                println!("resolved drift {id}");
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

async fn cmd_runs(agent: Agent, limit: u32, format: OutputFormat) -> Result<ExitCode> {
    let store = agent.store();
    let runs = tokio::task::spawn_blocking(move || store.recent_runs(limit))
        .await
        .context("runs task")??;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&runs)?),
        OutputFormat::Human => {
            if runs.is_empty() {
                println!("(no runs yet)");
            } else {
                for r in &runs {
                    println!(
                        "[{}] {} -> {}  observed={} drift={} {}",
                        r.id,
                        r.started_at,
                        r.finished_at.as_deref().unwrap_or("(running)"),
                        r.resources_observed,
                        r.drift_detected,
                        r.error.as_deref().unwrap_or(""),
                    );
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
