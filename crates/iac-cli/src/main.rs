// Phase 7cz.16: tests-only exemption for unwrap/expect/panic.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use iac_core::{
    Resource,
    executor::{ApplyResult, Executor, PlanResult},
    manifest,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod credentials;
mod gitops;
mod inventory;
mod render;
mod run_history;
mod ssh_dispatch;
mod validate_spec;

const APP: &str = "iac";

#[derive(Parser, Debug)]
#[command(name = APP, version, about = "Declarative infrastructure manager (Phase 0 MVP)")]
struct Cli {
    /// Override the default state directory ($IAC_STATE_DIR or ~/.iac/state).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,

    /// Output format.
    #[arg(long, short = 'f', global = true, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Actor name recorded in operation audit logs (defaults to $USER).
    #[arg(long, global = true)]
    actor: Option<String>,

    /// Verbosity. Can be repeated: -v, -vv.
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
    /// Parse manifests and validate basic shape.
    Validate {
        /// Path to a manifest file or a directory of manifests.
        path: PathBuf,
    },
    /// Show what would change without modifying the host.
    ///
    /// Two distinct modes:
    ///
    ///   1. LOCAL: `iac plan PATH` — read the manifest, diff against the
    ///      local host's state, print the changes. No server. This is the
    ///      common case for "what would `iac apply` do?".
    ///
    ///   2. REMOTE PREVIEW: `iac plan --server <url> --operation <op-id>`
    ///      — fetch a previously-submitted operation's stored
    ///      desired-state from the control plane and render it. Used by
    ///      approvers reviewing a `pending_approval` operation. NOTE:
    ///      this does NOT submit anything. To submit a manifest to a
    ///      server, use `iac apply --server <url>`.
    Plan {
        /// Local manifest path (LOCAL mode). Required unless
        /// `--operation` (REMOTE PREVIEW mode) or `--git-repo` is set.
        path: Option<PathBuf>,
        /// Control-plane URL. ONLY meaningful with `--operation`. To
        /// submit a manifest TO a server, use `iac apply --server`,
        /// not this command.
        #[arg(long)]
        server: Option<String>,
        /// Operation id to preview from the server (REMOTE PREVIEW
        /// mode). Requires `--server`.
        #[arg(long)]
        operation: Option<String>,
        /// Phase 7bd: render the dependency graph instead of the flat
        /// resource list. `ascii` prints an indented tree; `dot` emits
        /// graphviz syntax suitable for `dot -Tpng | display`. Only
        /// valid in remote mode (`--server --operation`) since the
        /// dependency edges live in the desired-state response.
        #[arg(long, value_parser = ["ascii", "dot"])]
        graph: Option<String>,
        /// Phase 7ch: GitOps. Clone `<repo>@<ref>` and plan from
        /// there. Designed for CI: returns a non-zero exit code on
        /// any policy / validation failure so a pipeline step can
        /// gate on it.
        #[arg(long, conflicts_with_all = ["path", "operation"])]
        git_repo: Option<String>,
        /// Git ref (branch/tag/sha) to check out. Defaults to `HEAD`.
        #[arg(long, default_value = "HEAD")]
        git_ref: String,
        /// Sub-directory inside the repo to plan from.
        #[arg(long)]
        git_path: Option<String>,
    },
    /// Apply manifests to the local host (or submit to a server with --server).
    Apply {
        /// Local manifest path. Required unless `--git-repo` is set.
        path: Option<PathBuf>,
        /// Skip the interactive confirmation. Required for non-tty runs.
        #[arg(long)]
        yes: bool,
        /// Submit to a control-plane URL instead of applying locally.
        #[arg(long)]
        server: Option<String>,
        /// Environment name passed to the server (defaults to `default`).
        #[arg(long, default_value = "default")]
        environment: String,
        /// Optional source-commit recorded in the operation audit trail.
        /// When `--git-repo` is set, `source_commit` is auto-resolved
        /// from the git ref and this flag is rejected.
        #[arg(long)]
        source_commit: Option<String>,
        /// Wait for the operation to reach a terminal status.
        #[arg(long)]
        wait: bool,
        /// Polling interval for `--wait`, in seconds.
        #[arg(long, default_value_t = 2)]
        wait_interval: u64,
        /// Phase 7ch: GitOps. Clone `<repo>@<ref>` and load manifests
        /// from there instead of a local path. The resolved SHA is
        /// recorded as `source_commit` automatically.
        #[arg(long, conflicts_with = "path")]
        git_repo: Option<String>,
        /// Git ref (branch/tag/sha) to check out. Defaults to `HEAD`.
        #[arg(long, default_value = "HEAD")]
        git_ref: String,
        /// Sub-directory inside the repo to load manifests from.
        #[arg(long)]
        git_path: Option<String>,
        /// Optional canary rollout percentage (1..=99). When set,
        /// the server splits each layer's agents into a canary batch
        /// (this percentage) and a baseline batch — baseline waits
        /// on canary success. Particularly useful for CI-driven
        /// applies where you want gradual rollout without operator
        /// hand-holding.
        #[arg(long)]
        canary_pct: Option<u8>,
        /// Phase 7ck: read an `AssignmentPayload` JSON from stdin and
        /// apply it locally. Exits 0 with `AssignmentResultRequest`
        /// JSON on stdout. This is the remote-applier mode used by
        /// the SSH push worker — operators don't run it directly.
        /// Mutually exclusive with `--server`, `--git-repo`, and a
        /// positional path: assignment payload is the only input.
        #[arg(long, conflicts_with_all = ["server", "git_repo", "path"])]
        assignment_stdin: bool,
        /// Phase 7cl: agent-less Ansible-style direct apply. Run the
        /// manifest on `user@host` over SSH without any server or
        /// pre-installed agent. Internally: pipe payload via SSH stdin
        /// to a remote `iac apply --assignment-stdin` invocation,
        /// parse the result.
        ///
        /// Form: `--ssh user@host[:port]` or `--ssh host`. Pair with
        /// `--ssh-key`, `--ssh-port`, `--ssh-remote-iac` to override
        /// the SSH transport details. Pass `--auto-bootstrap` to scp
        /// the local `iac` binary to the target if it's not already
        /// installed (only works when target arch matches).
        ///
        /// For multi-host fan-out use `--inventory` + `--group`
        /// instead.
        #[arg(long, conflicts_with_all = ["server", "assignment_stdin", "inventory"])]
        ssh: Option<String>,
        /// Identity file for `--ssh`/`--inventory`. Defaults to
        /// ssh-agent / system keys via `~/.ssh/config`.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// SSH port. Defaults to 22.
        #[arg(long)]
        ssh_port: Option<u16>,
        /// Path to the `iac` binary on the target. Defaults to
        /// looking it up via `command -v iac` over SSH.
        #[arg(long)]
        ssh_remote_iac: Option<String>,
        /// Phase 7cl-followup: auto-stage the local `iac` binary on
        /// the target via scp when it's not pre-installed and the
        /// target arch matches local. When arches differ, the tool
        /// errors with a curl-install hint.
        #[arg(long)]
        auto_bootstrap: bool,
        /// Phase 7cm: inventory file describing groups of hosts.
        /// Pair with `--group` to apply to every host in the group
        /// in parallel.
        #[arg(long, conflicts_with_all = ["server", "ssh", "assignment_stdin"])]
        inventory: Option<PathBuf>,
        /// Phase 7cm: group name from the `--inventory` file.
        #[arg(long, requires = "inventory")]
        group: Option<String>,
        /// Phase 7cm: keep only the host matching `<host-or-label>`
        /// from the resolved group. For "apply to one machine" tests.
        #[arg(long, requires = "group")]
        limit: Option<String>,
        /// Phase 7cm: maximum number of hosts to apply to in
        /// parallel. Default 5 — kind to small SSH servers; dial up
        /// for big fleets.
        #[arg(long, default_value_t = 5, requires = "inventory")]
        max_parallel: usize,
        /// Phase 7cm: stop the fan-out on first failure. Default is
        /// `--continue-on-error`: keep going through every host,
        /// summarize at the end.
        #[arg(long, requires = "inventory")]
        fail_fast: bool,
    },
    /// Observe current state of the resources in the manifest.
    Observe { path: PathBuf },
    /// Roll back a previously applied operation by id.
    ///
    /// Without `--server` (legacy local mode): re-runs the prior local
    /// state-backed reconciliation. Limited to what this host applied
    /// itself.
    ///
    /// With `--server`: Phase 7ci server-side rollback. The control
    /// plane builds a new operation that re-applies the prior
    /// desired-state for every resource the target operation
    /// touched, dispatched through the normal pipeline (policy +
    /// approval + canary). Resources that were first-applied in the
    /// target op (no prior state) are listed in the response as
    /// `orphaned` — operator deletes those manually.
    Rollback {
        operation_id: String,
        /// Submit to a control-plane URL instead of running a local
        /// rollback against this host's state directory.
        #[arg(long)]
        server: Option<String>,
        /// Free-form reason recorded in the audit log.
        #[arg(long)]
        reason: Option<String>,
        /// Optional canary percentage on the rollback operation
        /// itself. Recommended for production rollbacks — even
        /// rolling backward deserves blast-radius containment.
        #[arg(long)]
        canary_pct: Option<u8>,
    },
    /// List operations recorded in the state directory.
    Operations,
    /// Phase 9 follow-up admin wrapper: list agents registered with
    /// the control-plane. Thin wrapper over `GET /v1/agents`.
    Agents {
        /// Control-plane URL.
        #[arg(long)]
        server: String,
        #[command(subcommand)]
        action: AgentsAction,
    },
    /// Phase 9 follow-up admin wrapper: list operations on the
    /// control-plane with optional status filter.
    Ops {
        /// Control-plane URL.
        #[arg(long)]
        server: String,
        #[command(subcommand)]
        action: OpsAction,
    },
    /// Drift workflows against a control-plane.
    Drift {
        /// Control-plane URL. Required for all drift subcommands.
        #[arg(long)]
        server: String,
        #[command(subcommand)]
        action: DriftAction,
    },
    /// Approve a pending-approval operation on the control-plane.
    Approve {
        /// Control-plane URL.
        #[arg(long)]
        server: String,
        operation_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Reject a pending-approval operation. Terminal.
    Reject {
        #[arg(long)]
        server: String,
        operation_id: String,
        #[arg(long)]
        reason: String,
    },
    /// Read the control-plane's audit log.
    Audit {
        /// Control-plane URL.
        #[arg(long)]
        server: String,
        /// Limit returned rows.
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Filter by event kind (e.g. `operation.submitted`, `drift.accepted`).
        #[arg(long)]
        kind: Option<String>,
        /// Filter by actor (e.g. `admin`, `agent:01H...`).
        #[arg(long)]
        actor: Option<String>,
        /// Filter to a single operation id.
        #[arg(long)]
        operation_id: Option<String>,
        /// Filter to a single agent id.
        #[arg(long)]
        agent_id: Option<String>,
        /// Phase 9 follow-up: poll the audit log forever and stream
        /// new events as they land. Implements `tail -f` semantics
        /// for the audit chain by repeatedly fetching with `since_id`
        /// equal to the highest id seen so far.
        #[arg(long)]
        follow: bool,
        /// When `--follow` is set, how often to poll for new events
        /// (in seconds). Defaults to 2.
        #[arg(long, default_value_t = 2)]
        follow_interval_secs: u64,
    },
    /// Print version and exit.
    Version,
    /// Phase 7cn: run an ad-hoc shell command on one host or a
    /// group of hosts. Imperative complement to `iac apply` —
    /// useful for one-off operational tasks like `systemctl
    /// restart nginx` or `apt update`. Captures per-host stdout,
    /// stderr, and exit code.
    ///
    /// Usage:
    ///   iac run --ssh user@host -- 'uptime'
    ///   iac run --inventory inv.yaml --group prod-web -- 'apt update'
    Run {
        /// `--ssh user@host[:port]` for a single host.
        #[arg(long, conflicts_with = "inventory")]
        ssh: Option<String>,
        /// Identity file. Defaults to ssh-agent.
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// SSH port. Defaults to 22.
        #[arg(long)]
        ssh_port: Option<u16>,
        /// Inventory file (Phase 7cm format).
        #[arg(long, conflicts_with = "ssh")]
        inventory: Option<PathBuf>,
        /// Group from `--inventory`.
        #[arg(long, requires = "inventory")]
        group: Option<String>,
        /// Filter to one host within the group.
        #[arg(long, requires = "group")]
        limit: Option<String>,
        /// Max hosts to run in parallel.
        #[arg(long, default_value_t = 5)]
        max_parallel: usize,
        /// Stop on first failure (default: keep going).
        #[arg(long)]
        fail_fast: bool,
        /// The shell command to run. Pass after `--`:
        ///   iac run --ssh root@host -- 'uname -a && uptime'
        #[arg(last = true, num_args = 1.., required = true)]
        command: Vec<String>,
    },
    /// Phase 7da.3: show recent `iac run` invocations from the local
    /// audit log (`<state_dir>/run-history.jsonl`). The CLI-direct
    /// path of `iac run` (no `--server`) appends one entry per
    /// invocation; this command reads them back.
    History {
        /// How many of the most-recent records to show. Default 20.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Authenticate against a control-plane and save the bearer token to
    /// `~/.iac/credentials.json` (mode 0600). Subsequent commands that take
    /// `--server` will pick up the saved token automatically.
    Login {
        #[arg(long)]
        server: String,
        #[arg(long, short)]
        user: String,
        /// Non-interactive password (otherwise read from stdin without echo).
        /// Also honored via `IAC_LOGIN_PASSWORD`.
        #[arg(long)]
        password: Option<String>,
    },
    /// Revoke the saved token for a control-plane and remove the local entry.
    Logout {
        #[arg(long)]
        server: String,
    },
    /// Inspect or clear locally saved credentials. Tokens are NEVER printed.
    Creds {
        #[command(subcommand)]
        action: CredsAction,
    },
    /// Manage human users on a control-plane (admin-only on the server).
    Users {
        #[arg(long)]
        server: String,
        #[command(subcommand)]
        action: UsersAction,
    },
    /// Inspect the composite-resource expanders the server supports.
    Expanders {
        #[arg(long)]
        server: String,
        #[command(subcommand)]
        action: ExpandersAction,
    },
}

#[derive(Subcommand, Debug)]
enum ExpandersAction {
    /// List every expander with its emit list.
    List,
    /// Show one expander in detail (including spec fields).
    Show { kind: String },
}

#[derive(Subcommand, Debug)]
enum UsersAction {
    /// Create a new user. Password read from stdin if not provided.
    Create {
        #[arg(short, long)]
        user: String,
        /// Comma-separated role list, e.g. `viewer,operator`.
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        #[arg(long)]
        password: Option<String>,
    },
    /// List all users (no passwords).
    List,
    /// Replace a user's role list.
    SetRoles {
        user_id: String,
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
    },
    /// Disable a user (soft delete + revoke active tokens).
    Disable { user_id: String },
    /// Re-enable a previously disabled user.
    Enable { user_id: String },
    /// Reset a user's password.
    SetPassword {
        user_id: String,
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CredsAction {
    /// List saved (server, username, roles, expires_at) entries.
    List,
    /// Drop the saved entry for `server` without contacting the server.
    /// Use `iac logout` if you want to also revoke server-side.
    Clear {
        #[arg(long)]
        server: String,
    },
}

/// Phase 9 follow-up admin wrapper: read-side helpers over
/// `GET /v1/agents`. Added per operator request — the original
/// design routed everyone through `curl + jq`, but a
/// production-grade CLI saves a real chunk of toil.
#[derive(Subcommand, Debug)]
enum AgentsAction {
    /// Tabular dump of registered agents: name, env, status,
    /// last_heartbeat_at, managed-count, open-drift count.
    List,
}

/// Phase 9 follow-up admin wrapper: read-side helpers over
/// `GET /v1/operations`. See `AgentsAction`.
#[derive(Subcommand, Debug)]
enum OpsAction {
    /// Tabular dump of operations on the control-plane.
    List {
        /// Filter by status (`pending`, `running`, `succeeded`,
        /// `failed`, `partially_applied`, `pending_approval`,
        /// `rejected`). Omit for all.
        #[arg(long)]
        status: Option<String>,
        /// Max rows to return. Defaults to 50; server-clamped to 1000.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
}

#[derive(Subcommand, Debug)]
enum DriftAction {
    /// List open drift events on the server.
    List {
        /// Filter to a single agent id.
        #[arg(long)]
        agent_id: Option<String>,
    },
    /// Show one drift event with full diff.
    Show { id: i64 },
    /// Mark a drift event accepted (resolved without reverting state).
    Accept {
        id: i64,
        #[arg(long)]
        reason: String,
    },
    /// Silence a drift event for a duration (e.g. `7d`, `2h`, `30m`).
    /// Re-surfaces in `list` after the TTL expires.
    Ignore {
        id: i64,
        #[arg(long)]
        ttl: String,
    },
    /// Phase 7be: re-apply the resource's last known desired state to
    /// revert the drift. Server creates a fresh single-resource apply
    /// operation; the new operation id is printed. Drift is NOT
    /// auto-resolved — the operator should `accept` once the apply
    /// converges or wait for the agent's next observe to close it.
    Revert {
        id: i64,
        /// Optional source-commit recorded on the new operation.
        #[arg(long)]
        source_commit: Option<String>,
    },
    /// Phase 7bf: bulk-accept every open drift event matching the
    /// filter. At least one of `--agent-id` / `--kind` / `--severity`
    /// is required so a typo'd command can't wipe the entire drift
    /// history. `--reason` is required and stored on each accepted row.
    AcceptBulk {
        #[arg(long)]
        agent_id: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        reason: String,
    },
    /// Phase 7bf: bulk-ignore (silence with TTL) every matching open
    /// drift event. Same filter requirement as `accept-bulk`.
    IgnoreBulk {
        #[arg(long)]
        agent_id: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        ttl: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn init_tracing(verbosity: u8) {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = match verbosity {
        0 => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        1 => EnvFilter::new("info"),
        _ => EnvFilter::new("debug"),
    };
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn run(cli: Cli) -> Result<ExitCode> {
    let state_dir = resolve_state_dir(cli.state_dir.as_deref())?;
    let actor = cli
        .actor
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "unknown".into()));

    match cli.command {
        Command::Version => {
            println!("{APP} {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            ssh,
            ssh_key,
            ssh_port,
            inventory,
            group,
            limit,
            max_parallel,
            fail_fast,
            command,
        } => cmd_run(
            ssh,
            ssh_key,
            ssh_port,
            inventory,
            group,
            limit,
            max_parallel,
            fail_fast,
            command,
            &state_dir,
            &actor,
        ),
        Command::History { limit } => cmd_history(&state_dir, limit, cli.format),
        Command::Login {
            server,
            user,
            password,
        } => cmd_login(&server, &user, password.as_deref()),
        Command::Logout { server } => cmd_logout(&server),
        Command::Creds { action } => cmd_creds(action, cli.format),
        Command::Users { server, action } => cmd_users(&server, action, cli.format),
        Command::Expanders { server, action } => cmd_expanders(&server, action, cli.format),
        Command::Validate { path } => cmd_validate(&path, cli.format),
        Command::Plan {
            path,
            server,
            operation,
            graph,
            git_repo,
            git_ref,
            git_path,
        } => {
            // Phase 7ch: GitOps overlay. When `--git-repo` is set, fetch
            // the revision into the cache and treat the resulting path as
            // the manifest source. Mutually exclusive with `--operation`
            // (clap already enforces) but composable with `--server` —
            // the typical CI flow is `plan --git-repo … --git-ref … --server …`.
            if let Some(repo) = git_repo {
                let checkout = gitops::fetch_revision(
                    &repo,
                    &git_ref,
                    git_path.as_deref(),
                    &gitops::default_cache_dir(),
                )?;
                eprintln!("git: {repo}@{} ({})", git_ref, checkout.sha);
                if let Some(url) = server {
                    return cmd_plan_remote_from_path(
                        &checkout.root,
                        &url,
                        &actor,
                        cli.format,
                        Some(&checkout.sha),
                    );
                }
                return cmd_plan(&checkout.root, &state_dir, &actor, cli.format);
            }
            match (server, operation, path) {
                (Some(url), Some(op_id), _) => {
                    cmd_plan_remote(&url, &op_id, cli.format, graph.as_deref())
                }
                (Some(_), None, Some(_)) => Err(anyhow!(
                    "`iac plan` doesn't submit manifests to a server — \
                     pass `--server <url> --operation <op-id>` to preview a server-side operation, \
                     or drop `--server` to plan locally. To SUBMIT this manifest to a server, \
                     use `iac apply --server <url>`."
                )),
                (Some(_), None, None) => Err(anyhow!(
                    "`--server` requires `--operation <op-id>` (REMOTE PREVIEW mode). \
                     `iac plan` doesn't submit manifests; use `iac apply --server <url>` for that."
                )),
                (None, Some(_), _) => Err(anyhow!(
                    "`--operation` requires `--server <url>` (REMOTE PREVIEW mode)."
                )),
                (None, None, Some(path)) => {
                    if graph.is_some() {
                        return Err(anyhow!(
                            "`--graph` requires `--server <url> --operation <id>` \
                             (local plans don't carry dependency metadata yet)"
                        ));
                    }
                    cmd_plan(&path, &state_dir, &actor, cli.format)
                }
                (None, None, None) => Err(anyhow!(
                    "`iac plan` needs either a manifest path, \
                     `--server <url> --operation <id>`, or `--git-repo <url>`"
                )),
            }
        }
        Command::Apply {
            path,
            yes,
            server,
            environment,
            source_commit,
            wait,
            wait_interval,
            git_repo,
            git_ref,
            git_path,
            canary_pct,
            assignment_stdin,
            ssh,
            ssh_key,
            ssh_port,
            ssh_remote_iac,
            auto_bootstrap,
            inventory,
            group,
            limit,
            max_parallel,
            fail_fast,
        } => {
            // Phase 7ck: assignment-stdin mode (remote applier). Read
            // payload JSON from stdin, apply locally via Executor,
            // print AssignmentResultRequest JSON to stdout. Used by
            // the SSH push worker; operators don't run it manually.
            if assignment_stdin {
                return cmd_apply_assignment_stdin(&state_dir, &actor);
            }
            // Phase 7ch: resolve manifest source. When `--git-repo` is
            // set we clone + checkout, derive `source_commit` from the
            // resolved SHA, and feed the working tree path into the
            // existing flow. `--source-commit` is rejected in this case
            // — operator can't override what the git ref actually
            // points at.
            let (resolved_path, resolved_source_commit) = if let Some(repo) = git_repo {
                if source_commit.is_some() {
                    return Err(anyhow!(
                        "`--source-commit` is auto-resolved from --git-ref; remove the flag"
                    ));
                }
                let checkout = gitops::fetch_revision(
                    &repo,
                    &git_ref,
                    git_path.as_deref(),
                    &gitops::default_cache_dir(),
                )?;
                eprintln!("git: {repo}@{} ({})", git_ref, checkout.sha);
                (checkout.root, Some(checkout.sha))
            } else {
                let p = path.ok_or_else(|| {
                    anyhow!(
                        "`iac apply` needs either a manifest path, `--git-repo <url>`, \
                         or `--inventory <path> --group <name>`"
                    )
                })?;
                (p, source_commit)
            };
            // Phase 7cm: inventory + group fan-out. Resolves to N
            // SshTargets, dispatches in parallel up to `max_parallel`,
            // aggregates results. Mutually exclusive with --ssh
            // (single-target) and --server (control-plane mode).
            if let Some(inv_path) = inventory {
                let group = group.ok_or_else(|| anyhow!("`--inventory` requires `--group`"))?;
                if canary_pct.is_some() {
                    return Err(anyhow!(
                        "`--canary-pct` is server-side; --inventory does in-process fan-out \
                         and doesn't carry batched canary semantics"
                    ));
                }
                let inv = inventory::InventoryFile::load(&inv_path)?;
                let targets = inv
                    .resolve(&group, limit.as_deref())?
                    .into_iter()
                    .map(|t| {
                        t.with_overrides(ssh_key.as_deref(), ssh_port, ssh_remote_iac.as_deref())
                    })
                    .collect::<Vec<_>>();
                return cmd_apply_fanout(
                    &resolved_path,
                    targets,
                    max_parallel,
                    fail_fast,
                    auto_bootstrap,
                );
            }
            // Phase 7cl: direct SSH push without a control plane —
            // ansible-style one-command-per-target deploy.
            if let Some(target) = ssh {
                if canary_pct.is_some() {
                    return Err(anyhow!(
                        "`--canary-pct` is server-side; --ssh is a single-target push and \
                         doesn't carry batched canary semantics"
                    ));
                }
                return cmd_apply_direct_ssh(
                    &resolved_path,
                    &target,
                    ssh_key.as_deref(),
                    ssh_port,
                    ssh_remote_iac.as_deref(),
                    auto_bootstrap,
                );
            }
            if let Some(url) = server {
                cmd_apply_remote(
                    &resolved_path,
                    &actor,
                    cli.format,
                    yes,
                    &url,
                    &environment,
                    resolved_source_commit.as_deref(),
                    wait,
                    wait_interval,
                    canary_pct,
                )
            } else {
                if canary_pct.is_some() {
                    return Err(anyhow!(
                        "`--canary-pct` requires `--server`; canary is a server-side feature"
                    ));
                }
                cmd_apply(&resolved_path, &state_dir, &actor, cli.format, yes)
            }
        }
        Command::Observe { path } => cmd_observe(&path, &state_dir, &actor, cli.format),
        Command::Rollback {
            operation_id,
            server,
            reason,
            canary_pct,
        } => match server {
            Some(url) => cmd_rollback_remote(
                &url,
                &operation_id,
                &actor,
                cli.format,
                reason.as_deref(),
                canary_pct,
            ),
            None => {
                if reason.is_some() || canary_pct.is_some() {
                    return Err(anyhow!(
                        "`--reason` and `--canary-pct` require `--server <url>`"
                    ));
                }
                cmd_rollback(&operation_id, &state_dir, &actor)
            }
        },
        Command::Operations => cmd_operations(&state_dir, cli.format),
        Command::Agents { server, action } => cmd_agents(&server, action, cli.format),
        Command::Ops { server, action } => cmd_ops(&server, action, cli.format),
        Command::Drift { server, action } => cmd_drift(&server, action, cli.format),
        Command::Approve {
            server,
            operation_id,
            reason,
        } => cmd_op_approval(
            &server,
            &operation_id,
            ApprovalAction::Approve,
            reason.as_deref(),
        ),
        Command::Reject {
            server,
            operation_id,
            reason,
        } => cmd_op_approval(
            &server,
            &operation_id,
            ApprovalAction::Reject,
            Some(&reason),
        ),
        Command::Audit {
            server,
            limit,
            kind,
            actor,
            operation_id,
            agent_id,
            follow,
            follow_interval_secs,
        } => cmd_audit(
            &server,
            limit,
            kind.as_deref(),
            actor.as_deref(),
            operation_id.as_deref(),
            agent_id.as_deref(),
            cli.format,
            follow,
            follow_interval_secs,
        ),
    }
}

enum ApprovalAction {
    Approve,
    Reject,
}

fn cmd_users(server_url: &str, action: UsersAction, format: OutputFormat) -> Result<ExitCode> {
    use iac_core::protocol::v1::{
        CreateUserRequest, CreateUserResponse, UpdateUserRequest, UserView,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        match action {
            UsersAction::Create {
                user,
                roles,
                password,
            } => {
                let pw = read_password_for(&format!("password for new user {user}"), password)?;
                let resp = client
                    .post(format!("{server}/v1/users"))
                    .bearer_auth(&token)
                    .json(&CreateUserRequest {
                        username: user.clone(),
                        password: pw,
                        roles,
                    })
                    .send()
                    .await?;
                check_status(&resp)?;
                let body: CreateUserResponse = resp.json().await?;
                println!("created user {user} (id: {})", body.user_id);
                Ok(ExitCode::SUCCESS)
            }
            UsersAction::List => {
                let resp = client
                    .get(format!("{server}/v1/users"))
                    .bearer_auth(&token)
                    .send()
                    .await?;
                check_status(&resp)?;
                let users: Vec<UserView> = resp.json().await?;
                match format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&users)?),
                    OutputFormat::Human => {
                        if users.is_empty() {
                            println!("(no users)");
                        } else {
                            for u in &users {
                                let status = match &u.disabled_at {
                                    Some(at) => format!("disabled ({at})"),
                                    None => "active".into(),
                                };
                                println!(
                                    "{}\t{}\t[{}]\t{}",
                                    u.id,
                                    u.username,
                                    u.roles.join(","),
                                    status
                                );
                            }
                        }
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
            UsersAction::SetRoles { user_id, roles } => {
                update_user_request(
                    &client,
                    server,
                    &token,
                    &user_id,
                    UpdateUserRequest {
                        roles: Some(roles),
                        ..Default::default()
                    },
                    "roles updated",
                )
                .await
            }
            UsersAction::Disable { user_id } => {
                let resp = client
                    .delete(format!("{server}/v1/users/{user_id}"))
                    .bearer_auth(&token)
                    .send()
                    .await?;
                check_status(&resp)?;
                println!("disabled {user_id}");
                Ok(ExitCode::SUCCESS)
            }
            UsersAction::Enable { user_id } => {
                update_user_request(
                    &client,
                    server,
                    &token,
                    &user_id,
                    UpdateUserRequest {
                        disabled: Some(false),
                        ..Default::default()
                    },
                    "enabled",
                )
                .await
            }
            UsersAction::SetPassword { user_id, password } => {
                let pw = read_password_for(&format!("new password for {user_id}"), password)?;
                update_user_request(
                    &client,
                    server,
                    &token,
                    &user_id,
                    UpdateUserRequest {
                        password: Some(pw),
                        ..Default::default()
                    },
                    "password reset",
                )
                .await
            }
        }
    })
}

async fn update_user_request(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    user_id: &str,
    req: iac_core::protocol::v1::UpdateUserRequest,
    success_msg: &str,
) -> Result<ExitCode> {
    let resp = client
        .patch(format!("{server}/v1/users/{user_id}"))
        .bearer_auth(token)
        .json(&req)
        .send()
        .await?;
    check_status(&resp)?;
    println!("{success_msg} for {user_id}");
    Ok(ExitCode::SUCCESS)
}

fn read_password_for(prompt: &str, explicit: Option<String>) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("IAC_PASSWORD")
        && !p.is_empty()
    {
        return Ok(p);
    }
    rpassword::prompt_password(format!("{prompt}: ")).context("reading password")
}

fn cmd_login(server_url: &str, user: &str, password: Option<&str>) -> Result<ExitCode> {
    use iac_core::protocol::v1::{LoginRequest, LoginResponse};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        // Resolve password: explicit flag > env var > interactive prompt.
        let pw = if let Some(p) = password {
            p.to_string()
        } else if let Ok(p) = std::env::var("IAC_LOGIN_PASSWORD") {
            p
        } else {
            rpassword::prompt_password(format!("Password for {user}@{server_url}: "))
                .context("reading password")?
        };

        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp = client
            .post(format!("{server}/v1/auth/login"))
            .json(&LoginRequest {
                username: user.to_string(),
                password: pw,
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("login failed: {}", resp.status());
        }
        let body: LoginResponse = resp.json().await?;

        // Persist.
        let mut store = credentials::CredentialStore::load_default()?;
        store.upsert(
            server_url,
            credentials::Entry {
                username: user.to_string(),
                token: body.token,
                expires_at: body.expires_at.clone(),
                saved_at: jiff::Timestamp::now().to_string(),
                roles: body.roles.clone(),
            },
        );
        store.save_default()?;

        println!("logged in as {user} on {server_url}");
        println!("  roles:      {}", body.roles.join(", "));
        println!("  expires_at: {}", body.expires_at);
        Ok(ExitCode::SUCCESS)
    })
}

fn cmd_creds(action: CredsAction, format: OutputFormat) -> Result<ExitCode> {
    let mut store = credentials::CredentialStore::load_default()?;
    match action {
        CredsAction::List => match format {
            OutputFormat::Json => {
                // Strip token from each entry before serializing — `iac creds list`
                // is for human inspection, not for piping back to anything that
                // needs the secret.
                let safe: serde_json::Value = serde_json::json!({
                    "version": store.version,
                    "credentials": store.credentials.iter().map(|(server, e)| {
                        (server.clone(), serde_json::json!({
                            "username": e.username,
                            "roles": e.roles,
                            "expires_at": e.expires_at,
                            "saved_at": e.saved_at,
                        }))
                    }).collect::<serde_json::Map<_,_>>()
                });
                println!("{}", serde_json::to_string_pretty(&safe)?);
            }
            OutputFormat::Human => {
                if store.credentials.is_empty() {
                    println!("(no saved credentials)");
                } else {
                    for (server, entry) in &store.credentials {
                        println!("{server}");
                        println!("  user:       {}", entry.username);
                        println!("  roles:      {}", entry.roles.join(", "));
                        println!("  expires_at: {}", entry.expires_at);
                        println!("  saved_at:   {}", entry.saved_at);
                    }
                }
            }
        },
        CredsAction::Clear { server } => {
            let removed = store.remove(&server).is_some();
            store.save_default()?;
            if removed {
                println!("cleared {server}");
            } else {
                println!("no saved credentials for {server}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_logout(server_url: &str) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let mut store = credentials::CredentialStore::load_default()?;
        let entry = store.remove(server_url);
        store.save_default()?;
        // Best-effort revoke server-side. If the token's already expired or
        // the server is down we just delete locally and move on.
        if let Some(entry) = entry {
            let server = server_url.trim_end_matches('/');
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let _ = client
                .post(format!("{server}/v1/auth/logout"))
                .bearer_auth(&entry.token)
                .send()
                .await;
            println!("logged out {} from {server_url}", entry.username);
        } else {
            println!("no saved credentials for {server_url}");
        }
        Ok(ExitCode::SUCCESS)
    })
}

fn cmd_op_approval(
    server_url: &str,
    operation_id: &str,
    action: ApprovalAction,
    reason: Option<&str>,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        use iac_core::protocol::v1::{OperationApproveRequest, OperationRejectRequest};
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let resp = match action {
            ApprovalAction::Approve => {
                client
                    .post(format!("{server}/v1/operations/{operation_id}/approve"))
                    .bearer_auth(&token)
                    .json(&OperationApproveRequest {
                        reason: reason.map(str::to_string),
                    })
                    .send()
                    .await?
            }
            ApprovalAction::Reject => {
                let reason = reason
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| anyhow::anyhow!("--reason is required for reject"))?;
                client
                    .post(format!("{server}/v1/operations/{operation_id}/reject"))
                    .bearer_auth(&token)
                    .json(&OperationRejectRequest {
                        reason: reason.to_string(),
                    })
                    .send()
                    .await?
            }
        };
        check_status(&resp)?;
        match action {
            ApprovalAction::Approve => println!("approved {operation_id}"),
            ApprovalAction::Reject => println!("rejected {operation_id}"),
        }
        Ok(ExitCode::SUCCESS)
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_audit(
    server_url: &str,
    limit: i64,
    kind: Option<&str>,
    actor: Option<&str>,
    operation_id: Option<&str>,
    agent_id: Option<&str>,
    format: OutputFormat,
    follow: bool,
    follow_interval_secs: u64,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::AuditEvent;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let build_url = |since_id: Option<i64>, n: i64| -> String {
            let mut url = format!("{server}/v1/audit?limit={n}");
            if let Some(k) = kind {
                url.push_str(&format!("&kind={}", urlencode(k)));
            }
            if let Some(a) = actor {
                url.push_str(&format!("&actor={}", urlencode(a)));
            }
            if let Some(op) = operation_id {
                url.push_str(&format!("&operation_id={}", urlencode(op)));
            }
            if let Some(ag) = agent_id {
                url.push_str(&format!("&agent_id={}", urlencode(ag)));
            }
            if let Some(s) = since_id {
                url.push_str(&format!("&since_id={s}"));
            }
            url
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        // Phase 9 follow-up: `--follow` mode is a poll loop. We
        // start with one normal page (newest `limit` events,
        // printed in chronological order), record the max id seen,
        // then poll forever with `since_id` cursor until ^C.
        if follow {
            // Initial page in oldest-first order so the operator
            // sees recent history before live events start
            // streaming.
            let resp = client
                .get(build_url(None, limit))
                .bearer_auth(&token)
                .send()
                .await?;
            check_status(&resp)?;
            let mut events: Vec<AuditEvent> = resp.json().await?;
            events.sort_by_key(|e| e.id);
            let mut max_id = events.last().map(|e| e.id).unwrap_or(0);
            print_audit_events(&events, format)?;

            // JSON-mode follow keeps emitting JSON-array per poll;
            // human-mode just streams lines.
            let interval = std::time::Duration::from_secs(follow_interval_secs.max(1));
            loop {
                tokio::time::sleep(interval).await;
                let resp = match client
                    .get(build_url(Some(max_id), 1000))
                    .bearer_auth(&token)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("(transient HTTP error: {e}; retrying next interval)");
                        continue;
                    }
                };
                if let Err(e) = check_status(&resp) {
                    eprintln!("(server status error: {e}; retrying next interval)");
                    continue;
                }
                let mut batch: Vec<AuditEvent> = resp.json().await?;
                if batch.is_empty() {
                    continue;
                }
                batch.sort_by_key(|e| e.id);
                if let Some(last) = batch.last() {
                    max_id = last.id;
                }
                print_audit_events(&batch, format)?;
            }
        }

        let resp = client
            .get(build_url(None, limit))
            .bearer_auth(&token)
            .send()
            .await?;
        check_status(&resp)?;
        let mut events: Vec<AuditEvent> = resp.json().await?;
        // Server returns newest-first; print oldest-first for consistency
        // with the follow path.
        events.sort_by_key(|e| e.id);
        print_audit_events(&events, format)?;
        Ok(ExitCode::SUCCESS)
    })
}

/// Phase 9 follow-up: shared audit print path for both one-shot
/// `iac audit` and `--follow` polling. Human form is one line per
/// event with op/agent/drift tags appended.
fn print_audit_events(
    events: &[iac_core::protocol::v1::AuditEvent],
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            if !events.is_empty() {
                println!("{}", serde_json::to_string_pretty(events)?);
            }
        }
        OutputFormat::Human => {
            if events.is_empty() {
                // Silent in follow mode would be confusing on the
                // first poll; emit the "(no events)" marker only
                // when called from one-shot path. The follow loop
                // skips calling this on empty batches, so we'll
                // only land here for genuinely-empty initial reads.
                // Detection: caller always passes non-empty in
                // follow mode. Keep the marker for one-shot UX.
                println!("(no events)");
            } else {
                for e in events {
                    let mut tags: Vec<String> = vec![];
                    if let Some(op) = &e.operation_id {
                        tags.push(format!("op={op}"));
                    }
                    if let Some(ag) = &e.agent_id {
                        tags.push(format!("agent={ag}"));
                    }
                    if let Some(d) = e.drift_id {
                        tags.push(format!("drift={d}"));
                    }
                    let suffix = if tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", tags.join(" "))
                    };
                    println!(
                        "{} {} {} {}{}",
                        e.timestamp, e.severity, e.actor, e.kind, suffix
                    );
                }
            }
        }
    }
    Ok(())
}

/// Phase 9 follow-up admin wrapper: `iac agents list --server URL`.
/// GET /v1/agents → table. Replaces the previous `curl ... | jq`
/// pattern documented in the runbook.
fn cmd_agents(server_url: &str, action: AgentsAction, format: OutputFormat) -> Result<ExitCode> {
    use iac_core::protocol::v1::AgentSummary;
    let AgentsAction::List = action;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp = client
            .get(format!("{server}/v1/agents"))
            .bearer_auth(&token)
            .send()
            .await?;
        check_status(&resp)?;
        let agents: Vec<AgentSummary> = resp.json().await?;
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&agents)?),
            OutputFormat::Human => {
                if agents.is_empty() {
                    println!("(no agents)");
                } else {
                    println!(
                        "{:<25} {:<15} {:<10} {:<28} {:>8} {:>8}",
                        "name", "environment", "status", "last_heartbeat_at", "managed", "drifts"
                    );
                    for a in &agents {
                        let hb = a.last_heartbeat_at.as_deref().unwrap_or("-");
                        // AgentHealth is a serde enum without Display;
                        // route through serde to get the snake_case
                        // string form ("healthy", "stale", "missing").
                        let status_label = serde_json::to_value(a.status)
                            .ok()
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_else(|| format!("{:?}", a.status));
                        println!(
                            "{:<25} {:<15} {:<10} {:<28} {:>8} {:>8}",
                            a.name, a.environment, status_label, hb, a.managed, a.open_drifts
                        );
                    }
                }
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// Phase 9 follow-up admin wrapper: `iac ops list --server URL
/// [--status STATUS] [--limit N]`. GET /v1/operations → table.
fn cmd_ops(server_url: &str, action: OpsAction, format: OutputFormat) -> Result<ExitCode> {
    use iac_core::protocol::v1::OperationListItem;
    let OpsAction::List { status, limit } = action;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let mut url = format!("{server}/v1/operations?limit={limit}");
        if let Some(s) = &status {
            url.push_str(&format!("&status={}", urlencode(s)));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp = client.get(&url).bearer_auth(&token).send().await?;
        check_status(&resp)?;
        let ops: Vec<OperationListItem> = resp.json().await?;
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&ops)?),
            OutputFormat::Human => {
                if ops.is_empty() {
                    println!("(no operations)");
                } else {
                    println!(
                        "{:<28} {:<10} {:<15} {:<20} {:<28} {:<28}",
                        "id", "kind", "environment", "requested_by", "created_at", "finished_at"
                    );
                    for o in &ops {
                        let status_label: String = serde_json::to_value(o.status)
                            .ok()
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_else(|| format!("{:?}", o.status));
                        println!(
                            "{:<28} {:<10} {:<15} {:<20} {:<28} {:<28}",
                            o.id,
                            o.kind,
                            o.environment,
                            o.requested_by,
                            o.created_at,
                            o.finished_at.as_deref().unwrap_or("-")
                        );
                        // Print status on a continuation line to keep
                        // the header table tight on narrow terminals.
                        // (e.g. partially_applied is 18 chars.)
                        println!("    status={status_label}");
                    }
                }
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

fn cmd_expanders(
    server_url: &str,
    action: ExpandersAction,
    format: OutputFormat,
) -> Result<ExitCode> {
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Deserialize, Serialize)]
    struct SpecField {
        name: String,
        r#type: String,
        required: bool,
        description: String,
    }
    #[derive(Debug, Deserialize, Serialize)]
    struct ExpanderDescriptor {
        kind: String,
        description: String,
        emits: Vec<String>,
        #[serde(default)]
        spec_fields: Vec<SpecField>,
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        match action {
            ExpandersAction::List => {
                let resp = client
                    .get(format!("{server}/v1/expanders"))
                    .bearer_auth(&token)
                    .send()
                    .await?;
                check_status(&resp)?;
                let list: Vec<ExpanderDescriptor> = resp.json().await?;
                match format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&list)?),
                    OutputFormat::Human => {
                        if list.is_empty() {
                            println!("(no expanders configured)");
                        } else {
                            for d in &list {
                                println!("{}", d.kind);
                                println!("  {}", d.description);
                                println!("  emits: {}", d.emits.join(", "));
                            }
                        }
                    }
                }
            }
            ExpandersAction::Show { kind } => {
                let resp = client
                    .get(format!("{server}/v1/expanders/{kind}"))
                    .bearer_auth(&token)
                    .send()
                    .await?;
                check_status(&resp)?;
                let d: ExpanderDescriptor = resp.json().await?;
                match format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&d)?),
                    OutputFormat::Human => {
                        println!("{}", d.kind);
                        println!("  {}", d.description);
                        println!("  emits: {}", d.emits.join(", "));
                        if d.spec_fields.is_empty() {
                            println!("  (no spec fields documented)");
                        } else {
                            println!("  spec:");
                            for f in &d.spec_fields {
                                let req = if f.required { "required" } else { "optional" };
                                println!(
                                    "    {} <{}> ({})  {}",
                                    f.name, f.r#type, req, f.description
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

fn urlencode(s: &str) -> String {
    // Minimal percent-encoding for query params: keep alphanumerics and a few
    // safe punctuators, escape the rest. Avoids pulling another crate just
    // for query strings.
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char);
            }
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

fn cmd_drift(server_url: &str, action: DriftAction, format: OutputFormat) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(drift_async(server_url, action, format))
}

async fn drift_async(
    server_url: &str,
    action: DriftAction,
    format: OutputFormat,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::{
        DriftAcceptRequest, DriftBulkAcceptRequest, DriftBulkFilter, DriftBulkIgnoreRequest,
        DriftBulkResponse, DriftIgnoreRequest, DriftRevertRequest, DriftRevertResponse,
        DriftSummary,
    };
    let server = server_url.trim_end_matches('/');
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let admin_token = || credentials::resolve_admin_token_with_refresh(server);

    match action {
        DriftAction::List { agent_id } => {
            let mut url = format!("{server}/v1/drift");
            if let Some(id) = &agent_id {
                url.push_str(&format!("?agent_id={id}"));
            }
            let resp = http.get(&url).send().await?;
            check_status(&resp)?;
            let rows: Vec<DriftSummary> = resp.json().await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rows)?),
                OutputFormat::Human => {
                    if rows.is_empty() {
                        println!("(no open drift)");
                    } else {
                        for d in &rows {
                            println!("[{}] {} ({})", d.id, d.resource_id, d.severity);
                            for r in &d.diff.reasons {
                                println!("    {r}");
                            }
                        }
                    }
                }
            }
            Ok(if rows.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        DriftAction::Show { id } => {
            let resp = http.get(format!("{server}/v1/drift/{id}")).send().await?;
            check_status(&resp)?;
            let row: DriftSummary = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&row)?);
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::Accept { id, reason } => {
            let token = admin_token().await?;
            let resp = http
                .post(format!("{server}/v1/drift/{id}/accept"))
                .bearer_auth(&token)
                .json(&DriftAcceptRequest { reason })
                .send()
                .await?;
            check_status(&resp)?;
            println!("accepted drift {id}");
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::Ignore { id, ttl } => {
            let token = admin_token().await?;
            let until =
                parse_ttl_to_until(&ttl).with_context(|| format!("parsing --ttl {ttl:?}"))?;
            let resp = http
                .post(format!("{server}/v1/drift/{id}/ignore"))
                .bearer_auth(&token)
                .json(&DriftIgnoreRequest {
                    until: until.clone(),
                    reason: None,
                })
                .send()
                .await?;
            check_status(&resp)?;
            println!("ignored drift {id} until {until}");
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::Revert { id, source_commit } => {
            let token = admin_token().await?;
            let resp = http
                .post(format!("{server}/v1/drift/{id}/revert"))
                .bearer_auth(&token)
                .json(&DriftRevertRequest { source_commit })
                .send()
                .await?;
            check_status(&resp)?;
            let body: DriftRevertResponse = resp.json().await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                OutputFormat::Human => {
                    println!(
                        "submitted revert operation {} for {} (drift {id})",
                        body.operation_id, body.resource_id
                    );
                    println!(
                        "track with: iac plan --server <url> --operation {}",
                        body.operation_id
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::AcceptBulk {
            agent_id,
            kind,
            severity,
            reason,
        } => {
            let token = admin_token().await?;
            let req = DriftBulkAcceptRequest {
                reason,
                filter: DriftBulkFilter {
                    agent_id,
                    kind,
                    severity,
                },
            };
            let resp = http
                .post(format!("{server}/v1/drift/accept-bulk"))
                .bearer_auth(&token)
                .json(&req)
                .send()
                .await?;
            check_status(&resp)?;
            let body: DriftBulkResponse = resp.json().await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                OutputFormat::Human => {
                    println!("accepted {} drift event(s)", body.matched);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        DriftAction::IgnoreBulk {
            agent_id,
            kind,
            severity,
            ttl,
        } => {
            let token = admin_token().await?;
            let req = DriftBulkIgnoreRequest {
                ttl: ttl.clone(),
                filter: DriftBulkFilter {
                    agent_id,
                    kind,
                    severity,
                },
            };
            let resp = http
                .post(format!("{server}/v1/drift/ignore-bulk"))
                .bearer_auth(&token)
                .json(&req)
                .send()
                .await?;
            check_status(&resp)?;
            let body: DriftBulkResponse = resp.json().await?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                OutputFormat::Human => {
                    println!("ignored {} drift event(s) for {ttl}", body.matched);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn check_status(resp: &reqwest::Response) -> Result<()> {
    if resp.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("server returned {}", resp.status())
    }
}

fn parse_ttl_to_until(ttl: &str) -> Result<String> {
    // Accept "7d", "2h", "30m", "60s" — single suffix only. Convert to a
    // future RFC3339 timestamp.
    // Phase 7dh.11 (audit fix): pre-fix this used
    // `trimmed.split_at(trimmed.len() - 1)` which panics on a multi-byte
    // final char (e.g. fat-fingered `5µ`). Splitting on the char-boundary
    // length of the actual last char (via `chars().last()`) is safe.
    let trimmed = ttl.trim();
    let Some(last_char) = trimmed.chars().last() else {
        anyhow::bail!("empty");
    };
    let split = trimmed.len() - last_char.len_utf8();
    let (digits, unit) = trimmed.split_at(split);
    let n: u64 = digits.parse().context("number")?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 60 * 60,
        "d" => n * 60 * 60 * 24,
        "w" => n * 60 * 60 * 24 * 7,
        _ => anyhow::bail!("suffix must be s|m|h|d|w"),
    };
    let span = jiff::Span::new()
        .try_seconds(i64::try_from(secs).context("ttl too large")?)
        .context("span")?;
    let until = jiff::Timestamp::now()
        .checked_add(span)
        .context("ttl arithmetic overflow")?;
    Ok(until.to_string())
}

#[allow(clippy::too_many_arguments)]
fn cmd_apply_remote(
    path: &Path,
    actor: &str,
    format: OutputFormat,
    yes: bool,
    server_url: &str,
    environment: &str,
    source_commit: Option<&str>,
    wait: bool,
    wait_interval_secs: u64,
    canary_pct: Option<u8>,
) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    if resources.is_empty() {
        anyhow::bail!("no resources to submit");
    }
    if !yes {
        anyhow::bail!("non-interactive submission requires --yes");
    }
    // Reqwest needs an async runtime. Spin one up just for the submission.
    // Token resolution lives inside the runtime so the refresh resolver can
    // perform its (potentially blocking) HTTP round-trip there.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;

        // Phase 7r: pre-submit validation against the server's expander
        // catalog. Best-effort — if the catalog fetch fails (server
        // down, auth issue, network blip) we proceed and let the
        // server's serde rules be the authoritative gate. When the
        // catalog comes back, missing required fields / unknown fields
        // surface here so the operator sees errors locally before the
        // round trip.
        //
        // Phase 7bc: warn loudly on fetch failure. Previously silent —
        // an operator with a stale local manifest could submit
        // garbage and only see the rejection after the round-trip. A
        // visible "validation skipped" line makes the fall-through
        // explicit so operators can re-run with `--no-validate` style
        // intent or fix their connectivity first.
        match validate_spec::fetch_catalog(server_url, &token).await {
            Ok(catalog) => {
                let errors = validate_spec::validate_resources(&resources, &catalog);
                if !errors.is_empty() {
                    eprintln!("manifest validation failed:");
                    for e in &errors {
                        eprintln!("  {e}");
                    }
                    anyhow::bail!("{} validation error(s)", errors.len());
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: pre-submit validation skipped (catalog fetch failed: {e}). \
                     Server-side serde validation still applies."
                );
            }
        }

        submit_remote(
            &resources,
            actor,
            format,
            server_url,
            environment,
            source_commit,
            &token,
            wait,
            wait_interval_secs,
            canary_pct,
        )
        .await
    })
}

#[allow(clippy::too_many_arguments)]
async fn submit_remote(
    resources: &[Resource],
    actor: &str,
    format: OutputFormat,
    server_url: &str,
    environment: &str,
    source_commit: Option<&str>,
    admin_token: &str,
    wait: bool,
    wait_interval_secs: u64,
    canary_pct: Option<u8>,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::{
        CanarySpec, OperationStatus as OpStatus, OperationView, SubmitOperationRequest,
        SubmitOperationResponse,
    };
    let server = server_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resources_json: Vec<serde_json::Value> = resources
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    let canary = canary_pct.map(|pct| CanarySpec {
        pct,
        min_count: None,
    });
    let req = SubmitOperationRequest {
        environment: environment.to_string(),
        requested_by: actor.to_string(),
        source_commit: source_commit.map(str::to_string),
        summary: None,
        resources: resources_json,
        canary,
    };

    let resp = client
        .post(format!("{server}/v1/operations"))
        .bearer_auth(admin_token)
        .json(&req)
        .send()
        .await
        .context("submitting operation")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("server returned {status}: {body}");
    }
    let response: SubmitOperationResponse = resp.json().await?;

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
        OutputFormat::Human => {
            println!("operation: {}", response.operation_id);
            println!("assignments dispatched: {}", response.assignment_count);
            // Phase 7a: surface the blast radius right at submit time so the
            // operator sees the impact before walking away. For composite
            // kinds, resource_count > what the operator wrote because the
            // server expanded `service` into its primitives.
            let br = &response.blast_radius;
            println!(
                "blast radius: {} resource(s) across {} agent(s) [{}]",
                br.resource_count,
                br.agent_count,
                br.kinds.join(", ")
            );
            if !response.unrouted.is_empty() {
                eprintln!("unrouted resources:");
                for u in &response.unrouted {
                    eprintln!("  - {}: {}", u.resource_id, u.reason);
                }
            }
        }
    }

    if !wait {
        return Ok(ExitCode::SUCCESS);
    }

    // Poll until the operation reaches a terminal state.
    let interval = std::time::Duration::from_secs(wait_interval_secs.max(1));
    loop {
        tokio::time::sleep(interval).await;
        let resp = client
            .get(format!("{server}/v1/operations/{}", response.operation_id))
            .bearer_auth(admin_token)
            .send()
            .await
            .context("polling operation")?;
        if !resp.status().is_success() {
            anyhow::bail!("polling failed: {}", resp.status());
        }
        let view: OperationView = resp.json().await?;
        match view.status {
            OpStatus::Pending | OpStatus::Running => continue,
            terminal => {
                if matches!(format, OutputFormat::Json) {
                    println!("{}", serde_json::to_string_pretty(&view)?);
                } else {
                    println!("status: {terminal:?}");
                    for a in &view.assignments {
                        println!("  agent {} -> {}", a.agent_id, a.status);
                    }
                }
                return Ok(match terminal {
                    OpStatus::Succeeded => ExitCode::SUCCESS,
                    OpStatus::PartiallyApplied => ExitCode::from(4),
                    _ => ExitCode::from(5),
                });
            }
        }
    }
}

fn resolve_state_dir(flag: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = flag {
        return Ok(p.to_path_buf());
    }
    if let Ok(env) = std::env::var("IAC_STATE_DIR") {
        return Ok(PathBuf::from(env));
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".iac").join("state"))
}

fn build_registry() -> iac_core::ProviderRegistry {
    let mut reg = iac_core::ProviderRegistry::new();
    iac_providers::register_builtins(&mut reg);
    reg
}

fn load_manifests(path: &Path) -> Result<Vec<Resource>> {
    manifest::load_path(path).with_context(|| format!("loading manifests from {}", path.display()))
}

fn cmd_validate(path: &Path, format: OutputFormat) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    let registry = build_registry();

    let mut errors: Vec<(String, String)> = Vec::new();
    for r in &resources {
        match registry.require(&r.kind) {
            Err(e) => errors.push((r.id().to_string(), e.to_string())),
            Ok(p) => {
                // Drive a dry diff to surface per-provider spec validation errors
                // without touching the host. We feed an "absent" observation.
                let observed = iac_core::ObservedState::absent();
                if let Err(e) = p.diff(r, &observed) {
                    errors.push((r.id().to_string(), e.to_string()));
                }
            }
        }
    }

    match format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "resources": resources.iter().map(|r| serde_json::json!({
                    "id": r.id().to_string(),
                    "kind": r.kind,
                    "source": r.source.file,
                })).collect::<Vec<_>>(),
                "errors": errors.iter().map(|(id, e)| serde_json::json!({
                    "id": id,
                    "error": e,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Human => {
            println!("Loaded {} resource(s):", resources.len());
            for r in &resources {
                println!("  {} ({})", r.id(), r.source.file.display());
            }
            if errors.is_empty() {
                println!("\nValidation: OK");
            } else {
                eprintln!("\nValidation: {} error(s)", errors.len());
                for (id, e) in &errors {
                    eprintln!("  - {id}: {e}");
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn cmd_plan(path: &Path, state_dir: &Path, actor: &str, format: OutputFormat) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    let registry = build_registry();
    let executor = Executor::new(&registry, state_dir.to_path_buf(), actor);
    let result = executor.plan(&resources)?;
    emit_plan(&result, format)?;
    let exit = if result.has_changes() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    };
    Ok(exit)
}

/// Phase 7ch: CI-friendly "plan against the server's catalog without
/// applying." Fetches the expander catalog from `--server`, validates
/// resources locally against it, and renders the local plan view.
/// Exits non-zero on validation failure so CI gates on it. The
/// optional `source_commit` is only logged for traceability — no
/// state is mutated server-side.
///
/// Used by `iac plan --git-repo <…> --server <…>`. The git checkout
/// path replaces a local manifest path; everything else is the same
/// validation + local diff rendering flow.
fn cmd_plan_remote_from_path(
    path: &Path,
    server_url: &str,
    actor: &str,
    format: OutputFormat,
    source_commit: Option<&str>,
) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    if let Some(sha) = source_commit {
        eprintln!("source_commit: {sha}");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    let resources_for_validation = resources.clone();
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        match validate_spec::fetch_catalog(server_url, &token).await {
            Ok(catalog) => {
                let errors = validate_spec::validate_resources(&resources_for_validation, &catalog);
                if !errors.is_empty() {
                    eprintln!("manifest validation failed:");
                    for e in &errors {
                        eprintln!("  {e}");
                    }
                    anyhow::bail!("{} validation error(s)", errors.len());
                }
                eprintln!(
                    "server-side validation: OK ({} resources)",
                    resources_for_validation.len()
                );
            }
            Err(e) => {
                anyhow::bail!(
                    "could not validate against server catalog: {e}. \
                     CI mode requires server reachability — failing closed."
                );
            }
        }
        Ok::<(), anyhow::Error>(())
    })?;

    let state_dir = std::env::temp_dir().join("iac-plan-from-git");
    std::fs::create_dir_all(&state_dir).ok();
    let registry = build_registry();
    let executor = Executor::new(&registry, state_dir, actor);
    let result = executor.plan(&resources)?;
    emit_plan(&result, format)?;
    Ok(if result.has_changes() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

/// Phase 7b: render the desired-state preview for a server-side
/// operation. Closes the approver's "what am I greenlighting?" gap.
///
/// Phase 7bd: optional `graph` parameter switches output to a dependency
/// graph (ASCII tree or graphviz DOT) using the `metadata.dependsOn`
/// edges baked into each desired-state item.
fn cmd_plan_remote(
    server_url: &str,
    operation_id: &str,
    format: OutputFormat,
    graph: Option<&str>,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::OperationDesiredState;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let resp = client
            .get(format!(
                "{server}/v1/operations/{operation_id}/desired-state"
            ))
            .bearer_auth(&token)
            .send()
            .await?;
        check_status(&resp)?;
        let body: OperationDesiredState = resp.json().await?;

        // Phase 7bd: graph mode short-circuits the JSON / list rendering.
        // The `format` flag is ignored in graph mode — the output is the
        // graph syntax itself, not a structured payload.
        if let Some(g) = graph {
            print!("{}", render_dependency_graph(&body, g));
            return Ok(ExitCode::SUCCESS);
        }

        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
            OutputFormat::Human => {
                if body.items.is_empty() {
                    println!("(operation has no desired-state entries)");
                } else {
                    println!(
                        "operation {} — {} resource(s):",
                        body.operation_id,
                        body.items.len()
                    );
                    for item in &body.items {
                        let agent = if item.agent_id.is_empty() {
                            "<unrouted>".to_string()
                        } else {
                            item.agent_id.clone()
                        };
                        println!("  {} [{}] → agent {}", item.resource_id, item.kind, agent);
                    }
                }
            }
        }
        Ok(ExitCode::SUCCESS)
    })
}

/// Phase 7bd: render the operation's resource graph in either ASCII
/// (indented per-resource list with `↳` bullets for prereqs) or DOT
/// (graphviz digraph syntax). Returns the rendered string with a
/// trailing newline so the caller can `print!` it cleanly.
fn render_dependency_graph(
    body: &iac_core::protocol::v1::OperationDesiredState,
    format: &str,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if body.items.is_empty() {
        let _ = writeln!(out, "# operation {} has no resources", body.operation_id);
        return out;
    }
    // Build (resource_id → Vec<dependsOn ids>) from each item's metadata.
    let edges: Vec<(String, Vec<String>)> = body
        .items
        .iter()
        .map(|item| {
            let deps: Vec<String> = item
                .resource
                .get("metadata")
                .and_then(|m| m.get("dependsOn"))
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            (item.resource_id.clone(), deps)
        })
        .collect();

    match format {
        "ascii" => {
            let _ = writeln!(
                out,
                "operation {} — dependency graph ({} resource(s)):",
                body.operation_id,
                body.items.len()
            );
            for (id, deps) in &edges {
                let _ = writeln!(out, "  {id}");
                for dep in deps {
                    let _ = writeln!(out, "    ↳ depends on {dep}");
                }
            }
        }
        "dot" => {
            // Operation id goes in a comment; graphviz `dot -Tpng` accepts
            // the result directly. Quote ids so resource paths with `/`
            // don't break the parser.
            let _ = writeln!(out, "// iac operation {}", body.operation_id);
            let _ = writeln!(out, "digraph G {{");
            // Declare every node so isolated resources (no edges) still
            // appear in the rendered graph.
            for (id, _) in &edges {
                let _ = writeln!(out, "  {} [label={}];", quote_dot(id), quote_dot(id));
            }
            for (id, deps) in &edges {
                for dep in deps {
                    let _ = writeln!(out, "  {} -> {};", quote_dot(id), quote_dot(dep));
                }
            }
            let _ = writeln!(out, "}}");
        }
        // The clap value_parser already restricts to {ascii, dot}, but
        // belt-and-braces in case future callers reach this directly.
        other => {
            let _ = writeln!(out, "# unknown graph format: {other}");
        }
    }
    out
}

/// DOT label / node-id quoting. Backslash-escape `"` and `\`; everything
/// else passes through. `iac` resource ids are `kind/env/name` so a
/// quoted form is always safe (whereas the bare form contains `/` which
/// dot mostly tolerates but not always inside edge specs).
fn quote_dot(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Phase 7ck: read an `AssignmentPayload` JSON from stdin, apply
/// it locally through the Executor, print an
/// `AssignmentResultRequest` JSON to stdout. Designed for the
/// server-side SSH push worker — never run by an operator directly.
///
/// Exit code is always 0 when we manage to produce a result (even a
/// failure verdict). The result's status field carries the actual
/// outcome. This makes the server-side parser simpler: ssh exit > 0
/// means "ssh transport failed"; ssh exit 0 means "look at the
/// JSON for the verdict."
fn cmd_apply_assignment_stdin(state_dir: &Path, actor: &str) -> Result<ExitCode> {
    use iac_core::protocol::v1::{
        AssignmentPayload, AssignmentResultRequest, AssignmentResultStatus,
    };
    use std::io::Read;

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading assignment payload from stdin")?;
    let payload: AssignmentPayload =
        serde_json::from_str(&buf).context("decoding assignment payload (expected JSON)")?;

    // Convert each Value into a Resource via the manifest path. Reuses
    // the operator-facing parsing so server-side sanity checks already
    // ran upstream.
    let mut resources: Vec<Resource> = Vec::with_capacity(payload.resources.len());
    for value in &payload.resources {
        let resource: Resource = serde_json::from_value(value.clone())
            .context("decoding resource in assignment payload")?;
        resources.push(resource);
    }

    let registry = build_registry();
    let executor = Executor::new(&registry, state_dir.to_path_buf(), actor);

    // No prompt — this is a server-side dispatch.
    let result = match executor.apply(&resources) {
        Ok(r) => r,
        Err(e) => {
            // Even on infrastructure errors (state file unwritable,
            // etc.) we still emit a result JSON so the server-side
            // parser can mark this assignment failed cleanly.
            let req = AssignmentResultRequest {
                status: AssignmentResultStatus::Failed,
                items: vec![],
                summary: Some(format!("apply errored: {e}")),
            };
            println!("{}", serde_json::to_string(&req)?);
            return Ok(ExitCode::SUCCESS);
        }
    };

    let status = match result.operation.status {
        iac_core::operation::OperationStatus::Succeeded => AssignmentResultStatus::Succeeded,
        iac_core::operation::OperationStatus::PartiallyApplied => {
            AssignmentResultStatus::PartiallyApplied
        }
        _ => AssignmentResultStatus::Failed,
    };
    let summary = format!(
        "{} item(s); status={:?}",
        result.items.len(),
        result.operation.status
    );
    let req = AssignmentResultRequest {
        status,
        items: vec![],
        summary: Some(summary),
    };
    println!("{}", serde_json::to_string(&req)?);
    Ok(ExitCode::SUCCESS)
}

/// Phase 7cl: agent-less Ansible-style direct push. Read the manifest
/// locally, ssh to the target, pipe the payload to a remote
/// `iac apply --assignment-stdin` invocation, parse the result.
///
/// One target per invocation — operators wanting fan-out across many
/// hosts loop in their shell or use the control-plane `[[ssh_targets]]`
/// path (Phase 7ck) which is built for fleet dispatch.
///
/// `target` is `[user@]host`. Defaults to the system's `whoami` if
/// the user portion is omitted (matches `ssh` behavior). Operators
/// who need root override that explicitly: `--ssh root@host`.
fn cmd_apply_direct_ssh(
    path: &Path,
    target: &str,
    ssh_key: Option<&Path>,
    ssh_port: Option<u16>,
    ssh_remote_iac: Option<&str>,
    auto_bootstrap: bool,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::{AssignmentPayload, AssignmentResultStatus};

    let resources = load_manifests(path)?;
    if resources.is_empty() {
        anyhow::bail!("no resources to apply");
    }
    let mut target =
        ssh_dispatch::SshTarget::parse(target)?.with_overrides(ssh_key, ssh_port, ssh_remote_iac);
    // Phase 7da.1: probe + (maybe) bootstrap + apply all touch the
    // same host. ControlMaster pooling collapses 3 SSH handshakes
    // into 1.
    let pool = ssh_dispatch::SshConnectionPool::new()?;
    pool.apply_to(&mut target);
    eprintln!(
        "→ {label}: applying {} resource(s) from {}",
        resources.len(),
        path.display(),
        label = target.label,
    );
    let resources_json: Vec<serde_json::Value> = resources
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    let payload = AssignmentPayload {
        resources: resources_json,
    };
    let outcome = ssh_dispatch::dispatch_apply(&target, &payload, auto_bootstrap)?;
    println!(
        "← {label}: {:?}: {summary}",
        outcome.status,
        label = outcome.label,
        summary = outcome.summary,
    );
    if !outcome.stderr.is_empty() {
        eprintln!(
            "--- {label} stderr ---\n{}",
            outcome.stderr.trim_end(),
            label = outcome.label
        );
    }
    Ok(match outcome.status {
        AssignmentResultStatus::Succeeded => ExitCode::SUCCESS,
        AssignmentResultStatus::PartiallyApplied => ExitCode::from(4),
        AssignmentResultStatus::Failed => ExitCode::from(5),
    })
}

/// Phase 7cm: parallel apply across multiple SSH targets. Spawns up
/// to `max_parallel` workers, each runs `dispatch_apply` against its
/// target. Per-host outcome lines stream as they complete; final
/// summary at the end.
///
/// Exit codes:
///   0 — every host succeeded
///   4 — at least one host partially_applied (no full failures)
///   5 — at least one host failed
fn cmd_apply_fanout(
    path: &Path,
    targets: Vec<ssh_dispatch::SshTarget>,
    max_parallel: usize,
    fail_fast: bool,
    auto_bootstrap: bool,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::{AssignmentPayload, AssignmentResultStatus};
    use std::sync::{Arc, Mutex};

    if targets.is_empty() {
        anyhow::bail!("inventory resolved to zero hosts");
    }
    let max_parallel = max_parallel.max(1);
    let resources = load_manifests(path)?;
    let resources_json: Vec<serde_json::Value> = resources
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()?;
    let payload = Arc::new(AssignmentPayload {
        resources: resources_json,
    });

    // Phase 7da.1: shared ControlMaster pool for the fan-out. Per-host
    // sockets keyed by `%C` (hash of user@host:port) so distinct hosts
    // get distinct masters; same-host commands within one apply
    // collapse into one TCP+SSH session.
    let pool = ssh_dispatch::SshConnectionPool::new()?;
    let mut targets = targets;
    for t in &mut targets {
        pool.apply_to(t);
    }

    eprintln!(
        "→ fan-out: {} host(s), up to {max_parallel} parallel, manifest={}",
        targets.len(),
        path.display()
    );

    let outcomes: Arc<Mutex<Vec<ssh_dispatch::DispatchOutcome>>> =
        Arc::new(Mutex::new(Vec::with_capacity(targets.len())));
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(max_parallel.max(2))
        .enable_all()
        .build()
        .context("creating tokio runtime for fan-out")?;
    runtime.block_on(async {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_parallel));
        let mut handles = Vec::with_capacity(targets.len());
        for target in targets {
            let semaphore = semaphore.clone();
            let payload = payload.clone();
            let outcomes = outcomes.clone();
            let abort_flag = abort_flag.clone();
            handles.push(tokio::spawn(async move {
                if abort_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let _permit = semaphore.acquire().await;
                let label = target.label.clone();
                // dispatch_apply is sync (shells out to ssh). Wrap in
                // spawn_blocking so it doesn't pin a tokio worker.
                let r = tokio::task::spawn_blocking(move || {
                    ssh_dispatch::dispatch_apply(&target, &payload, auto_bootstrap)
                })
                .await
                .unwrap_or_else(|join_err| Err(anyhow::anyhow!("worker panicked: {join_err}")));
                let outcome = match r {
                    Ok(o) => o,
                    Err(e) => ssh_dispatch::DispatchOutcome {
                        label: label.clone(),
                        status: AssignmentResultStatus::Failed,
                        summary: format!("{e}"),
                        stdout: String::new(),
                        stderr: String::new(),
                    },
                };
                println!("← {label}: {:?}: {}", outcome.status, outcome.summary,);
                if outcome.is_terminal_failure() && fail_fast {
                    abort_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                // Phase 7cz.16: locked section is a Vec::push — cannot panic.
                #[allow(clippy::unwrap_used)]
                outcomes.lock().unwrap().push(outcome);
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });

    // Phase 7cz.16: same Mutex; no panics inside fan-out.
    #[allow(clippy::unwrap_used)]
    let outcomes = outcomes.lock().unwrap();
    let succeeded = outcomes
        .iter()
        .filter(|o| matches!(o.status, AssignmentResultStatus::Succeeded))
        .count();
    let partial = outcomes
        .iter()
        .filter(|o| matches!(o.status, AssignmentResultStatus::PartiallyApplied))
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o.status, AssignmentResultStatus::Failed))
        .count();
    eprintln!(
        "─ summary: {succeeded} ok, {partial} partial, {failed} failed (of {})",
        outcomes.len()
    );
    Ok(if failed > 0 {
        ExitCode::from(5)
    } else if partial > 0 {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    })
}

/// Phase 7da.3: print recent records from the local run-history.
fn cmd_history(state_dir: &Path, limit: usize, format: OutputFormat) -> Result<ExitCode> {
    let records = run_history::read_recent(state_dir, limit)?;
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        OutputFormat::Human => {
            if records.is_empty() {
                println!("(no `iac run` invocations recorded)");
                return Ok(ExitCode::SUCCESS);
            }
            for r in &records {
                let outcome = if r.failed_count == 0 {
                    format!("ok ({} host(s))", r.host_count)
                } else {
                    format!(
                        "{} ok / {} failed of {}",
                        r.ok_count, r.failed_count, r.host_count
                    )
                };
                println!(
                    "{ts}  {actor:>10}  {outcome:>30}  {cmd}",
                    ts = r.timestamp,
                    actor = r.actor,
                    outcome = outcome,
                    cmd = r.command,
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Phase 7cn: ad-hoc shell command on one host or a group of hosts.
/// Imperative complement to `iac apply` for one-off operational
/// tasks. Captures per-host stdout, stderr, and exit code.
#[allow(clippy::too_many_arguments)]
fn cmd_run(
    ssh: Option<String>,
    ssh_key: Option<PathBuf>,
    ssh_port: Option<u16>,
    inventory_path: Option<PathBuf>,
    group: Option<String>,
    limit: Option<String>,
    max_parallel: usize,
    fail_fast: bool,
    command: Vec<String>,
    state_dir: &Path,
    actor: &str,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::AssignmentResultStatus;
    use std::sync::{Arc, Mutex};

    if command.is_empty() {
        anyhow::bail!("no command supplied; pass after `--`: iac run --ssh host -- 'uptime'");
    }
    let shell_command = command.join(" ");

    // Resolve target list: --ssh single-host OR --inventory --group fan-out.
    let targets = if let Some(target_spec) = ssh {
        vec![
            ssh_dispatch::SshTarget::parse(&target_spec)?.with_overrides(
                ssh_key.as_deref(),
                ssh_port,
                None,
            ),
        ]
    } else if let Some(inv_path) = inventory_path {
        let group = group.ok_or_else(|| anyhow!("`--inventory` requires `--group`"))?;
        let inv = inventory::InventoryFile::load(&inv_path)?;
        inv.resolve(&group, limit.as_deref())?
            .into_iter()
            .map(|t| t.with_overrides(ssh_key.as_deref(), ssh_port, None))
            .collect()
    } else {
        anyhow::bail!("`iac run` needs `--ssh user@host` or `--inventory <path> --group <name>`");
    };
    if targets.is_empty() {
        anyhow::bail!("resolved to zero hosts");
    }

    // Phase 7da.1: pool SSH connections (ControlMaster) for the run.
    let pool = ssh_dispatch::SshConnectionPool::new()?;
    let mut targets = targets;
    for t in &mut targets {
        pool.apply_to(t);
    }

    eprintln!("→ run on {} host(s): {shell_command:?}", targets.len());
    let max_parallel = max_parallel.max(1);
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outcomes: Arc<Mutex<Vec<ssh_dispatch::DispatchOutcome>>> =
        Arc::new(Mutex::new(Vec::with_capacity(targets.len())));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(max_parallel.max(2))
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_parallel));
        let cmd = Arc::new(shell_command.clone());
        let mut handles = Vec::with_capacity(targets.len());
        for target in targets {
            let semaphore = semaphore.clone();
            let cmd = cmd.clone();
            let outcomes = outcomes.clone();
            let abort_flag = abort_flag.clone();
            handles.push(tokio::spawn(async move {
                if abort_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let _permit = semaphore.acquire().await;
                let label = target.label.clone();
                let cmd_str = cmd.to_string();
                let r = tokio::task::spawn_blocking(move || {
                    ssh_dispatch::dispatch_run(&target, &cmd_str)
                })
                .await
                .unwrap_or_else(|join_err| Err(anyhow::anyhow!("worker panicked: {join_err}")));
                let outcome = match r {
                    Ok(o) => o,
                    Err(e) => ssh_dispatch::DispatchOutcome {
                        label: label.clone(),
                        status: AssignmentResultStatus::Failed,
                        summary: format!("{e}"),
                        stdout: String::new(),
                        stderr: String::new(),
                    },
                };
                // Per-host output. Stream stdout immediately so
                // operators see results as they land.
                println!("┌─ {label}: {:?} ({})", outcome.status, outcome.summary);
                for line in outcome.stdout.lines() {
                    println!("│ {line}");
                }
                if !outcome.stderr.is_empty() {
                    for line in outcome.stderr.lines() {
                        eprintln!("│ ! {line}");
                    }
                }
                println!("└─");
                if outcome.is_terminal_failure() && fail_fast {
                    abort_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                // Phase 7cz.16: locked section is a Vec::push — cannot panic.
                #[allow(clippy::unwrap_used)]
                outcomes.lock().unwrap().push(outcome);
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });

    // Phase 7cz.16: same Mutex; no panics inside fan-out.
    #[allow(clippy::unwrap_used)]
    let outcomes = outcomes.lock().unwrap();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o.status, AssignmentResultStatus::Failed))
        .count();
    eprintln!(
        "─ summary: {ok} ok, {failed} failed (of {})",
        outcomes.len(),
        ok = outcomes.len() - failed,
    );
    // Phase 7da.3: persist the run to local audit log. CLI-direct path
    // doesn't have a control plane to record into, so the trail goes
    // to `<state_dir>/run-history.jsonl` — append-only NDJSON.
    if let Err(e) = run_history::append(
        state_dir,
        run_history::RunRecord::new(actor, &shell_command, &outcomes),
    ) {
        eprintln!("warning: couldn't write run-history: {e}");
    }
    Ok(if failed > 0 {
        ExitCode::from(5)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_apply(
    path: &Path,
    state_dir: &Path,
    actor: &str,
    format: OutputFormat,
    yes: bool,
) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    let registry = build_registry();
    let executor = Executor::new(&registry, state_dir.to_path_buf(), actor);

    // Plan first.
    let plan = executor.plan(&resources)?;
    if !plan.has_changes() {
        emit_plan(&plan, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    if !yes && !confirm_or_skip(&plan)? {
        eprintln!("aborted.");
        return Ok(ExitCode::from(3));
    }

    let result = executor.apply(&resources)?;
    emit_apply(&result, format)?;
    let exit = match result.operation.status {
        iac_core::operation::OperationStatus::Succeeded => ExitCode::SUCCESS,
        iac_core::operation::OperationStatus::PartiallyApplied => ExitCode::from(4),
        _ => ExitCode::from(5),
    };
    Ok(exit)
}

fn confirm_or_skip(plan: &PlanResult) -> Result<bool> {
    use std::io::Write;
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!("non-interactive run requires --yes to apply changes");
    }
    print!("Apply {} change(s)? [y/N] ", plan.change_count());
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn cmd_observe(
    path: &Path,
    state_dir: &Path,
    actor: &str,
    format: OutputFormat,
) -> Result<ExitCode> {
    let resources = load_manifests(path)?;
    let registry = build_registry();
    let _executor = Executor::new(&registry, state_dir.to_path_buf(), actor);

    let mut rows: Vec<serde_json::Value> = Vec::new();
    for r in &resources {
        let p = registry.require(&r.kind)?;
        let observed = p.observe(r)?;
        match format {
            OutputFormat::Human => {
                println!("{}", r.id());
                println!("  present: {}", observed.present);
                if !observed.facts.is_empty() {
                    println!("  facts:");
                    for (k, v) in &observed.facts {
                        println!("    {k}: {}", render::yaml_inline(v));
                    }
                }
            }
            OutputFormat::Json => {
                rows.push(serde_json::json!({
                    "resource": r.id().to_string(),
                    "observed": observed,
                }));
            }
        }
    }
    if matches!(format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_rollback(operation_id: &str, state_dir: &Path, actor: &str) -> Result<ExitCode> {
    let id = ulid::Ulid::from_string(operation_id)
        .map_err(|e| anyhow::anyhow!("invalid operation id: {e}"))?;
    let registry = build_registry();
    let executor = Executor::new(&registry, state_dir.to_path_buf(), actor);
    executor.rollback(id)?;
    println!("rolled back operation {id}");
    Ok(ExitCode::SUCCESS)
}

/// Phase 7ci: server-side rollback. POSTs to
/// `/v1/operations/{id}/rollback` and prints the new operation id
/// (which the operator can then track via `iac plan --server …
/// --operation …`).
fn cmd_rollback_remote(
    server_url: &str,
    operation_id: &str,
    actor: &str,
    format: OutputFormat,
    reason: Option<&str>,
    canary_pct: Option<u8>,
) -> Result<ExitCode> {
    use iac_core::protocol::v1::{CanarySpec, RollbackOperationRequest, RollbackOperationResponse};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    runtime.block_on(async move {
        let token = credentials::resolve_admin_token_with_refresh(server_url).await?;
        let server = server_url.trim_end_matches('/');
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        let req = RollbackOperationRequest {
            requested_by: actor.to_string(),
            reason: reason.map(str::to_string),
            canary: canary_pct.map(|pct| CanarySpec {
                pct,
                min_count: None,
            }),
        };
        let resp = client
            .post(format!("{server}/v1/operations/{operation_id}/rollback"))
            .bearer_auth(&token)
            .json(&req)
            .send()
            .await
            .context("submitting rollback")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("server returned {status}: {body}");
        }
        let result: RollbackOperationResponse = resp.json().await?;
        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            _ => {
                println!(
                    "rollback operation: {}\n  reverted: {} resources\n  assignments: {}",
                    result.new_operation_id, result.resources_reverted, result.assignment_count
                );
                if !result.resources_orphaned.is_empty() {
                    println!(
                        "  orphaned ({}, no prior state — manual cleanup needed):",
                        result.resources_orphaned.len()
                    );
                    for r in &result.resources_orphaned {
                        println!("    - {r}");
                    }
                }
            }
        }
        Ok::<ExitCode, anyhow::Error>(ExitCode::SUCCESS)
    })
}

fn cmd_operations(state_dir: &Path, format: OutputFormat) -> Result<ExitCode> {
    let dir = state_dir.join("operations");
    let mut entries: Vec<String> = Vec::new();
    if dir.exists() {
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            entries.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    entries.sort();
    match format {
        OutputFormat::Human => {
            if entries.is_empty() {
                println!("(no operations)");
            } else {
                for e in entries {
                    println!("{e}");
                }
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn emit_plan(plan: &PlanResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Human => render::plan_human(plan, std::io::stdout().lock())?,
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(plan)?),
    }
    Ok(())
}

fn emit_apply(result: &ApplyResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Human => render::apply_human(result, std::io::stdout().lock())?,
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(result)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iac_core::protocol::v1::{OperationDesiredState, OperationDesiredStateItem};
    use serde_json::json;

    fn body_two_with_one_edge() -> OperationDesiredState {
        OperationDesiredState {
            operation_id: "op-abc".into(),
            items: vec![
                OperationDesiredStateItem {
                    resource_id: "docker.container/prod/web".into(),
                    kind: "docker.container".into(),
                    agent_id: "agent-a".into(),
                    resource: json!({
                        "metadata": {
                            "name": "web",
                            "environment": "prod",
                            "dependsOn": ["file/prod/web-config"],
                        }
                    }),
                },
                OperationDesiredStateItem {
                    resource_id: "file/prod/web-config".into(),
                    kind: "file".into(),
                    agent_id: "agent-a".into(),
                    resource: json!({
                        "metadata": {
                            "name": "web-config",
                            "environment": "prod",
                        }
                    }),
                },
            ],
        }
    }

    #[test]
    fn graph_ascii_lists_each_resource_with_indented_deps() {
        let out = render_dependency_graph(&body_two_with_one_edge(), "ascii");
        assert!(out.contains("operation op-abc"));
        assert!(out.contains("docker.container/prod/web"));
        assert!(out.contains("↳ depends on file/prod/web-config"));
        assert!(out.contains("file/prod/web-config"));
    }

    #[test]
    fn graph_dot_emits_digraph_with_edges() {
        let out = render_dependency_graph(&body_two_with_one_edge(), "dot");
        assert!(out.starts_with("// iac operation op-abc\n"));
        assert!(out.contains("digraph G {"));
        // Both nodes declared.
        assert!(
            out.contains("\"docker.container/prod/web\" [label=\"docker.container/prod/web\"];")
        );
        assert!(out.contains("\"file/prod/web-config\" [label=\"file/prod/web-config\"];"));
        // Edge present.
        assert!(out.contains("\"docker.container/prod/web\" -> \"file/prod/web-config\";"));
        assert!(out.trim_end().ends_with("}"));
    }

    #[test]
    fn graph_handles_empty_operation() {
        let body = OperationDesiredState {
            operation_id: "op-empty".into(),
            items: vec![],
        };
        let out = render_dependency_graph(&body, "ascii");
        assert!(out.contains("op-empty"));
        assert!(out.contains("no resources"));
    }

    #[test]
    fn graph_dot_quotes_identifiers_with_special_chars() {
        let body = OperationDesiredState {
            operation_id: "op-x".into(),
            items: vec![OperationDesiredStateItem {
                resource_id: r#"weird"id\with"backslash"#.into(),
                kind: "file".into(),
                agent_id: "a".into(),
                resource: json!({"metadata": {"name": "x", "environment": "p"}}),
            }],
        };
        let out = render_dependency_graph(&body, "dot");
        // The quoted form must escape both `"` and `\`.
        assert!(out.contains(r#""weird\"id\\with\"backslash""#));
    }

    #[test]
    fn quote_dot_round_trip_basic_id() {
        assert_eq!(quote_dot("file/prod/x"), r#""file/prod/x""#);
    }
}
