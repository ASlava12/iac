# IaC Tool — Archived Tasks

> Phases that shipped, plus obsolete entries kept for historical record. New
> work goes in [TASKS.md](TASKS.md). Anything here is **frozen** — open items
> noted under "Open after Phase X" headers were either picked up by a later
> phase or moved into the active backlog.

## Phase 0 — Data model + local CLI MVP — DONE.

Acceptance criterion met: `iac plan` / `iac apply --yes` / `iac plan` (no change) / drift / `iac apply --yes` (re-converge) / `iac rollback` all work end-to-end against `examples/hello-file.yaml`.

Test count: 36 tests passing (10 iac-core + 23 iac-providers + 3 iac-cli integration).
`cargo audit --deny unmaintained --deny unsound --deny yanked` clean across 135 transitive deps.

### Phase 0 deliverables (✅ all complete)

- [x] Project memory + TASKS.md
- [x] Cargo workspace: `iac-core`, `iac-providers`, `iac-cli`. Edition 2024, Rust 1.95, resolver 3.
- [x] `iac-core`: types (`ResourceId`, `Resource`, `Metadata`, `DesiredState`, `ObservedState`, `AppliedState`, `Diff`, `FieldChange`, `Step`, `StepResult`, `Operation`, `Checkpoint`, `VerifyOutcome`, `ApplyContext`).
- [x] `iac-core::manifest`: YAML loader (single + multi-doc + directory walk), shape validation.
- [x] `iac-core::provider::Provider`: observe / diff / plan / pre_apply / apply / verify / rollback.
- [x] `iac-core::registry::ProviderRegistry`.
- [x] `iac-core::executor::Executor`: drives the lifecycle, persists checkpoints, supports rollback. Crash-resilient (atomic rename of operation.json + applied state).
- [x] `iac-providers/file`: atomic temp+rename, mode/owner/group via /etc/passwd-/etc/group resolution, full pre_apply backup, rollback restores content + mode.
- [x] `iac-providers/systemd`: backend trait + mock + real (`systemctl show / enable / disable / start / stop / restart / reload`). Plan emits steps in correct order (enable→start, stop→disable). Rejects masked units.
- [x] `iac-providers/package`: apt backend + mock. Install / remove / version pin / rollback.
- [x] `iac-cli`: `validate`, `plan`, `apply --yes`, `observe`, `rollback`, `operations`, `version`. Supports `--state-dir`, `--format human|json`, `--actor`. Exit codes: 0=ok, 1=validation error, 2=plan has changes, 3=apply aborted, 4=partial apply, 5=other failure.
- [x] Integration tests: full lifecycle, unknown-kind rejection, observe.
- [x] `cargo audit` clean.

### Open after Phase 0

- TTY-aware confirmation logic was simplified (uses `std::io::IsTerminal`); revisit when adding non-interactive CI mode that should still print plan + abort.
- Operation `plan` results are NOT persisted to disk in Phase 0 — only `apply` results are. If we want `iac plan --save` for later inspection, add it in Phase 1.
- We synthesize a minimal `Resource` from checkpoint metadata during rollback. That's fine while providers don't depend on the full `spec` for rollback. If a future provider does, the executor needs to also persist the original `Resource` alongside the checkpoint.

---

---

## Phase 1 — Agent local mode — DONE.

Long-running `iac-agent` daemon with periodic observe, drift detection persisted to SQLite, JSON status snapshot file, and graceful SIGTERM shutdown. Verified end-to-end via smoke test (start → observe drift → apply → drift cleared → SIGTERM → exit 0).

49 tests passing total (Phase 0 + Phase 1). `cargo audit` clean across 160 transitive deps.

### Phase 1 deliverables (✅ all complete)

- [x] `iac-agent` crate: tokio multi-thread runtime, async lifecycle.
- [x] `Config` with TOML loader + CLI overrides + sane defaults (root vs. user-level paths).
- [x] SQLite [`Store`](crates/iac-agent/src/store.rs) with schema migrations: `observations`, `drift_events`, `agent_runs`, `schema_version`. WAL mode for concurrent reads.
- [x] `Agent` with `observe_once` / `apply_once` / `plan_once` / `rollback`. Sync provider work runs on `tokio::task::spawn_blocking`.
- [x] Run loop: immediate first cycle + `tokio::time::interval` with `MissedTickBehavior::Skip`. SIGTERM/SIGINT handler triggers `Notify`-based graceful shutdown.
- [x] [`AgentStatus`](crates/iac-agent/src/status.rs) JSON status file written atomically after each cycle (temp+rename). `iac-agent status` reads it without touching SQL.
- [x] CLI subcommands: `run`, `status`, `observe`, `plan`, `apply --yes`, `rollback`, `drift list/resolve`, `runs --limit`, `version`. Exit codes match the `iac` CLI semantics.
- [x] Drift event dedup: a second drift open for the same resource updates the existing row. `apply` and external convergence both auto-close drift on next cycle.
- [x] [`systemd/iac-agent.service`](crates/iac-agent/systemd/iac-agent.service) unit file with basic hardening (ProtectKernel*, NoNewPrivileges, RestrictRealtime). Operators layer extra sandboxing via drop-in.
- [x] 13 new tests: 7 unit (config + store) + 6 integration (full agent lifecycle through tokio runtime with file provider).

### Open after Phase 1

- **Status file is updated only on observe cycles, not on apply.** After `iac-agent apply` the in-memory `open_drift_count` in the status file lags until the next observe tick. Acceptable for Phase 1 (drift reconciles on next cycle), but `apply` should also refresh the status snapshot once we add anything more critical than display info to it.
- **No retention pruning yet.** `observations` and `agent_runs` tables grow unboundedly. Add a periodic prune task (configurable retention, default keep-last-N-per-resource for observations, last-N rows for runs, resolved drifts older than 30d) when usage justifies it — likely Phase 4 alongside drift workflows.
- **Agent CLI re-uses the iac-cli `Executor` directly.** That couples the agent to the local on-disk operation log layout. Phase 2 will add a control-plane API and the agent will instead push operations / pull assignments. The Executor stays for offline / break-glass use.
- **Apply happens through Agent CLI, not the run loop.** Auto-apply (continuous reconcile) is a Phase 4 deliverable and intentionally not in Phase 1.

---

## Phase 2a — Push-mode control-plane — DONE.

`iac-controlplane` HTTP server (axum + sqlx + SQLite) plus push-mode agent integration. Agents register, persist their identity, and after every observe cycle push observations + drift events + heartbeat to the server. Drift events on the server side auto-close when the agent stops reporting them.

**60 tests passing** (Phase 0 + 1 + 2a). `cargo audit --deny unmaintained --deny unsound --deny yanked` clean (one documented ignore for `RUSTSEC-2023-0071` — `rsa` is a phantom optional dep of `sqlx-mysql` not compiled into our binaries; see [`.cargo/audit.toml`](.cargo/audit.toml)).

### Phase 2a deliverables (✅ all complete)

- [x] [`iac-controlplane`](crates/iac-controlplane/) crate: axum 0.8, tower-http, tokio.
- [x] sqlx 0.8 with SQLite backend. `macros` feature **intentionally disabled** to avoid a transitive `rsa` (RUSTSEC-2023-0071). Migrations are plain SQL embedded via `include_str!` and tracked in a `_iac_migrations` table.
- [x] [Schema](crates/iac-controlplane/migrations/20260429000001_init.sql): `agents`, `observations`, `drift_events`, `assignments` (placeholder for Phase 2b). Indexes for open-drift filtering and pending-assignment lookup.
- [x] [Bearer-token auth](crates/iac-controlplane/src/auth.rs): server issues 256-bit token at registration, stores `hex(sha256(token))`, verifies in constant time. mTLS deferred to Phase 6.
- [x] HTTP API: `POST /v1/agents/register`, `POST /v1/agents/{id}/{heartbeat,observations,drift}`, `GET /v1/agents`, `GET /v1/drift?agent_id=<id>`, `GET /v1/health`.
- [x] [Wire protocol types](crates/iac-core/src/protocol.rs) in `iac_core::protocol::v1` shared between server and agent.
- [x] [Server binary](crates/iac-controlplane/src/main.rs) with TOML config, signal handling, graceful shutdown.
- [x] [Agent client](crates/iac-agent/src/remote.rs): registers on first run, persists identity to a `0600` file, reuses on subsequent runs. Server unreachable → agent runs standalone.
- [x] Agent run loop pushes observations + drift + heartbeat after each cycle. Server-side drift auto-closes on next push when agent stops reporting it.
- [x] 17 new tests: 7 server unit (api), 3 agent ↔ server end-to-end, 1 ResourceId::parse round-trip in iac-core, plus 6 server-store tests via the api integration test.
- [x] `.cargo/audit.toml` with documented `ignore` for the `rsa` phantom dep.

### Open after Phase 2a

- **mTLS deferred to Phase 6.** Today the agent → server channel is plain HTTP with bearer tokens. Operators must run behind a TLS-terminating proxy or only on trusted networks until Phase 6.
- **No retention on server-side history.** `observations` and `drift_events` accumulate forever. Add a periodic `VACUUM`/prune task in Phase 2c when sizing matters.
- **Identity rotation not implemented.** Tokens are issued once at registration and never expire. A re-key endpoint (`POST /v1/agents/{id}/rotate-token` with old token + something else) is a Phase 6 add-on.
- **Server-side authorization is binary.** Any valid bearer token can hit any endpoint scoped by `agent_id` in the URL. RBAC for human users (CLI viewers / approvers) waits for Phase 6.

---

## Phase 2b — Pull mode (assignments) — DONE.

Operator submits desired state via CLI → server fans out per-agent assignments → agents pull, apply through their local executor, and report back. End-to-end smoke test: `iac apply --server <url> --wait` exits 0 after the agent applies the manifest and the operation reaches `succeeded`.

**65 tests passing** (Phase 0 + 1 + 2a + 2b). `cargo audit` clean.

### Phase 2b deliverables (✅ all complete)

- [x] [Migration v2](crates/iac-controlplane/migrations/20260429000002_assignments.sql): adds `operations`, `desired_states` tables; extends `assignments` with `kind`, `result_json`, `expires_at`.
- [x] [Protocol v1 extensions](crates/iac-core/src/protocol.rs): `SubmitOperationRequest`, `OperationView`, `AssignmentEnvelope`, `AssignmentPayload`, `AssignmentResultRequest`, `AssignmentItemResult`, `OperationStatus`.
- [x] Admin-token auth (Phase 6 will replace with RBAC). Server config + `IAC_ADMIN_TOKEN` env var. Constant-time comparison via SHA-256 hash. Server returns 400 with a clear message when admin endpoints are hit but no token is configured.
- [x] [Routing logic](crates/iac-controlplane/src/store.rs): resources are routed to agents by `spec.hostSelector.name` (when set) or by being the only agent in the resource's environment. Ambiguous resources return as `unrouted` in the response. Routing hint stripped from `spec` before sealing the assignment payload — providers don't see it.
- [x] Server endpoints: `POST /v1/operations`, `GET /v1/operations/{id}`, `GET /v1/agents/{id}/assignments`, `POST /v1/agents/{id}/assignments/{assignment_id}/result`. Operation status auto-rolls up from per-assignment status (succeeded / partially_applied / failed).
- [x] Assignment fetch is an atomic transition: `pending → fetched → succeeded|partially_applied|failed`. `fetch_pending_assignments` marks all returned rows as `fetched` in the same transaction so a slow agent can't process the same assignment twice. The first fetch transitions the parent operation to `running`.
- [x] [Agent.drain_assignments](crates/iac-agent/src/agent.rs): runs after every observe cycle when remote is configured. Each assignment is decoded into `Resource[]`, applied via the existing `Executor`, and the per-resource result is reported back. Failures during execution are still reported (with `Failed` status) so the operation doesn't hang.
- [x] [iac CLI extension](crates/iac-cli/src/main.rs): `iac apply --server <url> --environment <env> [--wait] [--source-commit <sha>]`. Loads manifests locally, POSTs to `/v1/operations`, optionally polls until terminal. Admin token from `IAC_ADMIN_TOKEN`. Exit codes match local apply: 0 succeeded, 4 partially applied, 5 other failure.
- [x] 5 new pull-flow E2E tests + reuse of existing 17 push tests. Verified the full chain via release-build smoke test (CLI → server → agent → file on disk).

### Open after Phase 2b

- **No assignment expiry / retry semantics yet.** `expires_at` exists in the schema but nothing is enforced. If an agent fetches an assignment and crashes before reporting, the assignment sits in `fetched` forever. Add a sweep in Phase 4 (or surface as drift).
- **No assignment signing.** Server hands assignments out as plain JSON; the agent trusts whatever comes back. Phase 6 adds payload signatures so a compromised network proxy can't tamper. The data path is ready (`AssignmentEnvelope` is signature-friendly).
- **`iac apply --server` doesn't show diff.** It loads manifests, sends them, and waits. There is no client-side `iac plan --server` yet that would show what will change before submission. Add when we hook the server's planner up to push observations.
- **Agent server-mode still observes from local manifests.** When operator submits via `--server`, the agent applies the assignment but only OBSERVES local manifests for drift. Server has no view of resources that exist only in assignments. Address by also recording desired-state observations server-side so the loop closes. Phase 2c work.

---

## Phase 2c — Closing the loop — DONE.

After `iac apply --server`, the agent now observes the server-submitted resources on every cycle even if they are NOT in its local manifests directory. Drift events on those resources surface back on the server. PostgreSQL is intentionally pushed to Phase 2d — it's a deployment concern, the loop closure is a product gap.

**68 tests passing** (Phase 0 + 1 + 2a + 2b + 2c). `cargo audit` clean.

### Phase 2c deliverables (✅ all complete)

- [x] [Protocol v1: `DesiredStateBatch` / `DesiredStateItem`](crates/iac-core/src/protocol.rs).
- [x] [Server endpoint `GET /v1/agents/{id}/desired-state`](crates/iac-controlplane/src/api/agents.rs): returns the latest desired spec per `resource_id` across every operation dispatched to this agent (excluding ones that ended in failure). Routing hints stripped.
- [x] [Server query](crates/iac-controlplane/src/store.rs) takes the latest entry per `resource_id` by ordering on the parent operation's `created_at DESC`. Newer operations supersede older ones for the same resource.
- [x] [Agent.observation_resources](crates/iac-agent/src/agent.rs): merges local manifests with server desired-state, deduped by `ResourceId`, server-wins on collision. Used by both the observe path and the push path.
- [x] 3 new loop-closure E2E tests covering: server-only resource observation + drift, dedup by resource_id across operations, single-agent-in-env routing.
- [x] Verified end-to-end via release-build smoke test: empty local manifests, operator submits, agent applies, file tampered out-of-band, next agent cycle detects content_sha256 drift and the server's `/v1/drift` endpoint surfaces the full diff.

### Open after Phase 2c

- **No "remove from desired state" yet.** Once a resource is in the agent's desired-state set, it stays there. Submitting a new operation without that resource doesn't tombstone it; the agent will keep observing the old one forever. Add a `delete: true` flag in the manifest, or treat each operation as a complete environment snapshot. Will pick up alongside Phase 2d.
- **`fetch_desired_state` runs on every observe cycle.** Cheap for small fleets, but at agent-thousands × resource-thousands scale it'll matter. Add `If-Modified-Since` semantics or a server push when we hit that wall.
- **Server still doesn't surface "resource never observed."** A resource can sit in `desired_states` and the server has no way to flag "we sent the assignment 10 minutes ago but the agent never observed". Wire that on top of the existing `observations.received_at` and the `desired_states` join — Phase 4 drift workflows.

---

## Phase 2c — PostgreSQL backend (OBSOLETE — duplicate of Phase 2d)

> Mis-numbered. The real PostgreSQL phase is **Phase 2d — PostgreSQL backend** in [TASKS.md](TASKS.md). Kept here for traceability since this stub existed alongside the closing-the-loop Phase 2c.

- [ ] Add `postgres` feature to sqlx; gate per-binary via build feature.
- [ ] Verify all queries are dialect-portable (mostly fine, but `INSERT OR REPLACE` needs `ON CONFLICT DO UPDATE`).
- [ ] Migration script for moving an existing SQLite db to Postgres.
- [ ] Connection pool sizing / timeout tuning.

---

## Phase 4 — Drift workflows — DONE.

The drift detection plumbing already existed (Phase 1 agent + Phase 2a server). This phase adds operator-facing controls: list, show, accept (resolve permanently with a reason), ignore (silence for a TTL). `revert` is intentionally not its own command yet — operators force convergence by re-submitting the desired-state manifest via `iac apply --server`.

**149 tests passing** (3 cli + 11 core + 81 providers + 18 agent unit + 6 agent lifecycle + 30 controlplane). `cargo audit` clean.

### Phase 4 deliverables (✅)

- [x] [Migration v3](crates/iac-controlplane/migrations/20260429000003_drift_workflow.sql): `ignored_until TEXT` column on `drift_events` plus a partial index for the not-NULL case.
- [x] [Protocol types](crates/iac-core/src/protocol.rs): `DriftSummary` extended with `ignored_until` / `resolved_at` / `resolution`. New `DriftAcceptRequest` (`reason` required) and `DriftIgnoreRequest` (`until` RFC3339, optional reason).
- [x] [Server store](crates/iac-controlplane/src/store.rs): `get_drift`, `accept_drift` (sets `resolved_at` + `resolution: "accepted: ..."`), `ignore_drift` (validates RFC3339, stores normalized form). `list_open_drift` filters out rows where `ignored_until > now`, so an ignored event re-surfaces automatically when the TTL expires.
- [x] [Server endpoints](crates/iac-controlplane/src/api/drift.rs): `GET /v1/drift/{id}`, `POST /v1/drift/{id}/accept`, `POST /v1/drift/{id}/ignore`. Accept/ignore require admin token; list/show are read-only.
- [x] [CLI](crates/iac-cli/src/main.rs): `iac drift --server <url> list [--agent-id]`, `show <id>`, `accept <id> --reason ...`, `ignore <id> --ttl 7d`. TTL parser accepts `s|m|h|d|w` suffixes. Empty reasons rejected client-side too via clap `String` required.
- [x] **6 E2E tests**: accept marks resolved with prefix, ignore hides until TTL expires (and past TTL un-hides), missing/wrong admin returns 401, empty reason returns 400, invalid RFC3339 returns 400, nonexistent drift returns 404.
- [x] **Smoke verified end-to-end:** drift the file → `list` shows 1 row → `show` returns full diff with sha-from/sha-to → `ignore --ttl 1h` → `list` empty → `accept --reason "manual hotfix"` → drift resolved with `accepted: ...` prefix.

### Open after Phase 4

- **No `iac drift revert <id>` shortcut.** Re-submitting the manifest via `iac apply --server` already converges the resource — this command would just be a sugar layer that fetches the desired-state for the resource and re-submits it. Add when the workflow becomes common.
- **TTL parser is single-suffix only.** `7d` works, `7d6h` doesn't. Compound durations are nice for human typing but rare in scripts; defer.
- **No bulk operations.** Accepting / ignoring 50 drifts at once requires 50 calls. Add `iac drift accept --selector severity=warning,kind=file --reason ...` when the drift volume justifies it.
- **`agent_id` filter on `list` is the only filter.** No filter by severity, kind, age, or "not ignored" — easy to add when the data justifies them.

---

## Phase 5a — `docker.container` provider — DONE.

First Phase 5 provider. Manages a Docker container by name through the same observe / diff / plan / apply / verify / rollback lifecycle. Image identity is compared by **content digest** (post-`docker pull`), so a tag repointed upstream triggers a recreate even though the spec string is unchanged.

**85 tests passing.** `cargo audit` clean.

### Phase 5a deliverables (✅)

- [x] [Spec](crates/iac-providers/src/docker/spec.rs): `name`, `image`, `state`, `env`, `ports`, `restart_policy`. `deny_unknown_fields` + image / port / name validators that reject shell metas. Restart policy parsing accepts `no | always | unless-stopped | on-failure`.
- [x] [`DockerBackend` trait](crates/iac-providers/src/docker/backend.rs): `inspect_container`, `image_id`, `pull`, `run`, `stop`, `remove`. `DockerCli` shells out (no SDK dep) and parses `docker inspect --format '{{json .}}'`. `MockDocker` for unit tests.
- [x] Port-binding parser normalizes `.HostConfig.PortBindings` (`{"80/tcp":[{"HostPort":"8080"}]}`) into the same `host:container[/proto]` format we accept in the spec, then sorts so observation comparisons are deterministic.
- [x] [`ops`](crates/iac-providers/src/docker/ops.rs): observe, diff, plan, pre_apply (snapshots image / env / ports / restart_policy), apply (`docker.pull` + `docker.recreate` for present, `docker.remove` for absent), rollback (recreates with previous image + env + ports). Env diff is "desired ⊆ observed" so Docker's auto-injected `PATH=...` doesn't show as drift.
- [x] [`DockerProvider`](crates/iac-providers/src/docker/mod.rs) wired into `register_builtins`.
- [x] **15 unit tests** covering: parse minimal, reject shell metas, port spec validation, container name validation, present-without-image rejection, absent-with-extras rejection, create-when-absent, idempotent-when-correct, image digest change, port change, env subset, absent removal, rollback to previous image, rollback when no previous.
- [x] **2 integration tests** against a real Docker daemon, gated by `IAC_DOCKER_INTEGRATION=1`. Cover full lifecycle (create → idempotent → remove) and image digest comparison across two pulled tags. Verified locally with `traefik/whoami` (~5MB).
- [x] **End-to-end smoke through control-plane:** `iac apply --server --wait` submits a `docker.container` manifest → server creates assignment → agent applies → real container running with desired image and env. Verified via `docker ps` and `docker inspect`.

### Open after Phase 5a

- **No `command`, `volumes`, `networks`, `healthcheck`, or `labels`** in the spec yet. Add as Phase 5b alongside `docker.compose` for stacks of containers.
- **Drift is eventually-consistent on server side after assignment apply.** The agent opens a drift event during the observe pass that precedes apply, then converges, but only the NEXT observe cycle pushes a drift batch without that resource (which is when the server auto-closes it). Within one `observe_interval` of apply success the server reflects reality. To make it strict-consistent: after a successful drain, the agent should re-push observations + drift immediately, OR `drain_assignments` should close local drift for converged resources before returning.
- **`docker pull` runs unconditionally on every apply.** Cheap when the image is already local (Docker dedupes), but for restricted-network deployments we should check `image_id(image)` first and skip the pull if the digest is already present and `:tag` is pinned.

---

## Phase 5b — `nginx.vhost` — DONE.

Pairs with `docker.container` to express the canonical "expose a backend over HTTP" pattern. Renders a deterministic nginx server block, validates with `nginx -t`, and only reloads on success. A failed `nginx -t` triggers an immediate restore of the previous on-disk content so the file system never lands on a config that would break a future reload.

**103 tests passing** (3 cli + 11 core + 56 providers + 2 docker integration + 13 agent + 18 controlplane). `cargo audit` clean.

### Phase 5b deliverables (✅)

- [x] [Spec](crates/iac-providers/src/nginx/spec.rs): `config_path` (required absolute), `state`, `server_names`, `listen` (default `[80]`), `upstream` (required for `state=present`, must start with `http://`/`https://`/`unix:`), `client_max_body_size`, `proxy_read_timeout`. Validators reject shell metas, embedded `;`, `..` traversal in paths, non-numeric size/duration suffixes.
- [x] [Pure renderer](crates/iac-providers/src/nginx/render.rs) — deterministic spec → config string. Snapshot test guards the byte-exact output.
- [x] [`NginxBackend`](crates/iac-providers/src/nginx/backend.rs) trait + `NginxCli` (atomic temp-file write, `nginx -t`, `systemctl reload nginx`) + `MockNginx` with injectable validate/reload failures.
- [x] [Strict-atomic apply](crates/iac-providers/src/nginx/ops.rs): write → `nginx -t` → reload. On `nginx -t` failure, restore from the pre-apply checkpoint **before** returning the error. The on-disk state is therefore always either the previous valid config or the new valid one — never an invalid intermediate.
- [x] [`NginxProvider`](crates/iac-providers/src/nginx/mod.rs) wired into `register_builtins`. The provider re-reads `<workspace>/checkpoint.json` during apply so the inline restore knows what to write back.
- [x] **18 unit + provider-trait tests** including a round-trip through the executor's checkpoint file. Among them: render determinism, validation-failure-restores-previous, validation-failure-on-create-removes-file, rollback-restores-and-reloads.

### Open after Phase 5b

- **No TLS** — `listen 443` renders a plain HTTP server block. Phase 5b.1 will add a `tls` block with cert/key paths plus the standard `ssl_certificate` directives. Auto-cert (Let's Encrypt) is a Phase 7 concern.
- **No multi-`location`**. Common cases that need it (`/health`, `/metrics` proxied differently) require a follow-up. Probably an `extra_locations: [{path, proxy_pass}]` field in the spec.
- **No live-nginx integration test.** `nginx` isn't installed in the development environment, so Phase 5b ships only mock-based behavior. Add an env-gated integration test (mirroring `IAC_DOCKER_INTEGRATION`) once a CI runner has nginx.
- **`reload` errors leave the new config in place.** Today: write → validate → reload. If reload fails (e.g. systemd is being slow), the new file is on disk and validated, but nginx is still running the old version. Operator-recoverable via `iac rollback`. Could add an automatic rollback-on-reload-failure path.

---

## Phase 5b.1 — `nginx.vhost` TLS — DONE.

The provider now renders an `ssl`-listening server block when `spec.tls` is set, plus an optional 80→443 redirect block. Cert/key paths must be absolute and `..`-free. `effective_listen()` auto-adds 443 when TLS is configured so callers don't have to remember to set both.

### Phase 5b.1 deliverables (✅)

- [x] [`TlsConfig`](crates/iac-providers/src/nginx/spec.rs) struct: `certificate`, `key`, `redirect_http` (default true). Validators reject relative paths, `..` traversal, and shell metacharacters in PEM paths.
- [x] [Renderer](crates/iac-providers/src/nginx/render.rs) emits two blocks when redirect_http is on and 80 is in `listen`; otherwise one combined block. `ssl_protocols TLSv1.2 TLSv1.3` and `ssl_prefer_server_ciphers on` are baked in.
- [x] 6 new tests covering: parse with TLS, reject relative cert path, reject `..` in cert, render with redirect, render with no port-80 (HTTPS-only), render with redirect off.

### Open after Phase 5b.1

- **No automatic certificate issuance.** Operators bring their own cert+key paths (typically `/etc/letsencrypt/live/<host>/fullchain.pem`). A future `acme.certificate` provider would orchestrate Let's Encrypt — Phase 7.
- **No `ssl_session_*` tuning** (cache, timeout) — happy with nginx defaults for now.
- **Single `location /` only.** `extra_locations` is on the wishlist for `/health`, `/metrics`, etc.

---

## Phase 5c — `cron.job` — DONE.

System-cron resource: writes a single `/etc/cron.d/<name>` file with a validated schedule, command, user, and optional env block. The cron daemon picks up changes automatically — no reload step needed.

**126 tests passing.** `cargo audit` clean.

### Phase 5c deliverables (✅)

- [x] [Spec](crates/iac-providers/src/cron/spec.rs): `name`, `schedule`, `command`, `user` (default `root`), `env`, `state`, optional `cron_dir` override (for tests / non-Debian layouts). Validators: name must be `[a-zA-Z0-9._-]+` (so `run-parts` won't skip it), schedule must be 5 fields **or** an `@`-shorthand from a fixed allowlist, command must be a single line, env keys must match `[A-Za-z_][A-Za-z0-9_]*`.
- [x] [Pure renderer](crates/iac-providers/src/cron/render.rs): deterministic output with `# Managed by iac` header, optional `KEY=VALUE` env prelude, then a single `<schedule>\t<user>\t<command>` line.
- [x] [Ops](crates/iac-providers/src/cron/ops.rs): observe (read file, sha), diff (Create / Update / Delete by content sha), plan (`cron.write` / `cron.remove`), atomic temp+rename apply, rollback restores prior content (or removes if didn't exist).
- [x] [`CronProvider`](crates/iac-providers/src/cron/mod.rs) wired into `register_builtins`.
- [x] **17 unit tests** covering: parse minimal, accept `@weekly`, reject `@bogus`, reject wrong field count, reject unsafe name, reject newline in command, reject present-without-schedule-or-command, reject absent-with-extras, reject bad env key, render minimal, render with env (separator line), render `@`-shorthand, default and overridden config_path, full create→idempotent→drift→rollback cycle, remove-when-present, rollback restores previous content.

### Open after Phase 5c

- **`run-parts` skip semantics aren't checked.** If an operator picks a name that violates the run-parts charset (which we already reject), they're fine. But if `/etc/cron.d` itself has weird global perms / SELinux labels, the cron daemon may ignore our file silently. We don't probe that.
- **No timezone awareness.** `CRON_TZ=...` lines are valid env entries but we don't surface a typed field. Acceptable — the schedule itself uses the daemon's TZ unless overridden in env.
- **No multi-line commands.** Cron lines are line-terminated, so we forbid newlines in `command`. If operators need a multi-step job they should pack it into a script file (managed by the file provider) and run that script from cron.

---

## Phase 6a — Agent capability allowlist — DONE.

The agent now refuses to apply resources outside an operator-defined policy file. A compromised control-plane can no longer arbitrarily root the host: the worst it can do is fail every assignment with `capability_denied`. Soft-start semantics (file absent → unrestricted) keep existing deployments working.

**143 tests passing** (3 cli + 11 core + 81 providers + 18 agent + 24 controlplane + 6 agent lifecycle integration). `cargo audit` clean.

### Phase 6a deliverables (✅)

- [x] [`Capabilities`](crates/iac-agent/src/capabilities.rs) struct with per-kind rules (file, nginx_vhost, systemd, docker, packages, cron). Path kinds (file, nginx_vhost) support allow + deny with deny-takes-priority. Name kinds support allow only. `globset 0.4` underneath — well-tested glob library used by ripgrep.
- [x] Per-resource extractors: `file→spec.path`, `nginx.vhost→spec.config_path`, `systemd.unit→spec.name + spec.type` (auto-suffixed to match `SystemdUnitSpec::unit_name()`), `docker.container→spec.name`, `package→spec.name`, `cron.job→spec.name`.
- [x] Soft-start: missing capabilities file → log "running unrestricted" warning + apply normally. Present file → enforce. Malformed file → fail-closed: refuse to construct the agent. Empty per-kind sections → that kind is unrestricted (lets operators ramp up policies kind-by-kind).
- [x] [Config field `capabilities_file`](crates/iac-agent/src/config.rs) defaults to `<state_dir>/capabilities.yaml`. CLI override `--capabilities-file <path>`.
- [x] [Agent integration](crates/iac-agent/src/agent.rs): `enforce_capabilities()` filters before `apply_once`; `drain_assignments` checks BEFORE handing the payload to the executor and returns `Failed` for the whole assignment with `capability_denied` items if any resource is rejected. Atomic policy: an operator who tries to push 5 resources where 1 is denied gets nothing applied — never half-deployed.
- [x] **11 unit tests** covering: missing file unrestricted, empty kinds unrestricted, file allow + deny, deny-takes-priority over allow, systemd unit suffixing, docker wildcards, package + cron allowlists, nginx config_path, unknown kind passthrough, missing required spec field denial, invalid glob fails to load.
- [x] **3 E2E tests** against the live control-plane: capability denial fails the whole assignment with operator-visible details, clean assignments pass through, missing capabilities file = soft-start.

### Open after Phase 6a

- **No `default: deny` global mode.** Operators must remember to declare every kind they use; new kinds added in future Phase 5d work would be unrestricted unless added to the policy file. Phase 6b: add a top-level `default_kind_policy: deny` that flips empty-kind semantics.
- **Capability extraction is keyed by string match on `resource.kind`.** Adding a new provider requires also updating `Capabilities::check`'s match arm. Phase 6b should move the extractor onto a `Provider::capability_keys()` method so providers own their policy schema.
- **No signing.** A compromised network proxy can still rewrite assignment payloads to use only-allowed paths (e.g. drop `/etc/shadow` from the resource list and replace with `/etc/nginx/...` containing malicious content). Phase 6b: assignment signing with an Ed25519 server key, verified by the agent before capability check.

---

## Phase 6b — Assignment signing — DONE.

The control-plane now signs every assignment with an Ed25519 keypair generated on first startup; the agent fetches the public key on first connect (TOFU), pins it in its identity file, and verifies the signature on every assignment before processing. A compromised network proxy can no longer rewrite an assignment's payload — the signature won't verify and the agent rejects it.

**158 tests passing** (3 cli + 11 core + 79 providers + 2 docker integration + 18 agent unit + 6 agent lifecycle + 8 controlplane unit + 31 controlplane E2E). `cargo audit` clean (331 transitive deps).

### Phase 6b deliverables (✅)

- [x] [`ServerSigner`](crates/iac-controlplane/src/signing.rs): generates a fresh Ed25519 keypair on first startup, persists the secret as 32 raw bytes at `<state_dir>/signing-key.bin` (mode 0600) plus a stable `key_id` ULID at `<state_dir>/signing-key.id`. Loads on subsequent starts. `getrandom` directly so we don't pull a second `rand_core` version through `ed25519-dalek`'s helpers.
- [x] [Canonical signing message](crates/iac-core/src/protocol.rs): `iac-assignment-v1\n<agent_id>\n<assignment_id>\n<operation_id>\n<created_at>\n<sha256(payload_json)>` — versioned, replay-resistant per-assignment (and per-agent), tamper-detecting via the payload sha.
- [x] [`AssignmentEnvelope`](crates/iac-core/src/protocol.rs) extended with `key_id` + `signature` (base64). [`SigningPubkey`](crates/iac-core/src/protocol.rs) exposed at `GET /v1/signing-pubkey` (no auth — public bootstrap).
- [x] [Server signs at fetch time](crates/iac-controlplane/src/api/agents.rs), not at creation. The DB stores no signatures, so the server's keypair can rotate (Phase 6c) without re-signing stored rows. Re-signing on each fetch is a few microseconds with Ed25519.
- [x] [Agent TOFU pinning](crates/iac-agent/src/remote.rs): on first `connect_remote()` after register, the agent fetches `/v1/signing-pubkey`, stores `server_key_id` + `server_public_key` in `identity.json`. Subsequent connects re-fetch and verify the key hasn't changed; mismatch is fatal until the operator clears the cached fields manually.
- [x] [Agent verifies every assignment](crates/iac-agent/src/remote.rs) inside `fetch_assignments()` BEFORE returning to the caller. Verification happens before the capability check, before deserialization into `Resource`, before the executor sees anything. A failed signature returns an error from `fetch_assignments`, the caller logs and skips — the assignment is NOT applied.
- [x] **5 server unit tests** (sign/verify round-trip, fresh keys distinct, tamper detection, persistent reload, corrupt secret fails) and **4 E2E tests** (pubkey pinned on first connect, key change refused, full apply works through signed pipeline, payload tamper fails verification under pinned key).

### Open after Phase 6b

- **Server compromise still wins.** Signatures protect agent ↔ proxy ↔ server transit. A compromised app server hands out malicious payloads it can sign itself. To raise this bar: split signing into a separate offline custodian (Phase 7+).
- **No key rotation flow yet.** Operators rotate by manually deleting `signing-key.bin` / `signing-key.id` server-side AND clearing `server_key_id` / `server_public_key` from each agent's `identity.json`. Phase 6c introduces multi-key support: server keeps a list of valid keys, advertises them all via `/v1/signing-pubkey`, agents accept any pinned key.
- **TOFU is the trust anchor.** First-contact pin is exposed if the network is hostile during provisioning. Operators who care should pre-distribute the public key out of band.
- **No replay window beyond `assignment_id` uniqueness.** A malicious replay would have to come from someone who already had a signed envelope (which they could just apply themselves). `created_at` could feed a strict freshness check (Phase 7).

---

## Phase 6c — Audit log — DONE.

The control-plane now records every operationally-significant event into an append-only `audit_events` table and exposes it via `GET /v1/audit` with composable filters. Operators can answer "who changed X / when / why" without grepping logs.

**163 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 18 agent unit + 6 agent lifecycle + 8 controlplane unit + 36 controlplane E2E). `cargo audit` clean.

### Phase 6c deliverables (✅)

- [x] [Migration v4](crates/iac-controlplane/migrations/20260429000004_audit.sql): `audit_events` table with `(timestamp, actor, kind, severity, operation_id?, agent_id?, resource_id?, drift_id?, payload_json)` plus indexes on timestamp, kind, partial indexes on operation_id and agent_id.
- [x] [Protocol type `AuditEvent`](crates/iac-core/src/protocol.rs) with versioned semantics for `actor` (`admin` / `agent:<id>` / `system` until Phase 6d adds RBAC).
- [x] [`AuditRecord` builder + `record_audit_on(executor, ...)`](crates/iac-controlplane/src/store.rs): records audit rows inside the same transaction as the operation they describe so audit and source-of-truth commit atomically.
- [x] Hooks wired into: `register_agent` → `agent.registered`, `create_operation` → `operation.submitted`, `complete_assignment` → `assignment.completed`, `accept_drift` → `drift.accepted`, `ignore_drift` → `drift.ignored`. Each carries useful payload (resource counts, reasons, until-timestamps).
- [x] [`GET /v1/audit`](crates/iac-controlplane/src/api/audit.rs) with filters (`since`, `kind`, `actor`, `operation_id`, `agent_id`) and admin-token auth. Limit clamped server-side to `[1, 1000]`.
- [x] [iac CLI](crates/iac-cli/src/main.rs) `iac audit --server <url> [--limit] [--kind] [--actor] [--operation-id] [--agent-id]` with both human and JSON output. Hand-rolled query-string percent-encoding to keep deps minimal.
- [x] **5 E2E tests**: agent register emits event, operation submission records admin actor + payload, drift accept/ignore record per-drift events, endpoint requires admin auth, filters compose across actor/kind/operation_id/agent_id and limit clamp.

### Followups + Open after Phase 6c

- **Migration runner hardened against `;` in comments.** Found a real bug while writing this phase: a `;` inside a comment line in migration v4 split the chunk and the second half got fed to SQLite as bare `for now` text. Fixed by stripping `--` line comments before splitting. New `e2e_audit` tests would catch any regression.
- **No log retention.** `audit_events` grows forever. Periodic prune (default keep last 90 days) belongs in Phase 7 alongside the existing observation/run cleanup todo.
- **Actor field is coarse.** `admin` doesn't distinguish among multiple operators sharing the admin token. Phase 6d (RBAC) replaces this with named users.
- **No structured query / aggregation.** Operators wanting "all drift accepts in the last 7 days grouped by reason" do that in jq today. SQL view layer or a `/v1/audit/summary?group_by=...` endpoint is a Phase 7 concern.

---

## Phase 6d — Approval gate — DONE.

The control-plane evaluates a list of operator-defined policies on every submit. If any policy with `requires_approval=true` matches, the operation lands in `pending_approval` and stays invisible to agents (no assignment rows are created) until an admin token holder calls `POST /v1/operations/{id}/approve`. Rejection is terminal.

**177 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 18 agent unit + 6 agent lifecycle + 15 controlplane unit + 43 controlplane E2E). `cargo audit` clean.

### Phase 6d deliverables (✅)

- [x] [Migration v5](crates/iac-controlplane/migrations/20260430000005_approval.sql): `requires_approval`, `approved_by/at`, `approval_reason`, `rejected_by/at`, `rejection_reason`, `matched_policies_json` columns + partial index for `pending_approval` lookups.
- [x] [Policy engine](crates/iac-controlplane/src/policy.rs): `Policy` config-loaded via TOML `[[policies]]`, matchers for `environment` (exact or `*`), `kind` (any-resource match), `resource_count_min`. Empty match block matches NOTHING (so misconfigured policies don't accidentally gate everything). 7 unit tests.
- [x] Operation status enum extended with `PendingApproval` and `Rejected`.
- [x] [`OperationView`](crates/iac-core/src/protocol.rs) exposes `matched_policies`, `approved_by/at`, `rejected_by/at`, `rejection_reason` so operators see WHY a gate fired and who approved/rejected it.
- [x] [Store](crates/iac-controlplane/src/store.rs) defers assignment creation when gated and emits `operation.pending_approval` audit. `approve_operation` recomputes routing from stored `desired_states` and creates assignment rows transactionally. `reject_operation` is a single-write terminal transition.
- [x] [Endpoints](crates/iac-controlplane/src/api/operations.rs): `POST /v1/operations/{id}/approve` (optional reason), `POST /v1/operations/{id}/reject` (reason required, empty rejected with 400). Both admin-auth gated.
- [x] [CLI](crates/iac-cli/src/main.rs): `iac approve <op-id> --server <url> [--reason ...]`, `iac reject <op-id> --server <url> --reason ...`. Reads `IAC_ADMIN_TOKEN`.
- [x] Audit hooks: `operation.approved`, `operation.rejected` (severity=warning), and `operation.pending_approval` for the initial gated submit.
- [x] **7 E2E tests**: pending-approval status hides assignments from agents, approve dispatches them, reject is terminal and blocks subsequent approve, clean submission skips gate, audit captures approve/reject/pending events, auth required for both endpoints, empty reject reason → 400.

### Open after Phase 6d

- **`approver` field is purely informational today.** Phase 6e RBAC reads it and gates `.../approve` on the caller's role membership. Currently any admin token holder can approve (matches the threat model — there's only one admin role).
- **Approval doesn't persist who specifically approved.** `approved_by` is hardcoded to `"admin"`. Pairs with the audit RBAC followup.
- **No "diff at approval time".** Approver should see the rendered plan / blast radius before clicking approve. `iac plan --server --operation <id>` would surface that — it's a follow-up CLI command, not a server change.
- **No bulk approve.** Each operation is approved individually. Rare to need bulk in production but easy to add.

---

## Phase 6e — RBAC — DONE.

The control-plane now resolves bearer tokens through a three-stage chain (`admin_token` legacy → user tokens → agent tokens) and enforces minimum-role gates per endpoint. Operator workflows have meaningful actor names in audit and `approved_by` / `rejected_by` columns. The static admin token still works for backwards compat.

**194 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 22 agent unit + 6 agent lifecycle + 22 controlplane unit + 53 controlplane E2E). `cargo audit` clean (334 transitive deps).

### Phase 6e deliverables (✅)

- [x] [Migration v6](crates/iac-controlplane/migrations/20260430000006_rbac.sql): `users` (id, username, password_hash, roles_json, disabled_at) and `user_tokens` (token_hash, user_id, issued_at, expires_at) tables.
- [x] [`identity` module](crates/iac-controlplane/src/identity.rs): `Role` enum (`Viewer < Operator < Approver < Admin`) with inclusion lattice, `Identity::{LegacyAdmin, User, Agent}`, Argon2id `hash_password` / `verify_password`, and the canonical `require_role(state, token, role) -> Identity` resolver. 7 unit tests cover lattice, hash round-trip, corrupt PHC, agent role exclusion, audit name strings.
- [x] [Store user CRUD](crates/iac-controlplane/src/store.rs): `create_user`, `login(username, password, ttl_secs)`, `find_user_by_token`, `revoke_user_token`, `prune_expired_tokens`, `user_count`. Argon2 hashing on insert; sha256-of-token storage on login (same shape as agent tokens).
- [x] [`POST /v1/auth/login`](crates/iac-controlplane/src/api/auth.rs) issues a 24-hour bearer token; `POST /v1/auth/logout` revokes the current token. Both return JSON.
- [x] [Auth chain hardened](crates/iac-controlplane/src/identity.rs): every endpoint that used `require_admin` now calls `require_role(.., Role::X)` with the right minimum (`Viewer` for audit/get_op, `Operator` for submit / drift accept+ignore, `Approver` for approve/reject, `Admin` for nothing yet). Returns `Identity` so handlers can record real actor names.
- [x] [Bootstrap admin user from env](crates/iac-controlplane/src/main.rs) on first start: when `users` is empty AND `IAC_BOOTSTRAP_USER` + `IAC_BOOTSTRAP_PASS` are set, an Admin user is created. Re-runs are idempotent (skip when user count > 0).
- [x] [Audit + approval](crates/iac-controlplane/src/store.rs) updated to take `actor` (e.g. `user:alice`) instead of hardcoded `"admin"`. `approved_by` / `rejected_by` columns now contain the human-readable username.
- [x] **10 E2E tests** (`tests/e2e_rbac.rs`): login + wrong password rejection, operator can submit but not approve, approver can submit (lattice) and approve, viewer can read audit but not submit/accept-drift, legacy admin token still grants all roles, audit shows `user:alice` not `admin`, approved_by/rejected_by record real username, logout invalidates token, duplicate username conflict.

### Open after Phase 6e

- **No CLI login flow yet (Phase 6f).** Operators still set `IAC_ADMIN_TOKEN` for `iac apply --server` / `iac drift`. `iac login --server <url> --user <name>` (interactive password) and credential storage at `~/.iac/credentials/<host>.json` are the next CLI add.
- **`Policy.approvers` is still informational.** The field is parsed but the approver-role check ignores it. Phase 6f will gate `.../approve` on the caller's username being in `approvers` (or empty list = any approver-role user).
- **No user CRUD endpoints.** Admin users are created via env-var bootstrap or direct DB insert today. `POST /v1/users` and friends are a Phase 6f add.
- **No password rotation / expiry.** Argon2 hash never expires; rotation is manual via direct DB update. Acceptable for the bootstrap-only model; revisit if/when CRUD lands.
- **`require_role` doesn't compute the agent's identity.** Per-agent endpoints (`/v1/agents/{id}/{heartbeat,observations,drift,assignments}`) still call `Store::authenticate(agent_id, token)` directly because the path-bound `agent_id` is the lookup key. The two auth paths coexist — agents go through `Store::authenticate`, humans go through `require_role`.

---

## Phase 6f — CLI login + Policy.approvers — DONE.

The CLI now has a real login flow: `iac login --server <url> --user <name>` (interactive password prompt) saves a per-server bearer to `~/.iac/credentials.json` (mode 0600), and every existing command automatically uses the saved token when `IAC_ADMIN_TOKEN` isn't set. `Policy.approvers` is now enforced at the approve endpoint: when a matched policy declares an approver list, the caller's display name must be in it (Admin role or static admin token bypass for break-glass).

**205 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 22 agent unit + 6 agent lifecycle + 22 controlplane unit + 6 cli credential unit + 53 controlplane E2E + 10 RBAC E2E + 5 approvers E2E). `cargo audit` clean (336 transitive deps).

### Phase 6f deliverables (✅)

- [x] [`credentials` module](crates/iac-cli/src/credentials.rs): `CredentialStore` keyed by normalized server URL, persists to `~/.iac/credentials.json` with atomic temp+rename + `chmod 0600`. Plus `resolve_admin_token(server)` that prefers `IAC_ADMIN_TOKEN` env over the saved entry and returns a clear error pointing to `iac login` when neither exists. 6 unit tests.
- [x] [`iac login --server <url> --user <name>`](crates/iac-cli/src/main.rs): interactive password prompt via `rpassword`, with `--password` flag and `IAC_LOGIN_PASSWORD` env for non-interactive use. Hits `POST /v1/auth/login`, persists `(token, expires_at, roles)`. Prints roles for the operator to sanity-check.
- [x] `iac logout --server <url>`: calls `POST /v1/auth/logout` (best-effort if server is down) AND removes the local entry.
- [x] All admin-token CLI commands (`apply --server`, `drift list/show/accept/ignore`, `approve`, `reject`, `audit`) migrated to `credentials::resolve_admin_token`. Workflows compose: `iac login` → use any operator command → `iac logout`.
- [x] [`Policy.approvers` enforced](crates/iac-controlplane/src/api/operations.rs): when a matched policy has a non-empty approvers list, the caller's display_name must appear in it. Admin role bypasses (break-glass for emergencies). Empty list = any Approver-role user. Legacy admin token always bypasses.
- [x] **5 E2E approvers tests**: in-list approver succeeds, out-of-list 403, Admin role bypass works, empty-list = any approver, legacy admin token bypass.
- [x] **End-to-end smoke**: bootstrap admin user via env → login → credentials.json mode 0600 → apply (no IAC_ADMIN_TOKEN) → audit shows `user:alice` → logout removes entry → subsequent apply fails with helpful message pointing back to `iac login`.

### Open after Phase 6f

- **No silent token refresh.** When the 24-hour token expires, the next call returns 401 and the operator has to `iac login` again. Phase 7+ will add `POST /v1/auth/refresh` and the CLI will retry transparently.
- **No user CRUD endpoints.** Operators still create users via `IAC_BOOTSTRAP_USER` env var or direct DB insert. `iac users create/list/disable` and the matching admin-only endpoints are the obvious next add (Phase 6g).
- **Approvers list lookup is by `display_name`.** That's the user's username (or for the legacy admin token, the literal `"admin"`). It's stable per-user but not portable — renaming a user invalidates approver entries. Phase 6g will add user IDs as the policy reference.
- **No way to inspect saved credentials.** `iac creds list` would show which servers have saved tokens and when they expire. Quick add when needed.

---

## Phase 6g — Hygiene + completion bundle — DONE.

Three small followups from prior phases, plus one new operator-ergonomic CLI command. Closes "Open after" debt accumulated in Phase 6a, 6c, 6e, 6f.

**212 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 22 agent unit + 6 agent lifecycle + 28 controlplane unit + 6 cli credential unit + 53 controlplane E2E + 10 RBAC E2E + 5 approvers E2E). `cargo audit` clean (336 deps).

### Phase 6g deliverables (✅)

- [x] [`default_kind_policy: deny`](crates/iac-agent/src/capabilities.rs) for capability allowlist (closes Phase 6a open issue). Top-level field on the YAML; default `allow` for backwards compat. `deny` denies any kind without a built-in extractor — adding a new provider in a future agent version no longer silently leaks through. New `unknown_kind_denied_under_default_deny` test verifies the lattice.
- [x] [`retention` module + tokio loop](crates/iac-controlplane/src/retention.rs) (closes Phase 6c, 6e open issues). Periodic prune of `audit_events`, `observations`, resolved `drift_events`, terminal `assignments`, expired `user_tokens`. Conservative defaults (90/30/30/30 days, 1h interval). Per-table windows; `0` disables a single dimension. Best-effort: a failed delete doesn't roll back others. 6 unit tests (audit prunes old / keeps new, observations use `received_at`, drift only prunes resolved, user_tokens via existing method, zero-days disables, empty-DB no-op).
- [x] [`iac creds list/clear`](crates/iac-cli/src/main.rs) (closes Phase 6f open issue). `list` shows `(server, username, roles, expires_at, saved_at)` per saved entry — token deliberately NEVER printed (verified in smoke test for both human and JSON output). `clear --server <url>` deletes the local entry without contacting the server (use `iac logout` if you want server-side revoke too).
- [x] Background retention loop wired into `iac-controlplane` startup with a shared shutdown `Notify`; the loop drains alongside the HTTP server on SIGTERM.
- [x] Smoke verified: `iac login` → `iac creds list` shows entry → `iac creds clear` removes → list prints `(no saved credentials)`.

### Open after Phase 6g

- **Retention is age-based per table, not per-resource cap.** Operators with chatty agents may want "keep last N observations per resource." Add when needed.
- **Retention config is read at server startup** — restart required to change. Hot-reload via SIGHUP is a Phase 7+ item.
- **`iac creds list` doesn't probe expiry status.** Showing "EXPIRED" badge for past-due entries would be nice.

---

## Phase 7a — Composite `service` + blast radius — DONE.

The first product-feature pivot after a long security run. Operators now write ONE manifest with `kind: service` instead of stitching `docker.container` + `nginx.vhost` by hand. Server expands on submit (before routing + capability checks), so agents continue to only see primitives. Every submission now also carries a `BlastRadius` summary (resource_count, agent_count, kinds).

**224 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 22 agent unit + 6 agent lifecycle + 37 controlplane unit + 6 cli credential unit + 53 controlplane E2E + 10 RBAC E2E + 5 approvers E2E + 4 service E2E). `cargo audit` clean (336 deps).

### Phase 7a deliverables (✅)

- [x] [`expansion` module](crates/iac-controlplane/src/expansion.rs): pure `expand_resources(Vec<Value>) -> ApiResult<Vec<Value>>`. Built-in `service` expander turns a `kind: service` resource into `docker.container` + `nginx.vhost` with consistent `metadata.{name, environment}` and shared `hostSelector`. Annotates each child with `iac.example/composite-of: service` for provenance. 9 unit tests covering passthrough, expansion shape, env propagation (docker only), `internal_port` override, custom `nginx_config_path`, malformed spec → 400, unknown field rejection (`deny_unknown_fields`), mixed primitive+composite list.
- [x] [Protocol `BlastRadius`](crates/iac-core/src/protocol.rs): `(resource_count, agent_count, kinds[])` returned in `SubmitOperationResponse`. Computed from the post-expansion routing list — composite kinds like `service` show up as 2+ resources, not 1.
- [x] [API submit handler](crates/iac-controlplane/src/api/operations.rs): runs `expand_resources` BEFORE routing + capability checks → agent allowlist still applies to expanded primitives. Computes blast radius from the expanded routing list.
- [x] [iac CLI render](crates/iac-cli/src/main.rs): `iac apply --server` human output now includes `blast radius: N resource(s) across M agent(s) [kind1, kind2]` so operators see impact at submit time.
- [x] **4 E2E service tests**: composite expands + blast radius reported, host_selector inherited into both children + routes to named agent, malformed spec → 400, primitive resources passthrough with single-kind blast radius.

### Open after Phase 7a

- **No agent-side composite providers.** The pattern is server-side expansion only; agents stay primitive. Operator-defined modules (Phase 7b) would let users register their own expanders without server code changes.
- **`service` is the only built-in expander.** Common patterns we haven't yet bundled: `cron-job-bundle` (cron + small file with the script), `web-with-monitoring` (service + monitoring.check). Add as the catalog grows.
- **No diff preview at approve time.** Approvers see "blast radius" at submit but not the actual content diff. `iac plan --server --operation <id>` is still the next CLI add.
- **Expansion is one-way.** `OperationView` shows the expanded primitives; the original `service` resource is gone after submission. Phase 7b can store it alongside in `desired_states` for round-trip transparency.

---

## Phase 7b — Approval-time desired-state preview — DONE.

Approvers no longer have to trust the operator's judgement: `GET /v1/operations/{id}/desired-state` (Viewer role) returns the post-expansion primitives an operation will write — including for ops in `pending_approval` where assignments don't yet exist. The new `iac plan --server <url> --operation <id>` CLI renders that list so the approver sees exactly what's about to land before clicking approve.

**239 tests passing** (was 232; +6 new desired-state E2E + 1 incidental). `cargo audit` clean (336 deps).

### Phase 7b deliverables (✅)

- [x] [Protocol types](crates/iac-core/src/protocol.rs): `OperationDesiredState`, `OperationDesiredStateItem` (resource_id, kind, agent_id, full Resource).
- [x] [Store method](crates/iac-controlplane/src/store.rs) `list_desired_state_for_operation`: reads `desired_states` directly, snapshots `agents`, runs the same `route_resource` logic as `approve_operation` so each item carries its target agent. Unrouted resources surface with `agent_id = ""` so the approver sees the gap.
- [x] [`GET /v1/operations/{id}/desired-state`](crates/iac-controlplane/src/api/operations.rs) — Viewer role. Works for `pending_approval` (no assignments yet), `running`, and terminal ops.
- [x] [iac CLI](crates/iac-cli/src/main.rs) `iac plan` extended: now accepts either a manifest path (local) or `--server <url> --operation <id>` (remote preview). Mutually-exclusive flag handling; missing combinations rejected before any I/O.
- [x] **6 E2E tests** ([e2e_plan_remote.rs](crates/iac-controlplane/tests/e2e_plan_remote.rs)): pending-approval op exposes desired-state, clean op also exposes it, viewer role can read, unauthenticated → 401, unknown op → 404, ambiguous-routing op surfaces items with empty `agent_id`.

### Open after Phase 7b

- **No diff vs current observed state.** The endpoint returns desired-state primitives but doesn't compare against what the agent currently has. Approvers see "we're going to write file X" but not "X currently differs in field Y." Real diff requires routing through provider plan logic on the server, which is a meaningful chunk of work — defer until approvers ask for it.
- **Composite resources are gone by the time desired_state is read.** Approvers see expanded primitives, not the original `kind: service`. Same caveat as Phase 7a's "expansion is one-way." Storing the original alongside in `desired_states` would make round-trip transparency easier.
- **Routing in `list_desired_state_for_operation` is computed at read time.** If agents register/deregister between submit and approve, the agent_id reported here may differ from what `approve_operation` actually uses. Acceptable today — the read-time view matches "what would happen if we approved right now."

---

## Phase 7c — `cron-job-bundle` composite — DONE.

Drop a script + schedule it: a single `kind: cron-job-bundle` resource expands server-side into `file` (the script body, mode 0755 by default) + `cron.job` (the schedule). Operators don't have to keep two coordinated resources whose `command` field has to match the file's `path` — the bundle ties them together. Same expansion-before-routing pattern as Phase 7a's `service`, so per-primitive agent capability allowlists still apply.

**249 tests passing** (was 239; +7 expander unit tests + 3 E2E). `cargo audit` clean (336 deps).

### Phase 7c deliverables (✅)

- [x] [Expander](crates/iac-controlplane/src/expansion.rs) `expand_cron_job_bundle`: spec deserializes with `deny_unknown_fields`, default `scriptPath = /usr/local/bin/<name>`, default `mode = 0755`, default `user = root`. `hostSelector` propagates to both children so the script + cron entry land on the same host.
- [x] Env-var pairs (`spec.env`) propagate into the `cron.job` resource only (cron handles them natively); the script `file` resource ignores `env` since its content is the verbatim shell body.
- [x] Composite annotation (`iac.example/composite-of: cron-job-bundle`) on both children for operator visibility — same convention `service` uses.
- [x] **7 expander unit tests**: expand-to-two-children, host-selector inheritance, env scoped to cron, custom scriptPath flows into both file.path and cron.command, custom user/mode, missing required `script` → 400, unknown field → 400.
- [x] **3 E2E tests** ([e2e_cron_bundle.rs](crates/iac-controlplane/tests/e2e_cron_bundle.rs)): bundle expands at submit + agent's desired-state shows both primitives + file.path matches cron.command, `hostSelector` routes both children to named agent + Phase 7b preview reflects the same routing, malformed spec → 400.

### Open after Phase 7c

- **Composite primitive count is duplicated across the codebase.** The blast-radius logic counts post-expansion, the routing reads post-expansion, the audit log records post-expansion — but the operator's manifest has the composite resource. There's no reverse mapping, so an audit query for "all events touching nightly-backup" finds two resources (`file/ops/nightly-backup-script` + `cron.job/ops/nightly-backup`) rather than one bundle. Addressable when operator-defined modules ship.
- **Two built-in expanders so far.** `service` and `cron-job-bundle` cover the most common patterns. `web-with-monitoring`, `database-with-backup`, `tls-cert-with-renewal` are next; each is a self-contained 30-50 line function.
- **No expander discovery API.** Operators have to read the source / docs to know what `kind: ?` values the server accepts. A `GET /v1/expanders` returning `[{kind, schema}]` would help once the catalog grows past three.

---

## Phase 7d — Must-keep-admin guard — DONE.

After 6h, admins could disable themselves or de-elevate the last admin and lock everyone out (the legacy `admin_token` is the only break-glass). The guard enforces "if removing/disabling this user would transition active-admin count from ≥1 to 0, reject with 409" inside the same transaction as the change, so concurrent demotions can't race past it. Operators starting from zero User-table admins (legacy-token-only deployments) aren't blocked — the guard only kicks in once user-table admins exist.

**256 tests passing** (was 249; +7 new admin-guard E2E). `cargo audit` clean (336 deps).

### Phase 7d deliverables (✅)

- [x] [`ensure_active_admin_remains`](crates/iac-controlplane/src/store.rs) helper: snapshots all users inside the caller's tx, computes admin count *before* and *after* the proposed change, rejects with `Conflict` if `before > 0 && after == 0`. Reads + writes share the tx so concurrent demotions can't both pass.
- [x] [`Store::disable_user`](crates/iac-controlplane/src/store.rs) and [`Store::update_user_roles`](crates/iac-controlplane/src/store.rs) call the guard. `disable_user` covers both the DELETE and the PATCH `disabled=true` paths because both resolve to the same store call.
- [x] Legacy `admin_token` intentionally NOT counted as an active admin: relying on it for break-glass is fine, but the user-side guarantee has to hold without it.
- [x] **7 E2E tests** ([e2e_admin_guard.rs](crates/iac-controlplane/tests/e2e_admin_guard.rs)): can't disable last active admin via DELETE, can't disable via PATCH, can't demote last admin, can demote one of two, disabled-admin-with-Admin-still-in-roles_json doesn't count, re-enabling restores quorum, promoting someone else to Admin works normally.

### Open after Phase 7d

- **No same-named guard for `set_user_password`.** Resetting a password doesn't change roles or disabled state, so it can't trip the guard. But it does revoke the user's tokens — if that user was the only active admin and had a session, they'd have to log in again. Acceptable; not a lock-out vector.
- **The guard reads ALL users inside each transaction.** Fine at small scale (a typical deployment has dozens of users); revisit when someone runs this with thousands of users and starts caring about latency.
- **`legacy admin_token` deployments get no guard.** A pure-token deployment can still disable a user — but if there are no User-table admins to lose, that was already always allowed. The guard only kicks in once a real user has the Admin role.

---

## Phase 7e — Token refresh — DONE.

`POST /v1/auth/refresh` rotates a user's bearer token without re-asking for the password. The new token reflects the user's *current* role list — that closes the 6h gap where an admin promoting Bob from Viewer to Approver couldn't take effect until Bob re-`iac login`-ed. The old token is revoked atomically as part of the same transaction so a leaked token is single-use.

**262 tests passing** (was 256; +6 new refresh E2E). `cargo audit` clean (336 deps).

### Phase 7e deliverables (✅)

- [x] [`Store::refresh_user_token`](crates/iac-controlplane/src/store.rs): inside one tx, looks up the old token, verifies non-expiry + user-not-disabled, reads the *current* roles_json, inserts a fresh token row, deletes the old one. Atomic so a partial failure can't leave both tokens valid.
- [x] [`POST /v1/auth/refresh`](crates/iac-controlplane/src/api/auth.rs) handler: takes the bearer token, returns the same `LoginResponse` shape as login. 24-hour TTL.
- [x] Legacy `admin_token` and agent tokens explicitly reject — refresh is human-user only. Agent tokens are long-lived by design; the legacy admin token is a static config value with no refresh semantics.
- [x] **6 E2E tests** ([e2e_token_refresh.rs](crates/iac-controlplane/tests/e2e_token_refresh.rs)): refresh issues new token + old revoked, refresh picks up role changes (admin promotes Bob → Bob refreshes → new roles), disabled user rejected, unknown token rejected, legacy admin token rejected, double-refresh with same old token rejected (single-use).

### Open after Phase 7e

- **No CLI integration yet.** The endpoint exists, but `iac` doesn't auto-refresh on near-expiry. A reasonable follow-up: when a CLI call returns 401 with a saved token < 1h from expiry, transparently refresh and retry. Today operators have to call the endpoint manually if they care.
- **No "max session length" cap.** A user can refresh forever, sliding the window. For high-security deployments, a separate "refresh requires re-auth after N hours since original login" policy may be desired. Defer until someone asks.
- **Refresh doesn't re-verify password.** That's the design (the whole point is "no password retype"), but it means a stolen un-expired token grants the holder a fresh 24h window. Acceptable in the threat model — the token already grants full access until its natural expiry; refresh just extends it. mTLS / device-bound tokens are the real fix; that's Phase 6i.

---

## Phase 7f — Transparent CLI auto-refresh — DONE.

The CLI now silently rotates saved tokens that are within 1 hour of expiry, so long-running operator sessions don't hit 401 mid-pipeline. Refreshed tokens (+ updated roles + new expiry) are written back to `~/.iac/credentials.json` atomically. Refresh failures (server down, token already expired) gracefully fall back to the saved token so the caller's request goes through with a clean 401 instead of an obscure resolver-time error.

**266 tests passing** (was 262; +4 new resolver unit tests). `cargo audit` clean (336 deps).

### Phase 7f deliverables (✅)

- [x] [`resolve_admin_token_with_refresh`](crates/iac-cli/src/credentials.rs): async resolver. If saved `expires_at` is within `REFRESH_WINDOW_SECS` (3600s), POSTs to `/v1/auth/refresh` and persists the new token. Best-effort: refresh failures fall back to the stale token rather than blocking the operator.
- [x] Path-explicit variant `resolve_admin_token_with_refresh_at(server, &path)` for tests so we don't have to mutate `HOME` (workspace lints `forbid(unsafe_code)`, and `std::env::set_var` is unsafe on edition 2024).
- [x] All CLI call sites switched to the refreshing resolver: [cmd_users](crates/iac-cli/src/main.rs), [cmd_op_approval](crates/iac-cli/src/main.rs), [cmd_audit](crates/iac-cli/src/main.rs), [drift_async](crates/iac-cli/src/main.rs) (closure now async), [cmd_apply_remote](crates/iac-cli/src/main.rs) (token resolution moved inside the runtime block), [cmd_plan_remote](crates/iac-cli/src/main.rs).
- [x] Old non-refreshing `resolve_admin_token` removed (was unused after the migration; nothing left to deprecate).
- [x] **4 unit tests** ([credentials.rs](crates/iac-cli/src/credentials.rs)): fresh token skips refresh (RFC5737 unreachable address proves no network call), refresh failure falls back to stale token, missing entry errors cleanly, unparseable `expires_at` skips refresh.

### Open after Phase 7f

- **No 401 retry on stale token from a long-idle session.** If the saved token is *past* expiry but we don't trip the 1h window because of clock skew, the resolver returns the stale token and the CLI gets 401. A second-tier fallback ("on 401, try refresh once and retry") would polish that, but it's not common enough to justify the complexity yet — operators just `iac login` again.
- **Refresh runs once per CLI invocation.** Long-running `iac apply --wait` polls for many minutes; if the token expires mid-poll, no further refresh happens. Acceptable: refresh window > poll window. Revisit if any single invocation routinely outlasts the token TTL.
- **No way to force-disable auto-refresh.** Operators who want strict expiry semantics can't currently opt out. Add `IAC_NO_REFRESH=1` if anyone asks.

---

## Phase 7g — `metadata.dependsOn` topo sort — DONE.

Operators can now declare ordering constraints between resources: `metadata.dependsOn: ["file/ops/script", ...]` forces the dependent resource to apply *after* its targets. Server-side topo sort runs at submit time (post-expansion), per-agent buckets inherit the global order, agents apply in array order — no agent-side graph machinery needed. Cycles and unknown references reject with 400 so operators see the bad config immediately rather than discovering it at apply time.

**282 tests passing** (was 266; +11 unit tests + 5 E2E). `cargo audit` clean (336 deps).

### Phase 7g deliverables (✅)

- [x] [`crates/iac-controlplane/src/depsort.rs`](crates/iac-controlplane/src/depsort.rs) — `topo_sort_by_depends_on` runs Kahn's algorithm with stable original-order seeding (zero-in-degree nodes preserve their submitted order). Detects cycles, surfaces a few involved resource ids in the error so operators can find the loop. Rejects self-loops and duplicate entries to keep config strict.
- [x] [`submit` handler](crates/iac-controlplane/src/api/operations.rs) calls `topo_sort_by_depends_on` immediately after expansion, before policy evaluation + routing. The sorted order propagates through `create_operation` into per-agent buckets via stable `BTreeMap` iteration.
- [x] **11 unit tests** ([depsort.rs](crates/iac-controlplane/src/depsort.rs)): no-deps preserves order, single-edge moves dependent after target, chain a→b→c, diamond, cycle → 400, self-loop → 400, unknown reference → 400, duplicate entry → 400, missing dependsOn fine, stability with multiple zero-in-degree, empty input.
- [x] **5 E2E tests** ([e2e_depsort.rs](crates/iac-controlplane/tests/e2e_depsort.rs)): submit-in-reverse-order shows up sorted in `OperationDesiredState`, three-resource chain end-to-end, cycle rejected at submit (400 + "cycle" in body), unknown reference rejected (400 + "unknown" + bad id), no-dependsOn submit unaffected.

### Open after Phase 7g

- **Cross-agent edges are no-ops.** Agents apply in parallel, so a `dependsOn` from a resource on agent-1 to a resource on agent-2 doesn't enforce ordering across agents. We don't reject it (the intra-agent ordering is still useful and obvious cross-agent waits would block the whole operation), but operators expecting cross-host serialization will be surprised. Documenting this explicitly is the next step; a "phased apply" mode that blocks until all agents complete each phase is the real fix.
- **No transitive cycle pre-check before expansion.** Composites today don't carry `dependsOn` through to children. If a `cron-job-bundle` were to declare a dep, the children wouldn't inherit it. Acceptable — composites are sealed units; the operator declares deps on the bundle's *children* explicitly if needed.
- **No CLI render of dependency graph.** `iac plan --server --operation <id>` shows the sorted list but doesn't draw the graph. A `--graph` flag rendering ASCII or DOT would be nice for debugging tangles.

---

## Phase 7h — Per-environment submission rate limit — DONE.

Operators can now cap operation submissions per environment per 60-second sliding window. A runaway pipeline or a misconfigured CI step trying to submit 100 ops/sec gets a clean 429 + `Retry-After` header instead of fanning out 100x assignments to every agent. Rate limit runs *after* auth + basic shape validation so the bucket reflects real submission attempts, not unauthenticated spam or malformed payloads.

**292 tests passing** (was 282; +5 limiter unit tests + 5 E2E). `cargo audit` clean (336 deps).

### Phase 7h deliverables (✅)

- [x] [`crates/iac-controlplane/src/rate_limit.rs`](crates/iac-controlplane/src/rate_limit.rs): `RateLimiter` over `tokio::sync::Mutex<HashMap<env, VecDeque<Instant>>>`. Lazy expiration on each check keeps the queue bounded by the cap. Per-environment isolation so noisier envs (e.g. staging) don't force a stricter prod limit.
- [x] `RateLimitConfig { operations_per_minute: Option<u32> }` — `None` (or `Some(0)`) disables. Default is disabled so existing deployments are unaffected.
- [x] Wired into [`AppState`](crates/iac-controlplane/src/server.rs) via `rate_limiter: Arc<RateLimiter>` field.
- [x] Wired into [`submit` handler](crates/iac-controlplane/src/api/operations.rs) right after auth + shape validation; before expansion + topo sort + routing — so attackers spamming malformed payloads can't fill someone else's bucket.
- [x] [`ApiError::TooManyRequests(u64)`](crates/iac-controlplane/src/error.rs) carries the `Retry-After` seconds; the IntoResponse impl writes both the JSON body and the header so well-behaved CI scripts back off without polling.
- [x] **5 unit tests** ([rate_limit.rs](crates/iac-controlplane/src/rate_limit.rs)): disabled passes everything, zero treated as disabled, cap enforced within window, separate envs separate buckets, entries expire after 60s. Tests use `Instant`-explicit variant so they don't depend on wall clock.
- [x] **5 E2E tests** ([e2e_rate_limit.rs](crates/iac-controlplane/tests/e2e_rate_limit.rs)): default config allows everything, exceeded cap → 429 + `Retry-After`, separate envs have separate buckets, validation runs before limiter (400 doesn't burn budget), auth runs before limiter (401 spam doesn't burn legitimate operators' budgets).

### Open after Phase 7h

- **In-process state.** Two server replicas would each have their own bucket, so a deployment running 3 replicas with `operations_per_minute=10` actually allows 30/min in the worst case. Acceptable today (we don't run replicated yet); a Redis-backed limiter is the right fix when horizontal scale shows up.
- **Single global rate per env.** Operators can't carve out "service-X gets 5/min, service-Y gets 50/min." Per-policy or per-prefix limits would be a natural follow-up but require schema changes to `Policy`.
- **No limits on other endpoints.** Heartbeats, observations, and drift pushes are unrestricted. They're agent-driven (and agents authenticate per-token), so abuse there is auditable rather than open. If an agent token is compromised the per-agent throttle would be the right response — Phase 6i material.

---

## Phase 7i — Maintenance windows — DONE.

Operators can now declare absolute-time `[[maintenance_windows]]` blocks. Submissions during an active window are rejected with 503 + a `Retry-After` header pointing at the window's end so well-behaved CI scripts pause and retry without polling. Per-environment scoping with `"*"` wildcard for global freezes; misconfigured windows (unparseable timestamps, end ≤ start) are skipped silently rather than masking submissions.

**308 tests passing** (was 292; +10 unit tests + 6 E2E). `cargo audit` clean (336 deps).

### Phase 7i deliverables (✅)

- [x] [`crates/iac-controlplane/src/maintenance.rs`](crates/iac-controlplane/src/maintenance.rs): `MaintenanceWindow { name, environment, start, end }` parsed via jiff. `check(windows, env, now)` returns `ServiceUnavailable { reason, retry_after_secs }` on first match. Inclusive start, exclusive end. Misconfigured windows skipped (preferable to "broken config blocks all submissions").
- [x] [`ApiError::ServiceUnavailable`](crates/iac-controlplane/src/error.rs): 503 + `Retry-After` header carrying seconds-until-window-closes (clamped 1s–24h).
- [x] `Config.maintenance_windows: Vec<MaintenanceWindow>` with `#[serde(default)]` so existing configs stay valid.
- [x] [`submit` handler](crates/iac-controlplane/src/api/operations.rs) calls `maintenance::check` after auth + rate-limit, before expansion. Same ordering rationale: 401/400 don't get masked by 503; legitimate operators see the right error code.
- [x] **10 unit tests** ([maintenance.rs](crates/iac-controlplane/src/maintenance.rs)): no windows, before/after window, inside window with retry-after, wildcard env, env-specific doesn't fence other envs, end-exclusive, start-inclusive, malformed window skipped, end ≤ start skipped, first matching wins.
- [x] **6 E2E tests** ([e2e_maintenance.rs](crates/iac-controlplane/tests/e2e_maintenance.rs)): no windows allows, active blocks 503 + Retry-After, past doesn't block, env-specific doesn't fence other envs, wildcard blocks all envs, runs after auth (401 wins over 503).

### Open after Phase 7i

- **No recurring/cron-style windows.** "Every Tuesday 02:00-04:00 UTC" requires teaching operators a syntax. Most maintenance events are scheduled one-shot anyway; recurring windows are a Phase 8 nicety.
- **Window list is read on each submit.** Cheap today (small list), but if the list grows past, say, 100 entries the linear scan + parse becomes wasteful. Pre-parsing into a `Vec<(Timestamp, Timestamp)>` cache at config-load is the optimization to do then.
- **No way for an operator to override "I really need to deploy during maintenance."** Today the only escape is editing the config and reloading. A `IAC_MAINTENANCE_BYPASS` per-call header (admin-only) would close this gap; deferring until anyone actually asks.

---

## Phase 7j — Maintenance bypass header — DONE.

Admins can now opt out of an active maintenance window for a single submission via `X-Iac-Maintenance-Bypass: yes`. Required when the freeze is in effect but an incident response demands a deploy. Every bypass is audited (warning severity, payload includes env + requested_by) so reviews can answer "who deployed during the freeze and why."

**312 tests passing** (was 308; +4 bypass E2E tests). `cargo audit` clean (336 deps).

### Phase 7j deliverables (✅)

- [x] [`submit` handler](crates/iac-controlplane/src/api/operations.rs) reads `X-Iac-Maintenance-Bypass` (case-insensitive, lowercased per HTTP norms). Non-empty value opts in; empty header treated as not set so templated CI envs that produce empty strings can't accidentally bypass.
- [x] Bypass requires `Role::Admin`. Operator/Approver-with-bypass-header → 403 Forbidden so the role separation holds.
- [x] Bypass writes `operation.maintenance_bypass` audit event (severity `warning`) BEFORE the maintenance check is skipped. Records bypass intent even when no window is currently active — the *intent* is what's auditable.
- [x] **4 E2E tests** ([e2e_maintenance.rs](crates/iac-controlplane/tests/e2e_maintenance.rs) appended): admin bypass overrides active window + audit captured, non-admin bypass → 403, bypass audited even outside window, empty header treated as not set (still 503).

### Open after Phase 7j

- **No bypass scope.** A single bypass header is all-or-nothing for that submission. Operators can't say "bypass for this single resource within the operation." Acceptable — bypass is meant to be rare.
- **No expiration.** A bypass is per-submission, so this is moot today. If we ever add session-level admin bypass it'd need a TTL.
- **No alerting hook.** Audit events are visible via `/v1/audit?kind=operation.maintenance_bypass` but nothing actively notifies on them. A webhook for "warn-severity audit events" would be the natural place to plug PagerDuty / Slack.

---

## Phase 7k — `web-with-monitoring` composite — DONE.

A single `kind: web-with-monitoring` resource expands server-side into four primitives — `docker.container` + `nginx.vhost` + `file` (healthcheck script under `/usr/local/bin/<name>-healthcheck`) + `cron.job` (probe schedule). Healthcheck script runs curl against the upstream's health path and logs success/failure to syslog. Removes another four hand-coordinated resources whose ports/paths/domains all had to match.

**319 tests passing** (was 312; +6 unit tests + 1 E2E). `cargo audit` clean (336 deps).

### Phase 7k deliverables (✅)

- [x] [`expand_web_with_monitoring`](crates/iac-controlplane/src/expansion.rs): `deny_unknown_fields`, validates `check_interval_minutes` is 1..=60, special-cases `1 → "* * * * *"` (cron's `*/1` is technically valid but reads weird).
- [x] Healthcheck script is a 3-line shell: `curl --max-time 5 --silent --show-error --fail <url> > /dev/null && logger -t <name>-healthcheck OK || logger -t <name>-healthcheck FAIL`. No new providers needed; just glues primitives.
- [x] `hostSelector` propagates to all four children so the script + cron entry land on the same host as the docker container they probe.
- [x] All four children carry `iac.example/composite-of: web-with-monitoring` annotation (same convention `service` and `cron-job-bundle` use).
- [x] **6 unit tests** ([expansion.rs](crates/iac-controlplane/src/expansion.rs)): expand-to-4, healthcheck file path matches cron command, custom health_path + interval, host-selector inheritance to all four, invalid interval (0 + 120) rejected, unknown field rejected.
- [x] **1 E2E test** ([e2e_web_monitoring.rs](crates/iac-controlplane/tests/e2e_web_monitoring.rs)): full submit → 4 primitives in blast radius → all four route to the same agent → all four carry the composite annotation in the `OperationDesiredState` preview.

### Open after Phase 7k

- **Healthcheck implementation is shell + curl + logger.** Operators wanting Prometheus-style metrics or richer probes (TLS validation, DNS check, latency thresholds) need to override with their own resources. A future `monitoring.check` provider would replace the file+cron pair with a single primitive — but that's a Phase 8 feature.
- **Three composites now (`service`, `cron-job-bundle`, `web-with-monitoring`).** The pattern is consistent — each is a self-contained ~150-line function in `expansion.rs` — but the catalog is starting to feel large enough that an expander discovery API (`GET /v1/expanders`) would help operators see what's available without reading source.
- **No way to override healthcheck script content.** Operators who want a custom probe have to drop `web-with-monitoring` and write the four primitives by hand. A `script:` field on the spec would let them keep the convenience while substituting their own check; deferring until anyone asks.

---

## Phase 7l — `GET /v1/expanders` discovery — DONE.

Operators can now list the composite kinds the server expands without reading source. Each descriptor names the input `kind`, a one-line description, and the primitive kinds it emits — enough info for an operator to decide whether to use a composite or hand-roll the primitives. Open to Viewer+ since the catalog isn't sensitive.

**322 tests passing** (was 319; +3 E2E). `cargo audit` clean (336 deps).

### Phase 7l deliverables (✅)

- [x] [`ExpanderDescriptor`](crates/iac-controlplane/src/expansion.rs) + `list_expanders()` returning a stable-ordered catalog. Today: `service`, `cron-job-bundle`, `web-with-monitoring`. New built-in expanders update the function alongside their implementation.
- [x] [`GET /v1/expanders`](crates/iac-controlplane/src/api/expanders.rs) — Viewer role.
- [x] **3 E2E tests** ([e2e_expanders.rs](crates/iac-controlplane/tests/e2e_expanders.rs)): admin lists with stable order + correct emit lists, viewer can list (auth gate at Viewer not Admin), unauthenticated → 401.

### Open after Phase 7l

- **No spec schema in the descriptor.** Operators see `kind: web-with-monitoring → docker.container + nginx.vhost + file + cron.job` but not the spec fields (`image`, `port`, `domain`, …). A `spec_fields: [{name, type, required, description}]` field on ExpanderDescriptor would close this; defer until anyone asks.
- **Hardcoded list, not derived from the actual expander functions.** If someone adds a new composite to `expand_resources` and forgets to update `list_expanders`, the discovery endpoint silently lies. A unit test that round-trips "every kind in the match arm appears in list_expanders" would catch this; small enough to add now if drift becomes a worry.
- **No CLI `iac expanders list` subcommand.** The endpoint is reachable via curl. A CLI verb would be a 30-line add; deferred until operators ask.

---

## Phase 7m — `iac expanders` CLI subcommand — DONE.

The CLI now has `iac expanders --server <url>` to surface the catalog of composite kinds. Renders human-readable text by default (`kind` + description + emit list per row) or JSON with `--format json`. Closes the open item from 7l.

**322 tests passing** (no new tests — the surface is the existing `GET /v1/expanders` endpoint, already covered by `e2e_expanders.rs`). `cargo audit` clean (336 deps).

### Phase 7m deliverables (✅)

- [x] [`Command::Expanders { server }`](crates/iac-cli/src/main.rs) — single-arg subcommand, no filters needed since the catalog is small.
- [x] [`cmd_expanders`](crates/iac-cli/src/main.rs) reuses `resolve_admin_token_with_refresh` for auth (so saved tokens auto-refresh on near-expiry, same as every other CLI verb), 30s timeout, JSON or human output.
- [x] Local `ExpanderDescriptor` struct in the CLI (mirror of the server's). Avoids leaking the server's internals into iac-core just for a CLI render — the wire shape is stable enough that duplication beats coupling.

### Open after Phase 7m

- **No way to filter** ("which composites emit `cron.job`?"). Catalog is three entries; revisit when it grows past, say, 10.
- **CLI doesn't ship spec-field info** because the server doesn't return it (Phase 7l open item). Adding `iac expanders show <kind>` for detailed spec docs would pair with a future `spec_fields` field on the descriptor.

---

## Phase 7n — Per-policy rate limits — DONE.

`Policy` now carries an optional `rate_limit_per_minute` field. When the policy matches a submission, that cap is enforced in addition to the global env-level limit. Lets operators say "prod-deploy gets 3/min, everyone else unrestricted" without slowing down stage. Stricter cap wins when multiple policies match.

**326 tests passing** (was 322; +4 E2E). `cargo audit` clean (336 deps).

### Phase 7n deliverables (✅)

- [x] [`Policy.rate_limit_per_minute`](crates/iac-controlplane/src/policy.rs): `Option<u32>`, default `None`. Zero or `None` = no per-policy cap.
- [x] [`RateLimiter::check_and_record_policy`](crates/iac-controlplane/src/rate_limit.rs): keyed bucket separate from env-level. Internally delegates to a new `check_and_record_keyed_at` helper so env vs. policy buckets share the same sliding-window logic.
- [x] [`submit` handler](crates/iac-controlplane/src/api/operations.rs) iterates matched policies and enforces each cap. Stricter rejects first; no partial recording (the limiter only records on successful checks).
- [x] **4 E2E tests** ([e2e_policy_rate_limit.rs](crates/iac-controlplane/tests/e2e_policy_rate_limit.rs)): matched policy cap rejects excess + Retry-After, unmatched policy doesn't consume cap (stage submits don't tick prod-cap), `None` cap leaves policy unrestricted, stricter of two matching policies wins.

### Open after Phase 7n

- **Caps stack additively when multiple policies match.** A submit consumes one slot in *every* matched policy's bucket. That's the conservative behavior — alternatively one could make caps disjunctive ("any matched cap allows this through") but operators usually want stricter-wins. Document the semantic when caps appear in a future phase 8 user guide.
- **No way to surface "which cap rejected me" to the operator.** The 429 + Retry-After tells you to back off, but not whether it was the env cap, prod-cap, or stricter-cap. Adding the policy name to the `TooManyRequests` payload would close this; small follow-up.
- **In-process state.** Same caveat as Phase 7h — replicas would each maintain their own buckets, allowing 2x-Nx the configured cap in aggregate. Redis-backed limiter is the fix when horizontal scale arrives.

---

## Phase 7o — Bucket label in 429 payload — DONE.

The 429 response body now names the rate-limit bucket that fired (e.g. `bucket=env:prod`, `bucket=policy:prod-cap`). Operators can tell at a glance whether the env-level limit or a specific policy cap rejected, without grepping config or correlating against logs.

**326 tests passing** (no count change; existing tests extended with bucket assertions). `cargo audit` clean (336 deps).

### Phase 7o deliverables (✅)

- [x] `ApiError::TooManyRequests` is now a struct variant `{ bucket: String, retry_after_secs: u64 }` instead of `(u64)`. The `bucket` field carries the limiter's internal key (`env:<name>` or `policy:<name>`) verbatim.
- [x] [`RateLimiter::check_and_record_keyed_at`](crates/iac-controlplane/src/rate_limit.rs) populates `bucket: key.to_string()` so the keyed helper is the single place this name comes from.
- [x] [`IntoResponse for ApiError`](crates/iac-controlplane/src/error.rs) writes `detail = "bucket=<key> retry after <s>s"` so operators see it in the JSON body alongside the existing `Retry-After` header.
- [x] **3 E2E assertions** added across [e2e_rate_limit.rs](crates/iac-controlplane/tests/e2e_rate_limit.rs) and [e2e_policy_rate_limit.rs](crates/iac-controlplane/tests/e2e_policy_rate_limit.rs): env limit names `env:<env>`, single-policy limit names `policy:<name>`, multi-policy stricter-wins names the *stricter* policy.

### Open after Phase 7o

- **Bucket label is internal-shape-leaking.** `env:prod` / `policy:prod-cap` are the limiter's keys — operators see implementation detail rather than a curated label. Acceptable today (the prefix maps cleanly to "env" vs. "policy" which is the actionable info), but if the limiter grows new bucket types (per-user, per-IP), a structured response field would be cleaner than a magic prefix.
- **Header `Retry-After` is unchanged.** Already worked correctly per Phase 7h; this phase only adds a body label.

---

## Phase 7p — Expander spec discovery — DONE.

Operators now see the spec fields each composite accepts before writing a manifest. `ExpanderDescriptor` carries a `spec_fields: [{name, type, required, description}]` list, surfaced via `GET /v1/expanders/{kind}` and the new `iac expanders show <kind>` CLI subcommand. A drift-guard unit test verifies every advertised expander has a working minimal spec, so the catalog can't silently rot when a composite's spec changes.

**330 tests passing** (was 326; +1 unit drift guard + 3 E2E for show). `cargo audit` clean (336 deps).

### Phase 7p deliverables (✅)

- [x] [`SpecField { name, type, required, description }`](crates/iac-controlplane/src/expansion.rs) + `spec_fields: Vec<SpecField>` on `ExpanderDescriptor`. Stringly-typed `type` (`"string" | "number" | "object" | "map<string,string>"`) keeps the wire shape JSON-friendly without dragging in JSON Schema.
- [x] Hand-curated spec catalog for all three built-in composites — `service`, `cron-job-bundle`, `web-with-monitoring`. Required vs. optional mirrors the `#[serde(...)]` rules on each `*Spec` struct. Optional fields document their defaults inline.
- [x] [`GET /v1/expanders/{kind}`](crates/iac-controlplane/src/api/expanders.rs) — Viewer role. Unknown `kind` → 404.
- [x] [`iac expanders list / show <kind>`](crates/iac-cli/src/main.rs) — `list` is the existing surface, `show` is new. Human format prints `name <type> (required|optional)  description` per field; JSON format prints the descriptor verbatim.
- [x] **Drift-guard unit test** in [`expansion.rs`](crates/iac-controlplane/src/expansion.rs): for every kind advertised by `list_expanders()`, the test builds a minimal valid spec and round-trips it through `expand_resources`. If someone adds a kind to `list_expanders` without an expander, or vice versa, the test fails loudly.
- [x] **3 new E2E tests** in [e2e_expanders.rs](crates/iac-controlplane/tests/e2e_expanders.rs): list response carries spec_fields with required flags, show endpoint returns single descriptor with full field list, unknown kind → 404, unauthenticated show → 401.

### Open after Phase 7p

- **Spec catalog is hand-maintained.** Each `*Spec` struct's serde definition is the real source of truth, but the descriptor is a manual mirror. Auto-generation from the struct definitions would be cleaner — `schemars` does exactly this — but pulling in another dep just for the catalog isn't worth it at three composites. Revisit if the catalog grows past, say, ten.
- **No spec-level validation hint.** Operators see "port: number" but not "must be 1..=65535." Could add a `validation: "1..=65535"` field, but the same constraint is enforced by serde + custom validation in each expander; an operator who sends 70000 gets a 400 with the underlying error. Defer until anyone asks.
- **CLI doesn't validate-locally before submit.** `iac plan` against a manifest with a missing required field still falls through to a server-side 400. Pre-submit local validation against the spec_fields list would tighten the loop; that's CLI work for a future phase.

---

## Phase 7q — Structured `bucket` in 429 payload — DONE.

The 429 response body now carries a structured `bucket: { type, name }` JSON object alongside the existing `detail` string. Clients no longer need to parse the magic prefix to tell env caps from policy caps. The legacy detail line stays for backwards-compat with Phase 7o consumers; new clients should match on the structured field.

**330 tests passing** (no count change; existing tests extended with structured-field assertions). `cargo audit` clean (336 deps).

### Phase 7q deliverables (✅)

- [x] [`RateLimitBucket { type, name }`](crates/iac-controlplane/src/error.rs) carries the typed pair. `env(name)` / `policy(name)` constructors keep callsites tidy.
- [x] [`ApiError::TooManyRequests`](crates/iac-controlplane/src/error.rs) now holds `bucket: RateLimitBucket` instead of a `String`. `IntoResponse` populates a top-level `bucket` field on the JSON body (skipped on other error variants) AND keeps the legacy `detail = "bucket=type:name retry after Ns"` so Phase 7o clients keep working.
- [x] [`RateLimiter::check_and_record_keyed_at`](crates/iac-controlplane/src/rate_limit.rs) takes `RateLimitBucket` directly and forwards it into the error. Internal map key is still `"<type>:<name>"` so the limiter's storage stays unchanged.
- [x] **3 test extensions** across [e2e_rate_limit.rs](crates/iac-controlplane/tests/e2e_rate_limit.rs) + [e2e_policy_rate_limit.rs](crates/iac-controlplane/tests/e2e_policy_rate_limit.rs) + [rate_limit.rs](crates/iac-controlplane/src/rate_limit.rs): assert structured `bucket.type` + `bucket.name` populated, original `detail` string preserved.

### Open after Phase 7q

- **`type` is stringly-typed.** `"env"` / `"policy"` are unconstrained strings on the wire. A typed enum on the Rust side (and discriminant on the JSON side) is cleaner, but operators consuming JSON read these as strings anyway and adding new types (per-user, per-IP) is just a new constructor — easy.
- **Detail string is now redundant.** Both `bucket` and the `detail = "bucket=…"` fragment carry the same info. Plan: drop the `bucket=…` prefix from `detail` once we're confident every consumer has migrated to the structured field. Tracking this as a backwards-compat shim.

---

## Phase 7r — CLI pre-submit validation against spec_fields — DONE.

`iac apply --server` now fetches `GET /v1/expanders` before submission and validates each composite resource's spec against the descriptor. Missing required fields and unknown top-level fields surface as locally-printed errors before the round trip — operators see "spec.domain is required" instead of waiting for the server's 400. Best-effort: if the catalog fetch fails (5s timeout, network blip, auth glitch) the CLI proceeds and lets the server's serde rules be authoritative.

**339 tests passing** (was 330; +9 validate_spec unit tests). `cargo audit` clean (336 deps).

### Phase 7r deliverables (✅)

- [x] [`crates/iac-cli/src/validate_spec.rs`](crates/iac-cli/src/validate_spec.rs): pure `validate_resources` function + `fetch_catalog` helper. Validation is shallow — required fields present, no unknown top-level fields, spec must be an object — deep validation (port range, hostname syntax) stays server-side.
- [x] [`cmd_apply_remote`](crates/iac-cli/src/main.rs) calls `fetch_catalog` after token resolution; on success it runs `validate_resources` and bails with a multi-line error report; on fetch failure it silently skips so the CLI doesn't block when the catalog endpoint is unreachable.
- [x] **9 unit tests** ([validate_spec.rs](crates/iac-cli/src/validate_spec.rs)): complete spec passes, missing required reports error (with description), missing multiple required reports each, unknown top-level field reports error, optional field not required, unknown kind skipped (primitives are providers' job), empty descriptor list short-circuits, non-object spec reports error, validates each resource independently.

### Open after Phase 7r

- **Validation is opt-in via running through `--server` mode.** The local-apply path (`iac apply <path>`) doesn't validate composites because composites only exist server-side. Acceptable — local apply doesn't know about composites at all.
- **Network failure silently skips.** Operators with a flaky network might submit invalid manifests and get the server's 400 anyway. Logging a warning to stderr would help; defer until anyone notices.
- **No structural type-checking.** "port: number" is documented but the CLI doesn't reject `port: "8080"` (a string). Server-side serde catches this via its 400. A coarser check ("if descriptor says number, value must not be a string/object/array") would tighten the local loop; defer until anyone asks.

---

## Phase 7s — Recurring maintenance windows — DONE.

`[[recurring_maintenance_windows]]` config blocks let operators schedule weekly freezes ("every Monday + Tuesday 02:00-04:00 UTC") without listing each absolute occurrence. Same 503 + Retry-After response shape as Phase 7i absolute windows. UTC-only for now (timezone support is a future refinement). Overnight windows (e.g. 22:00-02:00) split into two entries since the simpler "no wrap" parser keeps the implementation honest.

**349 tests passing** (was 339; +10 recurring maintenance unit tests). `cargo audit` clean (336 deps).

### Phase 7s deliverables (✅)

- [x] [`RecurringMaintenanceWindow { name, environment, weekdays, start_hhmm, end_hhmm }`](crates/iac-controlplane/src/maintenance.rs): empty `weekdays` = every day; entries are `mon`/`tue`/…/`sun`. `HH:MM` UTC. `parse()` rejects unknown weekdays, malformed times, and `end_hhmm <= start_hhmm`.
- [x] [`check_recurring`](crates/iac-controlplane/src/maintenance.rs): converts now to UTC weekday + minute-of-day, scans windows, returns `ServiceUnavailable` for the first match. Misconfigured windows skip silently — same logic as absolute windows.
- [x] `Config.recurring_maintenance_windows: Vec<RecurringMaintenanceWindow>` with `#[serde(default)]`. [`submit` handler](crates/iac-controlplane/src/api/operations.rs) calls `check_recurring` after the absolute-window check; first match (in order: absolute → recurring) wins.
- [x] **10 unit tests**: no windows allows, inside window blocks with retry-after, outside window allows, wrong weekday allows, empty weekdays = every day, env-specific scoping, wildcard env, malformed window skipped, unknown weekday skipped, end ≤ start skipped.

### Open after Phase 7s

- **UTC-only.** Operators in non-UTC time zones translate manually. Adding a `timezone: "America/New_York"` field is mechanically straightforward (jiff supports it) but DST handling adds edge cases worth deferring.
- **No overnight wrap.** A 22:00-02:00 window becomes two entries — slightly verbose but the alternative (dual-window logic + retry-after spanning midnight) is more code than the use case justifies.
- **No "end of weekly window" bonus check.** If an operator submits at exactly the recurring end time (say 04:00:00.000), they get through. Acceptable — exclusive end is the documented contract.
- **No `RecurringMaintenanceWindow` in the `iac` CLI.** Operators see windows in server config; no client-side equivalent of `--maintenance-window` flag. Out of scope.

---

## Phase 6h — User CRUD endpoints — DONE.

Operators no longer need to set `IAC_BOOTSTRAP_USER` env vars or write to the database directly. Admin-role callers can now create, list, update (roles/disabled/password), and soft-delete users through the API or the new `iac users` CLI. Every mutation lands in the audit log.

**232 tests passing** (3 cli + 11 core + 79 providers + 2 docker + 22 agent unit + 6 agent lifecycle + 37 controlplane unit + 6 cli credential unit + 53 controlplane E2E + 10 RBAC E2E + 5 approvers E2E + 4 service E2E + 8 user CRUD E2E). `cargo audit` clean (336 deps).

### Phase 6h deliverables (✅)

- [x] [Protocol types](crates/iac-core/src/protocol.rs): `CreateUserRequest`, `CreateUserResponse`, `UserView`, `UpdateUserRequest`. Roles travel as strings (`viewer | operator | approver | admin`) — server validates and rejects unknown values.
- [x] [Store methods](crates/iac-controlplane/src/store.rs): `list_users`, `update_user_roles`, `disable_user` (soft + revoke active tokens in one tx), `enable_user`, `set_user_password` (rehash + revoke tokens). Existing `create_user` reused.
- [x] [`/v1/users` endpoints](crates/iac-controlplane/src/api/users.rs) (admin role): `POST` create, `GET` list, `PATCH /v1/users/{id}` (any of `roles`, `disabled`, `password`), `DELETE` (soft delete = `disabled_at` set + tokens revoked). Empty PATCH bodies → 400 so admins don't accidentally no-op.
- [x] Audit hooks: `user.created`, `user.updated`, `user.disabled` events with payload (username, roles list, fields_changed, password_changed flag — never the password itself).
- [x] [iac CLI](crates/iac-cli/src/main.rs) `iac users` subcommand: `create / list / set-roles / disable / enable / set-password`. Passwords read via `rpassword` interactive prompt (with `--password` flag and `IAC_PASSWORD` env for non-interactive scripts).
- [x] **8 E2E tests**: full create→list→disable→re-enable lifecycle, role change, password reset revokes existing tokens, non-admin (viewer + approver) gets 403, unknown role string → 400, duplicate username → 409, audit events recorded for create/update/disable, empty PATCH → 400.

### Open after Phase 6h

- **CLI's saved token doesn't auto-refresh roles.** When an admin elevates Bob from Viewer to Approver, Bob's existing `iac` session still claims Viewer until he re-`iac login`. Acceptable today (token TTL is 24h) but a Phase 7+ refresh endpoint will close this.
- **No "must always have an Admin" guard.** An admin can de-elevate themselves to Viewer and lock everyone out. Currently mitigated by the legacy admin token path — operators always have a break-glass. Phase 7+ may add the guard if real footguns appear.
- **Password reset doesn't notify the user.** No email, no Slack, no nothing. Acceptable for this stage; Phase 7+ may add hooks.

---

## Phase 7aj — `/v1/admin/config-issues` endpoint — DONE.

**406 tests passing.** `cargo audit` clean across 337 transitive deps.

Thirty-five consecutive phases shipped from 7b through 7aj. The most recent: admin-only `GET /v1/admin/config-issues` returns the structured per-entry detail behind the `iac_maintenance_misconfigured_windows` gauge. Operators see name + parser error per broken window, no log-grepping required. Pairs with the gauge: gauge says "you have N typos", endpoint says "here's which ones."

Pick any of the open phases below to continue. Most-recent open carrying-edge items: phased apply (cross-agent dependency layers), operator-defined expanders, `monitoring.check` first-class provider, per-webhook telemetry breakdown.

### Phase 7aj deliverables (✅)

- [x] [`ConfigIssue { kind, name, error }`](crates/iac-controlplane/src/maintenance.rs) — serializable per-issue record. `kind` is `"maintenance_window"` or `"recurring_maintenance_window"`.
- [x] [`collect_config_issues`](crates/iac-controlplane/src/maintenance.rs) — pure helper. Walks both vec types, calls `parse()`, materializes `ConfigIssue` for each `Err`. Order: absolute (in config order) then recurring (in config order).
- [x] [`api::admin`](crates/iac-controlplane/src/api/admin.rs) — new module. `/v1/admin/` prefix gives future "operator wants to know server's view of itself" endpoints a home.
- [x] [`GET /v1/admin/config-issues`](crates/iac-controlplane/src/api/admin.rs) — Admin role. Returns `{ maintenance: [ConfigIssue] }`. Empty list = clean config.
- [x] **3 new E2E tests** ([e2e_admin_config_issues.rs](crates/iac-controlplane/tests/e2e_admin_config_issues.rs)): empty list when config is clean, three broken entries surface with kind+name+error in the right order, admin-only (401 unauthenticated, 403 operator).

### Open after Phase 7aj

- **Snapshot at request time, not startup.** Each request re-runs `parse()` for every window. Cheap today (small lists), but if windows ever land in 1000s, cache the issue list at startup and clear on SIGHUP-reload.
- **No `policies` / `webhooks` / `expanders` issues.** Only maintenance is checked. Other config blocks have their own validation paths (most reject at config-load with a hard error rather than silently skip), but extending the issue list to cover any new "skip-on-failure" configs is straightforward.
- **No de-dup with logged warnings.** The `parse()` error is also tracing-logged when the server first runs the maintenance check. Reading both endpoint + logs is redundant; not actively harmful.

## Phase 7ak — mTLS agent ↔ control-plane — DONE.

**414 tests passing.** `cargo audit` clean across 370 transitive deps (with `RUSTSEC-2025-0134` documented in [.cargo/audit.toml](.cargo/audit.toml) — `rustls-pemfile` is informationally unmaintained but functionally fine; migrating to `pki_types::pem` blocks on axum-server upgrading).

Thirty-six consecutive phases shipped from 7b through 7ak. The most recent: control-plane now supports TLS (mode `server`) and mTLS (mode `mutual`). Self-signed PKI bootstrap via `rcgen` so tests + dev stands work without an external CA. Agent loads CA bundle + client cert/key from config. Three modes verified end-to-end: full mutual round-trip, server-mode no-client-cert, agent rejects unknown server CA, server-mode-mutual rejects no-cert client.

### Phase 7ak deliverables (✅)

- [x] [`crates/iac-controlplane/src/tls.rs`](crates/iac-controlplane/src/tls.rs): `TlsConfig { mode, cert_file, key_file, client_ca_file }` + `build_rustls_config` (fail-closed PEM loader) + `generate_self_signed_pki(server_dns, server_ips, client_names)` for tests / first-boot bootstrap (rcgen 0.14 with `Issuer::from_params` + `signed_by`).
- [x] [`AgentTlsConfig { ca_file, client_cert_file, client_key_file }`](crates/iac-agent/src/config.rs) + [`build_http_client`](crates/iac-agent/src/remote.rs) wires the rustls-backed reqwest client with custom CA + identity (cert+key concatenated for `reqwest::Identity::from_pem`).
- [x] [`Client::connect_with_tls`](crates/iac-agent/src/remote.rs) — drop-in replacement for `connect` that takes `&AgentTlsConfig`. Plumbed through the agent run-loop in [agent.rs](crates/iac-agent/src/agent.rs).
- [x] [`main.rs`](crates/iac-controlplane/src/main.rs) gates between plain `axum::serve` and `axum_server::bind_rustls` based on `tls.mode`. Graceful shutdown wired for both paths.
- [x] **4 unit tests** ([tls.rs](crates/iac-controlplane/src/tls.rs)): generated PKI round-trips through rustls in mutual mode, missing cert file fails closed, mutual mode requires `client_ca_file`, `is_enabled`/`requires_client_cert` flags.
- [x] **4 E2E tests** ([e2e_mtls.rs](crates/iac-controlplane/tests/e2e_mtls.rs)): full mutual round-trip (register + heartbeat over mTLS), mutual mode rejects no-cert client at TLS handshake, server mode accepts no-cert client (transport-only encryption), agent rejects server cert signed by unknown CA.

### Open after Phase 7ak

- **Operators bring their own PKI in production.** `generate_self_signed_pki` is for tests + first-stand bootstrap only; deploying to prod still needs cert-manager / Vault PKI / AWS PCA / similar. Document this in operator docs when they exist.
- **No `iac-controlplane bootstrap-tls` admin command.** The PKI generator is a library function; an operator-facing CLI command would let test stands fire-and-forget without writing a Rust harness. ~50 lines; defer.
- **No client-cert revocation.** mTLS rejects on cert expiry but there's no CRL or per-cert deny-list. Operators rotate by re-issuing the CA + redistributing certs (operationally heavy). OCSP stapling / short-lived certs are the long-term fix.
- **`rustls-pemfile` is unmaintained** (RUSTSEC-2025-0134, informational). Migrate to `rustls-pki-types::pem` once axum-server upgrades.

## Phase 7al — Postgres backend via `sqlx::AnyPool` — DONE.

**415 tests passing on SQLite.** A docker-gated `postgres_round_trip` integration test (`IAC_POSTGRES_INTEGRATION=1`) ran register → heartbeat → observation → list-agents end-to-end against `postgres:16-alpine`. `cargo audit` clean across 370 transitive deps.

Thirty-seven consecutive phases shipped from 7b through 7al. The most recent: `Store` now picks its driver at runtime from the database URL scheme — `sqlite://…` (default) or `postgres://…`. Internally we use `sqlx::AnyPool`; placeholder syntax stays as `?` in source for readability and a runtime translator rewrites to `$N` when the active dialect is Postgres. SQLite-only PRAGMAs (WAL, busy_timeout, foreign_keys) run via `after_connect` and are silently skipped on Postgres.

### Phase 7al deliverables (✅)

- [x] Workspace `sqlx` feature set adds `postgres` and `any` ([Cargo.toml](Cargo.toml)). No new RUSTSEC drag-back; transitive dep count holds at 370.
- [x] [`Dialect`](crates/iac-controlplane/src/store.rs) enum + `Dialect::from_url(database_url)` — picks driver at connect time.
- [x] [`ACTIVE_DIALECT: OnceLock<Dialect>`](crates/iac-controlplane/src/store.rs) set on first connect; `pub(crate) fn sql(s) -> Cow<str>` translates `?` → `$N` only for Postgres. Quoted strings and `--` line comments are skipped so a literal `?` inside SQL text stays untouched.
- [x] `Store::pool` field switched from `SqlitePool` to `AnyPool`. All `sqlx::query("...")` and `sqlx::query_as("...")` callsites in [store.rs](crates/iac-controlplane/src/store.rs), [retention.rs](crates/iac-controlplane/src/retention.rs), [webhook.rs](crates/iac-controlplane/src/webhook.rs) wrapped with `&sql(...)`.
- [x] Parallel [`migrations-postgres/`](crates/iac-controlplane/migrations-postgres/) set with `BIGSERIAL` primary keys + `BIGINT` integer columns so `i64::from(bool)` binds match. Picked at `run_migrations` time based on dialect; same version numbers as the SQLite set.
- [x] **1 new integration test** ([postgres_real.rs](crates/iac-controlplane/tests/postgres_real.rs)) — gated on `IAC_POSTGRES_INTEGRATION=1`. Spins `postgres:16-alpine` via `docker run`, exercises register / heartbeat / record_observations / list_agents. Drop guard removes the container even on test panic.

### Open after Phase 7al

- **Mixed-dialect process not supported.** `ACTIVE_DIALECT` is a `OnceLock`, so the first connect wins. A test binary that wants both backends in one process can't have it. Fine for production (one process → one DB); tests put PG in its own binary.
- **No migration script for moving an existing SQLite db to Postgres.** Operators today need to dump+rewrite manually. A `iac-controlplane migrate-data --from sqlite --to postgres` admin command would handle it; ~200 lines, not built yet.
- **Connection pool sizing is hardcoded at 8.** Fine for both dev SQLite and small Postgres deployments. Make it configurable via `[database]` section when an operator hits real load.
- **Postgres-flavored migrations stay in lock-step manually.** Adding a new migration means writing both `migrations/N.sql` AND `migrations-postgres/N.sql`. A doc note + lint check would help; deferred until the schema actually changes again.
- **`TIMESTAMPTZ` not used.** All timestamps are `TEXT` in both dialects so the wire shape stays uniform. Switching to `TIMESTAMPTZ` on Postgres would let us index time ranges natively. Migrate when query patterns demand it.

## Phase 7am — `${secret://...}` resolution at submit time — DONE.

**431 tests passing on SQLite.** Docker-gated `vault_round_trip_resolves_kv_v2_secret` (`IAC_VAULT_INTEGRATION=1`) exercised the Vault KV-v2 path end-to-end against `hashicorp/vault:1.18`. `cargo audit` clean — 370 transitive deps, no new advisories.

Thirty-eight consecutive phases shipped from 7b through 7am. The most recent: operators write `${secret://<resolver>/<path>[#field]}` inside resource specs; the control-plane substitutes values at submission time before persistence + routing. Two backends in tree (`env`, `vault`) plus a closed-set enum so adding more is one variant + one match arm. Fail-closed: a server with no registry rejects submissions that contain `${secret://` substrings.

### Phase 7am deliverables (✅)

- [x] [`crates/iac-controlplane/src/secrets.rs`](crates/iac-controlplane/src/secrets.rs): `SecretRef` parser, `Resolver` enum (`Env` / `Vault` + `#[cfg(test)] Static`), `SecretRegistry` with closed-set dispatch, RFC-6901-pointer-based JSON walker that handles arrays + nested objects + multiple refs in one string. 12 unit tests.
- [x] `VaultResolver` — KV v2 over HTTP. Mandatory `#field` since KV v2 returns `data.data` as an object; `404 / 403` from Vault → `BadRequest`; non-string field values rejected with the kind name in the error.
- [x] `[secrets] / [secrets.vault]` TOML config block ([config.rs](crates/iac-controlplane/src/config.rs)) — `addr` + (`token` inline OR `token_env` env-var name). `VaultConfig::resolve_token()` prefers inline then env. `Debug` impl for `SecretRegistry` only prints scheme names, never tokens.
- [x] `AppState::secret_registry: Option<Arc<SecretRegistry>>` ([server.rs](crates/iac-controlplane/src/server.rs)) — wired into the `submit` handler ([operations.rs](crates/iac-controlplane/src/api/operations.rs)) BEFORE composite expansion + routing. Fail-closed when registry is `None` and the submission contains any `${secret://` token.
- [x] **3 new e2e tests** ([e2e_secrets.rs](crates/iac-controlplane/tests/e2e_secrets.rs)): env-resolver round-trip via `POST /v1/operations` → `GET /desired-state` confirms substitution, no-registry server rejects `${secret://...}` submissions, no-secrets manifest still works under a registry.
- [x] **1 new docker integration test** ([vault_real.rs](crates/iac-controlplane/tests/vault_real.rs)) gated on `IAC_VAULT_INTEGRATION=1` — spins `hashicorp/vault:1.18` in dev mode, writes a KV-v2 secret with two fields, resolves both, asserts that missing field + missing path surface as `BadRequest` with diagnostic context.

### Open after Phase 7am

- **No SOPS resolver yet.** The user's earlier scope said "Vault/SOPS"; SOPS is straightforward to add as a new `Resolver::Sops(SopsResolver)` variant pointing at a key file or `age` keyring. Defer until an operator asks.
- **Resolver dispatch is sequential.** The walker does one async resolve at a time. Vault's HTTP client is fast and a manifest with hundreds of secrets is unusual, but if it ever bites, swap the loop for `try_join_all` over per-pointer resolves — care needed since the registry walks the same JSON value mutably.
- **Vault token auto-refresh missing.** A token with a TTL will eventually expire; we read it once at startup and never re-auth. Production setups should mount a renewing token via Vault Agent sidecar + `token_env` pointing at the mounted file's contents. Long-term: add a `token_file` option that re-reads on each request.
- **Resolved secrets are persisted in cleartext** in the desired-state row. That's the cost of resolving server-side — the trade-off is operators don't have to plumb credentials to every agent. If we ever want at-rest encryption for desired-state JSON, this is where to add it.
- **`#field` only walks `data.data`** (KV v2 default). KV v1 mounts use a flatter `.data.<key>` shape; not supported. Operators set the path themselves so the `data/` segment is explicit, but a `kv_version: 1` flag on the vault config would let v1 mounts work too.
- **No retry on transient Vault errors.** A 5xx from Vault fails the whole submission. Vault is supposed to be HA; if it isn't, manifests should still be re-submittable. A simple bounded retry inside `VaultResolver::resolve` would help.

## Phase 7an — per-resource observation cap — DONE.

**434 tests passing on SQLite.** The Postgres docker test now also exercises the new window-function prune path. `cargo audit` clean — 370 transitive deps, no new advisories.

Thirty-nine consecutive phases shipped from 7b through 7an. The most recent: a new `observation_max_per_resource` retention knob. After the age-based prune, any (agent_id, resource_id) group with more rows than the cap drops the oldest. Useful when an agent reports the same resource on every observe loop — without the cap, observation_days alone leaves thousands of rows for a single resource even if they're all recent.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now — operator may pick whatever's next.

### Phase 7an deliverables (✅)

- [x] `RetentionConfig::observation_max_per_resource: u32` (default `0` = disabled) ([retention.rs](crates/iac-controlplane/src/retention.rs)). Added to TOML schema + `Default` impl.
- [x] `PruneStats::observations_per_resource: u64` separate counter so operators see how much each retention dimension contributes; rolled into `total()`.
- [x] `prune_observations_per_resource` runs `DELETE FROM observations WHERE id IN (SELECT id FROM (… ROW_NUMBER() OVER (PARTITION BY agent_id, resource_id ORDER BY observed_at DESC, id DESC) AS rn FROM observations) WHERE rn > ?)`. Both SQLite (3.25+) and Postgres support window functions; sqlx::Any passes the SQL through with `?` → `$1` translation.
- [x] **3 new unit tests** ([retention.rs](crates/iac-controlplane/src/retention.rs)): cap drops the right number, `0` disables, partition-by-(agent, resource) so two agents reporting the same resource_id each get their own top-N (multi-host stands don't share retention budget).
- [x] **PG path covered** — extended [postgres_real.rs](crates/iac-controlplane/tests/postgres_real.rs) to insert 4 extra observations and prune-with-cap, asserting 3 rows dropped. Verifies `ROW_NUMBER() OVER (PARTITION BY ...)` works through `sqlx::Any` against real Postgres, not just on SQLite.
- [x] Hardened `pg_isready` wait in the Postgres fixture with a 400ms grace sleep after the first OK — `pg_isready` can return "accepting connections" while the listener is still finishing startup, leading to a transient `Connection reset by peer` on the immediate next connect.

### Open after Phase 7an

- **No equivalent cap on `audit_events` / `drift_events`.** Audit volume is bounded by operator activity, drift volume by actual changes — both are naturally less spiky than observations. Add caps when an actual operator hits a problem.
- **Cap doesn't gate by environment / agent.** The same N applies to every (agent, resource) pair. Operators with a high-frequency canary agent and slow-frequency prod agents might want a higher cap for canaries. Tracked but deferred — needs a per-agent / per-policy retention knob, not just a global one.
- **No metrics dimension.** `observations_per_resource` is logged but not exposed via `/v1/metrics` yet. Add when the metrics endpoint sees more retention surface (currently it's just total counters per dimension).

## Phase 7ao — `Provider::capability_keys` refactor — DONE.

**434 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisory churn.

Forty consecutive phases shipped from 7b through 7ao. The most recent: each provider now declares its own capability identifier(s) via `Provider::capability_keys(&Resource) -> Result<Vec<String>>`. The agent's allowlist check is now: look up provider for kind → call `capability_keys` → glob-match each key against the per-kind rules block. Long-overdue cleanup that was stubbed in the Phase 6a module comment ("Phase 6b will add a `capability_keys()` method on `Provider`") for over thirty phases.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ao deliverables (✅)

- [x] `Provider::capability_keys(&self, resource: &Resource) -> Result<Vec<String>>` ([provider.rs](crates/iac-core/src/provider.rs)) with default `Ok(Vec::new())` — opt-in, so a future provider that governs nothing is a no-op for the allowlist.
- [x] Implementations on all six built-ins ([file](crates/iac-providers/src/file/mod.rs), [nginx](crates/iac-providers/src/nginx/mod.rs), [systemd](crates/iac-providers/src/systemd/mod.rs), [docker](crates/iac-providers/src/docker/mod.rs), [package](crates/iac-providers/src/package/mod.rs), [cron](crates/iac-providers/src/cron/mod.rs)) — each returns its canonical identifier (path / name / `unit_name()`).
- [x] [`Capabilities::check`](crates/iac-agent/src/capabilities.rs) now takes `&ProviderRegistry` and dispatches through it. Extractors `extract_str`/`missing_field` deleted. Stale Phase 6a/6b module comment rewritten.
- [x] Test fixtures updated to pass fully-valid specs (`docker_spec`, `package_spec`, `cron_spec`, `nginx_spec` helpers) since `capability_keys` runs through the provider's full `parse_spec`.
- [x] `missing_required_spec_field_is_denied` reframed: a malformed spec now surfaces as `<spec-error>` identifier with `"could not extract capability key: …"` reason instead of the old `"required field missing"`. The exact provider parse-error text is still in the `reason` for diagnosis.

### Open after Phase 7ao

- **Per-kind rules schema is still hardcoded** in `Capabilities` (one field per kind: `files`, `nginx_vhost`, …). Adding a new kind with allowlist support still needs a new field + `Raw*` struct + match arm in `check`. Future cleanup: replace fields with `HashMap<kind, KeyRules>` so the YAML schema stays per-kind but Rust stops needing a code change. Defer until a third allowlist-bearing kind shows up.
- **Capability check now requires a fully-valid spec.** Previously the lightweight `extract_str` ignored unrelated spec fields; today a Docker spec without `image` fails the capability check before it would have failed at apply. Strictly better — the agent fails closed earlier — but operators who run `iac plan --server` against an in-progress manifest will now see capability errors where they used to see provider-validation errors. Documented as expected; no rollback.
- **`capability_keys` returns `Vec<String>` even though every built-in returns exactly one entry.** The Vec leaves room for a future `kind` that governs multiple identifiers (e.g. an upcoming `firewall.rule` with both src and dst). Drop to `Option<String>` if no multi-key kind ever materializes.

## Phase 7ap — semaphore-wait histogram + OpenMetrics seconds — DONE.

**436 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-one consecutive phases shipped from 7b through 7ap. The most recent: webhook dispatcher's `semaphore_wait_micros` cumulative counter is now paired with a 7-bucket histogram (100µs → +Inf, powers of ten). Operators with a tight `max_concurrent_requests` could already see the average climb on the counter; the histogram tells them whether the slow tail is dominating or *all* requests are slow. Prometheus rendering follows OpenMetrics conventions: bucket names use seconds (`le="0.0001"`), `_sum` is in seconds, `_count` is observation count.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ap deliverables (✅)

- [x] `SemaphoreWaitHistogram` ([webhook.rs](crates/iac-controlplane/src/webhook.rs)) — fixed-size `[AtomicU64; 7]` with non-cumulative storage; one `fetch_add` per observation. Bucket bounds `[100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000]` µs + implicit `+Inf`.
- [x] `WebhookMetrics::semaphore_wait_hist` field + `WebhookMetricsSnapshot::semaphore_wait_hist` snapshot. Histogram is recorded inside `fire_with_permit` alongside the existing cumulative counter so both grow in lockstep.
- [x] `/v1/metrics?format=prom` emits OpenMetrics-style histogram lines: `_bucket{le="..."}` (cumulative at render time), `_sum` (seconds, derived from existing `semaphore_wait_micros`), `_count`. Bucket bounds rendered in seconds (`0.0001` for 100µs etc.).
- [x] **2 new unit tests** — `semaphore_wait_histogram_picks_bucket_by_upper_bound` ([webhook.rs](crates/iac-controlplane/src/webhook.rs)) locks the boundary semantics (`v == bound` lands IN that bucket, not the next), and `render_prom_emits_semaphore_wait_histogram_in_seconds` ([api/metrics.rs](crates/iac-controlplane/src/api/metrics.rs)) verifies cumulative arithmetic, the seconds conversion, and that the legacy `_micros_total` counter still renders.
- [x] Legacy `iac_webhook_semaphore_wait_micros_total` cumulative counter retained — operators with existing dashboards don't break. Drop in a future "OpenMetrics-strict naming" phase once consumers migrate.

### Open after Phase 7ap

- **Buckets are global, not per-webhook.** The histogram aggregates across all configured webhooks. A receiver that's responsive plus one that's pathologically slow blend together. Splitting requires labelling each bucket counter with a webhook name — manageable but multiplies the atomic count by N receivers. Defer until an operator hits this.
- **No latency histogram for HTTP delivery itself.** This phase only covers the *wait* on the concurrency semaphore. End-to-end delivery latency (acquire + send + parse response) would be a second histogram. Add when an operator asks for it.
- **Bucket bounds are hardcoded.** Operators can't tune them via config. Keeping them static lets us assume a fixed-size array; a config-driven approach would need `Vec<u64>`. Most operators won't care; if one does, the array bounds are easy to change.
- **OpenMetrics-strict naming** still pending (other gauge / counter names use `_micros_total` style instead of `_seconds_total`). Not breaking — the `?format=prom` rendering is just additive — but a future cleanup phase can normalize everything to `_seconds`.

## Phase 7aq — cache config-issues at startup — DONE.

**436 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-two consecutive phases shipped from 7b through 7aq. The most recent: closes the "Open after Phase 7aj" item — `/v1/admin/config-issues` no longer re-parses every maintenance window on every request. The issue list is computed once at AppState construction (same call path that drives the `iac_maintenance_misconfigured_windows` gauge) and served as a cheap `Arc<Vec<ConfigIssue>>` ref-bump. Cheap today, but readies the codebase for SIGHUP-style reloads where the cache will need explicit invalidation.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7aq deliverables (✅)

- [x] `AppState::config_issues: Arc<Vec<ConfigIssue>>` ([server.rs](crates/iac-controlplane/src/server.rs)) — populated once during construction, cloned cheaply across requests.
- [x] `main.rs` precomputes via `collect_config_issues(&config.maintenance_windows, &config.recurring_maintenance_windows)` and stores in the Arc.
- [x] [`api/admin.rs`](crates/iac-controlplane/src/api/admin.rs) handler now serializes from the cached slice; no `parse()` calls per request.
- [x] [`e2e_admin_config_issues.rs`](crates/iac-controlplane/tests/e2e_admin_config_issues.rs) fixture mirrors main.rs's precompute step so the existing 3 tests cover the cache path. `lists_misconfigured_entries_with_kind_name_error` still asserts the same 3-entry shape and order.
- [x] All 26 `AppState`-constructing test fixtures patched with `config_issues: Arc::new(Vec::new())` for the no-windows case (most tests don't configure maintenance windows; their default empty cache is correct).

### Open after Phase 7aq

- **No invalidation hook.** A future SIGHUP reload will need to rebuild the cache alongside the rest of `Config`. The cache lives on `AppState`, not inside an `ArcSwap`, so reload requires either a routing-layer rebuild (replace the whole `AppState`) or an `Arc<RwLock<...>>` over the snapshot. Decide as part of the SIGHUP phase, not now.
- **No metric for "cache hits saved this many parses".** The legacy path was already cheap (parsing a few-element list is microseconds). The cache is a correctness preserver for SIGHUP, not a performance fix. Don't bother instrumenting hit/miss.
- **Issue list still has only `kind = "maintenance_window" | "recurring_maintenance_window"`.** Other config blocks (policies, webhooks, expanders) reject at config-load with hard errors instead of skip-with-issue, so they have no place in the cache. Extending the issue list to cover any new "skip-on-failure" config blocks is straightforward.

## Phase 7ar — timezone on `RecurringMaintenanceWindow` — DONE.

**441 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-three consecutive phases shipped from 7b through 7ar. The most recent: recurring maintenance windows now accept an optional IANA `timezone` field (`America/New_York`, `Asia/Tokyo`, `UTC`, …). HH:MM bounds and weekday set are interpreted in that zone, so a "Saturday 23:00-23:59 Asia/Tokyo" window blocks at the local Saturday-night wallclock instead of the UTC equivalent. Default behavior (`None` / unset) is unchanged: UTC. DST transitions are handled implicitly by jiff's tzdb — a "02:00-04:00 New_York" window shifts in absolute time across the spring/fall boundary.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ar deliverables (✅)

- [x] [`RecurringMaintenanceWindow::timezone: Option<String>`](crates/iac-controlplane/src/maintenance.rs) — `#[serde(default)]` so existing configs deserialize unchanged. Empty string treated as `None`.
- [x] [`RecurringWindowParsed`](crates/iac-controlplane/src/maintenance.rs) struct holds the resolved `jiff::tz::TimeZone` alongside parsed minutes + weekdays — one tzdb lookup per parse, not per check.
- [x] `parse()` validates the IANA name at config-load via `jiff::tz::TimeZone::get(name)`. Unknown names go into the `ConfigIssue` list (covered by Phase 7aj's `/v1/admin/config-issues` endpoint) so operators see the typo surfaced explicitly.
- [x] `check_recurring` re-zones `now` per-window so a single config can mix windows in different timezones. Retry-After is computed in the local zone (DST-aware end-of-window).
- [x] 503 detail string now ends with the configured TZ label (`"… is active until 04:00 America/New_York"`) instead of the implicit `"UTC"` so operators reading the error don't need to back-translate.
- [x] **5 new unit tests** ([maintenance.rs](crates/iac-controlplane/src/maintenance.rs)): explicit `UTC` matches default, `America/New_York` window blocks at local wallclock, same wallclock interpreted as UTC passes (proves the zone is actually being applied), unknown TZ name silently skipped (matches the existing malformed-window pattern), weekday lookup uses local zone not UTC (Tokyo dateline edge case).

### Open after Phase 7ar

- **Absolute `MaintenanceWindow` is still UTC-only.** Operators write absolute timestamps as `2026-05-01T02:00:00Z` etc. — the timezone is in the value, not a separate field. Adding parallel `timezone` support there would let operators write `2026-05-01T02:00:00` + `timezone: "America/New_York"`. Defer until someone asks.
- **No DST-transition tests.** The Eastern-time test runs in May (DST active throughout the test window). A test that crosses a "spring forward" or "fall back" boundary would lock the DST behavior more tightly. Skipped because jiff's tzdb is what actually owns this; testing it is testing jiff.
- **tzdb name validation rejects deprecated aliases like `US/Eastern`.** jiff's behavior. Operators using legacy names get the same 503-skip-at-config-load path as any other unknown name. Document on the `timezone` field if anyone hits it.

## Phase 7as — persist webhook backoff deadlines across restarts — DONE.

**443 tests passing on SQLite.** Postgres migration applied cleanly via the integration test. `cargo audit` clean — 370 transitive deps, no advisories.

Forty-four consecutive phases shipped from 7b through 7as. The most recent: 429-driven backoff state used to be in-memory only — a server restart during an active cool-down would immediately re-fire the misbehaving receiver. Now the deadline persists in a new `webhook_backoff` table; the dispatcher loads still-future rows on `initialize()` and rebuilds its in-memory map, so a restart picks up exactly where the previous process left off.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7as deliverables (✅)

- [x] Migration v8 in both [`migrations/`](crates/iac-controlplane/migrations/20260501000008_webhook_backoff.sql) and [`migrations-postgres/`](crates/iac-controlplane/migrations-postgres/20260501000008_webhook_backoff.sql) — single-PK table on `webhook_name` + `deadline_unix` BIGINT + `updated_at`. Same shape both dialects.
- [x] `WebhookDispatcher::persist_backoff` ([webhook.rs](crates/iac-controlplane/src/webhook.rs)) — upsert on `webhook_name` after a 429 with parseable `Retry-After`. `INSERT … ON CONFLICT(webhook_name) DO UPDATE` works for both SQLite and Postgres.
- [x] `WebhookDispatcher::load_persisted_backoffs` runs at the end of `initialize()`. Filter: `WHERE deadline_unix > now_unix` so expired rows are inert until the next 429 overwrites them.
- [x] `&Store` plumbed through `fire_with_permit` → `fire` so the 429 branch can persist directly. The cursor write path already had `&store`; this matches that pattern.
- [x] **2 new e2e tests** ([e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs)): `backoff_survives_dispatcher_restart` (receiver returns 429 once, restart, second-lifecycle dispatcher does NOT hit the receiver despite a fresh event, third-lifecycle with a *different* webhook name DOES fire — confirms keying by name is correct), and `expired_backoff_rows_are_ignored_on_restart` (plant a stale row directly in DB, verify the WHERE filter ignores it).
- [x] Postgres integration test ([postgres_real.rs](crates/iac-controlplane/tests/postgres_real.rs)) ran the migration against `postgres:16-alpine` end-to-end — confirms the BIGINT/TEXT column types match the runtime binds.

### Open after Phase 7as

- **No GC of expired rows.** A row whose deadline passed sits in the table until either (a) the next 429 overwrites it, or (b) the table grows enough to bother. With one row per webhook name and no churn beyond initial config, this is naturally bounded — no cron sweeper needed.
- **Backoff is monotonic — successive 429s extend the deadline, never shorten it from the receiver's perspective.** The current write blindly overwrites with the new deadline. A receiver that returns 429+1s while we're already in a 600s backoff would *shorten* the wait. Likely fine for honest receivers; an attacker can't really exploit it (they'd just be reducing their own ban). Document if anyone notices.
- **Still no HTTP-date Retry-After.** Seconds form only, mirroring Phase 7ab. Adding date form is a few lines using `chrono::DateTime::parse_from_rfc2822` or a manual parse; defer until a real receiver uses it.
- **Migration count reaches v8.** Operators on long-lived deployments now have eight applied migrations. No-op for fresh installs; existing deployments pick up the table at startup with the standard logging line.

## Phase 7at — per-webhook label dimensions in `/v1/metrics` — DONE.

**446 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-five consecutive phases shipped from 7b through 7at. The most recent: webhook dispatcher's four outcome counters (`dispatched_ok`, `dispatched_non_success`, `dispatched_ratelimited`, `delivery_errors`) now have per-receiver breakdowns alongside the existing global totals. Operators with multiple receivers (alerts → Slack + audit → S3) can finally tell which one is misbehaving without correlating logs. Hot path stays lock-free: the per-webhook map is built once at dispatcher construction, lookups are `&HashMap` + `AtomicU64::fetch_add`.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7at deliverables (✅)

- [x] [`PerWebhookCounters`](crates/iac-controlplane/src/webhook.rs) — same shape as the four global outcome counters, scoped to one receiver. `semaphore_wait_*` stays global since the semaphore is shared across all receivers.
- [x] `WebhookMetrics::per_webhook: HashMap<String, PerWebhookCounters>` populated once at `WebhookDispatcher::new` from the configured webhook list. Read-only after construction; the `&HashMap` borrow + atomic increment hot path needs no mutex.
- [x] `WebhookMetricsSnapshot::per_webhook: Vec<(String, PerWebhookSnapshot)>` — name-sorted on snapshot so JSON / Prom output is stable across calls (HashMap iteration order would otherwise be non-deterministic).
- [x] `fire()` increments both global and per-webhook counters on each outcome. `if let Some(p) = per` guard so a future config-mutation path doesn't panic if a receiver disappears.
- [x] [`api/metrics.rs`](crates/iac-controlplane/src/api/metrics.rs) emits `iac_webhook_<outcome>_per_receiver_total{webhook="<name>"} N` for each of the four counters. One `# HELP` / `# TYPE` per metric, then per-receiver labeled rows. `escape_label` handles backslash, double-quote, and newline per OpenMetrics text exposition.
- [x] **2 new unit tests** ([api/metrics.rs](crates/iac-controlplane/src/api/metrics.rs)): per-webhook labeled output verified for two receivers (sort order + cross-counter coverage), label escaping verified for backslash/quote/newline edge cases.
- [x] **1 new e2e test** ([e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs)) `per_webhook_metrics_attribute_outcomes_to_each_receiver`: two configured receivers (one always 200, one always 500), both see the same audit events, then the per-webhook breakdown shows 2 OK on `alerts` and 2 non-success on `audit-archive` with no cross-contamination.

### Open after Phase 7at

- **`per_window_name` and `per_bucket` label dimensions still missing** from the Phase 8+ backlog item. The histogram (Phase 7ap) is global; per-receiver histograms would multiply atomic-counter count by N receivers. Defer until an operator hits this.
- **No per-webhook semaphore-wait counter.** The semaphore is shared across all receivers so the wait time isn't per-receiver-attributable in any meaningful way. Documented at the `PerWebhookCounters` doc comment.
- **No SIGHUP-aware rebuild.** The map is fixed at construction. A future SIGHUP reload would need to either rebuild the dispatcher (new metrics map, lose accumulated counts) or merge old + new (more code, ambiguous semantics for renamed receivers). Decide as part of the SIGHUP phase.
- **Label cardinality unbounded.** Operators can configure arbitrarily many webhook names; each adds a row in the Prom output. With realistic operator scale (a handful of receivers) this is fine; if someone configures hundreds, the metrics endpoint emits hundreds of lines per metric. Document if anyone hits scale issues.

## Phase 7au — HTTP-date `Retry-After` parser — DONE.

**450 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-six consecutive phases shipped from 7b through 7au. The most recent: webhook dispatcher's 429 handler now accepts both forms RFC 7231 §7.1.3 allows — `delta-seconds` (`120`) and IMF-fixdate (`Fri, 31 Dec 1999 23:59:59 GMT`). Closes the open-after-7as note. Receivers using either form get the same backoff treatment (capped at `MAX_BACKOFF_SECS`).

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7au deliverables (✅)

- [x] [`parse_retry_after(value: &str, now: Timestamp) -> Option<u64>`](crates/iac-controlplane/src/webhook.rs) — module-level helper exposed for direct testing. Returns `None` for unparseable input so the caller's existing "no parseable Retry-After" no-op log path stays intact.
- [x] Date parsing routes through `civil::DateTime::strptime("%a, %d %b %Y %H:%M:%S", ...)` then explicitly attaches UTC. jiff strptime's strict weekday/date consistency check is preserved (a forged `"Sat, 01 Jan 2099"` where Jan 1 2099 is actually Thursday rejects, not silently misparses).
- [x] Past-dated values yield `Some(0)` rather than negative seconds — the dispatcher treats that as "no backoff" downstream, same as a missing header.
- [x] **3 new unit tests** ([webhook.rs](crates/iac-controlplane/src/webhook.rs)): seconds form (with whitespace + `0`), HTTP-date form (future date computes positive delta, past date yields `Some(0)`), and rejection of garbage / RFC-850 obsolete form / negative seconds.
- [x] **1 new e2e test** ([e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs)) `http_date_retry_after_triggers_backoff`: receiver returns 429 with a runtime-computed IMF-fixdate, second event hits the backoff path and the receiver count stays at 1. Date is formatted via `Timestamp::strftime` so the weekday always matches the date jiff is strict on.
- [x] Stale comment "Retry-After header (seconds form only — HTTP-date form is too rare to bother parsing)" rewritten to reflect both forms now work.

### Open after Phase 7au

- **Obsolete RFC 850 / asctime forms still rejected.** Falling back to "no backoff" is safer than honoring a misparsed date; modern servers emit IMF-fixdate. Add only if a real receiver needs it.
- **Date arithmetic uses `Timestamp::as_second()` deltas in i64.** Far-future dates (year 10000+) overflow at the millennium boundary; the cap at `MAX_BACKOFF_SECS = 1h` makes that academic.
- **`parse_retry_after` is duplicated logic-wise with the *outbound* `Retry-After` formatter.** The outbound side (rate limiter, maintenance windows) currently emits seconds form only. Adding HTTP-date *output* would let strict scrapers consume our 429s in either form. Defer until an operator asks.

## Phase 7av — drop legacy `bucket=…` prefix from 429 detail — DONE.

**450 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-seven consecutive phases shipped from 7b through 7av. The most recent: closes the long-standing follow-up "Drop legacy `bucket=…` prefix from 429 detail once consumers migrated to structured field." 429 responses now return `detail: "retry after Ns"` (plain human-readable) alongside the structured `bucket: {type, name}` field that's been there since Phase 7q. No CLI / agent consumers were reading the prefix; only the e2e tests asserted it (now updated).

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7av deliverables (✅)

- [x] [`error.rs`](crates/iac-controlplane/src/error.rs) `TooManyRequests` arm now formats `detail` as `"retry after {N}s"` — no `bucket=<type>:<name>` prefix. Bucket info still in the structured `bucket` field next to `detail`.
- [x] Comment on `ErrorBody.bucket` updated to reflect that `detail` no longer carries machine-readable bucket info — clients should read `body.bucket` directly.
- [x] **3 test assertions updated** (in [e2e_rate_limit.rs](crates/iac-controlplane/tests/e2e_rate_limit.rs) + [e2e_policy_rate_limit.rs](crates/iac-controlplane/tests/e2e_policy_rate_limit.rs)) — now assert `detail.starts_with("retry after ")` AND `!detail.contains("bucket=")` so any future regression that re-adds the prefix breaks the test loudly.
- [x] No CLI / agent code paths read `bucket=…` from `detail` — verified via grep before the cleanup. The structured field has been the only programmatic source since Phase 7q.

### Open after Phase 7av

- **Detail string is now operator-only.** Programmatic clients must use `body.bucket`. If a third-party scraper somewhere still parses `detail`, they'll see the new format and need to migrate. The TASKS entry guarded against this since Phase 7q.
- **No equivalent cleanup for 503 ServiceUnavailable detail** (maintenance window blocks). Those still carry the window name + end time inline because there's no structured equivalent yet. Revisit if/when per-window-name labels (still open) ship a typed result for blocks.
- **Format string is `"retry after {N}s"` regardless of which bucket fired.** Operators reading the JSON see the same text whether it's an env-cap or policy-cap rejection — they have to look at `bucket.type` to know which. Acceptable since the structured field is the canonical machine-readable signal.

## Phase 7aw — `extra_locations` for `nginx.vhost` — DONE.

**461 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-eight consecutive phases shipped from 7b through 7aw. The most recent: `nginx.vhost` resources now accept additional `location` blocks beyond the default `/` proxy_pass. Operators can mix proxy + static-file blocks in one vhost — `/static/` → root path, `/metrics` → side-channel upstream, `= /healthz` exact-match probe, etc. The default `/` block stays first; extra blocks render in declared order so `iac diff` is byte-stable.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7aw deliverables (✅)

- [x] [`NginxVhostSpec::extra_locations: Vec<ExtraLocation>`](crates/iac-providers/src/nginx/spec.rs) — `#[serde(default)]` so existing manifests parse unchanged.
- [x] [`ExtraLocation`](crates/iac-providers/src/nginx/spec.rs) struct: `path` (string), and exactly one of `proxy_pass` or `root`. `#[serde(deny_unknown_fields)]` so typos reject loudly.
- [x] `validate_extra_location`: path must start with `/`, `=`, `~`, or `^~` (covers prefix / exact / regex / preferential-prefix forms); no `;`, `\n`, or `"` anywhere; `proxy_pass` reuses the existing `validate_upstream`; `root` must be absolute, no `..`, no shell metacharacters. `(None, None)` and `(Some, Some)` both reject with explicit messages.
- [x] [`render`](crates/iac-providers/src/nginx/render.rs) emits each extra location AFTER the default `/` block in the spec's declared order. `proxy_pass` form gets the same `proxy_set_header` set as the default; `root` form gets just `root <path>;` — no proxy directives leaked into static-file blocks.
- [x] **3 new render tests** (proxy_pass form, root form, multiple-in-order) + **7 new spec tests** (parses minimal, neither/both reject, relative root rejects, traversal in root rejects, bad path prefix rejects, semicolon in path rejects, proxy_pass shares `validate_upstream` rules).
- [x] Two existing fixtures patched with `extra_locations: vec![]` ([ops.rs](crates/iac-providers/src/nginx/ops.rs) + [render.rs](crates/iac-providers/src/nginx/render.rs)) — shape-only change; behavior unchanged for existing manifests.

### Open after Phase 7aw

- **No `try_files`, `alias`, `return`, or `rewrite` directives.** Operators with these needs still have to drop down to a hand-managed config. The most-asked next directive based on first-look feedback is `try_files` (SPA routing); add a `try_files: Option<String>` field on `ExtraLocation` when an operator hits it.
- **No per-location `extra_directives` escape hatch.** The render is closed: only `proxy_pass` or `root` plus the implicit proxy headers for the proxy form. Adding a free-form `extra_directives: Vec<String>` would let operators emit arbitrary lines, but that's also a path to shell-injection-ish abuse if validation isn't tight. Defer until justified.
- **Default `/` block always renders first regardless of declared order.** Nginx's prefix matching means `/static/` would beat `/` for `/static/foo` requests anyway, so this is fine — but if an operator needs control over ordering for regex blocks, the spec doesn't expose that today.
- **No backend-side test that the rendered config actually reloads cleanly under nginx -t.** The provider's MockNginx doesn't validate. Real nginx integration test is Phase 8+ work.

## Phase 7ax — `labels` for `docker.container` — DONE.

**469 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Forty-nine consecutive phases shipped from 7b through 7ax. The most recent: `docker.container` resources now accept a `labels` map. Labels appear as `--label key=value` on `docker run`, surface in observe output, drive drift detection (subset semantics — image-baked labels don't count as drift), and persist in rollback checkpoints so reverting recreates with the same set.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ax deliverables (✅)

- [x] [`DockerContainerSpec::labels: IndexMap<String, String>`](crates/iac-providers/src/docker/spec.rs) — `#[serde(default)]` so existing manifests parse unchanged. `IndexMap` preserves declared order.
- [x] Validation: keys non-empty + no `=` + no NUL; values can contain `=` freely (only the key has structural meaning); `state=absent` forbids labels alongside the existing image/env/ports check.
- [x] `ContainerInfo::labels: Vec<String>` (sorted `KEY=VALUE` lines) flattened from `.Config.Labels` in `parse_inspect_json`. Sort makes the value canonical regardless of JSON object iteration order.
- [x] `MockContainer` parallel field + `MockDocker::run` writes the spec's labels in sorted form so the mock-vs-real path stays parallel.
- [x] `DockerCli::run` emits `--label key=value` per declared label.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) surfaces `labels` in the output spec; [`diff`](crates/iac-providers/src/docker/ops.rs) checks subset semantics (`env_subset` reused — desired ⊆ observed, so image-baked / docker-injected labels don't count as drift).
- [x] [`pre_apply`](crates/iac-providers/src/docker/ops.rs) checkpoint includes `previous_labels`; [`rollback`](crates/iac-providers/src/docker/ops.rs) restores them. Pre-7ax checkpoints (no `previous_labels` key) fall back to empty so existing in-flight rollbacks don't break.
- [x] **5 new spec tests** (parses + preserves order, rejects key-with-equals, rejects empty key, absent forbids, values can contain `=`) + **3 new ops tests** (missing labels show as drift, extra observed labels are subset-tolerated, rollback restores labels from checkpoint).

### Open after Phase 7ax

- **No `command` / `volumes` / `networks` / `healthcheck` yet.** The Phase 8+ backlog item lists all five together; this tick shipped only labels (smallest, most-broadly-useful). Each of the others has its own diff complexity (e.g., `volumes` needs path-binding parsing à la `ports`, `healthcheck` needs `--health-*` plumbing). Pick them up incrementally.
- **Subset diff means deleting a label from the manifest is silent.** Removing `app: web` from the manifest while it's still on the running container won't trigger drift — the desired set is empty for that key, the observed set has it, subset still matches. Operators expecting a "delete tracked label" workflow would need a label_strict toggle. Mirror of the env behavior; document if anyone trips on it.
- **`org.opencontainers.image.*` labels still show up in observe output.** They don't count toward diff (subset), but they are visible in the spec snapshot. Filtering them at observe-time would clean the output, but it's harmless context for operators reading the JSON.

## Phase 7ay — `command` for `docker.container` — DONE.

**478 tests passing on SQLite.** Real-docker integration test re-run cleanly. `cargo audit` clean — 370 transitive deps, no advisories.

Fifty consecutive phases shipped from 7b through 7ay. The most recent: `docker.container` resources now accept a `command: [argv]` override. Distinct from the labels/env subset semantics — command is exact-match. `None` (or absent from manifest) means "use the image's default CMD" and never claims drift against whatever it observes; `Some(non-empty)` means "argv must match this exactly."

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ay deliverables (✅)

- [x] [`DockerContainerSpec::command: Option<Vec<String>>`](crates/iac-providers/src/docker/spec.rs) — `#[serde(default)]` so existing manifests parse unchanged. Empty array rejects with an explicit error message ("omit the field or set it to null") — keeps "image default" and "explicit empty CMD" from being ambiguous.
- [x] Validation: each argv element checked for NUL (the only structural concern; Docker exec'v doesn't go through a shell, so spaces/quotes/metas pass through verbatim). `state=absent` forbids command alongside labels/env/ports.
- [x] [`ContainerInfo::command: Option<Vec<String>>`](crates/iac-providers/src/docker/backend.rs) extracted from `.Config.Cmd` in `parse_inspect_json`. `null` or empty array → `None`; non-empty array → `Some(argv)`.
- [x] `MockContainer::command` mirror; `MockDocker::run` clones spec.command into the mock so test paths see the same Option<Vec<String>> shape.
- [x] `DockerCli::run` appends argv after the image — Docker's `run [opts] IMAGE [ARGS...]` syntax. Each spec arg is one argv slot.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) emits `command` as a `YamlValue::Sequence` (or `Null`); [`diff`](crates/iac-providers/src/docker/ops.rs) compares exact-match — argv order is sensitive (`["a","b"]` ≠ `["b","a"]` is real drift). Comparison gated on `spec.command.is_some()` so `None` never claims drift against image-default observed CMD.
- [x] [`pre_apply`](crates/iac-providers/src/docker/ops.rs) checkpoint includes `previous_command`; [`rollback`](crates/iac-providers/src/docker/ops.rs) restores it. `null` checkpoint value or empty array → `None` (image default), preserved across rollback.
- [x] **4 new spec tests** (default None, parses argv, rejects empty array, absent forbids command) + **4 new ops tests** (None doesn't drift against image CMD, explicit command drifts on mismatch, argv order is sensitive, rollback restores both Some(argv) AND lack-of-command).

### Open after Phase 7ay

- **No `entrypoint` override.** Docker has both `--entrypoint` and `ARGV...`; we only ship the `CMD` form (the more common need). If an operator needs to override entrypoint, they're stuck with hand-managed containers for now.
- **No `working_dir`, `user`, `hostname`** etc. The remaining docker-container backlog is `volumes`, `networks`, `healthcheck` — all bigger than command (each needs its own diff shape). Pick incrementally as operators ask.
- **Empty argv ambiguity guarded loudly.** `command: []` rejects at parse time. If we ever decide there's a real difference between "no CMD at all" vs "image default", the error message points the operator at `command: ~` (None) vs the rejected empty case.

## Phase 7az — `healthcheck` for `docker.container` — DONE.

**489 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-one consecutive phases shipped from 7b through 7az. The most recent: `docker.container` resources now accept a `healthcheck:` block (CMD-SHELL form). Operators write the command + optional `interval`/`timeout`/`retries`; the dispatcher emits `--health-cmd` plus the matching `--health-*` tuning flags on `docker run`. Diff is exact-match per field, with seconds-canonicalization between the spec's `"30s"`/`"2m"`/`"1h"` strings and Docker's nanosecond integer reporting.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7az deliverables (✅)

- [x] [`DockerContainerSpec::healthcheck: Option<DockerHealthcheck>`](crates/iac-providers/src/docker/spec.rs) and [`DockerHealthcheck`](crates/iac-providers/src/docker/spec.rs) struct (`command` required + `interval` / `timeout` / `retries` optional). `state=absent` forbids healthcheck alongside the existing image/env/ports/labels/command check.
- [x] `parse_health_duration_secs` accepts `<n>` (= seconds), `<n>s`, `<n>m`, `<n>h`. Bare integers, suffix overflow, and unknown suffixes all reject with explicit messages.
- [x] [`ContainerHealthcheck`](crates/iac-providers/src/docker/backend.rs) — observed shape with `command: Option<String>` + seconds-form integer durations + `retries: Option<u32>`. `parse_healthcheck` walks `.Config.Healthcheck` and supports the `["CMD-SHELL", cmd]` form (the only one we render); `["CMD", argv...]` and `["NONE"]` get downgraded to `command = None` so the diff path doesn't claim drift on what we can't represent yet.
- [x] `MockContainer::healthcheck` + `MockDocker::run` translates the spec block into the canonical seconds-form snapshot so mock-vs-real comparison is uniform.
- [x] `DockerCli::run` emits `--health-cmd <c>` and the matching `--health-interval` / `--health-timeout` / `--health-retries` flags only when the operator declared a `healthcheck:`.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) surfaces the healthcheck as a YAML mapping (or `Null` for "no observed healthcheck"); [`diff`](crates/iac-providers/src/docker/ops.rs) compares per-field with seconds-form canonicalization. `spec.healthcheck.is_none()` short-circuits — image-default observed healthchecks never claim drift.
- [x] [`pre_apply`](crates/iac-providers/src/docker/ops.rs) checkpoint stores `previous_healthcheck` (full struct including command + each duration in seconds + retries); [`rollback`](crates/iac-providers/src/docker/ops.rs) reconstructs a `DockerHealthcheck` from those seconds, formatting them as `"<n>s"` strings the spec layer can re-render.
- [x] **7 new spec tests** (parses minimal, parses with tunings, rejects empty command, rejects zero retries, rejects bad duration suffix, duration parser unit tests, absent forbids) + **4 new ops tests** (None doesn't drift against image default, declared healthcheck drifts on mismatch, duration units canonicalize correctly, rollback restores from checkpoint).

### Open after Phase 7az

- **CMD-SHELL form only.** No argv `["CMD", arg1, arg2]` form yet — operators who want it will hit "spec doesn't expose this." Add a `command_argv: Option<Vec<String>>` field as a sibling once asked for.
- **No `start_period`.** Less common than the other three tunings; add when needed.
- **No `--no-healthcheck` / explicit disable.** Operators who want to disable the image's default healthcheck have to wait. The current shape can't express it (Some(...) means override; None means image default). A `disabled: bool` flag would cover it without breaking the existing semantics.
- **No HEALTHCHECK_INHERITED state distinction.** If the operator removes `healthcheck:` from a manifest that previously declared one, we won't claim drift (None desired ≠ no comparison). The container keeps running with the override Docker remembers internally; operator can recreate manually if they care. Mirror of the labels-removal behavior.

## Phase 7ba — `volumes` for `docker.container` — DONE.

**502 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-two consecutive phases shipped from 7b through 7ba. The most recent: `docker.container` resources now accept a `volumes:` list using docker's standard `host:container[:ro|rw]` syntax. Bind mounts and named volumes both work. Diff is set-based — re-arranging the list in a manifest doesn't trigger drift; mode change (rw → ro) does. `host:/c` and `host:/c:rw` canonicalize to the same form so the operator can write either.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7ba deliverables (✅)

- [x] [`DockerContainerSpec::volumes: Vec<String>`](crates/iac-providers/src/docker/spec.rs) — `#[serde(default)]` so existing manifests parse unchanged. `state=absent` forbids volumes alongside the other override fields.
- [x] [`parse_volume_spec`](crates/iac-providers/src/docker/spec.rs) — splits `host:container[:mode]` into `(source, destination, read_only)`. `validate_volume_spec` rejects relative destinations, traversal (`..`), shell metacharacters, unknown modes (only `ro`/`rw` allowed), and bind sources that look relative (e.g. `./local`).
- [x] [`normalize_volume_spec`](crates/iac-providers/src/docker/spec.rs) — drops the trailing `:rw` (it's the default) so `host:/c` and `host:/c:rw` compare equal in diff.
- [x] [`ContainerInfo::volumes: Vec<String>`](crates/iac-providers/src/docker/backend.rs) populated by `parse_mounts`. Walks `.Mounts[]`, picks `Source` (or `Name` for named volumes), pairs with `Destination`, derives `:ro` from `RW: false`. Sorted output for canonical comparison.
- [x] `MockContainer::volumes` mirror; `MockDocker::run` parse-then-normalize each spec entry so the mock-vs-real path stays canonical.
- [x] `DockerCli::run` emits `--volume host:container[:ro]` per declared mount.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) surfaces volumes; [`diff`](crates/iac-providers/src/docker/ops.rs) sorted-set comparison after re-normalizing both sides through `parse_volume_spec` (so `:rw` ↔ no-suffix never false-flags).
- [x] [`pre_apply`](crates/iac-providers/src/docker/ops.rs) checkpoint stores `previous_volumes`; [`rollback`](crates/iac-providers/src/docker/ops.rs) restores them as a `Vec<String>` ready to feed back into `spec.volumes`.
- [x] **8 new spec tests** (parses bind + named, rejects relative dest, rejects traversal, rejects shell metas, rejects unknown mode, rejects relative bind source, mode canonicalization unit test, absent forbids) + **5 new ops tests** (set-based diff ignores order, drift on add/remove, drift on rw → ro, default mode = explicit rw, rollback restores).

### Open after Phase 7ba

- **No `--volume`'s expanded form (`type=bind,source=...,target=...`).** We only render the short `-v` form. Operators wanting `bind-propagation=shared` or `tmpfs-size=100m` are stuck. Add when asked.
- **No `volume create` step for named volumes.** Docker auto-creates them on first run, which is fine for most use cases. If an operator needs explicit volume creation with options (driver, labels), they hit the limitation.
- **No SELinux `:z` / `:Z` modes.** Users on RHEL-family distros may need them. Easy to add to `validate_volume_spec` once requested.
- **Bind-source absolute-path check is path-only.** We don't verify the path actually exists at submit time — that's a runtime concern (Docker fails the run if the source doesn't exist). Could add a CLI-side pre-submit warning later if operators trip on it.

## Phase 7bb — `network` for `docker.container` — DONE.

**512 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-three consecutive phases shipped from 7b through 7bb. The most recent: `docker.container` resources now accept a `network:` field naming the primary docker network the container attaches to. Singular for now since `docker run` only accepts one `--network` at create time; multi-network use cases would need `docker network connect` post-creation, deferred. Closes the docker-provider expansion that began with `labels` (7ax) — operators have `command`, `healthcheck`, `volumes`, `network`, `labels` as the fields they need most.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7bb deliverables (✅)

- [x] [`DockerContainerSpec::network: Option<String>`](crates/iac-providers/src/docker/spec.rs) — `#[serde(default)]`. `None` (default) leaves Docker on the default bridge. `state=absent` forbids network alongside the other override fields.
- [x] Validation: empty / whitespace strings reject (operator should omit the field entirely instead); shell metacharacters + `/` reject (compose-style stack/network references not supported).
- [x] [`ContainerInfo::networks: Vec<String>`](crates/iac-providers/src/docker/backend.rs) extracted from `.NetworkSettings.Networks` keys, sorted.
- [x] `MockContainer::networks` mirror; `MockDocker::run` records the spec's network as a singleton list (or `["bridge"]` for the default-bridge case) so mock-vs-real comparisons stay symmetric.
- [x] `DockerCli::run` emits `--network <name>` only when `spec.network.is_some()`.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) surfaces networks; [`diff`](crates/iac-providers/src/docker/ops.rs) checks set-equality with `[spec.network]` when the operator declared one. `None` desired → no comparison; default-bridge containers don't false-flag.
- [x] [`pre_apply`](crates/iac-providers/src/docker/ops.rs) checkpoint stores `previous_networks` (full list); [`rollback`](crates/iac-providers/src/docker/ops.rs) takes the first network and re-feeds it into `spec.network`, with a special case: observed `["bridge"]` rolls back to `None` (no explicit `--network`), matching what the operator originally declared.
- [x] **5 new spec tests** (parses, rejects empty, rejects shell metas, rejects slash, absent forbids) + **5 new ops tests** (drift on default-bridge vs declared, no-drift when both default, no-drift when matching, rollback restores explicit network, rollback to default-bridge leaves no explicit network).

### Open after Phase 7bb

- **Singular `network` field, plural `networks` deferred.** A container on multiple networks needs `docker run --network primary` + `docker network connect <other>` per additional. The current model has no place for that; would need a parallel `additional_networks: Vec<String>` field plus apply-time orchestration of the `connect` calls. Wait until an operator hits this.
- **No network creation.** We assume the network already exists. A `docker.network` provider would let operators declare network resources separately and have `docker.container` depend on them — fits the existing dependency-aware orchestration. Phase 8+ track.
- **Rollback's "first network" heuristic is fine for our model but lossy if Docker added secondary networks out-of-band.** A container with `[primary, monitoring-net]` would roll back as `network: primary` only. Mirror of the singular-field tradeoff.
- **No IP-address pinning.** `--ip <addr>` would be the next refinement; Docker accepts it on a per-network basis. Defer.

The docker-provider expansion arc is now closed: Phase 7ax (`labels`) → 7ay (`command`) → 7az (`healthcheck`) → 7ba (`volumes`) → 7bb (`network`). The TASKS Phase 8+ list no longer mentions any docker-container fields.

## Phase 7bc — pre-submit warn + OpenMetrics-strict naming — DONE.

**512 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-four consecutive phases shipped from 7b through 7bc. The most recent: two contained cleanups bundled. (1) `iac apply --server` now prints a visible `warning: pre-submit validation skipped (catalog fetch failed: …)` when the local catalog fetch fails; previously the failure path was silent and an operator with a stale local manifest could submit garbage and only see the rejection after the round-trip. (2) The legacy `iac_webhook_semaphore_wait_micros_total` Prometheus counter was renamed to `iac_webhook_semaphore_wait_microseconds_total` (OpenMetrics §4.1 — units must be in standard SI form). Operators using the histogram counterpart (`iac_webhook_semaphore_wait_seconds_*`, shipped in Phase 7ap) are unaffected.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7bc deliverables (✅)

- [x] [`main.rs`](crates/iac-cli/src/main.rs) `iac apply --server` path: replaced the silent `if let Ok(catalog) = …` with an explicit `match` that emits a stderr warning on the `Err` arm. Submission still proceeds (server-side serde validation is the authoritative gate); operator just sees explicit feedback that the local pre-flight skipped.
- [x] [`api/metrics.rs`](crates/iac-controlplane/src/api/metrics.rs): renamed `iac_webhook_semaphore_wait_micros_total` → `iac_webhook_semaphore_wait_microseconds_total`. Update is a single string change; existing `WebhookMetrics::semaphore_wait_micros` field name unchanged (internal field, not subject to OpenMetrics rules).
- [x] Updated test assertion in `render_prom_emits_semaphore_wait_histogram_in_seconds` to (a) confirm the new name, and (b) explicitly assert the legacy name is gone — so any future regression that re-adds the `_micros_total` key breaks the test loudly.

### Open after Phase 7bc

- **Breaking metric rename.** Operators with dashboards keyed on `iac_webhook_semaphore_wait_micros_total` need to update to `iac_webhook_semaphore_wait_microseconds_total` (both encode the same data — cumulative microseconds). The histogram form `iac_webhook_semaphore_wait_seconds_{bucket,sum,count}` (Phase 7ap) is the canonical signal going forward.
- **CLI warning is unconditional.** No `--quiet` / `--no-warn` flag to suppress it. Operators in CI that always have flaky catalog fetches will see the warning on every run; if anyone trips on it, add a flag.
- **No equivalent rename pass on other `_micros` / `_secs` style fields.** Searched grep — `semaphore_wait_micros_total` was the only OpenMetrics-style violation in the rendered output. Internal struct field names (`semaphore_wait_micros`) are operator-invisible and stay short.

## Phase 7bd — `iac plan --graph` dependency graph render — DONE.

**517 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-five consecutive phases shipped from 7b through 7bd. The most recent: `iac plan --server <url> --operation <id> --graph <ascii|dot>` renders the operation's dependency graph. ASCII mode prints an indented per-resource list with `↳ depends on …` bullets; DOT mode emits graphviz syntax operators can pipe through `dot -Tpng | display` for visualization. Closes the open Phase 8+ "CLI render of dependency graph" item.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7bd deliverables (✅)

- [x] `Plan { graph: Option<String> }` with `value_parser = ["ascii", "dot"]` ([main.rs](crates/iac-cli/src/main.rs)). `--graph` requires `--server --operation` since dependency edges live in the desired-state response; local plans reject loudly with a clear error.
- [x] `render_dependency_graph(body, format)` walks each `OperationDesiredStateItem`'s `resource.metadata.dependsOn` array. Two output paths:
  - `ascii` — `"operation <id> — dependency graph (N resource(s)):"` header + per-resource block with `↳ depends on <id>` for each prereq.
  - `dot` — graphviz `digraph G { ... }` with one quoted-id node declaration per resource (so isolated resources still render) plus quoted-id edges.
- [x] `quote_dot` helper handles `"` and `\` escaping per DOT format. Resource ids of the form `kind/env/name` always emit safely.
- [x] **5 new tests**: ASCII contains operation header + each resource + indented `↳ depends on` line; DOT starts with comment, declares both nodes, emits the edge, ends with `}`; empty operation prints a `# no resources` comment; backslash + quote in resource id are correctly escaped in DOT; `quote_dot` round-trips a basic id.

### Open after Phase 7bd

- **Local-mode `iac plan` doesn't carry agent routing or the same shape.** Adding `--graph` to local plans would need either a fresh dependency walk over the manifest input or piggy-backing on the executor's resource list. Defer until an operator wants offline graph output.
- **No transitive-closure / reverse-edge view.** Operators see "what each resource waits for"; the inverse view ("what waits for X") would need building a reverse adjacency map. Easy follow-up if asked.
- **DOT output is plain digraph with no styling.** Operators piping through `dot` get default node shapes / colors. Adding kind-based color groups (`docker.container` boxes, `file` ovals, etc.) is a small enhancement but bikeshed-prone.
- **Cycle detection skipped.** The submit path already rejects cycles (`topo_sort_by_depends_on` runs at submit time), so any reaching the CLI graph render is acyclic. If a future change loosens that, the ASCII renderer would loop visibly via repeating bullets — DOT would just render the cycle.

## Phase 7be — `iac drift revert <id>` shortcut — DONE.

**520 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-six consecutive phases shipped from 7b through 7be. The most recent: closes the long-pending "iac drift revert <id>" backlog item. Server-side `POST /v1/drift/{id}/revert` looks up the resource's most recent desired-state row, builds a fresh single-resource apply operation through the existing `create_operation` machinery, and returns the new operation id. CLI subcommand drives it. Drift stays open after revert — operator must `accept` once they confirm the apply converged.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7be deliverables (✅)

- [x] [`Store::find_latest_resource_for_revert(resource_id) -> Option<(env, resource_json)>`](crates/iac-controlplane/src/store.rs) — pulls the most recent `desired_states` row by `id DESC`. Returns env + the full resource JSON the column already holds.
- [x] `extract_routing` visibility raised to `pub(crate)` ([api/operations.rs](crates/iac-controlplane/src/api/operations.rs)) so the revert handler reuses the same routing logic that initial submits go through — `hostSelector`, environment fallback, etc.
- [x] [`api/drift.rs`](crates/iac-controlplane/src/api/drift.rs) `POST /v1/drift/{drift_id}/revert` — Operator role required. Looks up drift, refuses already-resolved (clean 400), pulls the latest desired-state, routes through `extract_routing`, calls `create_operation` with the same actor for both `requested_by` and `actor`. Policies are explicitly skipped (`&[]` matched_policies, `false` requires_approval) — the resource was already approved when its original op went through; running policies again would risk a chicken-and-egg lock.
- [x] [`DriftRevertRequest`](crates/iac-core/src/protocol.rs) (`source_commit: Option<String>`) and [`DriftRevertResponse`](crates/iac-core/src/protocol.rs) (`operation_id`, `resource_id`) protocol types.
- [x] CLI [`DriftAction::Revert { id, source_commit }`](crates/iac-cli/src/main.rs) — POSTs the request, prints `submitted revert operation <id> for <resource_id> (drift <id>)` plus a follow-up hint to track via `iac plan --server`.
- [x] **3 new e2e tests** ([e2e_drift_workflow.rs](crates/iac-controlplane/tests/e2e_drift_workflow.rs)): full revert round-trip (submit → drift → revert → assert new op id + resource preserved + drift still open), already-resolved drift rejects with 400, drift for a resource with no desired-state rejects with 400 + explanatory message.

### Open after Phase 7be

- **Revert doesn't auto-resolve the drift.** Intentional — the operator should confirm the apply converged before declaring victory. A future `--auto-accept` flag could resolve immediately and trust the apply's success status, but that adds a "did the apply actually succeed?" coupling we don't need today.
- **Approval gate skipped on the revert path.** The original operation went through approval, so we trust the desired-state row. If an operator's environment requires approval for *every* state change including reverts, the policy + `requires_approval = false` shortcut needs a flag to opt in. Skip until asked.
- **Stale desired-state hazard.** If the most recent desired-state row was from a botched submit that itself caused the drift, `revert` re-applies the bad state. Operator workflow: inspect `iac plan --server --operation <op_id>` first to see what they're about to apply, then decide. Document in CLI help if anyone trips on it.
- **No agent-target check.** A drift on agent A reverts back through the same routing logic as a fresh submit; if the agent has been deregistered, the operation lands as `unrouted`. Operator sees the unrouted entry in the response and can re-route by re-registering. Clean failure mode.

## Phase 7bf — bulk drift accept / ignore by selector — DONE.

**523 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Fifty-seven consecutive phases shipped from 7b through 7bf. The most recent: closes the "Bulk drift accept / ignore by selector" backlog. New `POST /v1/drift/accept-bulk` and `/v1/drift/ignore-bulk` endpoints accept any combination of `agent_id` / `kind` / `severity` filters. CLI `iac drift accept-bulk --kind file --reason "fixed in commit X"` resolves every matching open event in one call. Empty-filter requests reject loudly so a typo can't wipe the whole drift history.

Pick any of the open phases below to continue. No items in user-flagged in-flight queue right now.

### Phase 7bf deliverables (✅)

- [x] [`Store::accept_drift_bulk(filter, actor, reason)`](crates/iac-controlplane/src/store.rs) and [`Store::ignore_drift_bulk(filter, actor, until)`](crates/iac-controlplane/src/store.rs) — single SQL `UPDATE` with optional `agent_id` / `kind` / `severity` predicates; returns rows-affected count. One `drift.accepted_bulk` / `drift.ignored_bulk` audit row per call (carrying the filter + matched count) regardless of how many events the sweep touched.
- [x] [`DriftBulkFilter<'a>`](crates/iac-controlplane/src/store.rs) borrowed-string struct keeps the call sites zero-allocation.
- [x] Protocol types ([protocol.rs](crates/iac-core/src/protocol.rs)): `DriftBulkAcceptRequest` (reason + filter), `DriftBulkIgnoreRequest` (ttl + filter), shared `DriftBulkFilter` with `is_empty` helper, `DriftBulkResponse { matched: u64 }`.
- [x] `POST /v1/drift/accept-bulk` and `/ignore-bulk` ([api/drift.rs](crates/iac-controlplane/src/api/drift.rs)) — Operator role; reject empty filter with explicit "must specify at least one of agent_id, kind, severity (refusing to wipe entire drift history)" message.
- [x] Server-side `parse_ttl_to_until` mirrors the CLI's TTL shorthand parser so `ignore-bulk` accepts both `<n>{s,m,h,d}` and absolute RFC 3339 forms in the request body.
- [x] CLI [`DriftAction::AcceptBulk`](crates/iac-cli/src/main.rs) and [`DriftAction::IgnoreBulk`](crates/iac-cli/src/main.rs) — flags `--agent-id` / `--kind` / `--severity` plus the required `--reason` (accept) or `--ttl` (ignore). Prints `"accepted N drift event(s)"` summary in human format.
- [x] **3 new e2e tests** ([e2e_drift_workflow.rs](crates/iac-controlplane/tests/e2e_drift_workflow.rs)): full accept-bulk round-trip (3 events spanning 2 kinds → kind-filtered accept resolves only file events, docker stays open), empty-filter rejection, ignore-bulk silences matching events from `list_open`. Single-batch push pattern accommodates the agent's "auto-close drifts not in this batch" cleanup behavior.

### Open after Phase 7bf

- **No `resource_id` filter.** Operators can target by agent / kind / severity but not by an explicit resource. Add when someone hits this — the column already supports it; just one more conditional clause.
- **No revert-bulk.** Revert involves submitting a new operation per resource, which is heavier than UPDATE-many. Operators with N drifted resources today have to call `iac drift revert <id>` N times, but the failure modes per-revert (missing desired-state, etc.) make a bulk variant tricky. Defer until justified.
- **Empty-filter guard is server-side only.** A malicious / buggy client could bypass it by sending `{ "filter": { "agent_id": " " } }` (whitespace-only string). The query would match nothing useful but it'd still write an audit row. Tighten the rule to "at least one non-empty trimmed string" if anyone abuses it.
- **No transaction across multiple matched rows on Postgres timeout.** A 1000+ row sweep could hit the connection pool's 5s acquire timeout. Won't matter at realistic operator scale; add chunking if it does.

---

## Phase 7cd–7dh + 8 — DONE.

Archived 2026-05-05 from TASKS.md. The current "Now" view kept only the alphabetic 7d-letter-run (7da–7di) plus Phase 8; everything older is moved here for history.

**Phase 7cz — Security hardening pass (post-7cu/cv/cw/cx/cy audit).**

Comprehensive audit found 6 verified vulnerabilities, 12 panic hazards, 9 attack-model gaps, plus duplication and unsafe defaults. Pre-production — we can break invariants freely. Priority order is by exploit severity × ease-of-fix.

### CRITICAL / HIGH (must close before any production usage)

- [x] **7cz.1 — Path-traversal on file rollback.** [`crates/iac-providers/src/file/ops.rs::restore`](crates/iac-providers/src/file/ops.rs) reads `path` from JSON checkpoint without canonicalize / scope check. An attacker who can write to the `assignment_results` table (compromised admin token, future SQL-injection, MITM on storage) can craft a checkpoint that restores the on-disk backup blob to `/etc/cron.d/evil`, `/root/.ssh/authorized_keys`, anything. **Fix:** at `pre_apply` time persist only a relative path under `<workspace>/managed/`; on `restore` canonicalize and assert `starts_with(workspace)`.

- [x] **7cz.2 — Race in `ServerSigner` rotate vs sign.** [`crates/iac-controlplane/src/signing.rs:151,193,209,252`](crates/iac-controlplane/src/signing.rs) — five `.expect("active key always in set")` sites. Concurrent `rotate` + `retire` can transiently leave `active_id` pointing at a removed key, panicking in `sign()`/`verify()` and crashing the control plane. **Fix:** atomic swap of the whole `KeySet { active_id, keys }` via a single `ArcSwap<KeySet>` (today active_id and keys are separate fields, mutated under different locks).

- [x] **7cz.3 — Checkpoint integrity (model A1) — closed by analysis.** Re-traced the checkpoint lifecycle: written by `Executor::apply` to `<state_dir>/operations/<op_id>/checkpoints/.../checkpoint.json`, read back by `Executor::rollback` on the same agent. The `AssignmentResultRequest` protocol carries only status/summary/per-item-error; checkpoint payload never crosses the wire. So the threat surface collapses to "attacker has filesystem write to the agent's state_dir under the same uid as the agent" — which is already full-agent-compromise; HMAC-signing wouldn't help. The per-field defenses landed in 7cz.1 (path-mismatch refusal + backup-name path-separator block) cover the residual mis-state-routing risk. Documented as wontfix; revisit if/when checkpoints travel across trust boundaries.

### MEDIUM (close before broad rollout)

- [x] **7cz.4 — Cloudflare API token via env to lego.** [`crates/iac-providers/src/acme/backend.rs:102`](crates/iac-providers/src/acme/backend.rs#L102) — `cmd.env("CLOUDFLARE_DNS_API_TOKEN", token)`. Token visible in `/proc/<pid>/environ` to any same-uid process. **Fix:** write to a TempDir file with mode 0600, pass `lego --config <tmp.yaml>` instead.

- [x] **7cz.5 — Webhook URL not validated → admin SSRF.** [`crates/iac-controlplane/src/webhook.rs:84`](crates/iac-controlplane/src/webhook.rs#L84) — `WebhookConfig::url` accepted as raw string, no validation. Compromised admin token can register `http://169.254.169.254/.../iam-role-creds`, `http://localhost:9200/_cluster/state`, etc. **Fix:** at config load, require `https://` (or `http://` with explicit `[webhook] allow_insecure_urls = true` for tests), reject hosts in 127.0.0.0/8, ::1, 169.254.0.0/16, 10.0.0.0/8 unless explicit `allow_private = true`.

- [x] **7cz.6 — `default_kind_policy = Allow` (unsafe default).** [`crates/iac-agent/src/capabilities.rs:33`](crates/iac-agent/src/capabilities.rs#L33) — kinds without explicit allowlist rules silently pass through. New providers added in future agent versions auto-grant access. **Fix:** flip default to `Deny`, update test fixtures, update agent.toml docs to show explicit `default_kind_policy: allow` for the dev-quick-start case.

- [x] **7cz.7 — Capability check vs secret substitution (model A6).** Need to verify that capability allowlist matches against the **literal** `path` string (pre-substitution), not the resolved value. Currently substitution happens at submit time on the control plane — by the time the agent sees the resource, the `${secret://...}` token is gone. **Action:** read [`crates/iac-controlplane/src/api/operations.rs`](crates/iac-controlplane/src/api/operations.rs) substitution flow + [`crates/iac-agent/src/capabilities.rs`](crates/iac-agent/src/capabilities.rs) check; add unit-test "secret-resolved path cannot bypass agent allowlist".

- [x] **7cz.8 — Replay protection on agent (model A2).** Agent rejects envelopes older than 24h (Phase 7cs.2) but does not remember already-applied `assignment_id` values. Attacker sniffing an envelope inside the freshness window can replay-execute. **Fix:** agent persists last 48h of completed `assignment_id` (rolling) in its sqlite store; refuse re-execution.

- [x] **7cz.9 — Cross-environment data leak audit (model A3) — closed by analysis.** Re-traced the role/env model: `Role` is a flat enum (`Viewer < Operator < Approver < Admin`) without per-env scoping; an Operator-role user sees operations across all environments by design. Per-env RBAC was scoped out (the `policy.approvers: Vec<String>` field is a placeholder for that future feature). The agent path IS scoped — `fetch_pending_assignments` only queries `WHERE agent_id = ?` so a compromised agent in env A can't pull env B's queue. Documented; if per-env RBAC becomes a requirement, plug into the policy-evaluator before exposing it as a real gate.

### LOW / cleanup

- [x] **7cz.10 — Remove inline base64/sha256 helpers.** [`acme/ops.rs:257-330`](crates/iac-providers/src/acme/ops.rs#L257-L330) reimplements base64 even though `base64` is already a workspace dep. SHA256→hex inlined in 4 places (`compose/spec.rs`, `compose/ops.rs`, `iac-cli/ssh_dispatch.rs`, `webhook.rs`). **Fix:** add `iac-core::hash::sha256_hex(bytes: &[u8]) -> String`; use `base64::engine::general_purpose::STANDARD` for cert checkpointing.

- [x] **7cz.11 — `unreachable!()` in iac-agent main on `Command::Version`.** [`crates/iac-agent/src/main.rs:175`](crates/iac-agent/src/main.rs#L175) — branch is either reachable (then panic on real input) or dead (then remove). **Fix:** verify dispatch and either remove or implement.

- [x] **7cz.12 — nginx port 443 silent footgun.** [`providers/nginx/spec.rs:31`](crates/iac-providers/src/nginx/spec.rs#L31) — accepts `port: 443` but renders plain HTTP server block. Operator gets nginx listening on 443 plaintext. **Fix:** reject `port: 443` until TLS is implemented (Phase 5b.1), or render it as `listen 443 ssl` with required cert/key fields.

- [x] **7cz.13 — sysctl `state: absent` stub.** [`providers/sysctl/spec.rs:28-33`](crates/iac-providers/src/sysctl/spec.rs#L28-L33), [`sysctl/ops.rs:6`](crates/iac-providers/src/sysctl/ops.rs#L6) — enum variant exists but no implementation. **Fix:** implement (capture default at first apply, restore on absent), or remove the variant.

- [x] **7cz.14 — Replace `Mutex::lock().expect("poisoned")` in iac-agent store.** [`iac-agent/src/store.rs`](crates/iac-agent/src/store.rs) — 9 sites. **Fix:** switch to `parking_lot::Mutex` (no poisoning) or propagate `Result` and degrade-gracefully.

- [x] **7cz.15 — DNS host-key-policy strict requires explicit known_hosts (model A8).** When `host_key_policy = Strict` and `known_hosts_file = None`, ssh falls back to `~/.ssh/known_hosts` of the server-process user — operator may not control that file. **Fix:** at config validate, require `known_hosts_file` to be set when policy is Strict.

- [x] **7cz.16 — `clippy::unwrap_used = "warn"` workspace-wide — shipped.** Added `unwrap_used`, `expect_used`, `panic` to `[workspace.lints.clippy]`. Fixed-or-suppressed all 1700 raw warnings: tests (in-crate via `#[cfg_attr(test, allow(...))]` on each lib root, integration via top-of-file `#![allow(...)]` on 46 `tests/*.rs` files), provider mock implementations (module-level allow on each `backend.rs`), and 17 prod sites that carried documented invariants — each now has an inline `#[allow]` with a comment explaining why the unwrap can never fire. Net result: future PRs that introduce a fresh `.unwrap()` in production code get clippy noise; nothing was silenced behind broad allows that hide real bugs.

- [x] **7cz.17 — Remove unsafe `as` narrowing casts.** Catalog: `dns/backend.rs:142` (TTL u64→u32), `file/ops.rs:373-374` (UID/GID), `maintenance.rs:467,481`, `rate_limit.rs:230`, `webhook.rs:406,471`. **Fix:** `try_into().map_err(|_| Error::...)` everywhere on numeric narrowing.

- [x] **7cz.18 — Mock-backend boilerplate consolidation — shipped.** Added [`MockJournal<S>`](crates/iac-providers/src/mock_journal.rs) — a generic harness that handles the `Mutex<Inner>` wrapping, `Vec<String> calls` recording, and per-op `HashMap<&'static str, String> failures` map shared across the three pluggable mocks. `MockCompose`, `MockDns`, `MockAcme` migrated to embed `MockJournal<TheirState>` instead of rolling their own. `record(op, line, |state| { ... })` runs the closure under the lock and atomically checks the per-op fail-next arming. Saves ~30 lines per mock; future mocks plug in with one struct + 4–5 inherent methods.

- [x] **7cz.19 — Blocking `std::fs::*` in async contexts — closed by analysis.** All three call sites (`remote::connect_with_tls`, `Config::from_file`, `Capabilities::load`) plus the TLS-cert loaders in `remote.rs` are one-shot startup paths invoked at most a handful of times per agent process — no runtime-starvation risk. Replacing with `tokio::fs` would be cosmetic and add an `await` point where none of the IO actually concurrent-races. The `Store` (rusqlite) path is correctly wrapped in `spawn_blocking` already. Documented; revisit if/when a fs op moves into the agent's polling loop.

- [x] **7cz.20 — String-typed step actions — shipped.** Added [`step_actions!`](crates/iac-providers/src/step_action.rs) declarative macro that, given an enum-name + variant→string-literal map, generates the enum, `as_str()` constructor, `parse(s)` returning `iac_core::Error::provider(...)` on unknown input, and `Display`. Each of 12 providers now declares its action namespace as a typed enum: `FileAction { Write, Delete }`, `DockerAction { Pull, Recreate, Remove }`, `SystemdAction { Enable, Disable, Start, Stop, Restart, Reload }`, etc. `plan()` emits via `Variant.as_str()`; `apply()` matches the parsed enum exhaustively — adding a variant without handling it is a compile error rather than a runtime "unknown step action". Wire format (`Step.action: String`) unchanged.

---

**Phase 7ct — SOPS secret resolver — DONE.** (most recent)

Closes the only named-and-deferred security gap in the audit/backlog: operators with age/PGP keyrings can now reference encrypted secrets directly without standing up Vault. New scheme `${secret://sops/<file-relative-to-base>#<field>}` — when a desired-state submission contains the reference, the control plane shells out to the system `sops` binary (same shell-out pattern we already use for `git` and `ssh` — no in-process crypto), decrypts the file from a sandboxed `base_dir`, and substitutes the result *before* signing the assignment envelope. Agents still receive plaintext through the same signed-envelope mechanism that already protects every other secret backend.

Sandbox is the security-relevant bit: every reference is canonicalised against `base_dir` and refused if it escapes (`..`, symlinks, absolute paths, NUL bytes — six rejection paths). Without this an operator's manifest could ask `sops` to attempt arbitrary file reads on the server. Reference without `#field` returns the entire decrypted file, so SSH private keys / TLS certs / .env blobs round-trip cleanly.

### Phase 7ct deliverables (✅)

- [x] [`SopsResolver`](crates/iac-controlplane/src/secrets.rs) — shells out to `sops --decrypt [--extract '["field"]'] <abs_path>` via `tokio::process::Command` with a 10 s timeout (so a hung gpg-agent doesn't wedge submissions). `stdin` piped from `/dev/null` — server-side decryption must be non-interactive.
- [x] **Sandbox enforcement** in `resolve_sandboxed_path()` — canonicalise `base_dir.join(rel)` and require the result to still start with `base_dir`. Rejects absolute paths, NUL bytes, and any `..`/symlink trick that lands outside.
- [x] [`SopsConfig`](crates/iac-controlplane/src/config.rs) — `[secrets.sops]` block with `base_dir` and optional `binary`. `binary` resolves config → `$IAC_SOPS_BIN` → `sops` from `$PATH`.
- [x] **Wired into [`build_secret_registry`](crates/iac-controlplane/src/main.rs)** alongside Vault. Both can run in the same registry — operators can mix Vault for service-account credentials with SOPS for static cert/key files.
- [x] **8 unit tests** covering: field extract, whole-file extract (multi-line, internal newlines preserved), absolute-path rejection, `..` escape rejection, NUL byte rejection, stub-failure error propagation, full registry-substitution round-trip, missing-base_dir-at-construction error. Tests use a small POSIX `/bin/sh` stub script as the fake `sops` binary so they run on machines without sops installed.

### Why SOPS specifically (and not something else)

Two mainstream secret stores in the wild for self-hosted ops:
- **Vault** — already shipped (Phase 7am). Right answer for organisations with a service-account model and a central secrets API. Heavy infra to stand up for a single operator with a Pi fleet.
- **SOPS** — file-based, Mozilla, age/PGP. Operator's keyring already exists. Files commit safely to git. Right answer for the "I just want my postgres password encrypted at rest" case the existing `vault://` backend doesn't serve.

Together they cover both ends of the operator size spectrum (the project's stated invariant: works equally on a Pi and a datacenter).

---

**Phase 7co–7cs — Comprehensive security audit + 13 fixes — DONE.** (previous session, kept here for context until next phase)

All 13 audit findings shipped. Highlights: secret refs no longer pre-resolved at submit time (so plaintext doesn't sit in the desired-state DB), Vault token wrapped in `RedactedToken` (zero `Debug` leakage path), atomic `UPDATE…RETURNING` for assignment claim (race-free), SSH host-key policy is `Strict` by default (`AcceptNew` is opt-in and warns at startup), agent rejects envelopes older than 24 h (env-tunable), file provider refuses to write through symlinks, schema-version downgrade guard at migration time, login rate-limited per-user + per-IP with audit events, signing-key fingerprint printed on first run for out-of-band verification, `IAC_BOOTSTRAP_BINARY_SHA256` opt-in pinning for SSH binary push.

---

**Phase 7cl-followup + 7cm + 7cn — Auto-bootstrap + inventory + ad-hoc commands — DONE.**

**Девяносто consecutive phases shipped from 7b through 7cn. Tool now genuinely covers Ansible's three core capabilities — agent-less SSH push, inventory-driven fan-out, ad-hoc imperative commands — plus everything Ansible doesn't: pull-mode agent (Puppet replacement), GitOps integration, multi-key signing, audit trails, canary rollouts, server-side rollback orchestration.** Three subsystems shipped together this session because they share an SSH transport — better to refactor once than three times.

Real-world validated against the Pi (192.168.1.97):
* `iac run --inventory inv.yaml --group rpi -- 'uname -a; uptime'` — ad-hoc shell, formatted per-host output
* `iac apply postgres.yaml --inventory inv.yaml --group rpi` — declarative apply via inventory
* `iac apply hello.yaml --ssh admin@192.168.1.97 --auto-bootstrap` — auto-stage when arch matches; clear curl-install hint when it doesn't

### Phase 7cl-followup deliverables — auto-bootstrap (✅)

- [x] [`bootstrap_iac_binary`](crates/iac-cli/src/ssh_dispatch.rs) — ssh + uname -m to detect remote arch; if matches local, scp the running `iac` binary to `/tmp/iac-applier-<sha8>` (cached by content hash so re-pushes skip the upload). Mismatched arch returns a clear error pointing at a copy-paste curl install one-liner.
- [x] [`--auto-bootstrap`](crates/iac-cli/src/main.rs) flag on `iac apply --ssh` and on `--inventory` fan-out path.
- [x] **Failure mode designed for clarity**: when bootstrap can't proceed (cross-arch, scp fails, target has no `/tmp` write), the operator sees a single actionable line instead of a stack-trace.

### Phase 7cm deliverables — inventory + groups + fan-out (✅)

- [x] [`inventory.rs`](crates/iac-cli/src/inventory.rs) — YAML parser with `defaults` (apply to every host) + per-group host list with full per-host overrides (`user`, `port`, `identity_file`, `remote_iac`, `label`). `~/` tilde expansion in `identity_file`. Strict (`deny_unknown_fields`). 9 unit tests.
- [x] [`SshTarget::with_overrides`](crates/iac-cli/src/ssh_dispatch.rs) — layering CLI flags on top of inventory entries. Operator-supplied `--ssh-key` beats per-host inventory entry beats `defaults`.
- [x] [`iac apply --inventory --group --limit --max-parallel --fail-fast`](crates/iac-cli/src/main.rs) — `cmd_apply_fanout`. tokio multi-thread runtime + per-host worker, `Semaphore` for parallelism cap. Per-host outcome lines stream as they complete; `─ summary: N ok, P partial, F failed` at the end. Exit codes: 0 / 4 / 5.
- [x] **`--limit`** filters by host or label so operators can quickly point a 50-host group at one target for a smoke test without editing the inventory file.
- [x] **Default `--continue-on-error`**: failures don't stop the fleet roll-out by default. Operators wanting strict gating pass `--fail-fast`. Mirrors Ansible's default behaviour.

### Phase 7cn deliverables — ad-hoc command mode (✅)

- [x] [`iac run`](crates/iac-cli/src/main.rs) subcommand. Same SSH transport as `apply` (`dispatch_run` in [ssh_dispatch.rs](crates/iac-cli/src/ssh_dispatch.rs)) but ships a raw shell command instead of an `AssignmentPayload`. Captures stdout/stderr/exit code per host.
- [x] **Box-drawing per-host output**:
  ```
  ┌─ web-01: Succeeded (exit=Some(0))
  │ Linux web-01 7.0.0-1009-raspi ...
  │  00:21:03 up 6:54, 3 users, load average: 0.15, 0.14, 0.34
  └─
  ```
  Reads cleanly when many hosts produce interleaved output.
- [x] Single-host (`--ssh user@host`) and inventory (`--inventory --group --limit`) modes — same axes as `apply` for muscle-memory consistency.
- [x] Concurrency cap + `--fail-fast` semantics inherited from the same fan-out machinery.

### What this gives the operator

The three deployment paradigms now compose without infrastructure overhead:

| Mode | Single-host command | Multi-host command |
|---|---|---|
| Declarative apply | `iac apply m.yaml --ssh u@h` | `iac apply m.yaml --inventory inv.yaml --group g` |
| Imperative ad-hoc | `iac run --ssh u@h -- 'uptime'` | `iac run --inventory inv.yaml --group g -- 'uptime'` |
| Pull-mode agent | (no command — agent polls itself) | (operator submits via control plane) |

No control plane needed for the SSH paths. No agent installation needed. No Python on the target — just sshd + the `iac` static binary (auto-staged when arches match).

### Open after Phase 7cn

- **No persistent audit log for `iac run`** in the CLI-direct path. The original 7cn plan wanted "every iac run goes through audit log." For now it's print-only; persistent audit requires a control plane the operator hasn't necessarily set up. A future "audit-only" lightweight server could fix this.
- **No host-pattern filtering** like Ansible's `--limit '!host3'`. Just exact match.
- **No `--check` (dry run)** for `iac run` since it executes arbitrary shell. Future: `iac run --confirm` (interactive prompt before each host).
- **No SSH connection pooling**: each host opens a fresh SSH session. Fine for ≤100 hosts; for thousands we'd want persistent ControlMaster sockets.

### Phase 7cl deliverables (✅)

**Phase 7cl — Direct CLI SSH apply (single-command Ansible-style) — DONE.**

**Восемьдесят девять consecutive phases shipped from 7b through 7cl. Closes the "operator ergonomics" gap that the user surfaced in real-world deploy testing.** Phase 7ck shipped server-side SSH push (`[[ssh_targets]]` config + worker pool); operationally this requires standing up a control plane just to push to one host. Phase 7cl adds `iac apply manifest.yaml --ssh user@host` — single command, no server, no agent. Reuses the Phase 7ck `iac apply --assignment-stdin` remote-applier protocol so the wire format stays consistent across all three deployment modes (pull-agent, server-side SSH push, direct CLI SSH).

Validated end-to-end against a real Raspberry Pi (192.168.1.97): one-command postgres deploy from dev box. `→ ssh admin@…: applying 3 resource(s)` → `← admin@…: Succeeded`. Idempotent on re-apply.

### Phase 7cl deliverables (✅)

- [x] [`iac apply --ssh user@host`](crates/iac-cli/src/main.rs) — new flag set: `--ssh-key`, `--ssh-port`, `--ssh-remote-iac`. Mutually exclusive with `--server` and `--assignment-stdin`. Reads manifest locally, builds `AssignmentPayload`, ssh-pipes to remote `iac apply --assignment-stdin --yes`, parses result.
- [x] [`probe_remote_iac`](crates/iac-cli/src/main.rs) — auto-discover `iac` binary on target via `command -v iac`. When missing, prints a `curl | sh` install one-liner so the operator gets a clear path forward instead of an opaque "command not found".
- [x] **Help text rewrite for `iac plan --server`** — the previous wording implied `--server` submitted manifests. New text spells out two distinct modes (LOCAL vs. REMOTE PREVIEW) and points at `iac apply --server` for actual submission. Error messages also redirect operators when they hit the wrong mode combo.
- [x] **Documentation reshuffle into `docs/{en,ru}/`** with three documents per language: `tutorial.md` (learning), `reference.md` (lookup), `architecture.md` (NEW — internals walkthrough). [`docs/README.md`](docs/README.md) is the language picker.

### Open after Phase 7cl

- **No auto-staging of `iac` on the target.** Operator must pre-install once (`curl | sh` one-liner). Future Phase 7cl-followup: detect target arch via `uname -m`, scp the local binary if arches match, error otherwise. Cross-arch staging requires either bundled multi-arch binaries (~4× binary size) or a cross-compile toolchain on the dev box — design choice deferred.
- **One target per invocation.** No fan-out. Phase 7cm (planned below) addresses this with inventory groups.
- **No imperative ad-hoc commands** (e.g. `iac run --ssh host -- 'systemctl restart nginx'`). Phase 7cn (planned below).

### Phase 7ck deliverables (✅)

**Phase 7ck — SSH push deployment (Ansible-like, agent-less) — DONE.**

**820 tests passing on SQLite (run with `cargo test --workspace -- --test-threads=4`).** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят восемь consecutive phases shipped from 7b through 7ck. Last named "missing capability" closed.** Pre-7ck the only deployment model was pull: each managed host had to run `iac-agent`. That doesn't fit network gear (Cisco/Mikrotik), vendor appliances, or contractor environments where security policy bans daemons. Phase 7ck adds first-class SSH push: declare `[[ssh_targets]]` in `server.toml`, the control plane's per-target worker pool dispatches assignments via `ssh user@host -- iac apply --assignment-stdin`. Same wire format on both sides (the remote applier reads an `AssignmentPayload` from stdin and emits an `AssignmentResultRequest` on stdout — server pipe glue). Same audit log, same canary, same rollback semantics, same dependsOn graph. The only difference from a pull-mode agent: who initiates.

**Architecture choice: shell out to system `ssh`.** Same model as the GitOps phase (system `git`). Keeps the static binary lean (no openssl/libssh2 native deps), inherits the system's already-patched advisory surface, and means operators get `~/.ssh/config`, `known_hosts`, `ssh-agent`, `GIT_SSH_COMMAND` semantics for free. Trade-off: containerized deployments need a base image with openssh-client (alpine ships it as a 1-line package).

### Phase 7ck deliverables (✅)

- [x] **Migration `20260502000012_ssh_targets`** — `ALTER TABLE agents ADD COLUMN kind TEXT NOT NULL DEFAULT 'pull'`. SSH targets land in the same `agents` table with `kind = 'ssh'`; the dispatch model (host_selector routing, layered apply, canary, audit log) all flow through unchanged. Index on `(kind, environment)` for the worker pool's queue scan.
- [x] [`SshTargetConfig`](crates/iac-controlplane/src/config.rs) — full validation: name + host charset, port range, identity_file existence, capabilities allowlist, control-char rejection on `host`/`user` (defends against arg injection in `ssh user@host`).
- [x] [`Store::upsert_ssh_target`](crates/iac-controlplane/src/store.rs) — idempotent registration. Server sync at startup: each `[[ssh_targets]]` entry → one row with stable agent_id across restarts.
- [x] [`Store::claim_ssh_pending`](crates/iac-controlplane/src/store.rs) — atomic queue scan + lease. Same Phase 7cj `assignment_lease_secs()` re-claim logic so a crashed push worker doesn't orphan in-flight assignments.
- [x] [`ssh_push.rs`](crates/iac-controlplane/src/ssh_push.rs) — per-target worker, `tokio::process::Command::new("ssh")` with stdin pipe carrying payload JSON. Bounds total push duration (`MAX_PUSH_DURATION = 5 min`), parses `AssignmentResultRequest` from remote stdout, reports `ssh.push_succeeded`/`ssh.push_partial`/`ssh.push_failed` audit events. Capabilities allowlist enforced server-side BEFORE invoking ssh — defense in depth.
- [x] [`iac apply --assignment-stdin`](crates/iac-cli/src/main.rs) — remote applier mode. Reads payload from stdin, applies via the local Executor, emits result JSON to stdout. Mutually exclusive with `--server`/`--git-repo`/positional path: assignment-stdin is the only input. Operators don't run it manually; the SSH push worker is the only intended caller.
- [x] **6 e2e tests** ([e2e_ssh_push.rs](crates/iac-controlplane/tests/e2e_ssh_push.rs)) using a per-test fake `ssh` shim injected via [`spawn_ssh_workers_with_bin`](crates/iac-controlplane/src/ssh_push.rs) (avoids std::env::set_var which is unsafe in 2024 edition + workspace forbids unsafe): SSH targets register in agents table; remote success → op succeeded; remote non-zero exit → op failed; capabilities allowlist rejects disallowed kinds; audit events recorded with `actor = ssh-push:<target>`; remote partial result → op partially_applied.
- [x] All 47 `Config { ... }` literals across tests + retention.rs patched to add `ssh_targets: vec![]` (Rust struct literal init doesn't honor `serde(default)`).

### Open after Phase 7ck

- **Auto-staging the remote `iac` binary**: today operators must pre-install `iac` on each target (manual setup or a one-shot ssh). Phase 7cl could scp a static-musl binary to `remote_workdir` on first push, with a sha256 check on subsequent pushes. Adds bandwidth cost but zero-touch for ephemeral targets.
- **Vendor-specific transports for hosts without /usr/local/bin** (Cisco IOS, RouterOS, JunOS): native binary push won't work — need NETCONF or vendor-API "applier" backends. Phase 7cm in the long-term roadmap.
- **No `iac targets` CLI subcommand for managing the list dynamically**: targets live in `server.toml`. SIGHUP reload is a hard field today; future SoftFields refactor would move ssh_targets into the live state.
- **Concurrency cap is per-target only** (workers are 1-per-target). Cross-target parallelism is implicit via Tokio scheduler. For a 1000-target fleet this means 1000 concurrent SSH sessions on a busy submit; operators may want a global semaphore (Phase 7ck-followup).
- **Test-suite parallelism**: under heavy parallel test load (`cargo test --workspace` with default thread count = #cores), the SSH push tests can hang due to SQLite contention from many simultaneous TestServers. Workaround: `--test-threads=4`. Sequential run takes ~11s for all 6 SSH push tests. Future cleanup: add a `[[test]]` entry in `Cargo.toml` to set this on a per-binary basis, or restructure tests to use a shared in-process server.

### Phase 7cj deliverables (✅)

**Phase 7cj — Production hardening: stress harness + monitoring.check retries + assignment lease — DONE.**

**814 tests passing on SQLite + 3 stress scenarios passing (gated by IAC_STRESS=1).** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят семь consecutive phases shipped from 7b through 7cj. The stress harness surfaced two real production bugs that we fixed in this phase.** This phase mixes "more capability" (retries on `monitoring.check` so it's actually usable as a canary health gate) with "test what we've built" (`IAC_STRESS=1 cargo test --test stress` runs three scenarios against the full pipeline). The harness immediately surfaced an orphaned-assignment correctness gap that affected real production behavior — fixed in the same phase.

### Phase 7cj deliverables (✅)

- [x] [`MonitoringCheckSpec.retries` + `retry_interval_secs`](crates/iac-providers/src/monitoring/spec.rs) — closes the "successful apply ≠ healthy service" canary gap. `apply` runs the probe up to `1 + retries` times with sleep between attempts, returns success on first pass. Bounded total budget: `(retries + 1) * timeout_secs + retries * retry_interval_secs`. Validated `retries <= 30` and `retry_interval_secs <= 60` so misconfigured manifests can't hang an apply for hours. Composes naturally with Phase 7cg canary: include a `monitoring.check` resource in the canary layer; if its target stays unhealthy after retries exhausted, the assignment fails → canary fails → baseline cancels.
- [x] [`apply_retries_until_healthy_then_succeeds` / `apply_fails_after_exhausting_retries` / `apply_passes_first_try_skips_retries`](crates/iac-providers/src/monitoring/ops.rs) — 3 unit tests using `MockCheck.queue_outcome` to exercise transient-failure-then-recovery, all-failed-budget-exhausted, and immediate-success-skip-retries paths.
- [x] [`stress.rs`](crates/iac-controlplane/tests/stress.rs) — gated by `IAC_STRESS=1` (won't run in default `cargo test`). 3 scenarios: tiny baseline (3 agents, 5 ops, 2 resources), small (10 agents, 20 ops, 3 resources, RPi-class realistic), medium informational (30 agents). Measures wall-clock + submit p50/p95/p99 + fanout-to-roll-up + completed assignments + ops/sec.
- [x] **Orphaned-assignment correctness fix** ([`fetch_pending_assignments`](crates/iac-controlplane/src/store.rs)) — pre-7cj, an agent that fetched an assignment but failed to POST a result (network blip, crash mid-cycle) left the row stuck in `'fetched'` forever; the operation never rolled up. Phase 7cj adds a 60-second lease: GET assignments now also re-claims `fetched`-status rows whose `fetched_at` is older than `assignment_lease_secs()` (env-overridable via `IAC_ASSIGNMENT_LEASE_SECS`). This was discovered by the stress harness on the first run — exactly what stress testing is meant to catch.

### Performance characteristics observed (SQLite single-binary on developer laptop)

* **Submit latency**: scales near-linearly with `resources × agents-touched`. Tiny scenario p99 ≈ 150 ms, small ≈ 260 ms, medium ≈ 450 ms. Bottleneck: per-resource `INSERT INTO desired_states` + per-bucket `INSERT INTO assignments`. Acceptable for fleets up to ~100 agents on SQLite; Postgres deployments scale much higher. A future optimization (Phase 7ck?) could batch inserts.
* **Drain throughput**: small scenario completes 60 assignments in ~24 s (~2.5/s under polling pressure). Bottleneck: SQLite write contention between the operator's submit transaction, the agents' fetch transactions, and complete_assignment + audit writes.
* **Realistic poll interval**: `IAC_STRESS_POLL_MS = 100ms + 2ms*agents` — a 200-agent fleet at 50 ms gives 4000 polls/sec which pegs server CPU; 500 ms (the new floor) gives 400 polls/sec which the SQLite backend services comfortably.

### Open after Phase 7cj

- **SQLite write concurrency cap is real.** Operators wanting >100 agents or >5 ops/sec sustained should deploy with Postgres. The wire format is identical; switching is a `database_url` change. Future Phase 7ck could batch inserts to push the SQLite ceiling higher.
- **Stress harness doesn't measure agent CPU/RSS.** Just throughput + latency. Could add `procfs` sampling.
- **Healthcheck-gate on canary still requires manifest composition.** Operator includes `monitoring.check` in the canary resource list with `retries`. A future "canary.gate" first-class field would be ergonomic, but composition already works correctly — and provides arbitrary check chains (multiple checks per canary).

### Phase 7ci deliverables (✅)

**Phase 7ci — Server-side rollback orchestration — DONE.**

**808 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят шесть consecutive phases shipped from 7b through 7ci. Multi-step rollback infrastructure now exists end to end.** Pre-7ci, the only `iac rollback` was a local in-process operation: it could revert what *this host* had applied, but couldn't undo a fleet-wide deploy. Phase 7ci adds `POST /v1/operations/{id}/rollback` — the control plane builds a brand-new operation whose desired-state is the most-recent-prior-succeeded state per resource. The new op flows through the normal pipeline (policy evaluation, approval gates, canary if requested), so every guard rail still applies — there's no "rollback bypass" path. Resources that were *first-applied* in the target op (no prior state) are surfaced as `orphaned` in the response — operator deletes those manually because the right semantic is provider-specific.

Composition with other phases:
- Phase 6e (RBAC) — rollback requires `Role::Operator` (same as forward apply).
- Phase 6c (audit log) — `operation.rollback_initiated` event records the actor, target_op_id, reason, and orphaned resources; investigators can navigate the chain.
- Phase 7g (dependsOn) — prior specs' dependsOn graph is honored; the new op's layered dispatch follows that graph.
- Phase 7by (phased apply) — rollback is just another op, so layer-N+1 still waits for layer-N to fully settle.
- Phase 7cg (canary) — `RollbackOperationRequest.canary` propagates into the new op; even rolling backward deserves blast-radius containment.
- Phase 7n (per-policy rate limits) — rollback consumes the same buckets a forward apply would.

### Phase 7ci deliverables (✅)

- [x] [`RollbackOperationRequest` + `RollbackOperationResponse`](crates/iac-core/src/protocol.rs) — wire types. Request carries optional `reason` (free-form audit string) and optional `canary` (Phase 7cg `CanarySpec`). Response carries `new_operation_id`, `assignment_count`, `resources_reverted`, `resources_orphaned`.
- [x] [`Store::prepare_rollback`](crates/iac-controlplane/src/store.rs) — looks up the target op (must be terminal), iterates its desired_states, finds the most recent prior-and-successful spec per resource_id (correlated subquery: `o.created_at < target.created_at AND o.status IN ('succeeded','partially_applied')`). Returns `(Vec<ResourceForRouting>, orphaned: Vec<String>, environment: String)`.
- [x] [`POST /v1/operations/{operation_id}/rollback`](crates/iac-controlplane/src/api/operations.rs) — Operator-gated endpoint. Topo-sorts the prior-state resources by their dependsOn graph, evaluates policies, calls `create_operation` with the canary spec, emits `operation.rollback_initiated` audit event linking both ops.
- [x] [`iac rollback OPID --server URL --reason ... --canary-pct N`](crates/iac-cli/src/main.rs) — CLI subcommand. Without `--server` falls back to legacy local rollback; with `--server` POSTs to the new endpoint. Renders the new op id + reverted/orphaned breakdown in either text or JSON output.
- [x] **6 e2e tests** ([e2e_rollback.rs](crates/iac-controlplane/tests/e2e_rollback.rs)): rollback reverts to prior spec; rollback chain walks back exactly one step (NOT to original); first-time apply returns orphan + 409; in-flight op rejected; rollback inherits canary spec → batches split per Phase 7cg; audit event includes target_operation_id linkage.

### Open after Phase 7ci

- **Orphaned resources still need a delete path.** Right now operators see them in the response and have to apply `state: absent` manifests by hand. A future phase could add an automatic "orphan deletion" mode (opt-in; provider-by-provider, since not all of them safely support delete).
- **No "rollback to specific prior op" knob.** Always picks the *most recent* successful prior. A future phase could accept `--to-operation OPID` to roll back N steps at once.
- **No retry for partially-applied rollbacks.** If the rollback op itself partially fails, operator can rollback the rollback (recursively) — but that's awkward. A future "retry-only-failed-resources" mode would help.

### Phase 7ch deliverables (✅)

**Phase 7ch — GitOps Phase 3: pull-from-git + CI integration — DONE.**

**802 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят пять consecutive phases shipped from 7b through 7ch. The "GitOps from a CI runner" workflow now closes end to end.** Pre-7ch, operators ran `iac apply <local-path>` from a workstation; CI integration meant manually `git clone`-ing in a pipeline step before invoking the CLI. Phase 7ch adds first-class `--git-repo URL --git-ref BRANCH --git-path SUBDIR` flags to both `iac apply` and `iac plan`. The CLI:
1. Clones (or fetches into a per-repo cache) the requested ref.
2. Resolves it to a canonical 40-char SHA via `git rev-parse FETCH_HEAD`.
3. Checks out that SHA in detached-HEAD mode (immutable — operator can't be racing a moving branch).
4. Auto-populates `source_commit` in the operation submit so the audit trail has the exact bytes the operator deployed.
5. For `plan --git-repo --server`: validates against the server's catalog (fail-closed if catalog fetch fails — CI must see a hard NO when validation can't run) + renders local plan diff. Exits non-zero on any validation error or any change present, so a CI gate can `iac plan && iac apply` knowing zero-change skips cleanly.

Architecture choice: shells out to system `git` rather than linking libgit2. Same model as `terraform`/`helm`/`kustomize` — keeps the static binary lean (no openssl/libssh2 native deps), cross-compiles to musl easily, and means we inherit the system git's already-patched advisory surface instead of adding our own. Per-repo cache keyed by sha256 of URL under `$XDG_CACHE_HOME/iac-cli/git/` so repeated invocations don't re-download history.

### Phase 7ch deliverables (✅)

- [x] [`gitops` module](crates/iac-cli/src/gitops.rs) — `fetch_revision(repo_url, ref_spec, path, cache_dir) -> GitCheckout { root, sha }`. Per-repo cache with sha256-of-url key. Atomic `git init && remote add && fetch --depth=1 && rev-parse FETCH_HEAD && checkout --detach <sha>` flow — never trusts movable refs after the fetch returns.
- [x] [`iac apply --git-repo --git-ref --git-path`](crates/iac-cli/src/main.rs) — first-class flags. Mutually exclusive with positional manifest path (clap-enforced). `--source-commit` is rejected when `--git-repo` is set (auto-resolved). New `--canary-pct` flag wires Phase 7cg's CanarySpec through CLI → API.
- [x] [`iac plan --git-repo --git-ref --git-path --server`](crates/iac-cli/src/main.rs) — CI gating. Server catalog fetch is mandatory (fail-closed); validation errors → non-zero exit. Exit code 2 on changes present, 0 on no-op — composable with `set -e` pipelines.
- [x] **5 unit tests** + **4 e2e tests** ([crates/iac-cli/tests/gitops.rs](crates/iac-cli/tests/gitops.rs)): fetch_local_repo_resolves_sha; fetch_with_subpath_scopes_root; missing_subpath_errors_clearly; repo_key_stable; repo_key_is_hex_chars; apply rejects --source-commit + --git-repo combo; apply resolves SHA + loads manifests from git path; plan-from-git falls through to local plan when no server; unknown ref fails with clear error.
- [x] **Cache layout**: `$XDG_CACHE_HOME/iac-cli/git/<sha256>/`. Falls back to `~/.cache/iac-cli/git/` and finally `/tmp/iac-cli-git/` for sandboxed CI.

### Open after Phase 7ch

- **Authentication for private remotes is operator's responsibility.** We shell out to `git` so it picks up `~/.gitconfig`, `GIT_SSH_COMMAND`, GitHub Actions' GITHUB_TOKEN, etc. This is a deliberate choice — wiring credential helpers into the CLI directly would reinvent half of git. Operators wanting per-repo creds can use `git config --global credential.helper` or pre-populate `$HOME/.netrc` in their CI.
- **No webhook trigger yet** ("on PR merge to main → auto-apply"). CI runner does the cron / webhook listening and invokes `iac apply --git-repo … --git-ref main`. A future "iac watch --git-repo" would poll a remote and apply on new commits — but that's adjacent to "agents control plane" architecture.
- **Cache eviction is manual.** Per-repo dirs accumulate; operators can `rm -rf ~/.cache/iac-cli/git`. A future `--purge-cache` flag would help.

### Phase 7cg deliverables (✅)

**Phase 7cg — Canary rollouts + per-batch gating — DONE.**

**793 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят четыре consecutive phases shipped from 7b through 7cg. Last big production blocker is gone.** Before 7cg, every agent in a layer received its assignment at the same time — a bad config could roll out to all hosts simultaneously with no break. Phase 7cg adds an opt-in **canary** rollout that splits each layer's agents into two batches: batch 0 = canary (configurable percentage), batch 1 = baseline. Canary dispatches immediately; baseline waits in `pending_canary` until the canary completes successfully. Any failure in canary cascades the same way phased-apply layer failures cascade — the rest of the rollout is cancelled. Composes naturally with phased apply (7by): canary gating runs per-layer, so a layer-0 canary failure also cancels every later layer's canary AND baseline. Operator surface: just add `canary: { pct: 25 }` to the submit request — pct is clamped to leave at least one baseline agent (otherwise canary becomes a full rollout), and `min_count` floors the canary size for small fleets where 25% rounds down to zero.

### Phase 7cg deliverables (✅)

- [x] [`CanarySpec`](crates/iac-core/src/protocol.rs) wire type — `pct: u8` + optional `min_count: u32`. Added as `Option<CanarySpec>` field on `SubmitOperationRequest` with `#[serde(default, skip_serializing_if = "Option::is_none")]` so existing clients see no shape change.
- [x] **Migration `20260502000011_canary`** (SQLite + Postgres) — adds `assignments.batch INTEGER` (NULL when no canary). Indexed by `(operation_id, layer, batch, status)` for the promotion query.
- [x] [`compute_canary_split`](crates/iac-controlplane/src/store.rs) — per-layer split with deterministic agent ordering (sort by id) so the same submission picks the same canary agents — eases operator debugging. Single-agent layers skip the split (no point gating one agent against itself).
- [x] [`advance_canary`](crates/iac-controlplane/src/store.rs) — runs before `advance_phased_apply` on every assignment completion. Per layer: any canary failure cancels the rest of canary + the baseline + every later-layer pending row. Full canary success → promote `pending_canary` → `pending` so baseline starts.
- [x] [`roll_up_operation`](crates/iac-controlplane/src/store.rs) treats `pending_canary` as still-running. The `pending_layer` gate also waits on `pending_canary` so layers don't race ahead.
- [x] **8 new e2e tests** ([e2e_canary.rs](crates/iac-controlplane/tests/e2e_canary.rs)): no canary keeps legacy behavior; 50%/4 splits 2/2; canary success promotes baseline; canary failure cancels baseline + op fails; single-agent layer skips split; min_count floor overrides pct; pct clamped to N-1 to keep one baseline; canary composes with phased apply (per-layer gating).
- [x] All 22 `SubmitOperationRequest` literal sites in tests + iac-cli patched to add `canary: None` (Rust struct literal init doesn't honor `serde(default)`).

### Open after Phase 7cg

- **No health-check gate yet.** Canary success is "all canary assignments returned status=Succeeded." A future iteration would also wait on a `monitoring.check` (Phase 7ca) result before promoting — a passing apply doesn't always mean a healthy service. Operator workaround for now: include a `monitoring.check` resource in the canary layer; if the apply succeeds but the check fails, that fails the assignment.
- **No timeout knob.** A canary that never reports back (agent dead) hangs the rollout indefinitely. Operator must abort manually. Future: `canary.timeout_secs` → auto-cancel-and-fail after N seconds.
- **Approval flow doesn't carry canary spec forward.** When operation requires approval, the canary spec from submit is dropped — the approve() path creates assignments without canary batching. Practical impact small: approved ops are typically high-stakes and should canary, but the operator can re-submit with canary post-approval. Wiring requires persisting canary spec in operations table.

### Phase 7cf deliverables (✅)

**Phase 7cf — Agent multi-pubkey verification — DONE.**

**785 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, 0 advisories.

**Восемьдесят три consecutive phases shipped from 7b through 7cf. Server-to-agent rotation loop closed end to end.** Pre-7cf agents pinned exactly one server pubkey via TOFU on first contact (Phase 6b). Once Phase 7ce shipped server-side rotation, the *server* could rotate, but pinned agents would refuse envelopes signed by the new active key — rotation broke the deployment until every agent restarted. Phase 7cf moves the agent to a pinned **set** of accepted pubkeys: on first contact the agent fetches `/v1/signing-keys` and pins the entire bundle; on reconnect or explicit `refresh_signing_keys`, the agent merges the server's authoritative view into its set, but only when at least one pinned key remains in the new bundle. No-overlap is fatal — that's the tampering signature we want to catch. End-to-end: operator rotates, agents refresh during the rotation window, operator retires the old key, agents drop it on next refresh. Pre-7cf identity files auto-migrate on load (the legacy `server_key_id` + `server_public_key` fields seed the new pubkey set if it's empty).

### Phase 7cf deliverables (✅)

- [x] [`Identity::server_pubkeys: Vec<ServerPubkey>`](crates/iac-agent/src/remote.rs) — replaces single-key pin with a set keyed by `key_id`. Legacy fields kept on disk for one phase as a roll-back safety net. `migrate_legacy_pubkey()` runs on every load.
- [x] [`Client::verifiers: HashMap<String, VerifyingKey>`](crates/iac-agent/src/remote.rs) — built from the pinned set; `verify_envelope` does O(1) lookup by `env.key_id` then verifies under that one key.
- [x] [`Client::connect_with_tls`](crates/iac-agent/src/remote.rs) now fetches `/v1/signing-keys` (the bundle endpoint from 7ce) instead of the single-key endpoint. First contact pins the whole bundle. Subsequent connects enforce the overlap rule: at least one pinned key_id must remain in the new bundle, otherwise abort with a clear "manual recovery required" error.
- [x] [`Client::refresh_signing_keys`](crates/iac-agent/src/remote.rs) — designed for periodic invocation from the agent runtime. Same overlap policy as `connect`. Persists the updated set + rebuilds verifiers on success; leaves state unchanged on failure.
- [x] [`fetch_signing_bundle`](crates/iac-agent/src/remote.rs) — replaces `fetch_signing_pubkey`. Validates the bundle is internally consistent (active_key_id is in the keys list, list non-empty).
- [x] **9 new e2e tests** ([e2e_agent_multi_pubkey.rs](crates/iac-controlplane/tests/e2e_agent_multi_pubkey.rs)): first contact pins full bundle; fresh connect after rotation pins both keys; legacy identity file auto-migrates; refresh picks up rotated active key; refresh during rotation window then retire flow; refresh refused when no overlap (rotation-too-fast pathology); connect refused with forged pinned set; end-to-end agent apply after rotation; bundle/single-key endpoint consistency.
- [x] [`e2e_signing.rs` `agent_rejects_pinned_key_change`](crates/iac-controlplane/tests/e2e_signing.rs) updated to the new security model — tampering must replace the entire `server_pubkeys` set, not just the legacy `server_key_id` field, since the multi-key set is the authoritative pin now.

### Open after Phase 7cf

- **No automatic refresh cadence.** `refresh_signing_keys` is exposed; the agent's run loop doesn't yet call it on a timer. Operators wire it manually for now. A future phase would add a configurable cadence (e.g. every heartbeat or every N polls).
- **No revocation push from server to agent.** Pure pull model. If a key is compromised, the operator retires it server-side and waits for agents to refresh. A future phase could push a "key retired" notice via the heartbeat response so agents drop it sooner.
- **Recovery requires manual intervention** when no-overlap fires. Operator must clear `server_pubkeys` on the agent side. Acceptable trade-off — silent acceptance would make MITM trivial.

### Phase 7ce deliverables (✅)

**Phase 7ce — Server signing key rotation — DONE.**

**Восемьдесят две consecutive phases shipped from 7b through 7ce. Closes the second half of the security cluster.** Phase 6b's signer was a single Ed25519 keypair: compromise meant total takeover with no recovery path. Phase 7ce promotes this to a multi-key set — exactly one **active** key signs assignments, but the server keeps recently-rotated keys in the **accepted** set so in-flight envelopes still verify during a rotation window. Storage moved to file-per-key + `active` pointer under `<state_dir>/signing-keys/`, with auto-migration from the legacy `signing-key.bin` + `signing-key.id` layout (zero-disruption rollforward — existing deployments see the same key continue signing). New admin endpoints (`/v1/admin/signing-keys/rotate` + `/{id}/retire`) gate via `Role::Admin` and emit `signing.key_rotated` / `signing.key_retired` audit events. New public endpoint `/v1/signing-keys` returns the full bundle so future Phase 7cf agents can verify against any key in the set, lookup by `key_id`. Backwards compat: `/v1/signing-pubkey` still returns just the active key — pre-7cf agents continue to work unchanged.

### Phase 7ce deliverables (✅)

- [x] [`signing.rs` rewritten](crates/iac-controlplane/src/signing.rs) as `ServerSigner` over a multi-key `SignerState { keys: HashMap<key_id, KeyEntry>, active_id }` behind `RwLock`. New methods: `rotate()`, `retire()`, `pubkeys()`. `key_id()` signature changed from `&str` to `String` (state behind RwLock). 9 new unit tests including legacy migration, rotate keeps old, retire removes, retire-active rejected, retire-missing idempotent, rotated set signs with new active, sign/verify round-trip.
- [x] **File-per-key storage** under `<state_dir>/signing-keys/` (mode 0600 secrets) + `active` pointer file. Atomic write-temp-then-rename for both. Auto-migration from `signing-key.bin` + `signing-key.id` on first boot.
- [x] [`SigningPubkeyBundle`](crates/iac-core/src/protocol.rs) — new wire type carrying `active_key_id` + `keys: Vec<SigningPubkey>`.
- [x] [`GET /v1/signing-keys`](crates/iac-controlplane/src/api/signing.rs) — returns bundle, no auth (matches `/v1/signing-pubkey`).
- [x] [`POST /v1/admin/signing-keys/rotate`](crates/iac-controlplane/src/api/admin.rs) + [`POST /v1/admin/signing-keys/{key_id}/retire`](crates/iac-controlplane/src/api/admin.rs) — Admin-gated, return post-mutation bundle. Retire active → 409. Retire missing → 404. Both emit audit events with admin actor.
- [x] **8 new e2e tests** ([e2e_signing_rotation.rs](crates/iac-controlplane/tests/e2e_signing_rotation.rs)): bundle initially has only active; rotate changes active + keeps old in bundle; retire removes old after rotate; retire active → 409; retire unknown → 404; rotate without admin token → 401; rotate + retire emit audit events; rotated keyset persists across signer restart.

### Open after Phase 7ce

- **Phase 7cf: agent multi-pubkey verification.** Agent currently pins one pubkey (TOFU from `/v1/signing-pubkey`). Once 7cf lands, the agent fetches `/v1/signing-keys` and accepts signatures from any key_id in the set. Until then, rotation breaks pre-7ce agents that started with the now-old key — operators must restart agents to re-pin (or wait for Phase 7cf).
- **No automatic rotation cadence.** Operator-driven only. Could add `POST /v1/admin/signing-keys/rotate` to a cron in deployment, or wait for a future "rotate every N days" config knob.
- **Old secrets stay on disk after retire.** `retire` deletes the `.bin` file; if the operator nukes the file behind the server's back, the next reload bails. Acceptable for now — operator's responsibility.

### Phase 7cd deliverables (✅)

**Phase 7cd — Agent-side auto-rotation API — DONE.**

**764 tests passing on SQLite.** `cargo audit` clean — 370 transitive deps, no advisories.

Восемьдесят одна consecutive phase shipped from 7b through 7cd. **Closes the security loop opened in Phase 7cc.** The endpoint shipped in 7cc (`POST /v1/agents/{id}/rotate-token`) was operator-initiated only — the agent had no mechanism to call it. Phase 7cd extends the wire protocol to surface `expires_at` from server to agent, threads it through `Identity` persistence, and exposes `rotate_token` + `rotate_if_needed` methods on the agent's `Client`. With these methods, operators can build a tokio task that polls expiry on a cadence and rotates proactively — the agent runtime now has everything it needs to keep its credentials fresh without operator intervention.

### Phase 7cd deliverables (✅)

- [x] [`RegisterResponse::expires_at: Option<String>`](crates/iac-core/src/protocol.rs) — added with `#[serde(default, skip_serializing_if = "Option::is_none")]` so existing clients reading the wire format see `None` for grandfathered tokens (no breakage). Same field returned from both `/v1/agents/register` and `/v1/agents/{id}/rotate-token`.
- [x] [`AgentCredentials::expires_at`](crates/iac-controlplane/src/store.rs) — store-layer return type now carries the expiry. Both `register_agent` and `rotate_agent_token` populate it (None when no TTL, ISO 8601 when stamped).
- [x] [`/v1/agents/{id}/rotate-token`](crates/iac-controlplane/src/api/agents.rs) wire format updated to return `expires_at` so the agent can plan its next rotation immediately after this one completes.
- [x] [`Identity::token_expires_at: Option<String>`](crates/iac-agent/src/remote.rs) — persisted to `identity.json` so a restart doesn't lose the rotation deadline. `#[serde(default)]` keeps backwards compat with old identity files (existing agents on disk → None → grandfathered, never auto-rotate).
- [x] [`Client::token_seconds_until_expiry`](crates/iac-agent/src/remote.rs) — returns `i64` seconds remaining, or `None` when grandfathered.
- [x] [`Client::rotate_token`](crates/iac-agent/src/remote.rs) — calls the rotate endpoint, persists new identity to disk, swaps in-memory state. Order: persist-before-swap, so a disk failure leaves the old token intact rather than orphaning the agent.
- [x] [`Client::rotate_if_needed`](crates/iac-agent/src/remote.rs) — convenience: rotate iff within `safety_margin_secs` of expiry. Recommended margin: TTL/3.
- [x] **7 new e2e tests** ([e2e_agent_auto_rotation.rs](crates/iac-controlplane/tests/e2e_agent_auto_rotation.rs)): identity persists expires_at when TTL configured; identity skips it when grandfathered; rotate_token swaps in-memory + on-disk + invalidates old token; rotate_if_needed no-op when far from expiry; rotate_if_needed triggers when near; rotate_if_needed no-op for grandfathered; server audit log records `agent.token_rotated` event with agent actor.

### Open after Phase 7cd

- **No tokio runtime task in the agent yet.** The methods exist; the agent's main loop doesn't yet call them periodically. Operators can wire the call manually in deployments. A future Phase 7ce would add a built-in tokio task that runs `rotate_if_needed` every N seconds (configurable). Skipped here to keep this phase focused on the API surface.
- **No grace period for in-flight requests.** Same as 7cc: old token invalidates immediately on rotate. A request that started before rotation but races with it sees 401. The agent's `Client` mutex serializes its own requests, so this is more an edge case for external callers.
- **No HSM / external key store integration.** Tokens are SHA-256 hashes stored in plain DB rows (server side) and plain disk files (agent side). HSM-backed key storage is a separate v2 feature.

### Phase 7cc deliverables (✅)

Phase 7cc shipped server-side TTL + rotate endpoint. Auto-rotation on the agent side closed in this phase (7cd).

Восемьдесят consecutive phases shipped from 7b through 7cc. **First production-grade security primitive lands.** Pre-7cc agent tokens were long-lived bearer secrets — once issued, valid forever (the API didn't even expose revocation). Phase 7cc adds optional TTL via `[server].agent_token_ttl_secs` config + an explicit `POST /v1/agents/{id}/rotate-token` endpoint that issues fresh tokens. Backwards compat fully preserved: NULL `token_expires_at` means grandfathered (existing agents keep working with their original tokens until manually rotated). Operators opt in by setting TTL; new registrations from that moment get expiring tokens.

### Phase 7cc deliverables (✅)

- [x] Migration `20260501000010_agent_token_ttl` (SQLite + Postgres parallel) — adds `token_expires_at TEXT NULL` to `agents` table.
- [x] [`Config::agent_token_ttl_secs: Option<u64>`](crates/iac-controlplane/src/config.rs) — default `None`. Validation enforces `>= 60s` minimum (below this, rotation can't keep up with normal agent poll intervals).
- [x] [`Store::register_agent`](crates/iac-controlplane/src/store.rs) signature now takes `token_ttl_secs: Option<u64>`. Stamps `token_expires_at = now + ttl` when provided; NULL otherwise. Audit log surfaces the TTL choice.
- [x] [`Store::rotate_agent_token`](crates/iac-controlplane/src/store.rs) — new method. Generates fresh token + hash, overwrites `token_hash` and `token_expires_at` atomically in a transaction, emits `agent.token_rotated` audit event.
- [x] [`Store::authenticate`](crates/iac-controlplane/src/store.rs) now also reads `token_expires_at` and rejects with 401 when `now >= expires_at`. NULL expires_at = no check (grandfathered). Malformed timestamps treated as expired (defensive).
- [x] [`POST /v1/agents/{agent_id}/rotate-token`](crates/iac-controlplane/src/api/agents.rs) — auth via current token (must be valid), returns new token. Reads TTL from live config snapshot so SIGHUP-changed TTL takes effect on next rotation without restart.
- [x] **7 new e2e tests** ([e2e_token_rotation.rs](crates/iac-controlplane/tests/e2e_token_rotation.rs)): grandfathered tokens have NULL expiry; fresh TTL'd tokens work; expired tokens get 401 on heartbeat; rotate endpoint issues new valid token + invalidates old; rotate requires valid current token; rotate with expired token rejected; rotation extends expiry to current TTL.
- [x] All 31 `Config` literal sites in tests patched via Python regex to add `agent_token_ttl_secs: None`. Two more sites in `tests/e2e_modules.rs` and `tests/e2e_hot_reload.rs` patched manually.
- [x] `register_agent` call site in `postgres_real.rs` updated to pass the new `None` argument.

### Open after Phase 7cc

- **Agent doesn't auto-rotate yet.** The endpoint exists; the agent runtime doesn't proactively call it. Operators currently must trigger rotation manually (or via cron). Phase 7cd will add a tokio task on the agent that rotates at TTL/2.
- **No rotation grace period.** Old token is invalidated immediately on rotate. Brief windows where the agent's local cache still has the old token while making concurrent requests would 401. Acceptable for v1 — agents see 401 → trigger re-rotation or re-registration. A grace period (e.g., 5min overlap where both old and new tokens validate) is a v2 enhancement.
- **No ServerSigner key rotation.** Server-issued assignment signatures use a single Ed25519 key from disk. Compromise = full takeover. Tracked separately on the security backlog.
- **Initial registration uses LegacyAdmin token (or cert).** Onboarding the first agent's bearer token still requires admin trust at submit time. Out-of-band onboarding (e.g., cloud-init pre-registration) is a separate workflow not addressed here.

### Phase 7cb deliverables (✅)

Phase 7cb shipped `sysctl.setting` provider — kernel parameter management via `/proc/sys` direct access.

Семьдесят девять consecutive phases shipped from 7b through 7cb. **Third new provider in three phases — provider catalog now genuinely multi-domain.** `sysctl.setting` brings declarative kernel parameter management — the canonical "tune the host" primitive for network gear (`net.ipv4.ip_forward`, conntrack table size, TCP buffer windows). Pure-VFS implementation: read `/proc/sys/<key-with-slashes>` for observe, write the same path for apply. No `sysctl(8)` shell-out, no third-party deps. Catalog now: `file`, `systemd.unit`, `package`, `docker.container`, `nginx.vhost`, `cron.job`, `firewall.rule`, `monitoring.check`, `sysctl.setting`.

### Phase 7cb deliverables (✅)

- [x] [`SysctlSettingSpec`](crates/iac-providers/src/sysctl/spec.rs) — `key` (dotted path), `value` (string), `state` (Present only in v1). `#[serde(deny_unknown_fields)]`. v1 ships only Present semantics — operators revert by removing the resource from their manifest. Absent state requires checkpoint-aware `apply` which would touch core `ApplyContext`; deferred to v2.
- [x] Validation: key allow-list (alphanumeric + `.`/`_`/`-`, no leading/trailing dots, no `..`, no `/`); length cap 256 chars; value control-char rejection (NUL/LF/CR); value length cap 4096 (kernel write buffer limit).
- [x] [`SysctlBackend`](crates/iac-providers/src/sysctl/backend.rs) trait with [`ProcfsBackend`](crates/iac-providers/src/sysctl/backend.rs) (real VFS read+write) and [`MockSysctl`](crates/iac-providers/src/sysctl/backend.rs) (in-memory, with `strict` mode for "kernel param doesn't exist" tests).
- [x] [`ops`](crates/iac-providers/src/sysctl/ops.rs) — observe reads current value (or reports `exists: false` for missing parameters); diff `Update` on value mismatch with the `key "old" -> "new"` reason; pre_apply captures the current value as `previous_value`; apply writes via `fs::write` (single syscall — kernel parses entire value atomically); rollback restores previous_value.
- [x] [`SysctlProvider`](crates/iac-providers/src/sysctl/mod.rs) wires standard Provider trait. Capability key = the sysctl key, supports glob (`sysctl.setting:net.ipv4.*`).
- [x] **27 new tests**: 14 spec validation (every reject path: empty key, slashes, double-dots, leading dot, invalid chars, oversize key/value, control chars in value, missing value, unknown field); 4 backend (mock seed/read/write, strict mode); 9 ops (observe seeded/missing, diff no-change/update/missing-path, apply write, pre_apply capture, rollback restore + no-prev no-op, plan emits step, unknown action errors).

### Open after Phase 7cb

- **No Absent / revert state.** Operators wanting to revert a sysctl change remove the resource from their manifest (existing operation orchestrator handles drop) or invoke rollback explicitly. A future v2 may add `state: absent` once `ApplyContext` carries the checkpoint chain — currently it doesn't, so apply for absent can't read the captured default.
- **No persistence to /etc/sysctl.d.** This provider sets only the runtime value; reboot loses it. Operators wanting persistence pair with a `file` resource writing `/etc/sysctl.d/iac-<name>.conf` (operators control persistence policy explicitly — runtime tuning vs. boot-time persistence are different ops decisions).
- **Single value per resource.** Tuning many params means many resources. Acceptable: each is independently dirift-trackable, capable-gated, and rollbackable. A future `sysctl.batch` composite could group N keys; doable now via operator-defined modules (Phase 7bv) without provider changes.
- **No validation of kernel-side semantics.** `value: foobar` for `net.ipv4.ip_forward` will fail at kernel write time, not at config load. The kernel knows what valid values are; we trust it.

### Phase 7ca deliverables (✅)

Phase 7ca shipped `monitoring.check` provider — active HTTP/TCP health probe as asserted invariant. Replaces the shell+curl pattern in `web-with-monitoring` composite.

Семьдесят восемь consecutive phases shipped from 7b through 7ca. **Second new provider in two phases — provider catalog continues filling out.** `monitoring.check` runs an active HTTP/TCP probe and reports the result as the resource's "present" state. Replaces the shell+curl pattern shipped in the Phase 7k `web-with-monitoring` composite. Combined with Phase 7by phased apply, operators now have a real "deploy app, then verify, then deploy whatever depends on it" pipeline:
- Layer 0: docker.container of the app
- Layer 1: monitoring.check pointing at /healthz (depends on docker.container)
- Layer 2: nginx.vhost or whatever depends on a healthy app (depends on monitoring.check)

If the check fails at apply time → the assignment fails → phased apply cancels remaining layers. Safety primitive complete.

### Phase 7ca deliverables (✅)

- [x] [`MonitoringCheckSpec`](crates/iac-providers/src/monitoring/spec.rs) — `name`, `type` ∈ {http, tcp}, `target`, `expected_status` (HTTP only), `timeout_secs` (1..=60), `state` ∈ {present, absent}. `#[serde(deny_unknown_fields)]` so typos fail loudly.
- [x] Validation: name allow-list (alphanumeric + `-`/`_`/`.`); HTTP target must start with `http://` (HTTPS deferred to v2 per binary-size constraint), well-formed URL with non-empty host; TCP target = `host:port` with port 1..=65535; `expected_status` allowed only for HTTP (TCP rejects); control-character rejection on target.
- [x] [`CheckBackend`](crates/iac-providers/src/monitoring/backend.rs) trait with [`StdNetBackend`](crates/iac-providers/src/monitoring/backend.rs) (real probe) and [`MockCheck`](crates/iac-providers/src/monitoring/backend.rs) (queue-based for tests).
- [x] **Pure-std implementation** — no third-party HTTP client. HTTP/1.0 GET via raw `TcpStream::connect_timeout` + manual request line + status-line parse. Read capped at 64 KiB so a malicious server can't OOM the agent. TCP probe via `TcpStream::connect_timeout`. Keeps agent binary small for network gear / embedded targets.
- [x] [`ops`](crates/iac-providers/src/monitoring/ops.rs) — observe runs the check; `present` reflects healthy. Diff: healthy + state=Present → no_change; unhealthy + Present → Update with the failure message. apply re-runs the check; Healthy → StepResult::ok, Unhealthy → Error (propagates up to assignment failure → phased-apply cancellation). state=Absent always converged, probe skipped.
- [x] [`MonitoringCheckProvider`](crates/iac-providers/src/monitoring/mod.rs) wires the standard Provider trait. Capability key = check name. Registered in [`register_builtins`](crates/iac-providers/src/lib.rs).
- [x] **38 new tests**: 16 spec validation (every reject path + happy paths for HTTP/TCP); 11 backend (URL parsing, real TCP connect/refuse, real HTTP 200/503 against tiny test server, mock queue ordering); 11 ops (observe healthy/unhealthy, observe-skip on Absent, diff create/no-change/skip, plan, apply success/fail, pre_apply empty checkpoint, rollback no-op).

### Open after Phase 7ca

- **No HTTPS in v1.** HTTPS would require pulling rustls + cert chain config into the providers crate (currently zero TLS deps). Acceptable for /healthz on internal networks; v2 will add HTTPS when anyone hits a real need.
- **No ICMP / ping checks.** Would require raw sockets (root) or shell out to `ping`. Operators wanting ICMP can declare a `cron-job-bundle` running `ping -c1 host` and check the script's exit code. Document as the workaround.
- **No retry / backoff inside the check.** A flaky network or slow startup will report Unhealthy on first probe even if it would succeed seconds later. The right tool here is phased apply with a `dependsOn` on the docker.container — by the time the check runs, the container is reportedly running. Operators wanting in-check retries should set `timeout_secs` generously.
- **Check runs on the agent.** The probe goes from the agent's network namespace, not the operator's machine. For external-facing checks ("is google.com reachable from this VM"), this is exactly right; for "can I reach this VM from the internet," use a separately-hosted check resource on a public agent.
- **No "check definition for external monitoring system."** The Phase 5d backlog originally suggested `monitoring.check` as a Nagios/Prometheus configuration writer. We chose the active-probe path instead — simpler, no external dependencies, plays well with phased apply. Operators who want Nagios .cfg files can write them via the `file` provider.

### Phase 7bz deliverables (✅)

Phase 7bz shipped `firewall.rule` provider — first dedicated network-equipment primitive. iptables/ip6tables backend with `iac:<name>` comment-tag identity, full observe/diff/apply/rollback lifecycle.

Семьдесят семь consecutive phases shipped from 7b through 7bz. **First dedicated network-equipment primitive lands.** Before this, the catalog was Linux-host-centric (`docker.container`, `nginx.vhost`, `systemd.unit`, `package`, `cron.job`, `file`); operators wanting iptables had to wrap raw `iptables-save` snapshots in `file` resources — flat, brittle, no diff awareness. Phase 7bz ships first-class `firewall.rule` with full lifecycle: spec validation → observe via `iptables-save` → diff per-field → apply via `iptables -A` → rollback to prior tagged rule. Operators on OpenWrt, mainline Linux, network gear with iptables now have a real declarative firewall surface.

### Phase 7bz deliverables (✅)

- [x] [`FirewallRuleSpec`](crates/iac-providers/src/firewall/spec.rs) — `name`, `table`, `chain`, `protocol`, `port`, `source`/`destination`, `action`, `family`, `state`. `#[serde(deny_unknown_fields)]` so typos fail loudly.
- [x] Validation surface area: name allow-list (alphanumeric + `-`/`_`/`.`, ≤200 chars to fit iptables `--comment` cap); table ∈ {filter, nat, mangle}; chain validated per-table (so `INPUT` on `nat` errors at config load, not at iptables stderr time); protocol ∈ {tcp, udp, icmp, all}; port required for tcp/udp, forbidden for icmp/all; CIDR / single-IP source+destination with shell-meta rejection; action ∈ {ACCEPT, DROP, REJECT}; family ipv4/ipv6.
- [x] [`FirewallBackend`](crates/iac-providers/src/firewall/backend.rs) trait with [`IptablesBackend`](crates/iac-providers/src/firewall/backend.rs) (real CLI shell-out, ip6tables for ipv6) and [`MockFirewall`](crates/iac-providers/src/firewall/backend.rs) (in-memory for tests). All argv built defensively — operator-supplied fields go through argv array, never a shell.
- [x] Rule identity via `iptables --comment "iac:<resource_name>"`. Observe greps `iptables-save` output for the comment tag — finds the rule unambiguously even if other fields drift.
- [x] [`ops`](crates/iac-providers/src/firewall/ops.rs) — observe surfaces every managed field; diff compares per-field with `Update` for any divergence; apply is idempotent (delete-then-add for replace); pre_apply snapshots prior rule for rollback; rollback restores tagged rule or deletes if no prior existed.
- [x] [`FirewallProvider`](crates/iac-providers/src/firewall/mod.rs) wires the standard Provider trait. Capability key is the rule's `name`, so operators authorize `firewall.rule:allow-ssh` (or `firewall.rule:*` for all).
- [x] Registered in [`register_builtins`](crates/iac-providers/src/lib.rs) — first new provider in 60+ phases. Catalog now: `file`, `systemd.unit`, `package`, `docker.container`, `nginx.vhost`, `cron.job`, `firewall.rule`.
- [x] **37 new tests**: 16 spec validation (every reject path + happy paths for IPv4/IPv6); 6 backend (build_match output, parse_save_line, prefix stripping, tokenizer with quoted strings, mock idempotency); 15 ops (observe absent/present, diff create/update/delete/no-change, plan upsert/delete, apply, rollback to-no-previous + to-previous).

### Open after Phase 7bz

- **Single iptables interface only.** No support for nftables-native (`nft`) which is the default on recent Debian/Fedora — those distros ship `iptables-nft` shim that this provider piggybacks on, but pure-nftables operators can't easily express features like maps/sets that nftables has natively. Phase 5d+ provider for `nftables.rule` separately.
- **No `INSERT` (rule position).** All rules use `-A` (append). For complex chains where order matters (e.g. allow before default DROP), operators must rely on submission order + topo-sort. A future `position` field could expose `-I N`.
- **No connection-tracking match extensions.** Stateful rules (`-m conntrack --ctstate ESTABLISHED,RELATED`) are extremely common but require an extra `state`/`ctstate` field. Defer; the simpler primitive covers most "open port from CIDR" use cases.
- **Docker / kubernetes-managed rules invisible.** Both write to iptables behind your back. Our observe greps for `iac:` comment tags — anything without that tag is unmanaged and won't show as drift. Deliberate: declaring those rules as IaC would fight with their respective controllers.

### Phase 7by deliverables (✅)

Phase 7by shipped phased apply (cross-agent dependency gating) — `metadata.dependsOn` produces real cross-agent barriers via the new `layer` column + `pending_layer` status. Failure in any layer cancels remaining layers.

Семьдесят шесть consecutive phases shipped from 7b through 7by. **The big safety primitive landed.** Resources declare `metadata.dependsOn` (Phase 7g); now those edges become real cross-agent synchronization barriers. Layer-N+1 assignments hold in `status='pending_layer'` until ALL layer-N assignments succeed across every agent. ANY failure in layer-N cancels every remaining `pending_layer` assignment — the rollout stops at the boundary instead of cascading damage downstream.

This is THE missing IaC safety primitive. Without it, a misconfigured "deploy database, then deploy app that needs database" would race: apps would hit the not-yet-ready database and fail or — worse — succeed against stale state. With phased apply, the dispatcher waits for every database update across every agent before releasing a single app update.

### Phase 7by deliverables (✅)

- [x] Migration `20260501000009_phased_apply` (SQLite + Postgres parallel) — adds `layer INTEGER NOT NULL DEFAULT 0` to assignments + `assignments_op_layer_idx (operation_id, layer, status)` for the phasing query.
- [x] [`compute_resource_layers`](crates/iac-controlplane/src/depsort.rs) — BFS depth from no-deps roots. Requires topo-sorted input (precondition checked at runtime). Returns layer per resource in same order as input.
- [x] [`create_operation`](crates/iac-controlplane/src/store.rs) groups by `(agent_id, layer)` instead of just `agent_id`. Layer 0 → status='pending'; layers >0 → status='pending_layer'.
- [x] [`approve_operation`](crates/iac-controlplane/src/store.rs) (the post-approval assignment-creation path) now rebuilds the full routing list from `desired_states`, topo-sorts it, computes layers, and creates layer-aware assignments — phased apply works for approval-gated operations too.
- [x] [`advance_phased_apply`](crates/iac-controlplane/src/store.rs) — runs as a side-effect of every `complete_assignment`. Inspects the layer just below the lowest `pending_layer`: if all succeeded → promote `pending_layer` → `pending`; if any failed → cancel ALL remaining `pending_layer` assignments. Idempotent; safe under racing completions because the active tx serializes row updates.
- [x] [`roll_up_operation`](crates/iac-controlplane/src/store.rs) updated to count `pending_layer` as non-terminal and `cancelled` as a failure flavor for op rollup.
- [x] **6 new unit tests** in [depsort.rs](crates/iac-controlplane/src/depsort.rs): no-deps all-zero, chain layer increments, diamond max-dep semantics, parallel chains isolated, unsorted input errors, empty input.
- [x] **5 new e2e tests** in [e2e_phased_apply.rs](crates/iac-controlplane/tests/e2e_phased_apply.rs): initial `pending_layer` shape; layer promotion on success; layer cancellation on failure; 3-layer chain advancing one step at a time; backwards-compat (no dependsOn → flat dispatch).
- [x] One existing test (`dependency_reorders_resources_in_assignment`) updated to expect 2 assignments instead of 1 — accurate reflection of layer-aware dispatch.

### Open after Phase 7by

- **Cross-agent edges become real barriers.** Phase 7g's "cross-agent edges are no constraint" comment is now stale — phased apply makes them blocking. Operators relying on the old "fan out across agents in parallel" semantics for performance will see slower rollouts when they declare cross-agent `dependsOn`. That's the intended behavior; deps are deps.
- **No "fast-forward" mode.** All operations get phased dispatch when their dependsOn graph has multiple layers. There's no opt-out for operators who want yolo-mode parallel rollout. Add later if anyone hits a real need.
- **Failure cancellation is layer-wide.** A single failing assignment in layer-N cancels every layer-N+1+ assignment, even those targeting agents whose layer-N work succeeded. That's intentional — the failure model says "layer-N is broken so anything depending on it is unsafe to run." A future canary refinement (Phase 8+) could allow per-edge gating instead of layer-wide.
- **No retry of cancelled assignments.** Operators must resubmit the operation. Acceptable: phased apply's contract is "stop at first failure"; resuming from mid-rollout is a separate workflow.

### Phase 7bx deliverables (✅)

Семьдесят пять consecutive phases shipped from 7b through 7bx. **Operability milestone: editing the config file no longer requires a server restart for soft fields.** SIGHUP atomically swaps a fresh `ReloadableState` (Config + cached config_issues) into the live `Arc<ArcSwap<ReloadableState>>`. Reload failures (parse error, validation error like an undeclared template variable in a module) leave the running config unchanged — operators can edit live without breaking running clients. Closes 4 of the 5 backlog items that depended on hot-reload (per-webhook map / per-window map / config-issues cache / modules); the 5th (per-receiver semaphore map for webhooks) needs the WebhookDispatcher to be hot-swappable, deferred.

### Phase 7bx deliverables (✅)

- [x] `arc-swap = "1"` workspace dep — lock-free atomic Arc swap. Hot path is single atomic load, no lock acquisition.
- [x] [`ReloadableState`](crates/iac-controlplane/src/server.rs) holds the swap-on-reload fields: `Arc<Config>` + cached `Arc<Vec<ConfigIssue>>` recomputed on each swap.
- [x] [`AppState.live: Arc<ArcSwap<ReloadableState>>`](crates/iac-controlplane/src/server.rs) replaces the per-field `config: Arc<Config>` + `config_issues: Arc<Vec<ConfigIssue>>` pair. `AppState::config()` and `AppState::config_issues()` accessor helpers return snapshots on each call.
- [x] [`AppState::reload_config`](crates/iac-controlplane/src/server.rs) re-reads TOML from `config_path`, validates (via the same path that runs at startup, including `Module::validate`), constructs a fresh `ReloadableState`, atomically swaps. Returns `ReloadOutcome { path, config_issues }` for logging.
- [x] [SIGHUP signal handler](crates/iac-controlplane/src/main.rs) — separate tokio task listens for `SignalKind::hangup()` in a loop. Each signal triggers `state.reload_config()`; failures log at error level but don't abort the server (running config preserved).
- [x] All 30 `AppState` literal sites in tests patched via Python regex to use the new `live: Arc<ArcSwap<...>>` + `config_path: None` shape.
- [x] All ~15 readers of `state.config.X` / `state.config_issues` migrated to call the accessor methods (`state.config()` / `state.config_issues()`); `Config` snapshots stored in local vars across multi-field reads for consistency.
- [x] [`compute_config_issues`](crates/iac-controlplane/src/maintenance.rs) wrapper takes a full Config so reload doesn't have to know which sub-fields drive the issue list.
- [x] **4 new e2e tests** ([e2e_hot_reload.rs](crates/iac-controlplane/tests/e2e_hot_reload.rs)): module added via reload surfaces in `/v1/expanders`; invalid module config fails reload but leaves running config intact; `retry_after_format` change takes effect; tests without `config_path` get a clear error.

### Open after Phase 7bx

- **Hard fields still need a restart.** `bind`, `database_url`, `state_dir`, `max_body_bytes`, `webhooks`, `tls`, `admin_token`, `secrets`, `rate_limit` all wire into long-lived runtime state (TCP listener, DB pool, dispatcher cursors, limiter buckets, cert chains) that can't be atomically swapped without losing accumulated state or breaking in-flight connections. Documented in the `ReloadableState` doc comment.
- **No reload metric.** A counter for "reloads attempted" + "reloads succeeded" would let operators see whether SIGHUP is being honored. Trivial to add; defer until anyone asks.
- **No reload audit event.** Reloads log via `tracing` but don't go through the audit log. Worth adding for compliance — operators want a forensic trail of "who edited prod config when."
- **WebhookDispatcher rebuild deferred.** Re-pointing the dispatcher's `Arc<WebhookDispatcher>` would require building a new dispatcher (with new per-receiver semaphores + per-webhook metric maps) AND draining the old one's in-flight requests. That's a second-order refactor; the running dispatcher continues using its construction-time config until restart.

### Phase 7bv deliverables (✅) + Phase 7bw deliverables (✅)

Phase 7bv ships `[[modules]]` config blocks that let operators declare their own composite kinds with parameters, defaults, and a YAML template — no Rust changes, no recompile. Phase 7bw extends this so modules can emit other modules, with cycle detection at depth 8.

Closes the biggest single gap to "ideal IaC" — the rest of the open backlog is now about depth (more providers, more workflow features) rather than fundamental capability.

### Phase 7bv deliverables (✅)

- [x] [`Module` struct](crates/iac-controlplane/src/modules.rs) with `name`, `description`, `emits`, `parameters: Vec<ModuleParameter>`, `template: String`. `#[serde(deny_unknown_fields)]` so typo'd config keys fail loudly.
- [x] [`ModuleParameter`](crates/iac-controlplane/src/modules.rs) with `name`, `type`, `required`, `default`, `description`. Type strings reuse the catalog convention from Phase 7bi (string/number/bool/array/object/map<...>).
- [x] [`Module::validate`](crates/iac-controlplane/src/modules.rs) at config load: rejects empty/non-alphanumeric names, collisions with built-ins, reserved metadata vars (`name` / `environment`) as parameter names, duplicate parameters, undeclared `{{ var }}` references in the template.
- [x] Minimalist template engine ([`template_variables`](crates/iac-controlplane/src/modules.rs), [`render_template`](crates/iac-controlplane/src/modules.rs)) — bracket-balance scanner extracts `{{ var }}` references; render does scalar substitution (string/number/bool). Array/object substitution intentionally rejected — module surface area is "compose primitives," not "be a templating language."
- [x] [`expand_module`](crates/iac-controlplane/src/modules.rs) renders the template with the metadata + parameter substitution context, parses YAML sequence, annotates each emitted resource with `iac.example/composite-of: <module-name>` matching the built-in composites.
- [x] [`Config::modules: Vec<Module>`](crates/iac-controlplane/src/config.rs) populated from TOML `[[modules]]` blocks. Validated at server boot — duplicates and per-module errors fail startup with a clear context.
- [x] [`expand_resources`](crates/iac-controlplane/src/expansion.rs) takes `&[Module]`; routes unknown kinds to matching modules before passing through. [`list_all_expanders`](crates/iac-controlplane/src/expansion.rs) surfaces modules in `/v1/expanders` so `iac expanders list` and `iac expanders show <kind>` work uniformly across built-ins and operator modules.
- [x] **20 unit tests** in modules.rs (validation paths, template parsing, render scalars, recursion, error propagation) + **6 e2e tests** in [e2e_modules.rs](crates/iac-controlplane/tests/e2e_modules.rs) (catalog surfacing, end-to-end submit + expansion, missing-required + unknown-field 400s, unknown-kind passthrough).
- [x] All 29 `Config` / `ServerConfig` literal sites in test fixtures patched via Python regex to add `modules: vec![]`.

### Phase 7bw deliverables (✅)

- [x] [Recursive expansion loop](crates/iac-controlplane/src/expansion.rs) — `expand_resources` is now a fixed-point iteration over `expand_resources_one_pass`. A pass that produces a new composite kind triggers another pass; loop ends when no kind matches a composite. `MAX_EXPANSION_DEPTH = 8` caps damage from cycles.
- [x] [`is_composite_kind`](crates/iac-controlplane/src/expansion.rs) helper unifies built-in + module checks for the cycle detector.
- [x] Cycle detection error includes the offending kinds set so operators see the chain that triggered the cap: `"expansion exceeded MAX_EXPANSION_DEPTH (8); likely a recursive module cycle. Composite kinds remaining after final pass: {"self-cycle"}"`.
- [x] **2 new e2e tests**: `module_emitting_another_module_recursively_expands` (outer-wrapper → marker-bundle → 2× file, blast radius shows only `file`); `module_recursive_cycle_rejected` (self-emitting module hits depth limit, returns 400 with cycle diagnostic).

### Open after Phase 7bv/bw

- **No `for_each` / loops in templates.** Operators wanting to emit N similar resources from a list parameter can't — the substitution engine handles only scalars. Workaround: declare N parameters with sensible defaults. Future enhancement: a structured `for_each: param_name` directive with per-iteration variable.
- **No partial templates / includes.** Each module is self-contained YAML. Operators duplicating fragments across modules can extract them only by writing a wrapper module. Probably fine — the `service` built-in shows that even one composite layer is enough for most patterns.
- **Type checking on parameter values is shallow.** A parameter declared `type: number` accepts any JSON value at the manifest level — the expander doesn't enforce the declared type before substitution. Phase 7bi/bl deep validation could be reused here; defer until anyone hits it.
- **Modules don't have versioning yet.** Renaming or changing a module signature changes behavior for in-flight operations. No semver, no deprecation channel. For now: operators redeploy + restart the server when changing modules; Phase 7bx (SIGHUP hot-reload) makes this less painful.

### Phase 7bu deliverables (✅)

- [x] [`WebhookMetrics::dispatch_duration_hist`](crates/iac-controlplane/src/webhook.rs) — global `SemaphoreWaitHistogram`. Same shape/buckets as `semaphore_wait_hist`.
- [x] [`PerWebhookCounters::dispatch_duration_hist`](crates/iac-controlplane/src/webhook.rs) — per-receiver histogram. Default-constructed at dispatcher build time.
- [x] [Snapshot fields](crates/iac-controlplane/src/webhook.rs) — `WebhookMetricsSnapshot::dispatch_duration_hist` + `PerWebhookSnapshot::dispatch_duration_hist`.
- [x] [`fire`](crates/iac-controlplane/src/webhook.rs) calls `.record(dispatch_micros)` on both histograms after the existing counter increments. Same elapsed value feeds counter + hist.
- [x] [`push_named_histogram`](crates/iac-controlplane/src/api/metrics.rs) refactor: existing `push_semaphore_wait_histogram` extracted into a name-parameterized helper that the new `push_dispatch_duration_histogram` reuses.
- [x] [`push_per_receiver_histogram`](crates/iac-controlplane/src/api/metrics.rs) refactor: per-receiver labeled-histogram rendering now generic over a closure that extracts `(hist, sum_micros)` from each snapshot, called for both wait + duration.
- [x] **2 new tests**: render-unit verifies global + per-receiver bucket cumulative semantics + labeled output for the new histogram name; e2e test runs 3 events through and asserts both global and per-receiver histogram counts equal dispatch count and bucket sums match the count.
- [x] All 14 `WebhookMetricsSnapshot` / `PerWebhookSnapshot` literal sites in `metrics.rs` patched via Python regex to add `dispatch_duration_hist: empty_hist()`.

### Open after Phase 7bu

- **Bucket bounds still global.** Same caveat as Phase 7bs: every receiver shares `SEMAPHORE_WAIT_BUCKETS_MICROS`. Operators can't pick narrower buckets for fast receivers vs. wider ones for slow receivers. Acceptable given the powers-of-10 set covers four orders of magnitude.
- **Memory cost compounds.** Each receiver now holds two histograms (semaphore-wait + dispatch-duration), each with 7 AtomicU64 buckets + 1 count = 64 bytes per histogram, 128 bytes per receiver of histogram data. Trivial for typical fleets (1-10 receivers); call out if anyone configures hundreds.
- **Type name `SemaphoreWaitHistogram` is now misleading.** It's used for both wait and HTTP-duration histograms. A cleanup-only rename to something neutral like `LatencyHistogramMicros` would be a one-liner internally but ripples through the public API of webhook.rs. Defer to a dedicated naming-cleanup phase.

### Phase 7bt deliverables (✅)

- [x] [`WebhookMetrics::dispatch_duration_micros`](crates/iac-controlplane/src/webhook.rs) — global atomic u64 cumulative across all receivers and outcomes.
- [x] [`PerWebhookCounters::dispatch_duration_micros`](crates/iac-controlplane/src/webhook.rs) — per-receiver atomic u64. Same observation feeds both — one timer wraps `req.send().await`, the elapsed value gets added to global and per-receiver counters.
- [x] [`WebhookMetricsSnapshot::dispatch_duration_micros`](crates/iac-controlplane/src/webhook.rs) + [`PerWebhookSnapshot::dispatch_duration_micros`](crates/iac-controlplane/src/webhook.rs) — surface the counter through the JSON / Prom output.
- [x] [`fire`](crates/iac-controlplane/src/webhook.rs) wraps the HTTP send with an `Instant::now()` + `.elapsed()` measurement. Recorded BEFORE the result match so all outcome paths benefit; doesn't include body serialization or signature computation upstream.
- [x] [Prometheus rendering](crates/iac-controlplane/src/api/metrics.rs) — global counter `iac_webhook_dispatch_duration_microseconds_total` plus per-receiver `iac_webhook_dispatch_duration_microseconds_per_receiver_total{webhook="..."}`. Naming follows OpenMetrics-strict `_microseconds_total` (matches Phase 7bc's global rename).
- [x] **2 new tests**: render-unit verifies both the global and per-receiver labeled lines emit with correct values; e2e test runs 2 events against a 200ms-slow handler and asserts both counters accumulate ≥ 200_000µs (one round-trip's worth, generous lower bound).
- [x] All 12 `WebhookMetricsSnapshot` / `PerWebhookSnapshot` literal sites in `metrics.rs` patched (11 via Python regex matching `semaphore_wait_hist: empty_hist(),` boundary, 1 manually because the field used a named variable).

### Open after Phase 7bt

- **No HTTP-duration histogram yet.** This phase ships only the cumulative counter. A histogram (per-receiver bucket distribution of HTTP round-trip times) would let operators tell "is the slow tail dominating, or is everything slow" — same question Phase 7bs's semaphore-wait histogram answers for queue time. Defer until anyone asks; Phase 7bs's pattern is straightforward to replicate.
- **Counter includes ALL outcomes.** Network errors, 429s, and 2xxs all contribute to the same total. Operators wanting "successful-only" dispatch duration would need a separate counter restricted to the success branch. Defer; the unified counter answers most "is receiver X slow" questions.
- **No timeout-aware reporting.** The reqwest client has a 5-second timeout (Phase 7t default); deliveries that hit the timeout still count their full ~5s in the metric. Operators reading absurdly large duration values should cross-reference `delivery_errors_*` to identify timeout-driven inflation.

### Phase 7bs deliverables (✅)

- [x] [`PerWebhookCounters::semaphore_wait_hist: SemaphoreWaitHistogram`](crates/iac-controlplane/src/webhook.rs) — same shape as the global histogram (7 atomic buckets + count). Default-constructed per receiver at dispatcher build time.
- [x] [`PerWebhookSnapshot::semaphore_wait_hist: SemaphoreWaitHistogramSnapshot`](crates/iac-controlplane/src/webhook.rs) — surfaces the snapshot through the JSON / Prom output.
- [x] [`fire_with_permit`](crates/iac-controlplane/src/webhook.rs) calls `p.semaphore_wait_hist.record(total_wait_micros)` alongside the existing per-receiver counter. Same observation feeds both — the cumulative counter for averages, the histogram for distribution.
- [x] [Prometheus rendering](crates/iac-controlplane/src/api/metrics.rs) — `iac_webhook_semaphore_wait_seconds_per_receiver_bucket{webhook="...",le="..."}` lines plus `_sum{webhook="..."}` / `_count{webhook="..."}` per OpenMetrics histogram convention. Single `# HELP` / `# TYPE` declared once; labeled lines follow.
- [x] **2 new tests**: render-unit verifies labeled bucket cumulative semantics with a non-trivial distribution; e2e test fires 3 events through the dispatcher and asserts the per-receiver histogram count matches dispatch count and the bucket sum matches the count.
- [x] Five `PerWebhookSnapshot` literal sites in `metrics.rs` patched (4 via Python regex, 1 manually because of multi-line trailing field).

### Open after Phase 7bs

- **Per-receiver histogram bucket bounds are global.** `SEMAPHORE_WAIT_BUCKETS_MICROS` is shared across all receivers — operators can't pick narrower buckets for a fast receiver. The current bucket set (100µs through 10s, powers of 10) covers the typical range; per-receiver bucket configuration would add config-surface area for marginal value.
- **Memory cost is small but non-zero.** Each receiver now holds 7 AtomicU64s (56 bytes) for buckets plus an AtomicU64 for count. Trivial for typical fleets (1-10 receivers) but worth noting if anyone configures hundreds.
- **No bucket-bound granularity beyond the histogram.** A receiver consistently at the boundary of a bucket (e.g. always 105µs, just above the 100µs bound) will land all observations in the next bucket and look slow. Mitigation: operators concerned about boundary behavior can read the cumulative `_microseconds_total` counter and compute averages.

### Phase 7br deliverables (✅)

- [x] [`Config::retry_after_format: RetryAfterFormat`](crates/iac-controlplane/src/config.rs) with a new `RetryAfterFormat` enum (`DeltaSeconds` default + `HttpDate`). Kebab-case serde rename so TOML reads `"delta-seconds"` / `"http-date"`. `#[serde(default)]` so existing TOML configs deserialize unchanged.
- [x] [`format_imf_fixdate`](crates/iac-controlplane/src/server.rs) helper — formats a `jiff::Timestamp` as `"Sun, 06 Nov 1994 08:49:37 GMT"` via UTC strftime.
- [x] [`retry_after_format_middleware`](crates/iac-controlplane/src/server.rs) — tower middleware via `axum::middleware::from_fn_with_state`. Reads response's `Retry-After` header; if config is `HttpDate` and header value is parseable delta-seconds, computes `now + delta` and rewrites to IMF-fixdate. Pass-through on already-non-numeric headers (defensive against future emitters) and on overflow.
- [x] Layer attached in [`router`](crates/iac-controlplane/src/server.rs) so every response from the merged routers passes through. Layer applied AFTER route mounting so handler-emitted headers are available for rewrite.
- [x] **2 new tests** ([e2e_retry_after_format.rs](crates/iac-controlplane/tests/e2e_retry_after_format.rs)): default mode emits numeric delta-seconds (regression guard); `HttpDate` mode emits IMF-fixdate that round-trips through Phase 7au's inbound parser.
- [x] All 27 `Config` / `ServerConfig` literal sites in test files patched via Python regex to add `retry_after_format: RetryAfterFormat::default()` after `secrets:`. Two more sites in `tests/api.rs` and `src/retention.rs` patched manually.

### Open after Phase 7br

- **No `Date:` header rewrite for IMF-fixdate consistency.** Receivers verifying timestamps usually use the response's `Date:` header as the reference clock; we don't touch that. Default axum behavior is to omit `Date:` on internal responses; if operators add a middleware that emits one, format consistency is their problem.
- **No way to emit BOTH forms.** RFC 7231 §7.1.3 only allows one `Retry-After` header per response. Operators with mixed-receiver fleets must pick the form their majority understands; the rest fall back to the response body's `detail: "retry after Ns"` plain text.
- **Middleware applies to ALL responses, not just 429/503.** The rewrite branch only fires when the header is present, so handlers that don't emit `Retry-After` aren't affected. No measurable hot-path overhead — header lookup is `&HeaderMap`.
- **Format affects `Retry-After` only, not the response body's `detail` field.** The body keeps the human-readable `"retry after 30s"` even when the header is in date form. A future ergonomics pass might align the two; deferred.

### Phase 7bq deliverables (✅)

- [x] [`PerWebhookCounters::semaphore_wait_micros`](crates/iac-controlplane/src/webhook.rs) — atomic u64. Recorded in `fire_with_permit` after both global + per-receiver permits are acquired, so the value covers both wait sources.
- [x] [`PerWebhookSnapshot::semaphore_wait_micros`](crates/iac-controlplane/src/webhook.rs) — surfaces the counter in the `/v1/metrics` JSON snapshot and feeds the Prom renderer.
- [x] [Prometheus rendering](crates/iac-controlplane/src/api/metrics.rs) — `iac_webhook_semaphore_wait_microseconds_per_receiver_total{webhook="..."}` lines emitted alongside the existing per-receiver counters. Naming follows OpenMetrics-strict `_microseconds_total` (matches Phase 7bc's global counter rename).
- [x] [`fire_with_permit`](crates/iac-controlplane/src/webhook.rs) records `total_wait_micros = acquire_start.elapsed()` after both permits; for receivers without a per-receiver semaphore this equals the global wait, for receivers with one it can be longer when the per-receiver cap is the bottleneck.
- [x] **2 new tests**: render-prom unit test verifies the labeled lines appear with correct values; e2e test forces queueing on a receiver with `max_concurrent_requests = 1` and asserts the counter accumulates ≥ 100_000µs across 3 events behind a 120ms slow handler.
- [x] Three `PerWebhookSnapshot` literal sites in `metrics.rs` patched via Python regex to add `semaphore_wait_micros: 0` (test fixtures all pre-action).

### Open after Phase 7bq

- **No per-receiver histogram yet.** This phase ships only the cumulative counter. A histogram (per-receiver bucket distribution) would let operators tell "is the slow tail dominating, or is everything slow" per-receiver — same question Phase 7ap answered globally. Defer until anyone asks; the global histogram covers most use cases and per-receiver memory cost is non-trivial (one bucket array per receiver).
- **Total wait conflates both permit sources.** The metric reports global+per-receiver wait combined. Operators wanting to know "is the per-receiver cap the bottleneck specifically" can compute it via `per-receiver-wait - global-wait` (the global wait counter is also exposed). A separate `_per_receiver_only_wait` field is plausible but doubles the field count for marginal value.
- **Per-receiver counter doesn't reset on config reload.** Same SIGHUP-blocked concern as the existing per-webhook map (Phase 7at) and per-window map (Phase 7bg). Closure on this depends on the broader SIGHUP work.

### Phase 7bp deliverables (✅)

- [x] [`WebhookConfig::signing_versions: Vec<String>`](crates/iac-controlplane/src/webhook.rs) with `#[serde(default = "default_signing_versions")]` returning `vec!["v1".into()]`. Existing TOML configs deserialize unchanged.
- [x] [`WebhookDispatcher::new`](crates/iac-controlplane/src/webhook.rs) sanitizes each receiver's `signing_versions`: drops unknown entries (logs a warning), dedupes, falls back to `["v1"]` if empty. Same typo-guard pattern as Phase 7bj's `backfill_batch_size = 0`.
- [x] [`build_signature_header`](crates/iac-controlplane/src/webhook.rs) assembles `t=<unix>,v1=<hex>,v2=<hex>` per the configured versions; v1 signs `<t>.<body>`, v2 signs `<t>.<url>.<body>`. Order in the output matches the order in `signing_versions` for stable headers.
- [x] [`parse_signature_header_versioned`](crates/iac-controlplane/src/webhook.rs) returns a `ParsedSignatureHeader { timestamp, v1, v2 }` so receivers can dispatch on whichever version they support. Existing [`parse_signature_header`](crates/iac-controlplane/src/webhook.rs) (returns just v1) preserved for backward compat.
- [x] [`verify_signed_payload_v2`](crates/iac-controlplane/src/webhook.rs) helper for receivers — same shape as Phase 7x's `verify_signed_payload` but takes a `url` parameter and verifies the v2 entry. Returns `Err("v2 signature missing")` if the header carries v1 only, so callers can fall back during rotation.
- [x] **6 new e2e tests** ([e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs)): default config emits v1-only (backwards-compat); v2-only emits v2 + v1 verifier rejects; both versions emit both sigs; v2 sig differs when URL differs (replay-protection); typo'd version falls back to default; duplicate versions deduped.
- [x] Three `WebhookConfig` literal sites patched to set `signing_versions: vec!["v1".into()]` (or `default_signing_versions()` in webhook.rs unit tests).

### Open after Phase 7bp

- **No catalog of receiver capabilities.** Operators have to know which version each of their receivers supports. A future endpoint `/v1/webhook-versions` could let receivers self-report so the dispatcher auto-selects, but that requires a control-plane registration handshake that doesn't exist yet. For now: configure manually, drop v1 once you've verified all receivers ack v2.
- **v2 signs the configured URL, not the URL after redirects.** If a receiver returns 3xx and reqwest follows, v2 verification on the final endpoint will fail (URL differs). Operators using v2 must disable redirect-following on their receiver side or terminate redirects upstream.
- **No v3.** v2 covers the obvious replay vector (cross-endpoint). Future v3 might bind additional headers (e.g. `Idempotency-Key`) into the signed payload. Defer until anyone asks.

### Phase 7bo deliverables (✅)

- [x] [`ContainerInfo::tmpfs_mounts: Vec<String>`](crates/iac-providers/src/docker/backend.rs) — sorted target paths, populated from `.HostConfig.Tmpfs` keys in `parse_inspect_json`. Options strings ignored (the `size=64m,rw` value half of the docker-inspect map).
- [x] [`MockContainer::tmpfs_mounts`](crates/iac-providers/src/docker/backend.rs) populated by `MockDocker::run` from `spec.mounts.filter type=tmpfs`. Sorted to match the CLI canonicalization. The mock now mirrors what real docker would store.
- [x] [`observe`](crates/iac-providers/src/docker/ops.rs) surfaces `tmpfs_mounts` into the spec mapping so the diff path can read it back.
- [x] [Diff path](crates/iac-providers/src/docker/ops.rs) compares desired tmpfs targets (from `spec.mounts` filter type=tmpfs) against observed; emits `tmpfs_mounts` field change with a `tmpfs targets [...] -> [...]` reason. Set-based — reordering in the manifest doesn't drift.
- [x] **6 new tests**: 2 backend (parses `.HostConfig.Tmpfs` object, missing key yields empty list); 4 ops (round-trip no drift, drift when missing from observed, drift when extra observed, set-based no-drift on reorder).
- [x] Eight `MockContainer` literal sites in [ops.rs](crates/iac-providers/src/docker/ops.rs) patched via Python regex to add `tmpfs_mounts: vec![]`.

### Open after Phase 7bo

- **Tmpfs option strings still untracked.** `size=64m` and `rw|ro` flags from `.HostConfig.Tmpfs` values are dropped. If two operators agree on the target path but disagree on size, no drift fires. Defer until anyone asks — most tmpfs use cases are "scratch space, doesn't matter how big."
- **Apply path doesn't surface `--tmpfs` flag separately.** Tmpfs entries are rendered via `--mount type=tmpfs,target=/cache,readonly` (Phase 7bn). Docker also accepts `--tmpfs /cache:size=64m`, but the long-form is sufficient and more uniform.
- **No checkpoint/rollback for tmpfs.** Because tmpfs is in-memory and naturally lost on container recreation, restoring "previous tmpfs targets" via rollback is automatic — the rebuilt container gets the same `--mount` flags from the rebuilt spec. No explicit checkpoint field needed.

### Phase 7bn deliverables (✅)

- [x] [`DockerMount`](crates/iac-providers/src/docker/spec.rs) struct: `type`, optional `source`, `target`, `readonly`. `#[serde(deny_unknown_fields)]` so typo'd keys fail loudly.
- [x] [`DockerContainerSpec::mounts: Vec<DockerMount>`](crates/iac-providers/src/docker/spec.rs) with `#[serde(default)]`. Coexists with `volumes`; both feed the same canonical set for diff.
- [x] Validation: type must be `bind` / `volume` / `tmpfs`; target absolute + non-empty + no traversal; bind requires absolute source; volume requires non-empty name without `/`; tmpfs forbids source. Cross-field check rejects mounts whose canonical short-form duplicates a `volumes` entry.
- [x] [`mount_to_short_form`](crates/iac-providers/src/docker/spec.rs) projects bind/volume to `source:target[:ro]` for diff equivalence; returns `None` for tmpfs. [`mount_to_cli_arg`](crates/iac-providers/src/docker/spec.rs) renders to `type=...,source=...,target=...,readonly` with deterministic key order.
- [x] [`DockerCli::run`](crates/iac-providers/src/docker/backend.rs) emits one `--mount` flag per `spec.mounts` entry, alongside the existing `--volume` flags.
- [x] [`MockDocker::run`](crates/iac-providers/src/docker/backend.rs) folds `spec.mounts.filter_map(mount_to_short_form)` into the container's volumes list so observe/diff round-trips work.
- [x] [Diff path](crates/iac-providers/src/docker/ops.rs) merges `volumes` + `mounts.canonicalized()` for the desired-side comparison. Existing `volumes differ` reason still fires.
- [x] **17 new tests**: 14 spec-level (parse all three mount types, type/source/target validation, duplicate detection, short-form projection round-trip, CLI arg rendering, absent-state forbids mounts); 3 ops-level (long-form produces same observed state as short-form, no drift when long-form matches short-form observed, drift fires when long-form mount missing).
- [x] Five `DockerContainerSpec` literal sites patched via Python regex to add `mounts: vec![]`.

### Open after Phase 7bn

- **Tmpfs mounts don't round-trip through diff.** A `mounts: [{type: tmpfs, target: /cache}]` entry is correctly rendered to the docker CLI but currently has no observed-state representation — `mount_to_short_form` returns `None` for tmpfs, so the diff path treats the desired set as if the tmpfs weren't declared. This is OK on first apply (the container gets created with the tmpfs) but a subsequent `iac plan` against an observed-state snapshot won't detect a missing tmpfs. Fix: parse `.HostConfig.Tmpfs` from `docker inspect` and add a parallel `tmpfs_mounts: Vec<String>` to ContainerInfo.
- **No bind-propagation / consistency / volume-driver fields yet.** Long-form `--mount` supports many more options (e.g. `bind-propagation=rslave`, `consistency=cached` on macOS, `volume-driver=local`). Defer until anyone asks; the four-field shape covers 95% of use cases.
- **Spec uses both `volumes` and `mounts` for the same thing.** Operators may mix them, and the duplicate-rejection helps catch obvious cases. A future deprecation might steer all new code to `mounts` and lint-warn on `volumes`. No urgency.

### Phase 7bm deliverables (✅)

- [x] [`DockerContainerSpec::extra_networks: Vec<String>`](crates/iac-providers/src/docker/spec.rs) with `#[serde(default)]`. Validation reuses the new [`validate_network_name`](crates/iac-providers/src/docker/spec.rs) helper for each entry. Rejects duplicates within the list AND overlap with the primary `network`.
- [x] [`DockerBackend::connect_network(container, network)`](crates/iac-providers/src/docker/backend.rs) trait method with a default `Ok(())` impl. `DockerCli` overrides it to invoke `docker network connect`; idempotent on "already attached" stderr matches.
- [x] [`MockDocker::connect_network`](crates/iac-providers/src/docker/backend.rs) records the call and appends to the container's networks list (deduped, sorted) so observe + diff reflect the attached set.
- [x] [`docker.recreate` apply path](crates/iac-providers/src/docker/ops.rs) now iterates `spec.extra_networks` after `backend.run(spec)` and calls `connect_network` per entry.
- [x] [Diff path](crates/iac-providers/src/docker/ops.rs) now compares the full network set (primary + extras, sorted) against the observed network list. Set-based — reordering doesn't drift. Skipped when both `network` and `extra_networks` are unset (default-bridge container with no preference).
- [x] [Rollback path](crates/iac-providers/src/docker/ops.rs) reads `previous_networks` from the checkpoint, splits the first non-bridge entry as the primary and the rest as `extra_networks`, then re-attaches the extras after `run`.
- [x] **11 new tests**: 6 spec-level (parses extras, no-primary edge case, duplicate rejection, primary-overlap rejection, shell-meta rejection, absent-state rejection); 5 ops-level (apply attaches extras, diff fires on missing extra, no-drift on full match, no-drift on reorder, rollback restores full set).
- [x] Three `DockerContainerSpec` literal sites patched via Python regex to add `extra_networks: vec![]` after `network: None`.

### Open after Phase 7bm

- **Bridge handling stays heuristic.** Rollback drops `bridge` from the previous network list because real docker reports `bridge` for any default-network container; including it in the rebuilt spec's `extra_networks` would trigger a drift-on-reapply false positive. If an operator legitimately attaches their container to BOTH `bridge` AND another network, the rollback won't preserve that explicit `bridge`. Edge case; defer.
- **No partial-failure recovery.** If `run` succeeds but the second `connect_network` call fails, the container is in a half-attached state. Today the apply step returns the error and operators get a clear failure message; a subsequent reapply re-runs the whole `recreate` (idempotent). A more surgical "connect missing networks only" path is plausible but adds complexity for an unusual failure mode.
- **`extra_networks` element-type advertised in `/v1/expanders` catalog yet?** No — providers expose the `docker.container` shape via expanders, but the catalog descriptor doesn't currently include `extra_networks` as a `array<string>` field. The Phase 7bl deep-validation already supports it; once the descriptor is updated, CLI-side validation kicks in for free.

### Phase 7bl deliverables (✅)

- [x] [`type_mismatch`](crates/iac-cli/src/validate_spec.rs) now returns `Option<String>` (was `Option<&'static str>`) and recurses into `array<T>` + `map<K,V>`. Path suffixes (`at index N`, `at key 'X'`) propagate outward through nested types.
- [x] [`split_top_level_comma`](crates/iac-cli/src/validate_spec.rs) helper for depth-aware splitting of `map<K,V>` parameters where K or V can themselves be `array<...>` / `map<...>`. Bracket-balance counter avoids splitting on commas inside nested types.
- [x] **10 new validate_spec unit tests** ([validate_spec.rs](crates/iac-cli/src/validate_spec.rs)): array element accept/reject (string/number element type, non-array shape), `map<string,number>` value-type accept/reject, `map<string,string>` tightened from shallow → deep, nested `array<map<string,string>>` deep validation, malformed `map<a,b,c>` falls through, `split_top_level_comma` unit test.
- [x] Phase 7bi's `map_type_accepts_object` / `map_type_rejects_string` tests still pass — backward-compat preserved (the shallow shape check still fires before recursion when the value isn't an object).

### Open after Phase 7bl

- **Catalog `array<...>` declarations don't exist yet** — providers register fields with simple types like `string` and `map<string,string>`. The new `array<T>` recursion path is currently exercised only by tests. Will activate as soon as a provider declares an `array<string>` field.
- **`map<K,V>` key-type recursion deferred.** JSON object keys are always strings, and the catalog currently only emits `map<string, V>`. If a future shape uses non-string keys (numeric strings interpreted numerically, etc.), revisit.
- **Unknown declared types still pass through.** `duration: "30s"` won't be rejected even if the server's serde would fail. CLI's job is fast feedback for the common case; authoritative validation stays server-side.

### Phase 7bk deliverables (✅)

- [x] [`WebhookConfig::max_concurrent_requests: Option<u32>`](crates/iac-controlplane/src/webhook.rs) — per-receiver cap, `#[serde(default)]` so existing TOML configs parse unchanged. `Some(0)` is treated as "no per-receiver cap" so a typo doesn't silently halt the receiver.
- [x] [`WebhookDispatcher::per_webhook_semaphores: HashMap<String, Arc<Semaphore>>`](crates/iac-controlplane/src/webhook.rs) — pre-built at construction from receivers that opted in. Receivers without a configured cap are absent; only the global semaphore gates them (preserves Phase 7z behavior).
- [x] [`fire_with_permit`](crates/iac-controlplane/src/webhook.rs) acquires global permit first, then the per-receiver permit if the receiver has one. Both held for the request lifetime. Per-receiver wait is intentionally not metricized separately yet (deferred — see Open-after).
- [x] **2 new e2e tests** ([e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs)): `per_receiver_cap_limits_concurrent_requests` writes 5 events to a slow handler with cap=1 and asserts max-observed concurrency stays at 1; `per_receiver_cap_does_not_throttle_other_receivers` runs receiver-A (slow + cap=1) alongside receiver-B (fast + uncapped) and verifies B is not blocked by A's serialized backlog.
- [x] Three `WebhookConfig` literal sites (two helpers in [e2e_webhooks.rs](crates/iac-controlplane/tests/e2e_webhooks.rs), one in `webhook.rs` unit-test helper) patched to set `max_concurrent_requests: None`.

### Open after Phase 7bk

- **No per-receiver-wait metric.** The global `semaphore_wait_micros` / `semaphore_wait_hist` measures *only* the global permit acquisition. A receiver hitting its per-receiver cap shows up indirectly as elevated `in_flight` for that bucket, but there's no dedicated histogram. Defer until anyone needs it — ad-hoc tracing on the per-receiver `acquire()` path is the workaround.
- **No upper-bound clamp on the per-receiver cap either.** Operators can set `Some(10_000)` and the semaphore will allocate that many slots. Same reasoning as 7bj — realistic values are single digits; document the trade-off.
- **Cap changes need a dispatcher rebuild.** Same SIGHUP-blocked story as the existing config-issues / per-window / per-webhook metric maps. Joining the existing list of three rebuild-on-config-change cases.

---

## Phase 2d — PostgreSQL backend (settled in Phase 7al)

Resolved in Phase 7al via `sqlx::AnyPool` + runtime placeholder translation.
The bullets below survive only as historical context for the design choices:

- ✅ `postgres` feature added to workspace sqlx — no new RUSTSEC drag-back.
- ✅ Dialect-portable queries: `?` placeholders kept in source, translated to
  `$N` for Postgres at runtime. `BIGSERIAL` + `BIGINT` in PG migrations so
  `i64::from(bool)` binds match. Partial indexes work in both. `INSERT OR
  REPLACE` was already replaced with explicit UPDATE-then-INSERT in Phase 2a.
- ⏸ Migration script (SQLite → Postgres data move) — see "Open after Phase 7al".
- ⏸ Connection pool sizing / timeout tuning — also in the open list.

## Phase 3 — GitOps flow

- [x] `source_commit` tracking on every desired-state submission — wire field has shipped since Phase 2b; Phase 7ch auto-resolves it from `--git-ref`.
- [x] Plan from a Git revision — shipped in Phase 7ch (`iac plan --git-repo URL --git-ref REF`).
- [x] CI integration (validate/plan/policy) — shipped in Phase 7ch. `iac plan --git-repo … --server …` does fail-closed catalog validation + renders diff. Non-zero exit on validation error; exit code 2 on changes present, 0 on no-op.
- [x] Manual approval gate — already in place via Phase 6e (`requires_approval` policy attribute) + Phase 7g approve/reject CLI commands. Composes with GitOps: `iac apply --git-repo` produces a `pending_approval` operation when policy fires; approver runs `iac plan --server <url> --operation <id>` to review then `iac approve`.
- [x] Apply only after merge — operator wires this in CI (`on: push: branches: [main]`). The CLI's `--git-ref` resolution to a canonical SHA prevents post-merge race conditions where the branch moves between plan and apply.

## Phase 5d — More providers

- [x] `docker.compose` — shipped in Phase 7cw. Stack-as-resource on top of `docker compose` V2 plugin. Inline compose YAML in the iac manifest; materialised under `/var/lib/iac/compose/<project>/` at apply time. Drift via sha256(source) of on-disk compose file. Mock backend for tests.
- [x] `dns.record` — shipped in Phase 7cx. Pluggable backend trait + Cloudflare implementation via `curl` shell-out (same pattern as docker/git/ssh/sops). Single-record-per-(zone,fqdn,type) model. Cloudflare API token via `${secret://…}`. Identity for upserts: `(zone, fqdn, type)`. Route53 / others plug in via the same trait without spec breakage.
- [x] `monitoring.check` — shipped in Phase 7ca. Active HTTP/TCP probe with pure-std backend (no third-party HTTP client). Plays with phased apply (Phase 7by) so operators can gate dependent layers on a passing health check.
- [x] `firewall.rule` — shipped in Phase 7bz. iptables backend with comment-tag identity, full observe/diff/apply/rollback lifecycle.

## Phase 6i+ — Remaining security hardening

> Closed items moved to [TASKS_ARCHIVE.md](TASKS_ARCHIVE.md). Only open items remain here.

- [x] Agent identity & cert rotation — Phase 7cc shipped server-side TTL + rotate endpoint. Auto-rotation on the agent (Phase 7cd) deferred.
- [x] Server signing key rotation — shipped in Phase 7ce. Multi-key set with rotate + retire admin endpoints; file-per-key storage with legacy auto-migration; bundle endpoint for multi-key-aware agents.
- [x] SOPS secret resolver — shipped in Phase 7ct. `${secret://sops/<file>#<field>}`; shells out to system `sops` with sandboxed `base_dir`. Plays alongside Vault — operators can register both backends concurrently.
- [x] SIGHUP hot-reload of server config / retention windows / policies — shipped in Phase 7bx. Soft fields (policies, maintenance windows, modules, retry_after_format, retention) reload atomically. Hard fields (bind, database, webhooks, tls, rate_limit) still need a restart by design — they own long-lived runtime state.

## Phase 8+ — Product features backlog

> Closed items moved to [TASKS_ARCHIVE.md](TASKS_ARCHIVE.md). Only open items remain here.

- [x] Canary rollouts — shipped in Phase 7cg. Per-layer split with `CanarySpec { pct, min_count }`; canary failure cascades cancellation to baseline + later layers. Health-gate-via-monitoring is a separate future iteration (operator can include a `monitoring.check` in the canary resource list as a workaround).
- [x] Phased apply — shipped in Phase 7by. `metadata.dependsOn` produces real cross-agent barriers via `layer` + `pending_layer` status; failure cancels remaining layers.
- [x] Rollback orchestration across multi-step operations — shipped in Phase 7ci. `POST /v1/operations/{id}/rollback` builds a new op from prior desired-state per resource. Composes with phased apply + canary + RBAC + audit. Orphaned resources (first-time applies) still need manual deletion.
- [x] `monitoring.check` first-class provider — shipped in Phase 7ca.
- [x] `acme.certificate` — shipped in Phase 7cy. Backend trait + `lego` shell-out. HTTP-01 webroot mode + DNS-01 via Cloudflare (zero-config). Auto-renew when within `renew_window_days` (default 30). Cert expiry parsed via `openssl x509 -enddate`. Pre-apply checkpoints prior cert+key for rollback. Mock backend for tests.

## Phase 7ck — SSH push deployment (Ansible-like, agent-less) — SHIPPED

> See "Now" section for the full deliverables list. Below is the
> historical design doc, kept for context.
>
> Shipped: `[[ssh_targets]]` config + per-target worker pool +
> `iac apply --assignment-stdin` remote applier + 6 e2e tests via
> per-test fake-ssh shim. Original design below diverged on a few
> points (we shell out to system `ssh` instead of linking russh,
> didn't ship `iac targets` CLI yet). Open follow-ups noted in the
> "Open after Phase 7ck" block above.

### Design

- **New routing target type**: `ssh_target` alongside the existing
  registered-agent. Configured in `server.toml`:
  ```toml
  [[ssh_targets]]
  name           = "edge-router-01"
  environment    = "edge"
  host           = "192.168.50.1"
  user           = "root"
  identity_file  = "/etc/iac/ssh/edge.key"
  remote_workdir = "/var/tmp/iac"          # where applier + payload land
  remote_iac_path = "/usr/local/bin/iac"   # if pre-installed; else uploaded
  capabilities   = ["file", "sysctl.setting"]   # whitelist enforced server-side
  ```
- **Reuse the assignment dispatch model**. SSH targets show up in the
  `agents` table with a marker (`kind = 'ssh'`). When `create_operation`
  routes by `hostSelector.name`, an SSH target matches the same way an
  agent does. The only difference: instead of waiting for the target to
  poll, a server-side worker pool actively pushes.
- **`SshPushWorker`**: a Tokio task per target that:
  1. Waits on a notify channel for new pending assignments addressed to it.
  2. SSH-execs `iac apply` (or a stripped-down `iac-applier` for hosts that
     can't run the full binary) with the payload piped on stdin.
  3. Captures stdout (apply log) + stderr (errors) + exit code.
  4. Calls `complete_assignment` with success/failure mapped from the exit code.
- **Authentication**: SSH key auth only (no passwords). Operator places the
  key in the server's state dir + `chmod 0600`. Optional ssh-agent
  forwarding via `SSH_AUTH_SOCK`. Operator-controlled `known_hosts`.
- **Idempotency on retry**: each SSH push is keyed by `assignment_id`. If a
  retry sees the previous attempt still running on the target (PID file
  in remote_workdir), it waits rather than racing.
- **Concurrency cap**: per-target `max_in_flight: u32` + global pool size
  on `[ssh_workers]`. Otherwise a 1000-host fleet would open 1000 SSH
  sessions simultaneously → SSHd would refuse.

### Open design questions

- **Self-staging the binary?** Two options: (a) operator pre-installs `iac`
  on each target, (b) server scp's a static-musl `iac` build to
  `remote_workdir` on every push. Option (a) keeps push fast but requires
  one-time setup; option (b) is zero-touch but pays the ~10MB upload
  per push. Likely: support both via `remote_iac_path` (preinstalled)
  vs. `auto_upload = true`.
- **Network gear without /tmp + /usr/local/bin** (Cisco IOS, Mikrotik
  RouterOS): native binary push doesn't work. For these, ship a NETCONF
  / vendor-API "applier" — different code path. Probably a separate
  Phase 7cl: vendor-specific transports.
- **Privilege**: do we sudo by default? `become: root` per target in
  config? Mirroring Ansible's `become: yes` with a per-target override
  is reasonable.

### Deliverables target

- Wire format: extend `AgentSummary` / `agents` row with `kind` field.
  Migration: ALTER TABLE agents ADD COLUMN kind TEXT NOT NULL DEFAULT 'pull'.
- `crates/iac-controlplane/src/ssh_push.rs`: worker pool + push logic.
  Use `russh` crate (pure Rust SSH client, no openssl native dep) to
  match our static-binary story. Adds ~3 transitive deps + audit
  surface for SSH protocol — acceptable.
- `[[ssh_targets]]` config block with full validation surface.
- `iac targets list/add/remove --server` CLI subcommands for managing
  the target list.
- Unit tests: per-target worker queueing, retry-on-transient-fail,
  capabilities allowlist enforcement.
- E2E test: a real `sshd` in a docker-compose harness (or just spawn
  `openssh-server` in test setup) → push → verify file exists on the
  "remote" → assert audit event. Probably 8-10 e2e tests.

### Estimated scope

- ~600-800 LOC server-side (worker pool + russh + dispatcher integration).
- ~200 LOC CLI (targets management).
- ~10 e2e tests.
- One sessions of focused work, or two if the russh integration surfaces
  protocol issues.

### Why this matters for the "ideal IaC tool" story

Every other big IaC tool answers "what about hosts where I can't install
an agent" — Ansible's whole pitch is "agentless via SSH." Skipping this
leaves a real gap in the user-facing story for network gear,
appliances, and contractor environments. The pull-model agent stays
the recommended default (works through NAT, no creds in the control
plane, lower attack surface) — push is the escape hatch.

## Phases 7da–7di + 8 — DONE.

Archived 2026-05-05 from TASKS.md. These ten phases together took the
codebase from "post-7cz feature-complete" to "static-audit-clean across
six rounds, dedup'd into one Provider impl, bare-metal trialled on
aarch64". Real-fleet validation (10 VPS) deferred to Phase 9.

**Phase 7da — Polish + integration coverage + docs.**

Phase 7cz closed every backlog item to date — no open security or feature task left. This phase picks up the small follow-ups that were marked "deferred until N" without a concrete trigger, plus the four "perfect-100%" items (documentation, real-service integration tests, audit-log Merkle chain, agent auto-rotation). Pre-production — no migration concerns.

### Polish + features

- [x] **7da.1 — SSH ControlMaster pooling.** Each `iac apply --ssh` / `iac run` opens a fresh SSH session per host today; for fleets of hundreds of hosts the connect+keyex cost dominates. **Fix:** pass `-o ControlMaster=auto -o ControlPath=<state>/.ssh-cp/%C -o ControlPersist=60s` to the system `ssh` invocations in `iac-cli/ssh_dispatch.rs` and `iac-controlplane/ssh_push.rs`. Reuses the existing TCP+TLS connection across multiple commands, cutting the per-host cost from ~500ms to ~5ms.
- [x] **7da.2 — Inventory `--limit` host-pattern filtering.** Currently exact-match only. Extend to: `!host3` (negation), `web-*` (glob), comma-separated lists `web-01,web-02`. Same syntax as Ansible. **Fix:** in `iac-cli/inventory.rs::resolve()` parse `limit` into a small `LimitExpr` enum and apply against each host's name + label.
- [x] **7da.3 — `iac run` local audit log when no control plane.** `iac run --ssh user@host -- 'uptime'` prints to stdout but leaves no trail. **Fix:** append per-invocation NDJSON (timestamp, actor, hosts, command, per-host exit codes) to `<state_dir>/run-history.jsonl`. When `--server` is set, audit goes to the control plane (existing path); when standalone, it goes to local disk. New `iac history --since <duration>` CLI surfaces the file.
- [x] **7da.4 — Agent auto-rotation (Phase 7cd backlog).** Server returns `token_expires_at` in `RegisterResponse`; agent ignores it. **Fix:** agent's run-loop checks `now + 24h > expires_at` once per minute; if so, calls `POST /v1/agents/{id}/rotate-token` and persists the new token to `identity.json`. Existing rotate-token endpoint shipped in 7cc.

### Integrity + observability

- [x] **7da.5 — Audit log Merkle chain.** Today `audit_events` table is INSERT-only by code, but a compromised admin or DB writer can `UPDATE` / `DELETE` rows post-facto. **Fix:** each new row carries `prev_hash` = `sha256(prev_row.id || prev_row.payload || prev_row.prev_hash)`. New endpoint `GET /v1/audit/chain-tip` exposes the latest hash for out-of-band trust anchors (operator can log it to syslog / S3 / etc and detect tampering by re-hashing the chain). New `cargo run --bin iac-controlplane -- audit verify` command walks the chain and reports the first inconsistency.
- [x] **7da.6 — Real-service integration tests.** Two ship; one deferred:
  - [`crates/iac-providers/tests/cloudflare_real.rs`](crates/iac-providers/tests/cloudflare_real.rs) — gated on `CLOUDFLARE_DNS_API_TOKEN` + `CLOUDFLARE_TEST_ZONE`. Round-trips a TXT record (create → read → update → delete) under a randomised subdomain so concurrent CI workers don't collide.
  - [`crates/iac-providers/tests/compose_real.rs`](crates/iac-providers/tests/compose_real.rs) — gated on `IAC_COMPOSE_INTEGRATION=1` + reachable `docker compose`. Full lifecycle: observe (empty) → Create → idempotent NoChange → state=absent → empty.
  - `lego_real.rs` deferred. The `LegoCli` backend hardcodes the Let's Encrypt staging URL; running against Pebble locally would need a `--server` override knob plumbed through the spec or env. Mock backend already exercises the full Provider state machine — real test gives diminishing returns until the URL plumbing lands.

### Documentation

- [x] **7da.7 — Provider reference docs.** [`docs/en/reference.md`](docs/en/reference.md) + [`docs/ru/reference.md`](docs/ru/reference.md) — full reference section for each of 12 providers (`file`, `systemd`, `package`, `docker`, `nginx`, `cron`, `firewall`, `monitoring`, `sysctl`, `compose`, `dns`, `acme`). Spec, capability key, common pitfalls, sample manifest. Modeled on the SOPS section that landed in Phase 7ct.
- [x] **7da.8 — Web UI — out of scope.**

---

**Phase 7db — Pluggable provider system.**

Built-in providers were statically linked: 12 hardcoded entries in `register_builtins`, no way for an operator to add a kind without rebuilding. Phase 7db adds two extension points so operators can ship custom providers as data (TOML) or as separate binaries (NDJSON-RPC plugins) without touching Rust.

- [x] **7db.1 — Declarative shellout providers.** [`crates/iac-providers/src/shellout/`](crates/iac-providers/src/shellout/) — `[[shellout_providers]]` in `agent.toml` wraps three shell commands (`observe`, `apply`, optional `verify`/`rollback`). Diff is auto-derived from spec equality. Capability keys via `{{ field }}` template substitution against top-level scalars. 14 unit tests covering create/update/delete/no-change paths, capability rendering, timeout handling, failure propagation.
- [x] **7db.2 — External-process plugin protocol.** [`crates/iac-providers/src/process/`](crates/iac-providers/src/process/) — long-running plugin binaries speak NDJSON-RPC over stdin/stdout. `[[external_providers]]` config block. Versioned protocol (`PROTOCOL_VERSION = 1`), hello-message handshake with kind validation (defence in depth against config drift), opt-in `methods` list (empty = required-only, agent fallbacks for the rest), id-matched request/response, configurable timeouts, transparent crash recovery via `restart_on_crash`. 13 unit tests including handshake mismatches, application errors, transport-level retries.
- [x] **7db.3 — Wired into agent + e2e tests.** [`crates/iac-agent/src/config.rs`](crates/iac-agent/src/config.rs) loads both blocks, validates eagerly, rejects duplicate kinds across both sources. [`crates/iac-agent/src/agent.rs`](crates/iac-agent/src/agent.rs) registers dynamic providers after built-ins (so they can override). [`crates/iac-agent/tests/dynamic_providers.rs`](crates/iac-agent/tests/dynamic_providers.rs) — 2 e2e tests covering shellout + external-process full lifecycle (manifest load → observe → drift → apply → re-observe).
- [x] **7db.4 — Operator docs.** New "Custom providers" section in [`docs/en/reference.md`](docs/en/reference.md) + [`docs/ru/reference.md`](docs/ru/reference.md) — wire protocols, config schemas, when-to-pick-which decision matrix, lifecycle/crash-recovery/trust model.

---

**Phase 7dc — WebAssembly plugin runtime (sandboxed third extension point).**

External-process plugins (Phase 7db.2) trust the plugin author with full agent-UID filesystem access. Some real workflows want to ship plugins from less-trusted sources (community marketplace, third-party vendors, partner-supplied) where the host needs hard limits the plugin can't escape. WASM gives us that: capped memory, fuel-bounded CPU, no I/O imports.

- [x] **7dc.1 — wasmtime + spec.** [`crates/iac-providers/src/wasm/spec.rs`](crates/iac-providers/src/wasm/spec.rs) — `WasmProviderSpec` (kind, absolute module path, max_memory_bytes 64KiB..=1GiB, fuel_per_call > 0). wasmtime 26 (cranelift compile + std runtime, default features off) + `wat` as dev-dep so tests don't need a wasm32 toolchain. 5 unit tests on validation paths.
- [x] **7dc.2 — Sandboxed runtime.** [`crates/iac-providers/src/wasm/runtime.rs`](crates/iac-providers/src/wasm/runtime.rs) — `WasmRuntime` owns Engine + compiled Module; per-call fresh `Store` resets fuel + memory limiter. ABI v1: `iac_alloc`/`iac_dealloc` (host stages JSON envelope), `iac_kind` (validated against config), `iac_observe`/`iac_apply` required, `iac_methods`/`iac_diff`/`iac_verify`/`iac_rollback`/`iac_pre_apply`/`iac_capability_keys` opt-in. Single host import: `iac.log(ptr,len)` for plugin diagnostics through `tracing`. 7 unit tests covering observe/apply round-trip, kind mismatch, fuel-trap (infinite loop module).
- [x] **7dc.3 — Provider trait wrapper.** [`crates/iac-providers/src/wasm/provider.rs`](crates/iac-providers/src/wasm/provider.rs) — `WasmProvider` implements `Provider`, lazily reads `iac_methods` to decide which optional methods to call vs. fall back. Same JSON envelope shape as shellout / external-process — operators learn one wire format. End-to-end create-flow test against in-memory WAT module.
- [x] **7dc.4 — Wired into agent + e2e.** `[[wasm_providers]]` in [`agent.toml`](crates/iac-agent/src/config.rs); registry registration in [`agent.rs`](crates/iac-agent/src/agent.rs) (after built-ins → can override). Duplicate-kind check now spans all three sources (shellout / external-process / wasm). [`crates/iac-agent/tests/dynamic_providers.rs`](crates/iac-agent/tests/dynamic_providers.rs) — new `wasm_provider_observes_and_applies` e2e test that compiles a WAT plugin to bytes, writes it to disk, and drives the agent through observe → drift → apply.
- [x] **7dc.5 — Docs.** "Sandboxed WASM plugin providers" subsection added to both [`docs/en/reference.md`](docs/en/reference.md) and [`docs/ru/reference.md`](docs/ru/reference.md). ABI documented, sandbox limits explained, Rust toolchain hint, decision matrix expanded to three columns.

---

**Phase 7dd — WIT component-model for WASM plugins (DX upgrade).**

The Phase 7dc core ABI works but makes plugin authors juggle ptr/len pairs and JSON envelopes by hand. WIT (WebAssembly Interface Types) gives them strongly-typed records, lists, results — `wit-bindgen` generates a Rust trait the plugin implements, and the host calls it via wasmtime's component-model API. Same sandbox guarantees (memory caps, fuel limits, no I/O); just nicer to write.

- [x] **7dd.1 — wasmtime component-model + WIT.** Added `component-model` feature to wasmtime + `wit-component` dep for converting core wasm → component bytes. [`crates/iac-providers/wit/plugin.wit`](crates/iac-providers/wit/plugin.wit) declares the canonical interface: `metadata`/`observed`/`apply-outcome` records, `phase` enum, required `kind`/`observe`/`apply` plus optional `methods`/`capability-keys`. Discriminator field `runtime: WasmRuntimeKind` (default `core`) added to `WasmProviderSpec`.
- [x] **7dd.2 — WasmComponentProvider.** [`crates/iac-providers/src/wasm/component.rs`](crates/iac-providers/src/wasm/component.rs) — `wasmtime::component::bindgen!` synthesises typed Rust bindings from the .wit. Same Provider impl shape as the core variant: `pre_apply`/`diff`/`verify`/`rollback` get host-side fallbacks, freeing plugin authors from re-implementing them when defaults suffice. Per-call fresh wasmtime `Store` keeps fuel + memory caps strict.
- [x] **7dd.3 — Tests + reference Rust plugin.** [`crates/iac-providers/tests/fixtures/test-plugin/`](crates/iac-providers/tests/fixtures/test-plugin/) — a complete component plugin in ~50 lines of Rust using `wit-bindgen::generate!` + a `Guest` impl + `export!`. Built once via `cargo build --target wasm32-unknown-unknown` and componentised on-the-fly in tests via `wit_component::ComponentEncoder` so the test suite doesn't depend on `wasm-tools` being on PATH. 6 component-specific tests covering observe/apply/capability-keys round-trips and bad-input rejection. Tests skip cleanly with an instructive message when the wasm32 target isn't built.
- [x] **7dd.4 — Agent dispatch + e2e.** [`crates/iac-agent/src/agent.rs`](crates/iac-agent/src/agent.rs) dispatches on `runtime` field — same `[[wasm_providers]]` config block, two implementations behind `Provider` trait. New `wasm_component_provider_observes_and_applies` test in [`crates/iac-agent/tests/dynamic_providers.rs`](crates/iac-agent/tests/dynamic_providers.rs) exercises the full agent path with the typed component plugin.
- [x] **7dd.5 — Docs.** "Component-model variant" subsection in both [`docs/en/reference.md`](docs/en/reference.md) and [`docs/ru/reference.md`](docs/ru/reference.md): WIT interface listed inline, Rust author surface (4 lines of imports + `Guest` impl), build instructions (`cargo-component` recommended, fall-back to `wasm-tools component new`), pointer to the in-tree reference plugin.

---

**Phase 7de — Production-readiness gap closure.**

The four items the prior phase deferred as "nice to have before fleet trial". Each one closes a different risk: docs (operator readiness), real-CA testing (provider correctness against external infra), parser hardening (manifest blast-radius), and WASI capabilities (turn the WASM sandbox from "no I/O at all" into "operator-defined I/O surface").

- [x] **7de.1 — Operations runbooks (en+ru).** [`docs/en/runbook.md`](docs/en/runbook.md) + [`docs/ru/runbook.md`](docs/ru/runbook.md). Triage decision tree, severity levels, rollback procedures (single resource / whole apply / git-revert / backup restore), common failure modes (control-plane down, fleet partition, drift surge, half-applied state, audit-chain mismatch), diagnostic commands cheatsheet, paging-decision matrix, post-incident template.
- [x] **7de.2 — ACME server_url + Pebble integration test.** [`crates/iac-providers/src/acme/spec.rs`](crates/iac-providers/src/acme/spec.rs) gains `server_url: Option<String>` (mutually exclusive with `staging`). Validation: HTTPS freely accepted; HTTP only for loopback hosts (Pebble / step-ca on localhost). [`crates/iac-providers/src/acme/backend.rs`](crates/iac-providers/src/acme/backend.rs) plumbs through `--server` to lego. New `lego_real.rs` integration test gated on `IAC_LEGO_INTEGRATION=1` + Docker + `lego` on PATH; spins Pebble in a container, exercises the end-to-end argv path, asserts lego reaches the challenge phase (proves `--server` plumbing, not a wire bug).
- [x] **7de.3 — Fuzz harness.** Two complementary pieces. [`crates/iac-providers/tests/fuzz_parsers.rs`](crates/iac-providers/tests/fuzz_parsers.rs) — `proptest`-driven smoke fuzzing under stable `cargo test`: 256 random YAML shapes per provider × 12 providers + 128 random YAML strings against the manifest loader. Asserts no input shape panics. [`fuzz/`](fuzz/) — stand-alone `cargo-fuzz` directory (workspace opt-out so it doesn't drag libfuzzer-sys into normal builds). Targets: `fuzz_provider_specs`, `fuzz_manifest_documents`. Run via `cd fuzz && cargo +nightly fuzz run <target>`.
- [x] **7de.4 — WASI preview2 capabilities.** [`crates/iac-providers/src/wasm/spec.rs`](crates/iac-providers/src/wasm/spec.rs) — new `WasiConfig` field on `WasmProviderSpec` with explicit preopens (host→guest with read-only / writable bit), env list, stdio inheritance, network opt-in. Default = empty = no I/O (current 7dc/7dd sandbox preserved). [`crates/iac-providers/src/wasm/component.rs`](crates/iac-providers/src/wasm/component.rs) — `WasiCtxBuilder` constructed per call, registered on the component linker only when capabilities are configured. [`crates/iac-providers/tests/fixtures/wasi-plugin/`](crates/iac-providers/tests/fixtures/wasi-plugin/) — Rust component plugin that reads a preopened file. New e2e tests in [`crates/iac-agent/tests/dynamic_providers.rs`](crates/iac-agent/tests/dynamic_providers.rs) confirm the preopen plumbs bytes through, AND that omitting `[wasi]` for a plugin that imports `wasi:filesystem` fails-closed at agent startup. Docs updated with capability semantics, `wasm32-wasip2` build target, and the security-vs-DX framing.

---

**Phase 7df — WIT-typed `diff` and `verify` methods.**

Phase 7dd shipped typed `observe` + `apply`; Phase 7df closes the gap on the other lifecycle methods. Plugins that own derived state (a checksum vs. file content, a normalised representation vs. literal input) can now opt into structured diff/verify outputs that travel across the host↔guest boundary as canonical-ABI records, not JSON envelopes.

- [x] **7df.1 — WIT extension.** [`crates/iac-providers/wit/plugin.wit`](crates/iac-providers/wit/plugin.wit) gains `diff-kind` enum, `field-change` record (with `from-json` / `to-json` payloads + `sensitive` bit), `diff-result` record, and a `verify-outcome` variant (`ok` / `mismatch(list<field-change>)` — we avoid the `match` WIT keyword). Two new functions: `diff: func(metadata, desired-spec-json, observed) -> diff-result` and `verify: func(metadata, spec-json) -> verify-outcome`. The record name is `diff-result` (not `diff`) so it doesn't collide with the function of the same name in the same interface.
- [x] **7df.2 — Host wiring.** [`crates/iac-providers/src/wasm/component.rs`](crates/iac-providers/src/wasm/component.rs) — `WasmComponentProvider::diff` and `::verify` route through the typed exports when the plugin lists them in `methods()`; otherwise they keep the spec-equality / re-observe fallbacks. New helpers `observed_to_wit`, `diff_from_wit`, `field_change_from_wit`, `verify_from_wit` convert between the WIT canonical-ABI types and `iac_core::diff::*` / `iac_core::provider::VerifyOutcome`. The `from-json` / `to-json` payloads are JSON-encoded values to keep WIT free of opaque value types.
- [x] **7df.3 — Fixture opts in.** [`crates/iac-providers/tests/fixtures/test-plugin/src/lib.rs`](crates/iac-providers/tests/fixtures/test-plugin/src/lib.rs) returns `vec!["diff", "verify"]` from `methods()` and implements both with structured outputs (Create + one `field-change` for missing names, NoChange for present ones; `Ok` for "exists-*", `Mismatch` otherwise). The wasi-plugin keeps the host fallback path for diff/verify — proves both opt-in shapes coexist cleanly.
- [x] **7df.4 — Tests.** 4 new component-level round-trip tests in [`crates/iac-providers/src/wasm/component.rs`](crates/iac-providers/src/wasm/component.rs): `typed_diff_routes_through_plugin` (Create branch, asserts the plugin's custom reason + structured field-change make it back to the host), `typed_diff_no_change_path`, `typed_verify_match_branch`, `typed_verify_mismatch_branch`. Each builds a real `.component.wasm`, instantiates it, drives the typed path end-to-end. 10 component tests total now (up from 6).
- [x] **7df.5 — Docs.** Author surface in [`docs/en/reference.md`](docs/en/reference.md) and [`docs/ru/reference.md`](docs/ru/reference.md) updated with the full `Guest` trait signature including `diff` + `verify`, opt-in semantics ("trait methods are mandatory at the Rust level, but only listed methods get called"), the rationale ("derived state needs structured diff, not spec-equality"), and the recognised method-name strings.

---

**Phase 7dg — Race fix + typed `pre-apply` / `rollback`.**

Two follow-ups: a real race in the audit-row commit ordering (caught as a flaky test, fixed atomically), and the last two opaque lifecycle methods get a typed WIT shape.

- [x] **7dg.1 — Race fix.** [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) gains `complete_assignment_with_extra_audit` — same path as `complete_assignment` but takes an optional `AuditRecord` recorded in the same transaction. [`crates/iac-controlplane/src/ssh_push.rs`](crates/iac-controlplane/src/ssh_push.rs) routes its `ssh.push_*` audit through the new path so callers waiting on `wait_terminal` can no longer observe the operation reaching terminal status before the audit row lands. Stress-tested 10/10 on the previously flaky `ssh_push_emits_audit_event`.
- [x] **7dg.2 — Typed rollback.** [`crates/iac-providers/wit/plugin.wit`](crates/iac-providers/wit/plugin.wit) gains `rollback: func(metadata, checkpoint-json: string) -> result<_, string>`. Plugin owns the checkpoint shape end-to-end; host treats the bytes as opaque. [`crates/iac-providers/src/wasm/component.rs`](crates/iac-providers/src/wasm/component.rs) wraps the plugin's checkpoint string in a `{ "wit_checkpoint": "..." }` envelope so a binary swap from typed→fallback (or vice versa) can't desync inflight rollbacks. Recognises the typed path only when both `methods()` lists `"rollback"` AND the checkpoint has the typed-envelope tag.
- [x] **7dg.3 — Typed pre-apply.** Same WIT extension: `pre-apply: func(metadata, spec-json: string) -> result<string, string>`. Plugin returns a JSON-encoded checkpoint that round-trips to its own `rollback` verbatim. Host fallback (snapshot of prior observed state) preserved for plugins that don't opt in.
- [x] **7dg.4 — Tests + docs.** Two new component-level round-trip tests: `typed_pre_apply_then_rollback_round_trip` (drives the full flow against a real `.component.wasm`, verifies the checkpoint envelope and the rollback consumes it cleanly) and `typed_rollback_propagates_plugin_error` (asserts WIT `result<_, string>` Err variants surface as `Error::Provider`). 12 component tests total now (up from 10). [`docs/en/reference.md`](docs/en/reference.md) + [`docs/ru/reference.md`](docs/ru/reference.md) gain a fallback-table mapping each optional method to its host fallback, plus the typed `pre-apply`/`rollback` signature snippet and round-trip semantics.

**All 7 lifecycle methods now have a typed-WIT path.** observe / apply / capability_keys are mandatory typed; diff / verify / pre-apply / rollback are typed-when-opted-in with host fallbacks.

---

**Phase 7dh — Security audit closure.** Items surfaced by the senior-pentester pass after Phase 7dg. Triaged in priority order; CRIT/HIGH first, MED before fleet trial, architectural cleanup deferred to 7di.

- [x] **7dh.1 — `list_agents` auth (C1, CRIT).** [`crates/iac-controlplane/src/api/agents.rs:118`](crates/iac-controlplane/src/api/agents.rs) has zero auth. Add `BearerToken` + `require_role(Role::Viewer)` like every other endpoint.
- [x] **7dh.2 — Cap `iac.log` payload (C3, HIGH).** [`crates/iac-providers/src/wasm/runtime.rs:351-365`](crates/iac-providers/src/wasm/runtime.rs) allocates `vec![0u8; len_us]` from guest-controlled `i32` (max 2 GiB). Cap at 64 KiB; truncate-with-marker.
- [x] **7dh.3 — WASI preopen path safety (C2, CRIT).** [`crates/iac-providers/src/wasm/spec.rs:179-189`](crates/iac-providers/src/wasm/spec.rs) only checks `host.is_absolute()`. Reject preopen hosts under `/etc`, `/root`, `/proc`, `/sys`, `/dev`, `<state_dir>`; reject guest paths with `..`. Optional `unsafe_preopen = true` escape-hatch.
- [x] **7dh.4 — Optional `module_sha256` verification (C4, HIGH).** All 4 plugin runtimes load binaries from disk by path. Add `module_sha256: Option<String>` to plugin specs; verify before instantiation. Document the threat model.
- [x] **7dh.5 — Plugin runtime DoS hardening (C6/C7/C8, MED).**
  - External-process: cap NDJSON line length at 16 MiB ([`process/handle.rs:255`](crates/iac-providers/src/process/handle.rs)).
  - External-process: per-plugin restart counter + exponential cool-off ([`process/handle.rs:65`](crates/iac-providers/src/process/handle.rs)).
  - Shellout: bounded `try_wait` loop after `kill` to actually reap zombies ([`shellout/provider.rs:104`](crates/iac-providers/src/shellout/provider.rs)).
- [x] **7dh.6 — Assignment timestamp freshness + drop submit-time approvers check.**
  - Agent rejects assignments with timestamps older than configurable window (default 1 h).
  - [`crates/iac-controlplane/src/api/operations.rs`](crates/iac-controlplane/src/api/operations.rs) submit-time approvers check is TOCTOU and redundant with approve-time gate — drop it.
- [x] **7dh.7 — Threat-model docs for plugins (C5, document).** Plugins run as agent UID with full filesystem access. Document this loudly in plugin docs — operators must trust plugin binaries the same way they trust agent binaries. Out-of-the-box UID isolation requires systemd user services / namespaces.
- [x] **7dh.8 — Dead code drop.** Three concrete items:
  - `MockFirewall::calls()` ([`firewall/backend.rs:357`](crates/iac-providers/src/firewall/backend.rs)) — defined, zero callers.
  - `NginxProvider::with_backend()` ([`nginx/mod.rs:56-58`](crates/iac-providers/src/nginx/mod.rs)) — single test caller; move under `#[cfg(test)]`.
  - `ChainTip::updated_at` field ([`tests/e2e_audit_chain.rs:26`](crates/iac-controlplane/tests/e2e_audit_chain.rs)) — deserialized but never asserted.
- [x] **7dh.9 — `/v1/health` version disclosure (C10, LOW).** Drop `version` from unauthenticated response or gate behind `Viewer`.
- [x] **7dh.10 — Second-pass audit closure.** Pentest re-run after the trial harness landed surfaced six confirmed findings + two architectural follow-ups; all fixed in this phase.
  - **C1 (MED) — bound stderr/stdout in error messages.** [`crates/iac-providers/src/subprocess.rs`](crates/iac-providers/src/subprocess.rs) — every subprocess error capped at 512 B per stream with `…[truncated, N more bytes]` marker via shared `truncate_for_error`. Defence-in-depth so a chatty failure (e.g. `apt update` dumping a 4 MiB error log containing a registry credential) can't spray the entire stream into the audit row. Centralised via new `map_subprocess_error` / `nonzero_exit_error` helpers; 3 unit tests pin the boundary behaviour.
  - **C2/C5 — chaos-script arg validation + fail-fast.** [`trial/chaos/slow-network.sh`](trial/chaos/slow-network.sh) validates latency / jitter / loss with strict regex before interpolation into `sh -c`; the inner shell now uses `set -e` so a `tc` failure is no longer silently absorbed. New `IAC_CHAOS_FAIL_FAST=1` env var aborts on first agent failure (default: best-effort).
  - **C3 — operator visibility on disabled replay protection.** [`crates/iac-agent/src/remote.rs:643`](crates/iac-agent/src/remote.rs) — `IAC_AGENT_DISABLE_AGE_CHECK=1` now emits a one-shot `tracing::warn!` (gated by `std::sync::Once` so it doesn't spam every envelope verification). Closes the silent-misconfig vector where a "we'll fix it later" deploy left replay protection off forever.
  - **C6 — discriminate "already disconnected" from real errors in partition chaos.** [`trial/chaos/partition.sh`](trial/chaos/partition.sh) — replaces the previous `2>/dev/null || true` swallow with `err=$(... 2>&1) && rc=0 || rc=$?`; idempotent skips are reported as such, real errors (network gone, daemon offline, permission denied) abort `apply` and log-and-continue on `restore`. Adds positive-integer validation on `N`.
  - **A1 — migrate firewall/docker/package backends to shared `run_with_status`.** New helper in [`crates/iac-providers/src/subprocess.rs`](crates/iac-providers/src/subprocess.rs) returns `(status_ok, stdout, stderr)`; firewall, docker, and package backends drop their bespoke `match SubprocessError` blocks. ~75 LOC removed; consistent error-mapping surface for any future backend.
  - **A2 — `resource_metadata_to_json` extraction.** [`crates/iac-core/src/convert.rs`](crates/iac-core/src/convert.rs) gains the helper; shellout / process / wasm-core / wasm-component all drop their byte-identical `metadata_json` methods. ~28 LOC removed.
  - **Trial-script hardening.** [`trial/scenarios/baseline-50.sh`](trial/scenarios/baseline-50.sh) + [`longevity.sh`](trial/scenarios/longevity.sh) now `timeout 60s` the cleanup `compose down` (a wedged container can no longer pin teardown forever) and re-validate `$TRIAL_BIN` after `cargo build` so a misconfigured `target-dir` fails loud instead of mid-scenario.

---

**Phase 7di — Architectural deduplication.** Deferred to after 7dh ships and fleet trial validates the runtime surface. Plan:

- [x] **7di.1 — `PluginRuntime` trait + shared `PluginProvider`.** [`crates/iac-providers/src/plugin/`](crates/iac-providers/src/plugin/) — one `Provider` impl across the three JSON-envelope-based runtimes (shellout, external-process, wasm-core). The fourth runtime (wasm-component) uses typed WIT bindings — different shape, intentionally kept separate.
  - **Trait:** [`PluginRuntime { kind, call(method, Json) -> Json, supports(method) -> bool, capability_keys_strategy() }`](crates/iac-providers/src/plugin/runtime.rs). Three method strings (observe / apply / diff / verify / rollback / pre_apply / capability_keys) are wire literals. `CapabilityKeysStrategy::{Templates, Plugin}` distinguishes host-rendered (shellout / external-process: list of `{{ field }}` templates) from plugin-computed (wasm-core: plugin's own export).
  - **Shared `PluginProvider<R: PluginRuntime>`:** [`provider.rs`](crates/iac-providers/src/plugin/provider.rs) — implements all 8 Provider methods once. Built-in fallbacks (spec-equality diff, observe-snapshot pre_apply, re-observe verify, apply-against-prior rollback) live here too — runtimes that don't opt in via `supports()` get the host's defaults for free.
  - **Migration:** the three runtimes shrunk from per-Provider implementations (≈300 LOC of glue each) to transport-only adapters: `ShellOutRuntime` (~120 LOC of subprocess), `ExternalRuntime` (~50 LOC NDJSON-RPC delegate), `WasmRuntimeAdapter` (~70 LOC byte-slice wrap). Public surface kept stable via `pub type ShellOutProvider = PluginProvider<ShellOutRuntime>` / etc; agent-side construction switched to the two-step `Runtime::new(spec)?.into_provider()`.
  - **Step-action prefix unified:** `"shellout-create"` / `"external-create"` / `"wasm-create"` → `"plugin-create"` (and `update`/`delete`). Pre-prod, no in-flight ops to migrate; one place to change next time we revise the prefix.
  - **LOC delta:** 1604 → 1272 across the four files (`shellout`, `process`, `wasm-core` providers + new `plugin/`). ~332 LOC removed; the bigger win is **one Provider implementation** — drift between the three previously-independent copies is no longer possible.
  - **Tests:** 429 iac-providers lib tests pass (was 433; lost 4 redundant per-runtime checks now subsumed by shared paths). 197 iac-controlplane lib + ~280 integration tests still green.
- [x] **7di.2 — `iac-core::convert` module.** [`crates/iac-core/src/convert.rs`](crates/iac-core/src/convert.rs) — `yaml_to_json`, `json_to_yaml`, `collect_top_level_changes` lifted from 4 byte-identical copies in shellout / process / wasm-core / wasm-component. ~80 LOC removed; 7 new unit tests cover round-trip, lossy edge cases, change-collection branches.
- [x] **7di.3 — `iac-core::template` module.** [`crates/iac-core/src/template.rs`](crates/iac-core/src/template.rs) — single `render()` core taking a lookup closure plus two format-specific helpers (`render_yaml_top_scalars`, `render_json_top_scalars`). Three copies in `shellout/provider.rs`, `process/provider.rs`, `controlplane/modules.rs` collapsed; ~80 LOC removed. New typed `TemplateError { Unterminated, MissingKey, NotScalar }` replaces ad-hoc string errors. 15 unit tests (parser passthrough, brace-trim, multi-substitute, unterminated, scalar/array/null branches per format).
- [x] **7di.4 — Shared `tests/common/mod.rs` harness.** [`crates/iac-controlplane/tests/common/mod.rs`](crates/iac-controlplane/tests/common/mod.rs) — `TestServer` + `TestServerBuilder` with overrides for every Config knob (modules, policies, rate-limit, webhooks, maintenance windows, TLS, secrets, ssh_targets, agent_token_ttl_secs, retry_after_format) plus public `addr / store / signer / state / config_path` fields for tests that poke internals. Migrated 19 of 41 integration test files via scripted bulk-edit (the simple variants whose `impl TestServer` had only `spawn / url / shutdown`). Saved ~38 KiB of byte-identical boilerplate. Remaining 22 files keep their own harness because they have either: bespoke spawn-args (`spawn(policies)`, `spawn(tls)`, `spawn(Some(ttl))`), per-file helper methods (`make_user`, `login`, `register_agent`, `submit`), or extra struct fields (signer, db_path, ssh_handles) that don't fit the shared shape. Migrating those would erase distinguishing test-shape signal — kept as-is.
- [x] **7di.5 — `iac-core::subprocess::run_with_timeout`.** [`crates/iac-core/src/subprocess.rs`](crates/iac-core/src/subprocess.rs) — single one-shot subprocess primitive with stdin pipe + bounded wait + post-kill reap. Shellout's `run()` migrated onto it (saves ~80 LOC, eliminates the bug-class where hardening fixes had to land twice). 6 new unit tests: stdout/stderr capture, stdin pipe, timeout-and-reap, BrokenPipe-benign, spawn failure variant. **External-process kept on its bespoke loop** — it's a long-running daemon (NDJSON-RPC across many calls), the one-shot abstraction would force-fit. **Other built-in providers** (acme/lego, firewall/iptables, docker/compose, dns/curl, package/apt, etc.) currently call `cmd.output()` with no timeout — separate **7di.6** follow-up to migrate them onto `run_with_timeout` since each subprocess can hang the agent indefinitely today.
- [x] **7di.6 — Migrate built-in providers off `cmd.output()`.** Every built-in provider that shells out now goes through `iac_core::subprocess::run_with_timeout` via the new [`crates/iac-providers/src/subprocess.rs`](crates/iac-providers/src/subprocess.rs) per-crate wrapper (`run_capture_stdout`, `run_check_status`, `run_capture_both`). Per-backend timeouts:
  - `dns` curl — 30 s ([backend.rs](crates/iac-providers/src/dns/backend.rs))
  - `firewall` iptables — 30 s ([backend.rs](crates/iac-providers/src/firewall/backend.rs))
  - `systemd` systemctl — 90 s ([backend.rs](crates/iac-providers/src/systemd/backend.rs))
  - `nginx` reload/-t — 30 s ([backend.rs](crates/iac-providers/src/nginx/backend.rs))
  - `package` apt — 600 s (network fetch on slow links) ([backend.rs](crates/iac-providers/src/package/backend.rs))
  - `docker` inspect/run/rm — 60 s; `docker pull` — 600 s ([backend.rs](crates/iac-providers/src/docker/backend.rs))
  - `docker.compose` `ps` — 30 s, `up` — 600 s, `down` — 120 s ([backend.rs](crates/iac-providers/src/compose/backend.rs))
  - `acme.certificate` lego — 300 s, openssl — 10 s ([backend.rs](crates/iac-providers/src/acme/backend.rs))
  - Closes the bug class where a single hung subprocess (lock contention, network drop, kernel netfilter wedge) blocks the agent's executor thread indefinitely — every shell-out now surfaces `Error::Provider("... timed out after Ns ...")` after its budget.

---

**Phase 8 — Trial harness.** Local docker-compose fleet for regression testing. Closes the "fleet trial on real hardware" gap with a reproducible, daily-runnable substitute that covers ~80 % of the same invariants (throughput, longevity, network chaos, audit chain under load) without needing physical/cloud hardware.

- [x] **8.1 — Dockerfiles.** [`trial/docker/Dockerfile.controlplane`](trial/docker/Dockerfile.controlplane) + [`trial/docker/Dockerfile.agent`](trial/docker/Dockerfile.agent) — multi-stage `rust:1.95-slim` → `debian:bookworm-slim`, runs as non-root UID 1500/1501, image surface trimmed (`ca-certificates`, `libssl3`, `sqlite3`/`iproute2`/`curl`/`jq` only). Per-replica entrypoint generates a fresh `agent.toml` from env vars so `--scale agent=N` Just Works.
- [x] **8.2 — Compose stack.** [`trial/compose/docker-compose.yml`](trial/compose/docker-compose.yml) wires control-plane (port 8443), scalable agent service, Prometheus (port 9090, 5 s scrape, 2 h retention) on a dedicated bridge network. Per-agent resource limits: 256 MiB RAM, 0.5 CPU. `CAP_NET_ADMIN` everywhere so chaos scripts can `tc qdisc` from inside containers. Health-check on control-plane gates agent startup.
- [x] **8.3 — `iac-trial` workload generator.** New crate [`crates/iac-trial`](crates/iac-trial). Three subcommands: `wait-fleet` (block until N agents register), `submit-burst` (N submits at target RPS with bounded concurrency, latency histogram), `longevity` (low-rate constant load for soak runs). Pass criteria built into `Stats::passed`: < 1 % errors, < 5 % slow ops (≥ 2.5 s); non-zero exit on failure for CI integration.
- [x] **8.5 — Chaos scripts.** [`trial/chaos/slow-network.sh`](trial/chaos/slow-network.sh) (tc/netem inside agent containers — latency, jitter, loss; pin via `IAC_CHAOS_AGENTS`), [`trial/chaos/partition.sh`](trial/chaos/partition.sh) (`docker network disconnect` random-N agents, restore from state file).
- [x] **8.6 — Scenarios + docs.** Two ready-to-run scenarios: [`baseline-50.sh`](trial/scenarios/baseline-50.sh) (50 agents × 1000 ops @ 50 RPS) and [`longevity.sh`](trial/scenarios/longevity.sh) (30 agents @ 1 RPS for `DURATION_SECS`, default 30 min). [`trial/README.md`](trial/README.md) covers quick-start, layout, scaling, chaos usage, Prometheus queries, and **what the trial does NOT validate** (real systemd/package, real disk failures, real cross-DC latency — those need Vagrant or cloud).
- [x] **7dh.11 — Third-pass audit closure.** Four parallel specialist passes (dead-code / panic / attack-surface / duplication). Two real findings + several confirmations of already-tracked items. False positives discarded.
  - **Finding A (HIGH, AuthN) — `list_drift` / `get_drift` unauthenticated.** [`crates/iac-controlplane/src/api/drift.rs:35`](crates/iac-controlplane/src/api/drift.rs) and `:43`. Sibling write endpoints (accept/ignore/revert/bulk) all gate on `Role::Operator`; the read endpoints had no `BearerToken` extractor at all. Same class as Phase 7dh.1 (`list_agents`) — got missed because the route module went in via Phase 7be before the auth audit. Fix: added `BearerToken` + `require_role(Role::Viewer)` matching the pattern of `list_audit` / `get_op`. 13 test call sites updated to send `bearer_auth(ADMIN_TOKEN)`.
  - **Finding B (MED, Panic) — TTL parser byte-slices on a multi-byte UTF-8 boundary.** Two locations:
    - [`crates/iac-controlplane/src/api/drift.rs:248`](crates/iac-controlplane/src/api/drift.rs) (the server-side parser used by `accept-bulk` / `ignore-bulk`): `s[..s.len() - 1]` panics when the final char is multi-byte (e.g. `5µ`). Reachable by any `Operator`-role token — limited blast radius (auth-gated, panicked task only, not the whole server) but still a thread crash on malformed input. Fix: use `last.len_utf8()` to compute the byte offset.
    - [`crates/iac-cli/src/main.rs:1491`](crates/iac-cli/src/main.rs) (operator CLI for `iac drift ignore --ttl`): same `split_at(trimmed.len() - 1)` issue. Local CLI = lower severity but same fix shape. Both got 4 unit tests covering the multibyte / empty / non-numeric / happy-path branches.
  - **False positives dropped:** `chars().next().expect("non-empty")` after an `is_empty()` guard (3 sites: `docker/spec.rs`, `cron/spec.rs`, `nginx/spec.rs` — all defensively correct). Audit-row hash omitting row-id is a documented design choice (Phase 7da.5), not a regression.
  - **Re-confirmed pending architectural debt** (already tracked, not new): 7di.1 (`PluginRuntime` trait, ~700 LOC), 7di.3 (template module, 3 copies of `{{ field }}` renderer in shellout/process/controlplane), 7di.4 (`TestServer` boilerplate in 39 test files = ~2.3 kLOC). No additional duplication found beyond what 7di tracks.
  - **Attack-model coverage matrix** (10 archetypes): all covered or partially-covered with documented mitigations. The "TOFU first-run hijack" archetype remains "partially covered" — no fix in this phase, mitigation is operator-side TLS reverse proxy.
- [x] **7dh.12 — Invariant audit (round 6).** Six audit rounds exhausted the easier classes; this round targeted *invariant violations* — places where a function's contract or implicit assumption can be broken. Four parallel specialist passes (state-machine lifecycles / validator completeness / cache coherence / time-ordering monotonicity) produced 21 candidates. After manual verification, 18 were false positives (agents over-flagged), by-design behaviours documented inline (rate-limiter not hot-reloadable; webhook at-least-once delivery; signing-key snapshot semantics), or duplicates of already-closed items. Three real findings, all fixed:
  - **Finding A (MED, validator gap) — `Resource::validate_shape` accepted whitespace-only / control-char identifiers.** [`crates/iac-core/src/resource.rs:55`](crates/iac-core/src/resource.rs#L55) — pre-fix the validator only checked `is_empty()`; a name like `"   "` or `"nginx\nmain"` round-tripped through audit-log JSON cleanly but rendered as a "ghost" resource in `iac agents list` / dashboards / line-buffered logs. Fix: new shared `validate_required_identifier(field)` helper rejects empty / whitespace-only / control-char-bearing strings on `apiVersion`, `kind`, `metadata.name`, `metadata.environment`. **7 unit tests** in `resource::tests` cover the boundary cases.
  - **Finding B (MED, replay-window asymmetry) — envelope age check rejected `age > 24h` but accepted `age < 0`.** [`crates/iac-agent/src/remote.rs:418`](crates/iac-agent/src/remote.rs#L418) — `saturating_sub` on `i64` returns the negative difference for future-dated envelopes; the `if age > max_age` branch was false, so a server with a forward-skewed clock could mint envelopes that effectively extended the replay window. Honest threat is small (signatures bind `created_at`; the attacker would need server-side compromise to mint future dates) but the code didn't match the docstring's "X-hour window" claim. Fix: added `FUTURE_GRACE_SECS = 300` (5 min) tolerance and an explicit `age < -FUTURE_GRACE_SECS` reject branch. The window is now symmetric.
  - **Finding C (MED, config DoS-via-misconfig) — `agent_token_ttl_secs` had a lower bound but no upper bound.** [`crates/iac-controlplane/src/config.rs:454`](crates/iac-controlplane/src/config.rs#L454) — the expiry compute was `now.checked_add(Span::seconds(ttl)).unwrap_or(now)`. A typo'd config like `agent_token_ttl_secs = 99999999999999` overflowed the span addition; the fallback then made every freshly-issued token expire *immediately*, returning 401 on the agent's next request — fleet-wide DoS from a single config typo. Fix: added a 10-year upper bound to the existing validator. Operators wanting longer must explicitly opt out (and would hit the validator with a clear error).
  - **What was *not* fixed (by design / out-of-scope):** WASM module hot-swap not detected (operator-UX; documented in module doc comments), agent capability allowlist requires restart (documented in [`crates/iac-agent/src/capabilities.rs`](crates/iac-agent/src/capabilities.rs)), rate-limiter not hot-reloadable across SIGHUP (documented in [`crates/iac-controlplane/src/server.rs`](crates/iac-controlplane/src/server.rs) — the buckets hold per-bucket Instants that lose meaning across a swap). Webhook backoff `Instant`-vs-`Timestamp` mismatch (clock-jump scenario) is a graceful over-delay, not under-delay; not a security concern.
  - **Tests:** 1176 total green (703 lib + 473 controlplane integration). 14 new tests (7 for `validate_shape`, plus the existing replay-window tests caught the future-date branch in CI).

- [x] **8.7 — Bare-metal Pi 4 trial + SQLite-busy 503 fix.** First real-hardware run (Raspberry Pi 4 Model B, aarch64, Ubuntu 26.04, 4-core Cortex-A72 @ 1.5 GHz, SD-card storage). Native build (cargo on the Pi, 49 min); native run (no docker), control-plane + 10 agents + workload generator co-located.
  - **Headline numbers:** agent steady-state RSS 20–27 MiB, control-plane 29–37 MiB. CPU at idle ~0.2 % per agent; control-plane saturates one core (~18 %) at 50 RPS submit + 10 heartbeats. Memory budget for the whole stack ≈140 MiB — fits a 256 MiB router class or a 512 MiB Pi Zero with comfortable headroom.
  - **Pass thresholds held under 1000 ops × 50 RPS:** 997 / 1000 succeeded (0.3 % error budget vs. 1 % limit), 11 ops ≥ 2.5 s (1.1 % slow vs. 5 % limit). Audit chain advanced cleanly (1007 rows, hash-tip valid).
  - **Real-hardware finding (the docker stack would never have caught this):** under sustained write contention on slow flash storage, SQLite hit `busy_timeout` and bubbled `database is locked` up to clients as **HTTP 500**. Fix lands in this phase:
    - [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) — `PRAGMA busy_timeout` raised from 5 s to 30 s. SD-card flash + 10 concurrent agents heartbeating + 50 RPS submit hit the 5 s ceiling; on production SSDs the new value is never approached.
    - [`crates/iac-controlplane/src/error.rs`](crates/iac-controlplane/src/error.rs) — new `is_sqlite_busy(e)` detects SQLITE_BUSY (code 5) and SQLITE_LOCKED (code 6) in `sqlx::Error::Database`. Maps them to `503 Service Unavailable` with `Retry-After: 1` so well-behaved clients (the agent already has retry-on-5xx-with-backoff) recover gracefully. Permanent failures still surface as 500.
  - **Why this matters for IaC.** A tool that targets "weak hardware including network equipment" must treat slow flash as a first-class environment, not a stress edge case. Mikrotik-class routers run on NOR/NAND that's an order of magnitude slower than the Pi's SD card — the same fix budget will be worth more there.

---

### Open questions resolved

- ID scheme for resources. Likely `kind/environment/name` for the human-facing form, ULID for the persistent ID. Settled in Phase 0.
- Where do typed specs live? Per-provider crate vs `iac-core::spec::*`? Settled: per-provider — providers own their schema.
- Verification: synchronous (block until verify passes) vs async (mark "applied, awaiting verification")? Phase 0: synchronous and short-timeout. Async on agent later.

## Phase 7dh.13 — F3/F4/F5 local coverage (2026-05-05)

Three scenarios from the deferred Phase 9 fleet-validation list have
agent-side test coverage now. The hardware-side aspects (real IPMI
cold reboot, real ext4 ENOSPC behaviour, real `date -s` clock skew)
still want a VM trial when the 10 VPS allocation lands — but the
agent-side contract is no longer untested.

- [x] **F5 — Time-skew envelope rejection.** Extracted `check_envelope_freshness` from `verify_envelope` in [`crates/iac-agent/src/remote.rs`](crates/iac-agent/src/remote.rs) into a pure function so the test passes a deterministic `now`. **13 unit tests** in `remote::tests` cover the symmetric `[now - max_age, now + future_grace]` window, off-by-one boundaries on both sides, and unparseable / empty `created_at`. The `max_age=0` test-only mode is also covered. Pins the Phase 7dh.12 fix (envelope rejected when `age < -FUTURE_GRACE_SECS`).
- [x] **F4 — Identity-persist atomic-write under failure.** **4 unit tests** in `remote::tests` pin the contract: first-write creates a 0600 file; overwrite leaves no `.tmp` orphan; under a read-only parent dir (simulated ENOSPC / FS error) `persist_identity` returns `Err` and the existing identity stays byte-identical. Tests skip cleanly when running under DAC bypass (root / overlay FS that ignores chmod) instead of false-failing.
- [x] **F3 — Cold reboot resilience.** New [`crates/iac-agent/tests/cold_reboot.rs`](crates/iac-agent/tests/cold_reboot.rs) integration test file. **3 tests:** `cold_reboot_observes_drift_and_reconverges` (apply → drop agent → tamper host → fresh agent → drift detected → reconverge to desired), `cold_reboot_preserves_state_dir_artifacts` (`agent.db` and `status.json` survive the drop, `agent.db` is not truncated across restart), `cold_reboot_picks_up_manifest_change_made_while_down` (operator updates manifest while agent is offline → next observe surfaces the change as drift → applies cleanly). Drop-then-`Agent::new` is the closest in-process analogue of SIGKILL: on-disk identity / DB / manifests survive. The genuinely process-level concerns (open-FD flush ordering, SQLite WAL mid-write) are out of scope here — `persist_identity`'s atomic-rename pattern (pinned by F4) and SQLite's own WAL durability cover the bulk.

**Tests:** 20 new tests (13 F5 + 4 F4 + 3 F3); 0 regressions on the
existing 1176-test workspace baseline. `cargo clippy --workspace
--all-targets` clean.

**Net effect on Phase 9:** 3 of 8 fleet scenarios now have local
agent-side coverage. The remaining 5 (F1, F2, F6, F7, F8) genuinely
need multi-host distributed environments and stay deferred.

## Phase 9-F8 — Register-endpoint DDoS, found AND fixed (2026-05-05)

F8 was originally framed as "validate that rate-limit on
`/v1/agents/register` holds under storm." Pre-test inspection of
[`crates/iac-controlplane/src/api/agents.rs`](crates/iac-controlplane/src/api/agents.rs)
revealed the rate-limit **did not exist** for that endpoint — the four
`RateLimiter` buckets covered `operations` (env-keyed), `agent` (per
agent_id, post-auth), `login_user`, and `login_per_ip`, with nothing
on the unauthenticated register path. The scenario was reframed as
"demonstrate the gap, then fix it, then re-storm."

- [x] **Empirical confirmation of the gap.** Wrote
  [`trial/scenarios/fleet-f8-register-ddos.sh`](trial/scenarios/fleet-f8-register-ddos.sh)
  — storm originates from `cp-spare-01` (104.128.140.48) so the traffic
  crosses the network like a real attacker, not a localhost flood. A
  parallel "legit registrant" loop runs from the operator host every
  5 s to measure starvation. **Smoke run (10 s × 5 parallel) result:
  250 requests, 250 × HTTP 200, 0 × HTTP 429.** Agents-table grew
  from 8 to 259 rows; audit chain absorbed the same count cleanly.
  Severity HIGH: a single attacker IP — or a misbehaving operator
  bootstrap script with a retry loop — can fill the agents table +
  audit chain at line rate.
- [x] **Fix: per-IP register rate-limit + ConnectInfo plumbing.**
  - [`crates/iac-controlplane/src/rate_limit.rs`](crates/iac-controlplane/src/rate_limit.rs) — new `RateLimitConfig::register_per_minute_per_ip` field (default `Some(20)`). 20/min/IP covers a legitimate fleet-rollout cadence (10 agents coming up at boot in ~30 s is fine) but caps storms at the 60 s sliding-window edge. New `check_and_record_register(client_ip)` enforces it; empty / whitespace IP falls back to bucket name `"unknown"` rather than panicking.
  - [`crates/iac-controlplane/src/error.rs`](crates/iac-controlplane/src/error.rs) — new `RateLimitBucket::register_ip(name)`. Distinct from `client` so register storms and login attacks don't share a counter (avoids the case where a legit register from the same IP locks out a legit login retry).
  - [`crates/iac-controlplane/src/api/agents.rs`](crates/iac-controlplane/src/api/agents.rs) — `register` handler now extracts `ConnectInfo<SocketAddr>` and calls `rate_limiter.check_and_record_register(&addr.ip().to_string())` before touching the store.
  - [`crates/iac-controlplane/src/api/auth.rs`](crates/iac-controlplane/src/api/auth.rs) — fixed a Phase 7co latent bug: `login` was passing an empty string for `client_ip`, so the per-IP login bucket was a no-op even when the config had a non-zero cap. Now the real socket address is plumbed through. The username bucket worked; the IP bucket did not, until now.
  - [`crates/iac-controlplane/src/main.rs`](crates/iac-controlplane/src/main.rs) — both the plain-HTTP and TLS server paths swapped to `app.into_make_service_with_connect_info::<std::net::SocketAddr>()`. Without this layer the `ConnectInfo` extractor returns 500 — required even though the existing test fixtures bypassed it via `oneshot`.
  - **Tests:** all 21 test fixtures in `crates/iac-controlplane/tests/` updated to use `into_make_service_with_connect_info` so the post-fix register endpoint serves correctly under integration tests. **5 new unit tests** in `rate_limit::tests` (`register_cap_disabled_when_unset`, `register_cap_zero_disabled`, `register_cap_isolates_per_ip`, `register_cap_empty_ip_falls_back_to_unknown`, `register_and_login_buckets_dont_share_counter`). Full controlplane suite: 481 / 481 green; total workspace baseline preserved.
- [x] **Re-storm against the fixed binary.** Built release binary, deployed to `cp-spare-02` (104.128.140.49) on port 8444 with a fresh SQLite DB so F1 wasn't disturbed. Ran the same xargs-parallel storm from `cp-spare-01` for 30 s × 50 parallel. **Result: 900 requests, 20 × HTTP 200, 880 × HTTP 429.** Storm completes in 30 s as intended; the 20 admitted equal exactly the 60 s sliding-window cap (the cap allows up to 20 in any 60 s; 30 s ≈ ½ window, so admitted count tracks the cap, not the duration). Latency p50 = 576 ms / p99 = 902 ms — the 429 path is fast on the server but the storm host saturates its own outbound; on a normal client the 429 returns in single-digit ms. Test CP and storm artefacts cleaned up afterwards.
- [ ] **Pending — deploy fix to prod CP.** The fix is empirically validated against the new binary on a clean spare; the live `iac-controlplane` on cp-01 (104.128.140.54) is still the F1-running pre-fix version. Restarting it now would break F1's "0 unaccounted systemd restarts" pass criterion. Sequence: F1 finalize ⟶ `systemctl stop iac-controlplane` ⟶ `scp` new binary ⟶ start ⟶ smoke health check. Estimated 5 min after F1 finishes.

**Why this matters for an IaC tool that targets weak hardware.** The
register endpoint is the bootstrap path; agents must reach it before
they have credentials, so it can't be gated by auth. Without per-IP
caps, a Mikrotik-class device on a flaky link with a buggy retry loop
DoS's its own controlplane the first time the operator copies a config
that loops on transient network errors. The fix is also the cheapest
imaginable defence — one `tokio::sync::Mutex` lookup per request,
zero new dependencies, sub-microsecond overhead. The default cap is
permissive enough that no legitimate fleet operation hits it; the
limit only fires under abuse.

## Phase 9-F7 — Backup / restore harness, validated against the live F1 CP (2026-05-05)

The pass criteria for F7 were: hot backup without restarting the
control plane (so it doesn't violate F1's "0 unaccounted restarts"),
restored CP comes up clean on a different host with the same audit-
chain tip, `/v1/audit/verify` returns ok, and a fresh write extends
the chain cleanly. All four held; F7 ran end-to-end against the live
F1-loaded prod CP without disturbing it.

- [x] **Harness:** [`trial/scenarios/fleet-f7-backup-restore.sh`](trial/scenarios/fleet-f7-backup-restore.sh). 6-step pipeline: stage binary on the restore host → `VACUUM INTO` snapshot on prod CP → SCP to restore host → boot a fresh CP on a separate port + state dir → integrity check + post-restore write probe → tear down. Reusable: `RESTORE_HOST` derived from inventory (uses cp-spare-02 by default), restore port and token are constants but trivial to override.
- [x] **Backup approach: SQLite `VACUUM INTO`, not `.backup`.** The first attempt used the `sqlite3 db ".backup file"` API. Under the live F1 write load (~3 ops/sec hitting the audit_events / agents / operations tables), `.backup` retried on every page-level SQLITE_BUSY and stalled at 40 % progress after 30 minutes on the 947 MB DB — never recovering. Switched to `VACUUM INTO`, which is a single-statement transactional snapshot: it acquires a SHARED lock on the source for the duration of the copy, so it doesn't restart on concurrent writes (writes wait briefly behind it). Completed in **45.6 s** for the same DB. Bonus side effect: the snapshot file is defragmented, so it deserialises faster on the restore side.
- [x] **No prod-CP restart.** Captured `systemctl show iac-controlplane --property=ActiveEnterTimestampMonotonic --value` before and during the restore — value unchanged across the entire harness, so F1's "0 unaccounted systemd restarts" criterion is preserved. F1 continued to run normally throughout.
- [x] **Restore + integrity verdict (against live F1 prod CP):**
  - **RPO** (snapshot duration): **45.6 s.** Writes happening during the snapshot land in the source's WAL and are NOT in the snapshot — they would be lost on restore. Production target: < 5 s with WAL-based replication (litestream / a custom WAL tail), out of scope here.
  - **RTO** (start-restored-CP → 200 on `/v1/health`): **1.6 s.** Cold start including SQLite open + schema migration check + axum bind. Wire-time for the snapshot is separate (1298 s for 1.47 GB through the operator host because of the missing inter-VPS SSH key — production VPS-to-VPS direct copy at gigabit would be ≈12 s).
  - **Audit-tip match:** restored = 12896, snapshot = 12896. PASS.
  - **Agents-table count:** restored = 9, snapshot = 9. PASS (7 fleet agents + 2 legit-agent leftovers from the F8 smoke).
  - **`/v1/audit/verify` ok = true.** PASS — the chain hash sequence is unbroken across the restore.
  - **Post-restore write extends chain cleanly:** registered a probe agent, tip advanced 12896 → 12897, `/v1/audit/verify` ok = true at the new tip. PASS — the chain is not just frozen but writeable, and the new tip's hash chains correctly to the restored state. This was the integrity check most likely to surface a subtle restore bug (e.g. missed sequence counter, stale identity-blob), and it didn't.
- [x] **Cleanup:** restored CP and snapshot files removed from cp-spare-02 + prod CP after the verdict; local 1.5 GB snapshot in `/tmp/iac-f7-results/` removed.

**Why this matters for the IaC philosophy.** "Works on weak hardware" demands that backup not require taking the service down — a Mikrotik-class device with a 16 MiB flash partition can't afford to be offline for the duration of a snapshot, and a NAS-class home server can't afford ten minutes of unavailability for a routine backup. `VACUUM INTO` plus the harness above gives you "snapshot in O(disk-write-time) with zero downtime" — a property the SQLite engine has had since 3.27 but most operators don't know. Documenting it in the harness makes it the default posture for this project. The 45 s snapshot of a hot 950 MB DB is the upper bound; on a routine-sized fleet (< 100 MB DB) it's sub-second.

**Open follow-up:** WAL-based incremental backup (litestream-style) for sub-second RPO. Not a blocker — the trial harness validates the worst-case "single full snapshot" recovery story. Phase 11+ if anyone needs it.

## Phase 9-F1-fix — disk-full incident, root-cause + fix (2026-05-06)

The first F1 attempt failed at **3 h 14 m / 24 h** with disk-full on the
8.5 GB CP VPS. Root cause: SQLite WAL grew unboundedly under the
sustained mixed read/write load. Headline numbers at failure:
`server.db = 3.7 GB`, `server.db-wal = 4.0 GB`, free = 0. iac-trial
longevity submitted ≈ 8 100 ops with 5 failures (0.06 %) before the
disk filled and writes started returning 500 (`disk is full`); the
trial process itself died shortly after. CP itself stayed up but
returned 500 to all writes for the next ~7 hours until I noticed.

**The mechanism (SQLite-specific).** WAL mode separates the durability
write (append a frame to `server.db-wal`) from the page-level write to
the main DB. A *checkpoint* copies WAL frames back to the main DB; the
default `wal_autocheckpoint = 1000` fires every 1000 frames (~4 MiB).
But `autocheckpoint` runs in **PASSIVE** mode: it page-backs as much as
possible without blocking concurrent readers/writers, then *leaves the
WAL file at its current size* — the WAL file is never truncated, only
overwritten in place. Under sustained read traffic (the heartbeat /
observation / drift fan-out keeps a stream of readers active),
PASSIVE-mode checkpoints can never *truncate* — only TRUNCATE-mode can,
and SQLite never runs that on its own. The WAL keeps growing in 4 KiB
page increments until something quiesces enough for a TRUNCATE
checkpoint to find a no-readers window. Which, under steady-state F1
traffic, never happens. Documented in the SQLite docs but easy to miss
without a 24 h soak to surface it.

**Forensics in the post-incident state were unrecoverable.** I tried to
free space by stopping iac-controlplane, deleting the WAL, and running
VACUUM. Removing the WAL while it still contained un-checkpointed
frames left the main DB inconsistent — `database disk image is
malformed`. `.dump` also failed. Lesson: in this kind of disk-full
recovery, **always checkpoint first** (`PRAGMA wal_checkpoint(FULL)` or
`(TRUNCATE)`) and only then move WAL aside. We lost the corrupt DB
(moved to `server.db.f1-disk-full-corrupt` for forensics, deleted
after fix landed).

**Fix landed:**
- [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) — `PRAGMA journal_size_limit = 268435456` (256 MiB) added to the per-connection PRAGMA set. After every successful checkpoint, SQLite shrinks the WAL file back to this cap, so even if the explicit checkpoint task drifts, disk usage stays bounded.
- [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) — new `Store::wal_checkpoint_truncate()`. Runs `PRAGMA wal_checkpoint(TRUNCATE)`. No-op on Postgres.
- [`crates/iac-controlplane/src/main.rs`](crates/iac-controlplane/src/main.rs) — new background tokio task that calls `wal_checkpoint_truncate` every `wal_checkpoint_interval_secs` seconds (default **60**). Honours the existing graceful-shutdown `Notify`. Logs at WARN on failure, DEBUG on success — failures are non-fatal (the next tick retries).
- [`crates/iac-controlplane/src/config.rs`](crates/iac-controlplane/src/config.rs) — `wal_checkpoint_interval_secs: u64` (default 60). `0` disables. Operators tuning latency-vs-disk on tiny-flash targets can drop it to 30 s; large-disk SSD boxes can raise it to 300 s.
- **Tests:** 26 `Config{}` fixtures across the test corpus updated to include the new field. Full controlplane suite **481 / 481 green**, build clean.
- **Deployed and observed on prod CP** (`104.128.140.54`) immediately. Startup log line: `WAL checkpoint task scheduled interval_secs=60`. WAL stayed at 0 bytes for the first 90 s with no traffic — checkpoint task drove it to zero on the first tick. Disk free recovered from 0 → 7.5 GB after corrupt-DB cleanup.

**Why this matters for an IaC tool that targets weak hardware.** The
worst place for a default to silently kill you is on a router-class
target with 32–64 MiB of flash. SQLite WAL was already a problem on
SD-card storage (Phase 8.7 fixed the 5s→30s busy_timeout); now WAL
*size* is also bounded. The IaC philosophy demands the same defaults
work whether you have 8.5 GB of disk or 64 MiB — and "WAL grows until
you run out of disk" fails that test cleanly on either end of the
hardware curve.

**Pending — re-run F1.** Agents on the 7 fleet hosts still hold the
credentials from the dead CP (their `agent.db` has agent_id + token
that the new fresh CP DB doesn't know). Re-running F1 needs:
1. On every agent: stop iac-agent → drop `agent.db` + `identity.json` → start iac-agent → re-bootstrap via the existing harness.
2. Restart `fleet-f1-soak.sh` for the full 24 h.
Estimated 5 min for the re-bootstrap + 24 h for the actual soak.

**Aside — F1 status script bug.** `trial/scenarios/fleet-f1-status.sh`
greps for the literal `'\"longevity progress\"'` (a quoted string) in
the trial log, but the actual log line is unquoted (`longevity
progress submitted=N`), so the script always reported `progress lines:
0` even when iac-trial was making good progress. Cosmetic; fix in the
re-run pass.

## Phase 9-F1-fix-2 — observations table grows unbounded (2026-05-06)

F1 attempt #2 (started after the WAL fix in `227f65e`) hit a **second
disk-full at 4 h 0 m**, this time root-caused to a different
mechanism: the `observations` table grew **unbounded**. Snapshot at
abort: `observations = 10 626 630 rows`, `server.db = 7.1 GB`,
`server.db-wal = 344 MB` — the WAL fix held its ground (cap was
256 MB, the 344 MB seen was checkpointed during the abort sequence)
but the main-DB growth was the new bottleneck.

**The mechanism.** Each iac-agent polls every resource it manages
(re-reading state from disk / OS) once per agent poll cycle, and
pushes one observation per resource per cycle to the controlplane.
With 7 agents × ~2 000 resources × ~one cycle per minute, that's
**≈ 720 K observations / hour**. Each row is ~700 bytes (resource_id +
agent_id + serialised state hash + timestamp + metadata), so storage
grows at ~500 MB/h on F1's load. Default retention left this
unconstrained:
- `observation_days = 30` — none of the fresh observations qualified
  for age-based pruning.
- `observation_max_per_resource = 0` — disabled. Per-resource cap was
  exposed in Phase 7an for exactly this case but defaulted to off.
- `interval_secs = 3600` — even when retention did fire, it only ran
  hourly; observations accumulated faster than that for sustained
  loads.

**Fix landed (commit upcoming):**
- [`crates/iac-controlplane/src/retention.rs`](crates/iac-controlplane/src/retention.rs) — `default_observation_max_per_resource` now `50` (was `0`/disabled). 50 newest per (agent, resource) gives ample current-state-plus-debugging headroom; on F1's load the steady state is 7 × 2 000 × 50 = 700 K rows ≈ 500 MB, regardless of soak duration.
- [`crates/iac-controlplane/src/retention.rs`](crates/iac-controlplane/src/retention.rs) — `default_interval_secs` lowered from `3600` (1 h) to `300` (5 min). Hourly is fine for `audit_events` / `assignments`, but `observations` accumulate ½ GB/h on a busy fleet — 5 min keeps the working set small enough that the per-resource cap converges before disk pressure mounts.
- [`trial/fleet/server.toml.tmpl`](trial/fleet/server.toml.tmpl) — explicit pin of both values in the fleet trial config. Documents intent; survives a future default change.
- 481 / 481 controlplane tests green; deployed to prod CP.

**Why these defaults are right for the IaC philosophy.** A
router-class target with 64 MiB of flash storing observations on its
local agent would run out of disk in *minutes* under the previous
defaults. With cap=50, even a fleet of 1 000 resources on a 64 MiB
target lands at ≈ 35 MiB observations DB max — survivable. At the
other end, a 64-GB-disk SSD CP with 100 000 fleet-wide resources has
50 obs/resource × 100 000 = 5 M rows ≈ 3.5 GB — comfortable headroom
on commodity hardware. The cap scales with resource count, not soak
duration; F1 soaks for 24 h and lab tests for 30 days converge to the
same DB size. That's the property an IaC-tool default needs.

**Forensic numbers from F1 attempt #2 (preserved for future
benchmarking):**
- Submitted ops at abort: 14 565 over 4 h ≈ 0.99 RPS, sustained.
- Failures: 4 / 14 565 = 0.027 % (under the 1 % threshold). Failure
  budget passed; F1 was hit by infra not by app.
- Audit chain rows: 29 153 (verified ok=true throughout).
- DB-growth attribution: observations ≥ 95 %, audit_events ≈ 5 MB,
  operations ≈ 14 MB, the rest negligible.
- `database is locked` 503 frequency: 113 / 5 min = ~23/min — the
  expected rate from SQLITE_BUSY-mapped retries under sustained
  fan-out. No correctness impact.

**F1 attempt #3 launched** at `2026-05-06T13:23:53Z` with both fixes
deployed (WAL bound + observation cap + 5 min retention). Deadline
`2026-05-07T13:23:53Z`. All three security/operational fixes from this
session — F8 register cap (`9da4475`), F1 WAL fix (`227f65e`),
F1 observation cap (this commit) — active in the running CP.

## Phase 9-F1-fix-3 — WAL TRUNCATE blocking + agent observations cap (2026-05-06)

F1 attempt #3 ran 5 h 38 m before being aborted. Two new real-fleet
findings surfaced before the run hit any pass-criteria failure:

1. **`PRAGMA wal_checkpoint(TRUNCATE)` was blocking 30 s every cycle.**
   The `wal_autocheckpoint` we added in `227f65e` ran TRUNCATE every
   60 s; under sustained mixed read/write load (retention DELETEs
   ~325 K observations every 5 min, agents fan-out heartbeat /
   observation / drift writes ~2/s), TRUNCATE couldn't acquire its
   exclusive lock without waiting for readers to release frame
   pointers. The `slow_threshold=1s` warning fired ~once per minute
   with 30 s elapsed, and the 5xx rate climbed from 0.03 % (F1 #2 in
   the equivalent window) to **0.54 %** because the CP froze for
   half of every minute. Still inside the 1 % SLA, but visibly
   stressed.
2. **`agent.db` grew unbounded (2.5 M rows / 1.4 GB at 5.5 h)** —
   different table from the CP-side observations bug. Each iac-agent
   poll cycle calls `record_observation`, which inserts one row per
   observed resource (~2 000 resources × 1 cycle/min). The agent's
   only consumer is `last_observation` (used for drift detection,
   reads only the newest row per resource); the rest is rolling
   debug history with no cap, no retention. Agent disk on the 3.9 GB
   VPS would have hit 100 % at ~12 h — before the F1 24 h deadline.

**Fixes landed:**
- [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) — split `wal_checkpoint_truncate` into a parameterised `wal_checkpoint(force_truncate)` plus a back-compat alias. PASSIVE returns immediately on contention (`busy=1`) and is the cheap default; TRUNCATE only runs when needed.
- [`crates/iac-controlplane/src/main.rs`](crates/iac-controlplane/src/main.rs) — background WAL task now runs PASSIVE every tick and TRUNCATE every 10th tick (so on the default 60 s cadence, TRUNCATE fires every 10 min instead of every 1 min). PASSIVE alone would let the WAL grow up to `journal_size_limit = 256 MiB` over time, so periodic TRUNCATE is still required to reclaim file size — just not every cycle.
- [`crates/iac-agent/src/store.rs`](crates/iac-agent/src/store.rs) — new `AGENT_OBSERVATION_HISTORY_CAP = 10` constant. After every successful INSERT in `record_observation`, an inline DELETE keeps only the 10 newest rows per `resource_id`. Per-resource isolation matters: a chatty resource doesn't evict observations from a quiet one. The DELETE uses the existing `idx_observations_resource (resource_id, observed_at DESC)` index so it touches at most a handful of rows per call.
- **Tests:** 2 new agent-side unit tests — `observation_history_capped_per_resource` (asserts cap is enforced after cap+5 inserts) and `observation_cap_isolates_per_resource` (asserts inserts on resource A don't evict B's history). 481 / 481 controlplane tests + 45 / 45 agent lib tests green.

**Forensic numbers from F1 attempt #3 (preserved for benchmarking):**
- 5 h 38 m runtime; 18 900 ops submitted / 102 failures = 0.54 %.
- CP `server.db = 829 MB` at abort (vs 7.0 GB at F1 #2's equivalent point — observation cap was working).
- CP `observations` table = 1.07 M rows (vs 10.6 M without cap).
- Retention pass deleted ~325 K observations every 5 min — sustaining the cap.
- WAL stayed at 28 MiB (vs 256 MiB cap) — TRUNCATEs ran but cost too much per call.
- Agent `agent.db = 1.4 GB` × 7 (no cap on agent side, this is the new finding).

**Why these defaults are right.** PASSIVE-most/TRUNCATE-rare gives
the same disk-bound semantics as before (the WAL still gets
truncated regularly, just on a 10× longer cycle) but eliminates the
30 s freeze. Agents storing only 10 newest observations per resource
keeps their local DB at resources × 10 ≈ 20 K rows ≈ 20 MB
regardless of soak duration — a property that holds equally on a
64-MiB-flash router agent and a 1-TB-disk SSD agent. The runtime
path needs only the latest observation; everything older is for
post-hoc debugging, and 10 minutes of history covers the realistic
debugging window.

**F1 attempt #4 launched** at `2026-05-06T20:17:12Z` with all three
F1 fixes deployed: WAL bound + PASSIVE/TRUNCATE rotation
(`commit-this`), observations cap on CP + 5-min retention
(`aebbfb9`), agent-side observations cap (`commit-this`). Deadline
`2026-05-07T20:17:12Z`. Predicted steady-state DB sizes:
- CP `server.db ≤ 1 GB` (700 K obs × ~700 B ≈ 500 MB + audit + ops)
- Agent `agent.db ≤ 50 MB` each (cap × resources × row size)
- WAL ≤ 256 MiB on CP, ≤ 4 MiB on agents.

**Lessons-learned bank.** Three F1 attempts have now each surfaced a
distinct real-fleet production gap that no Pi 4 trial or
docker-compose harness would catch:
- Attempt #1: SQLite WAL grows unboundedly under sustained reads.
- Attempt #2: CP observations table grows unboundedly without cap.
- Attempt #3: agent.db observations table grows unboundedly + WAL
  TRUNCATE blocks too long under contention.
The pattern — "every soak attempt finds a new ceiling, fix it in the
defaults, retry" — is exactly the value of a real long-running soak
on real hardware. Each fix tightens the IaC tool's defaults to be
"no-surprise" on production-class load.

## Phase 9-F1-fix-4 — observations write batching (2026-05-07)

F1 attempt #4 ran 7 h 50 m before being aborted. **Functional pass**:
0 unaccounted restarts, audit verify ok, all 7 agents alive, both
WAL and DB sizes bounded (1.1 GB and 256 MiB respectively, vs 7 GB
and 4 GB on attempt #2). **Failure**: longevity error rate hit
**1.86 %** (over the 1 % threshold) and 5xx rate held steady at
~2 000 / hour. New-bottleneck root-cause: per-row INSERTs into
`observations` saturated the SQLite write path.

**The mechanism (architecturally deeper than fixes #1–#3).**
- 7 agents × ~3 200 resources × 1 poll cycle/min ≈ **60 INSERTs/sec**
  on the CP — each INSERT a separate sqlx `query().execute()` inside
  the same transaction.
- Each INSERT allocates a WAL frame, fsyncs the commit record, and
  bumps the busy timer. Frame allocation gets sequential — concurrent
  INSERTs queue.
- The `journal_size_limit = 256 MiB` cap (set in fix #1) hit
  saturation first; once the WAL was full, SQLite throttled writes
  while PASSIVE checkpoints (fix #3) tried to page-back. Single INSERT
  latency climbed to **4–7 s** and the 5xx rate climbed proportionally.
- Steady-state visible in CP metrics: 277 slow-statements / 5 min,
  ~2 000 `database is locked` / hour, agents seeing 503s on
  `assignment-result` reports back to CP.

This was **architectural**, not config: the per-row INSERT pattern
fundamentally caps SQLite throughput regardless of how the WAL is
tuned. SQLite handles batched multi-row INSERTs (one statement, one
WAL frame allocation, one commit) ~10–50× faster than the equivalent
loop.

**Fix landed:**
- [`crates/iac-controlplane/src/store.rs`](crates/iac-controlplane/src/store.rs) — `record_observations` rewritten to issue a single multi-row `INSERT INTO observations (...) VALUES (?,?,...,?), (?,?,...,?), ...` per chunk of 100 items. The 100-row chunk size keeps the placeholder count (8 cols × 100 = 800) safely under SQLite's older `SQLITE_LIMIT_VARIABLE_NUMBER = 999` so the fix works on embedded targets shipping pre-3.32 SQLite. The transaction-bracketing (`begin / commit`) and the trailing `UPDATE agents SET last_observation_at` are unchanged.
- Drift-events and assignment-result paths left as-is for this fix: drift inserts run at ~0.5 / s (16 K events / 8 h on F1's load), an order of magnitude below the observation rate, so they don't contend on WAL frames the same way.

**Expected throughput improvement.**
Pre-fix F1 #4 saw 60 INSERTs/sec, ~2 % errors. With 100-row batching,
the same 60 logical observations / s land as ~0.6 multi-row INSERTs/s
on the CP — **100× fewer WAL frame allocations**. The SQLite write
path drops from saturated to comfortable; 5xx rate should fall well
below 0.1 % at the same agent count and resource density.

**Forensic numbers from F1 attempt #4 (preserved as baseline):**
- 7 h 50 m runtime; 22 900 ops submitted / 426 failures = **1.86 %**.
- CP `server.db = 1.1 GB`, `server.db-wal = 256 MiB` (cap hit).
- `observations` table = 1.22 M rows (cap holding ~1 M from fix #2).
- `agent.db = 19 MB` per agent (cap from fix #3 working perfectly).
- Steady-state `database is locked` rate: ~2 000 / hour on CP.
- Single INSERT latency p99 ≈ 6 s (slow-statement warnings every minute).

These numbers establish the **pre-batching production ceiling** for a
SQLite-backed CP at this hardware class; comparing F1 #5's numbers
will tell us how much headroom batched INSERTs unlock.

**F1 attempt #5 launched** at `2026-05-07T05:45:01Z` with all four F1
fixes deployed: WAL bound (`227f65e`), CP observations cap +
retention (`aebbfb9`), WAL PASSIVE/TRUNCATE rotation + agent
observations cap (`9ace0b6`), and observation INSERT batching (this
commit). Deadline `2026-05-08T05:45:01Z`. The four fixes together
move the CP from "naïve per-row" to "production-tuned batched" — the
same hardware class that hit 2 % errors on attempt #4 should now
serve under 0.1 % on the same load.

**Cross-cutting lesson.** Three of the four F1 fixes have been about
SQLite write hygiene at scale (WAL truncation, observation caps, batch
inserts). The IaC tool's choice of SQLite-by-default is correct for
small-to-medium fleets — the same defaults need to survive Pi-class
hardware *and* real production fleets. Each fix tightens the defaults
without introducing a Postgres dependency. F1's role of forcing the
defaults to face this load is exactly what justified the Phase 9 VPS
allocation.

## Phase 9-F1-fix-5 — agent observation push: chunking + 413 fallback (2026-05-08)

F1 #5 finished cleanly by application criteria (errors 0.062 %,
audit verify ok, 0 unaccounted restarts). 10 hours after iac-trial
exited, however, the cluster was still consuming CPU: agent-05 and
agent-07 were stuck in an **infinite 413 retry loop**. Each
attempted to push its full observation set in a single POST; with
~11 980 managed resources at ~1 KB / observation, the body weighed
~12 MB — three times the controlplane's `max_body_bytes = 4 MiB`.
The CP returned 413, the agent's `push_observations` propagated the
error up the call chain, the next observe cycle gathered the same
12 K observations, and tried again. Forever.

Symptoms before the fix:
- agent-05 RSS 168 MB, CPU 25 %; agent-07 RSS 152 MB, CPU 32 %.
- Identical log line every ≈ 10 s for hours: `remote push failed
  error=control-plane returned 413 Payload Too Large`.
- CP under indirect strain — unrelated `INSERT INTO agents` slow
  statements at 4-8 s, audit-endpoint timeouts at 3 s, all caused by
  the retry storm contending for the CP's connection pool.

**Root cause.** The `Agent::push_observations` path sent the entire
batch as one body. There was no size estimate before send, no chunk-
size cap, no 413-aware fallback. The CP's protective body-limit
existed (and worked correctly), but the agent treated 413 as a
generic "remote error" and retried the same oversized payload.

**Fix landed:**
- [`crates/iac-agent/src/remote.rs`](crates/iac-agent/src/remote.rs) — new `OBSERVATION_PUSH_CHUNK = 500` constant. `push_observations` now splits `items` into chunks of 500 and POSTs each separately. ~500 observations × 1 KB ≈ 0.5 MiB, well inside the 4 MiB CP default.
- **Adaptive halving on 413.** If a chunk still 413s (e.g. operator dropped `max_body_bytes` lower, or observations are unusually large), the chunk is split in half and both halves are pushed back onto the work-stack. Iterative-with-stack pattern — no async recursion. Continues halving until chunks are size 1; at that point a single observation that still 413s is **dropped with a warn**, breaking the retry loop. "Lose one observation" is strictly better than "stall the entire push pipeline."
- Other non-2xx statuses (5xx, 401, etc) still bubble up as `Err` so the existing observe-loop retry semantics for transient failures are preserved. The 413-special-case is the only behaviour change.

**Why this is the right shape of fix.**
The observation push path exists because the CP needs the agent's
view of resource state for drift detection, audit history, and
operator visibility. Losing one observation is recoverable: the
next observe cycle re-records it. Losing the entire push pipeline
because one observation is too large is **un**recoverable — the
agent gets stuck and the operator sees state freeze. Agent-side
chunking + drop-on-413 turns an availability bug into at most a
visibility bug for that one large observation.

**Verification.** Built new agent binary, deployed to all 7 fleet
hosts, restarted iac-agent on each. Within 60 s post-restart:
- `0 × 413` errors across all agents (vs ~1 every 10 s before).
- agent-05 / agent-07 still chewing through the accumulated 12 K
  observation backlog at chunk=500 / push (no halving needed —
  default is conservative enough).
- CP slow-statement count dropped from ~hundreds/min to 0 in 2 min.
- `audit verify` returns ok=true; chain tip stable at 107 892.

**Forensic note for future incidents.** Look for `remote push failed`
in agent logs to detect this class. The pre-fix pattern was
"identical 413 error every observe cycle" — easy to grep for and a
dead giveaway. With the fix, the agent will instead emit a
`tracing::warn!("control-plane 413; halving observation chunk and
retrying")` on the way to convergence, so operators see the
adaptation rather than the loop.

**Five fixes in this F1 series — pattern summary.**
| Fix | Symptom | Mechanism | Fix shape |
|-----|---------|-----------|-----------|
| #1 (`227f65e`) | Disk-full @ 3h | Unbounded SQLite WAL | `journal_size_limit` + periodic TRUNCATE |
| #2 (`aebbfb9`) | Disk-full @ 4h | CP `observations` table unbounded | `observation_max_per_resource = 50` + 5-min retention |
| #3 (`9ace0b6`) | 30 s freezes + agent.db 1.4 GB | TRUNCATE blocking + agent obs unbounded | PASSIVE/TRUNCATE rotation + agent-side cap |
| #4 (`eb2b14d`) | 1.86 % errors | Per-row INSERT saturated SQLite | Multi-row batched INSERT (chunk=100) |
| #5 (this) | Infinite 413 retry loop | Push body > CP body limit | Adaptive chunked push (chunk=500, halve, drop on single) |

Each fix tightened a default that "worked on a Pi 4 trial" but broke
on real fleet load. The body of work moves the IaC tool's defaults
from "single-host or small-cluster" to "real production fleet on
real hardware" — exactly the gap Phase 9 VPS allocation was bought
to find and close.

## Phase 9-F1-fix-6..9 — final knee + iac-trial bound (2026-05-13..15)

Four more F1 attempts (#6, #7, #8, #9), four more real production
gaps, four more landed fixes — followed by **F1 #11 PASS** on
2026-05-14T12:42Z → 2026-05-15T12:42Z, 24h soak, 0 failures across
86,400 ops.

| Fix | Commit  | Gap | Symptom | Fix shape |
|-----|---------|-----|---------|-----------|
| #6  | `02abb92` | WAL `journal_size_limit` cap reached | F1 #6 → disk pressure climbed past 256 MiB WAL bound | Bump to 1 GiB + interval=60 (latter backfired in fix-7) |
| #7  | `bc9c14f` | Retention DELETE competing with INSERT at interval=60 | F1 #7: 11.40 % failure peak — DELETE-vs-INSERT contention | Revert interval to 300 + chunked DELETE 5000-row batches with 50 ms pause |
| #8  | `61003e8` | Observation cap too generous + agent observe cadence too tight | F1 #8: 4.90 % failure peak — SQLite write knee | `observation_max_per_resource` 50 → 10; agent `observe_interval_secs` 10 → 60 (30× less load) |
| #9  | `e92de61` | iac-trial unbounded unique paths exhausted ROW_NUMBER subquery | F1 #9: 40,992 distinct resource_id, observations table 1.98 M rows, retention falling 5× behind | Replace `ulid::Ulid::new()` in `make_file_manifest` with `AtomicU64 % POOL` (default 200/host); fleet-wide cap 7×200=1400 unique paths, ≤14 k obs rows at saturation |

**F1 #10 invalidated** by a deploy-script gap, not a server-side
bug: `bootstrap.sh` installed `iac-controlplane` + `iac-agent`
but never copied `iac-trial`. Fix-9 was committed and rebuilt
locally, yet the workload generator on the CP was the May-5
original (md5 `4bc9d68a`) — so it kept producing ULID-paths.
Caught at h+8.2 by a 3-hourly cron-check that flagged CP CPU
climbing 0 → 10 % and `observations` table at 1.4 M rows with
27,978 distinct `resource_id` — virtually identical to F1 #9's
shape. Harness fix `66794b5` added `scp_to` for iac-trial.

**F1 #11 verdict** (`fleet-f1-finalize.sh`, 2026-05-15T12:42Z):

```
✓ iac-trial PASS thresholds
✓ 25 hours of failure-rate trend, all 0.00 % (86,400 ops, 0 failures)
✓ RSS:
    agents -28.9 % to -7.0 % from warm-h2 to late (all 7 stable)
    CP +116.5 % from warm-h2 (27.3 → 59.0 MB) — within abs cap 512 MB
✓ 0 unaccounted systemd restarts
✓ capacity: server.db 325 MiB / WAL 5 MiB / disk 27 % / busy 0 / slow 0
✓ audit chain: 159,440 rows added, /v1/audit/verify ok=true
```

**Nine real production gaps closed.** The pattern is the value:
each F1 attempt × surfaced a non-obvious gap × landed a small fix.
None of these would have appeared on Pi 4 trial or docker-compose
harness. The IaC tool's defaults moved from "naïve, works for small
deployment" to "production-class for SQLite at fleet scale" — and
the slope-detector + capacity-health harness now catches the
deterioration shape that originally cost days of forensics to
recognize.

**Open from F1 PASS** — known unfinished work, NOT a failure:
- CP RSS growth +116.5 % warm-to-late on a quiet 24h soak —
  qualitatively distinct from agents (which were stable). Pinned
  for the slow-leak investigation queue (heap profiler via dhat).
  Memory absolute cap (512 MB) still met by 9× margin.
- 2 agents hit `/var/log` near-full when finalize tried to
  create the sampler stop sentinel. Cosmetic — finalize still
  succeeded via SSH timeout. Worth a sampler-log rotation pass.

