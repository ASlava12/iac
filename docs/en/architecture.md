# Architecture

How `iac` is built. Read this if you want to contribute, debug
weird behaviour, or evaluate the tool against your design needs.

## One-paragraph overview

`iac` is a single-binary, agent-based IaC tool written in Rust.
Operators describe desired state in YAML manifests; per-host agents
(or SSH-pushed remote applier) reconcile the host to that state.
A central control plane keeps audit trails, gates risky operations
through approval + canary, and dispatches work to agents. Three
deployment modes coexist: pull-mode agent (Puppet-like), SSH push
from control plane (Ansible-like), and direct CLI SSH (single-command
ad-hoc). The wire format is identical across all three.

## Crate layout

The repo is a Cargo workspace. Each crate has a focused responsibility
and a stable internal API.

```
crates/
├── iac-core         # primitives: Resource, Diff, Executor, wire protocol
├── iac-providers    # per-kind lifecycle (file, systemd, docker, ...)
├── iac-agent        # long-running daemon: poll, observe, apply, drift
├── iac-controlplane # central server: REST API, store, dispatcher
├── iac-cli          # operator-facing `iac` binary
```

Why this split:
* **iac-core** is the protocol surface. Wire types live here so the
  agent and the control plane can never disagree about the shape of
  an `AssignmentEnvelope` or `OperationView`.
* **iac-providers** is the heaviest crate (~430 unit tests). Each
  provider (`file`, `docker.container`, etc.) follows the same
  lifecycle: `observe → diff → apply → rollback`. Adding a new
  provider doesn't touch core or controlplane code. Phase 7di.1
  unified the three JSON-envelope-based dynamic runtimes (shellout,
  external-process, wasm-core) onto a single `PluginProvider<R:
  PluginRuntime>` impl in `iac-providers/src/plugin/`; the typed
  WIT-based wasm-component runtime keeps its own Provider impl by
  design.
* **iac-agent** and **iac-controlplane** depend on core + providers
  but never on each other directly — they meet on the wire.
* **iac-cli** is the operator UX. CLI parsing (clap), output rendering,
  credential management. No business logic — it calls into core /
  providers / makes HTTP calls.

## The three-state model

Everything in `iac` is built around three states per resource:

| State | Where it lives | Who writes it |
|---|---|---|
| **Desired** | Operator's YAML manifest | Operator |
| **Observed** | What `observe()` reads from the host (running container, file contents, sysctl value, ...) | Provider's `observe()` |
| **Applied** | The state we last wrote (checkpoint for rollback) | Provider's `apply()` saves a checkpoint |

`diff(desired, observed)` produces a list of `Change`s. `apply()` takes
those changes and converges. `rollback()` reverses what's in the
checkpoint chain.

Every provider implements this same lifecycle. See `iac-providers/src/file/ops.rs`
for the canonical example.

## The dispatch model

When an operator submits a manifest:

```
┌────────────┐  POST /v1/operations           ┌──────────────────┐
│  iac CLI   │──────────────────────────────▶│  controlplane    │
└────────────┘  AssignmentEnvelope          ┌─└──────────────────┘
                                            │  ┌──────────────────┐
                                            │  │  store: SQLite/  │
                                            │  │  Postgres        │
                                            │  └──────────────────┘
                                            ▼
                            ┌─────────────────┴──────────────────┐
                            ▼                                    ▼
                    ┌───────────────┐                  ┌──────────────┐
                    │  agent (pull) │                  │  ssh push    │
                    │  poll-based   │                  │  worker      │
                    └───────┬───────┘                  └──────┬───────┘
                            │                                 │
                            ▼                                 ▼
                    ┌───────────────┐                  ┌──────────────┐
                    │   target      │                  │   target     │
                    │   host        │                  │   host       │
                    └───────────────┘                  └──────────────┘
```

The control plane:
1. Validates the operation (RBAC, policies, manifest schema).
2. Routes resources to agents via `metadata.spec.hostSelector.name`.
3. Computes layers from `dependsOn` (Phase 7by phased apply).
4. If canary specified, splits each layer into batch 0 (canary) and
   batch 1 (baseline).
5. Persists assignment rows in the store, sorted by layer + batch.

Pull-mode agents poll `GET /v1/agents/{id}/assignments` periodically.
SSH push targets are dispatched proactively by per-target Tokio worker
tasks. Both call `complete_assignment` when done; the outcome rolls up
into the operation status.

## Layered apply with canary

Two orthogonal axes gate dispatch:

* **Layers** (Phase 7by) come from `metadata.dependsOn`. Layer-N+1
  cannot start until every layer-N assignment has reached terminal
  state (succeeded). A failure in any layer cancels every later layer.
* **Canary batches** (Phase 7cg) within a layer split agents into
  `batch=0` (dispatched first, the canary) and `batch=1` (waits in
  `pending_canary`). Failure in canary cancels the rest of the rollout.

Composition: layer-N canary runs first, then layer-N baseline, then
layer-N+1 canary, etc.

The state machine lives in `iac-controlplane/src/store.rs::advance_phased_apply`
and `advance_canary`.

## Signing + verification

Every assignment dispatched to an agent is signed Ed25519 by the
control plane. Agents verify before applying. Phase 7ce introduced
multi-key rotation: the server keeps an active key + recently-rotated
keys in the verification set; agents pull the bundle from
`GET /v1/signing-keys` and accept signatures from any pinned key.

The signing module is `iac-controlplane/src/signing.rs`; agent
verification is in `iac-agent/src/remote.rs::verify_envelope`.

## Authentication & RBAC

Three identity classes share one bearer-token surface:

| Class | Source | Phase |
|---|---|---|
| `LegacyAdmin` | Static `admin_token` in server.toml | bootstrap |
| `User` | `iac users create`, Argon2id hash in DB | 6e |
| `Agent` | `POST /v1/agents/register`, sha256-hashed token | 2a |

Roles form an inclusion lattice: `Viewer < Operator < Approver < Admin`.
RBAC checks live in `iac-controlplane/src/identity.rs::require_role`.

Token TTL + rotation (Phase 7cc-7cd) is opt-in via
`agent_token_ttl_secs` in server.toml.

## Audit log

Every state-changing call appends a row to `audit_events`. The schema
lives in migration `20260429000004_audit.sql`. Events:
`operation.{submitted,approved,rejected,failed,succeeded}`,
`agent.{registered,token_rotated,heartbeat_lost}`,
`drift.{detected,accepted,reverted}`,
`signing.key_{rotated,retired}`,
`ssh.push_{succeeded,partial,failed}`,
`maintenance.window_{entered,exited}`.

Operators query via `iac audit --server <url> --kind ... --limit ...`
(filters are exact-match per field — no server-side `since`-style time
window; narrow client-side with `jq` if needed).

## Storage

Two backends, identical wire format:
* **SQLite** — single binary, single file. Trialled on a Raspberry
  Pi 4 (Phase 8.7) at 10 agents × 1000 ops × 50 RPS with 0 errors.
  WAL mode + 30s `busy_timeout` (Phase 8.7 bumped from 5s after
  bare-metal flash storage exposed contention). Default for homelab
  deployments. SQLITE_BUSY surfaces as HTTP 503 with
  `Retry-After: 1`, not 500, so well-behaved clients back off.
* **Postgres** — production scale-out. Wire identical, just change
  `database_url`. Migrations live in `migrations-postgres/` mirroring
  `migrations/` — kept in sync manually so we never depend on
  `sqlx::migrate!` macros (avoids sqlx-cli + SQLite/PG-specific syntax
  divergence).

## SIGHUP hot reload

A subset of config (policies, modules, retention, maintenance windows)
reloads without a restart on `SIGHUP`. Implemented via `arc_swap::ArcSwap`
holding a `ReloadableState`. Hard fields (bind, db_url, tls, webhooks,
rate_limit) own long-lived runtime state and need a restart by design.

## Code conventions

* `forbid(unsafe_code)` workspace-wide.
* `edition = "2024"`, `rust-version = "1.95"`, `resolver = "3"`.
* sqlx 0.8 with `Any` driver — `?` placeholders runtime-translated
  for Postgres.
* No-comment-by-default policy: comments explain *why*, not *what*.
  Provider lifecycle docs live in module-level `//!` rustdoc.
* Tests are the canonical examples. Reading
  `crates/iac-controlplane/tests/e2e_*.rs` is the fastest path to
  understanding any feature.

## Phase log

Development history is recorded in [`TASKS.md`](../../TASKS.md) (current
roadmap + most recent shipped phase) and [`TASKS_ARCHIVE.md`](../../TASKS_ARCHIVE.md)
(closed phases). Phase numbers (`7ck`, `7cj`, etc.) are stable —
they're referenced from code comments to anchor "why does this look
like this?" answers.

## Where to look in the code for X

| If you want to understand... | Read |
|---|---|
| The wire format | `crates/iac-core/src/protocol.rs` |
| How a single resource flows through apply | `crates/iac-core/src/executor.rs` + any `iac-providers/src/<kind>/ops.rs` |
| How operations get dispatched | `crates/iac-controlplane/src/store.rs::create_operation` |
| How layers + canary cascade on failure | `crates/iac-controlplane/src/store.rs::{advance_phased_apply, advance_canary}` |
| How the agent loop polls and applies | `crates/iac-agent/src/agent.rs` |
| How SSH push dispatches | `crates/iac-controlplane/src/ssh_push.rs` |
| How RBAC + auth resolves | `crates/iac-controlplane/src/identity.rs` |
| How signing + rotation works | `crates/iac-controlplane/src/signing.rs` |

The e2e test next to each feature is usually the cleanest read of how
it actually works end-to-end:
`crates/iac-controlplane/tests/e2e_<feature>.rs`.
