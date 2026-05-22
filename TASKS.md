# IaC Tool — Working Tasks

> Living roadmap. Updated as work progresses. Source of truth for "what's
> next" across sessions. Completed phases live in
> [TASKS_ARCHIVE.md](TASKS_ARCHIVE.md); long-deferred / hardware-gated
> items live in [FUTURE.md](FUTURE.md).

## Status (2026-05-17)

**Phase 9 closed** by spec — F1 / F2 / F6 PASS on real fleet,
F3/F4/F5/F7/F8 covered by local tests or prior fleet harnesses
(see archive 7dh.13, 9-F7, 9-F8, 9-F1-fix-1..10, 9-F2, 9-F6,
9-F1-stress-burst). Ten production gaps closed across the F1
attempts and one in the F2 retry (`227f65e`, `aebbfb9`,
`9ace0b6`, `eb2b14d`, `7cccd3b`, `02abb92`, `bc9c14f`, `61003e8`,
`e92de61`, `df29039`). CP slow-leak verdict: NOT a Rust leak
(commit `3cfffbf` — dhat 371 KB peak, 63 KB at clean shutdown).

**Phase 10 cross-compile** done end-to-end (commit `f3f0a21` +
runbook recipe in `684436a`). Real-MIPS-device bring-up moved to
[FUTURE.md](FUTURE.md) (hardware-gated, $25–35).

**Phase 11 prep:** Litestream WAL replication PoC landed
in an earlier session.

**Trigger-bound backlog cleared proactively** (commit batch
2026-05-17, archive section "Phase 9 trigger-bound batch"):
RateLimiter SIGHUP hot-reload, `/v1/audit/verify` pagination,
capability-allowlist watcher, WASM-module SHA-256 change
detection, nftables firewall backend. Plus admin CLI wrappers
(`iac agents list` / `ops list` / `audit --follow`) from the same
"don't wait for the complaint" wave (`b56fad7`).

**F8 X-Forwarded-For trusted-proxy bucketing** (commit `c36dc89`)
— closes the single-source / multi-source rate-limit story.
Harness `fleet-f8m-xff.sh` spins an ephemeral CP locally and
proves three distinct buckets across X-F-F headers; 7 unit tests
cover the IP-extraction edge cases.

**F1 density variant PASS** (harness `ef3a01c` + fixups `80c65e1`)
— 2026-05-18T12:43Z. 28 agents × 24h × 1 RPS, 0 failures across
75,600 ops, agent RSS stable-or-shrinking, CP RSS +676 % within
abs cap by 2× margin. Validates the agent-count axis. See archive
`Phase 9-F1-stress-density`.

**Workspace health:** 1132 / 1132 tests green;
`cargo clippy --workspace --all-targets` clean.

---

## Open — Active backlog

### Phase 9 — Soak validations (long wall-clock)

Three variants remain pending; all need ≥ 24 h to validate.
Harnesses are staged and syntax-checked.

- [ ] **F1 72h variant** — `./trial/scenarios/fleet-f1-stress-matrix.sh
      72h`. 3× baseline duration. Catches slow leaks that aggregate
      below the 24h threshold (e.g. 0.1 MB/h growth ≈ 7 MB / 24 h
      invisible, 22 MB / 72 h trips the absolute-cap check). All
      Phase 9 fixes 1–10 active.
- ~~**F1 density variant**~~ — **PASS** 2026-05-18T12:43Z. 24h
      soak at 28 agents (7 baseline + 21 density-suffixed),
      75,600 ops, 0 failures, 0 unaccounted restarts, audit ok
      (172,525 rows verified). Agent RSS shrank during the soak
      (-8.5 % to -26.4 %); CP RSS scaled linearly with agent
      count (+676 %, same glibc-fragmentation shape as F1 #11,
      within abs cap by 2×). See archive `Phase 9-F1-stress-density`.
- ~~**mimalloc allocator validation**~~ — **DONE 2026-05-22, hypothesis refuted.** 24h F1 baseline against
      `--features mimalloc` CP: PASS by application criteria
      (0 failures, 0 restarts), but CP RSS grew +40 MB absolute
      vs stock glibc's +32 MB. mimalloc's lower percentage
      (+78 % vs +116 %) is the artefact of its higher warm baseline
      (50 MiB vs 27 MiB). The growth is not glibc-fragmentation
      after all; the real source is SQLite page cache + sqlx
      connection-state buffers + tokio arenas — all of which
      scale with workload state, not allocator behaviour. mimalloc
      feature flag preserved as an opt-in (it's still a valid
      choice for specific workloads), but no longer pitched as a
      slow-leak mitigation. See archive `Phase 9-mimalloc-validation`.

---

## v2 / out-of-scope

Not on the current roadmap. Listed so they don't surface as "did we
think about this?" in future planning sessions.

- Multi-tenancy (separate orgs sharing a control-plane).
- Web UI — everything is CLI today; the API is fully documented and
  self-served via curl + jq.
- Federation between control-planes (multi-region active-active).
- Built-in providers: `kubernetes`, `terraform-state`, `helm.release`.
- Provider marketplace / signed plugin distribution.
- Native macOS / Windows agent builds (currently Linux-only).

---

## Decisions log

- **Language: Rust.** Single-binary, agent capability enforcement, security. (User picked over Go; original plan suggested Go.)
- **Phase 0 starts at the data model**, not at "make a thing apply nginx configs". Three-state model (desired/observed/applied) must work before any provider beyond the trivial.
- **No async in Phase 0.** Sync I/O is enough for local file/systemd/package operations. Async tokio comes in Phase 1 with the agent daemon.
- **YAML loader: `serde_yaml_ng`**. Original `serde-yaml` is archived/unmaintained as of late 2024. Will revisit.
- **State paths:** `/var/lib/iac/state/` (applied state), `/var/lib/iac/checkpoints/` (rollback backups). Configurable via `--state-dir`.
- **sqlx `macros` feature disabled.** Pulls a transitive `rsa` (RUSTSEC-2023-0071) via `sqlx-mysql`. Migrations are plain SQL embedded via `include_str!` and tracked in a `_iac_migrations` table.
- **Composite expansion happens server-side, before routing + capability checks.** Agents stay primitive; per-primitive allowlists keep applying.
- **Rate limit + maintenance check run after auth.** 401/400 don't get masked by 429/503; legitimate operators see the right error code.
- **Workspace lints `forbid(unsafe_code)`.** `std::env::set_var` is unsafe on edition 2024, so test helpers take explicit paths instead of mutating `HOME`.
- **API is the contract, CLI is the ergonomics layer.** Read-side admin tooling (list operations, list agents, tail audit) lives behind `curl + jq` against documented endpoints. ~~Add wrappers only after a concrete operator complaint.~~ Revised 2026-05-16: three list-style wrappers (`iac agents list`, `iac ops list`, `iac audit --follow`) landed proactively because the curl+jq flow was clunky enough during F1–F8 fleet operations that the cost of having them was clearly less than the cost of typing `curl -H "Authorization: Bearer $TOKEN" .../v1/agents | jq ...` every time. The underlying principle still stands — API stays the contract, CLI stays the ergonomic skin — but the "wait for a complaint" gate was too conservative.
- **Trigger-bound backlog gate relaxed (2026-05-17).** Same realisation: items kept under "wait for a concrete trigger event" stayed under-explored in practice. Five rows landed proactively this session (RateLimiter SIGHUP, audit/verify pagination, capability watcher, WASM SHA-256 detector, nftables backend) when the use-case was obvious from F1–F8 operations or the marginal cost was low. Keep the trigger-bound section for items whose *design* depends on the trigger details (e.g. nftables-native firewall provider could have gone either way on default backend; needed RHEL operator concretely confirming "yes I want nft" to land as `IAC_FIREWALL_BACKEND` env-var dispatch). Don't keep it as a permanent procrastination shelf.
- **LegacyAdmin token is bootstrap-permanent.** Originally slated for removal once user-auth landed (Phase 7e); design moved to "keep, gate behind config (`admin_token = null` after bootstrap)" because a fresh control-plane has no users yet and `iac users create` requires Admin.
