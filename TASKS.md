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

**F1 mimalloc validation refuted** (2026-05-22T17:43Z) — same 24h
F1 baseline shape against `--features mimalloc` CP; PASS by
criteria but +40 MB absolute vs stock's +32 MB. Hypothesis
(arena fragmentation is the slow-leak) refuted. See archive
`Phase 9-mimalloc-validation`.

**F1 72h variant PASS by criteria** (2026-05-25T19:35Z) — 72h
soak, 246k ops, 0.01 % cumulative failures (100× under cap),
0 restarts, CP RSS +857 % within 512 MB cap by 1.6× margin.
Surfaced **gap-#12**: `desired_states` SELECT slowdown past
~150 k rows (the 72h-specific finding). Harness emitted FAIL
on `/v1/audit/verify` HTTP timeout on the 500k-row chain;
incremental verify via `?from_id=N` confirms chain integrity.
See archive `Phase 9-F1-stress-72h`.

**Phase 9 fully closed.** All F1 variants (baseline / burst /
density / mimalloc / 72h) + F2 / F6 / F7 / F8 (all sub-variants)
done. Two new open follow-ups from 72h findings — both
deferred, neither a release blocker.

**Workspace health:** 1132 / 1132 tests green;
`cargo clippy --workspace --all-targets` clean.

---

## Open

Nothing. Phase 9 fully closed. Both 72h follow-ups landed:

- ~~**gap-#12: `desired_states` SELECT slowdown**~~ —
  **closed by F1 fix #12** (commit `dc8bdfe`). New
  `desired_state_max_per_resource` retention cap (default 10)
  mirrors the observations cap shape: ROW_NUMBER per
  resource_id, chunked DELETE with 50 ms pauses to avoid
  blocking writers. Steady-state at 14 k rows for the trial's
  1400-resource pool — two orders of magnitude below the
  150 k SELECT knee. 2 new unit tests, all 1134 workspace
  tests green.
- ~~**Harness: finalize `/v1/audit/verify` cursor**~~ —
  **closed by commit `3a78fc9`**. fleet-f1-finalize.sh now
  passes `?from_id=$start_id` (read from chain-tip-start.json
  one block up) so verify walks only soak-added rows.
  --max-time bumped 30 → 60 s as belt-and-braces.

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
