# IaC Tool — Working Tasks

> Living roadmap. Updated as work progresses. Source of truth for "what's
> next" across sessions. Completed phases live in
> [TASKS_ARCHIVE.md](TASKS_ARCHIVE.md).

## Status (2026-05-16)

Static-clean across six audit rounds (7dh.1–12), three architectural
deduplication waves (7di.1–6), a bare-metal trial on Pi 4 (8.7),
**ten F1 real-fleet fixes** (commits `227f65e`, `aebbfb9`,
`9ace0b6`, `eb2b14d`, `7cccd3b`, `02abb92`, `bc9c14f`, `61003e8`,
`e92de61`, `df29039`; see archive 9-F1-fix-1 through 9-F1-fix-10),
**Phase 10 cross-compile end-to-end** (commit `f3f0a21`; mipsel-musl
iac-agent at 7.0 MiB stripped — fits OpenWrt flash budget),
**Phase 9 observability stack** (Prometheus + Grafana on
cp-spare-01 scraping all 10 VPS), **Phase 11 prep** (Litestream
WAL replication PoC), **F8 multi-source-IP follow-up PASS**
(commit `93f5936`). 1117/1117 workspace tests green,
`cargo clippy --workspace --all-targets` clean.

**Phase 9 closed:**
- **F1 PASS attempt #11** (2026-05-15T12:42Z): 24h soak, 86,400
  ops, 0 failures, 9 production gaps closed.
- **F2 PASS** (2026-05-15T13:11Z): rolling 7 × 60 s blackhole-route
  network partition, all 7 agents recovered 28–56 s.
- **F6 PASS** (2026-05-15T16:30Z): pre-swap 50-op burst survived
  CP rolling upgrade; 7/7 agents rolled, audit chain ok.
- **CP slow-leak investigation** (commit `3cfffbf`): NOT a Rust
  leak — dhat profile shows 371 KB peak, 63 KB at clean shutdown,
  99.996 % of allocations freed. The F1 #11 +32 MB RSS is glibc
  arena fragmentation + SQLite page cache, not a bug.

**Open (not blockers):**
- F1 stress matrix burst (5 RPS × 24h) — running 2026-05-15T17:14Z
  → 2026-05-16T17:14Z; surfaced gap-#11 (write knee at 5×: busy/5min
  hit 37× cap). Verdict pending finalize.
- F1 stress matrix 72h / density variants — pre-staged.
- Phase 10 real-MIPS device bring-up — hardware-gated ($50 + day).

---

## Now — Deferred until external dependency

### Phase 9 — Real fleet validation (10 VPS)

User holds the hardware allocation. The Pi 4 trial (Phase 8.7) covered
one narrow case (10 agents × 50 RPS, single-host SD-flash); F1–F8 below
need multi-host distributed environments to be meaningful. Not the same
as the docker-compose trial harness (Phase 8) — that one mocks
network/timing on a single host.

| #  | Scenario                                    | Pass criterion                                  | Why a real fleet |
|----|---------------------------------------------|-------------------------------------------------|------------------|
| ~~F1~~ | ~~24 h soak: 7 agents × 1 RPS~~         | ~~RSS not climbing > 5 % over 24 h; 0 unaccounted restarts; audit chain verifies clean~~ | **PASS on attempt #11** (2026-05-15T12:42Z). 86,400 ops, 0 failures, audit ok, 0 restarts, RSS within bounds. 9 production gaps closed across attempts 1–9 (see archive `9-F1-fix-1..5` and `9-F1-fix-6..9`). Stress matrix queued. |
| ~~F2~~ | ~~Network partition (rolling 20 % per cycle)~~  | ~~recovery time < 5 min after restore; no split-brain; replay-protection still rejects re-played envelopes~~ | **PASS 2026-05-15T13:11Z** (commit `df29039` + `3c91322`). Rolling 7 × 60 s blackhole-route per agent (iptables/nft absent on trial Ubuntu 24.04 minimal — switched to `ip route add blackhole`). Recovery 28–56 s per agent (threshold 180 s). Audit chain integrity ok across all cycles. Replay-protection probe skipped because no in-flight envelopes (no workload running) — already pinned by 13 deterministic unit tests in `iac-agent::remote::tests`. |
| ~~F3~~ | ~~Cold reboot of an agent under apply~~ | ~~partial-state reconciles to desired on next observe~~ | **Done locally — see archive 7dh.13.** Real-fleet IPMI/SIGKILL semantics still want validation, but the agent-level reconvergence contract is now pinned by 3 integration tests (`tests/cold_reboot.rs`). |
| ~~F4~~ | ~~Disk-full / inode-full on an agent~~  | ~~graceful degradation; agent reboots clean; no identity-file corruption~~ | **Done locally — see archive 7dh.13.** Atomic-write contract on `identity.json` pinned by 4 unit tests in `remote::tests`. Real disk-full / overlayfs behaviour still wants a VM trial. |
| ~~F5~~ | ~~Time-skew attack (agent clock 25 h in past)~~ | ~~replay-protection holds (Phase 7cq.2 / 7dh.12)~~ | **Done locally — see archive 7dh.13.** Symmetric-window age check pinned by 13 deterministic unit tests in `remote::tests`. |
| ~~F6~~ | ~~Rolling upgrade agent v1 ↔ controlplane v2~~  | ~~wire-protocol compatibility; in-flight ops complete; no agent re-registration storm~~ | **PASS 2026-05-15T16:30Z** (commit `7cdb3dd`). Phase A: 50-op pre-swap burst accepted by v1 CP, all 50 + per-op overhead drained on v2 CP (audit chain advanced 57 → 107). Phase B: 7/7 agents swapped sequentially, all heartbeat post-swap + probe-op PASS. Open follow-ups (not blockers): CP graceful-shutdown 332 s on 50 in-flight ops → SHUTDOWN_TIMEOUT_SECS knob; agent first-heartbeat-after-swap up to 325 s → force-heartbeat-on-start. |
| ~~F7~~ | ~~Backup/restore of controlplane DB~~   | ~~RPO/RTO measured; audit-chain integrity preserved across restore~~ | **Done — see archive 9-F7.** Hot `VACUUM INTO` snapshot of the live CP DB (no service restart, F1 untouched), restore on a separate VPS, full integrity check + post-restore write. RPO 45.6 s (snapshot time on a 947 MB live DB), RTO 1.6 s (cold-start of restored CP to first 200 on `/v1/health`). audit-tip match + `/v1/audit/verify` ok=true. |
| ~~F8~~ | ~~DDoS on `/v1/agents/register`~~       | ~~rate-limit holds; legitimate agents not starved~~ | **Done — see archive 9-F8.** Empirical storm proved the gap (250 req / 10 s from one IP, 0 × 429); per-IP register cap (default 20/min) + axum `ConnectInfo` plumbing land in this fix. Re-storm at 30 s × 50 against the fixed binary returned 20 × 200 / 880 × 429 as expected. Multi-source-IP / `X-Forwarded-For` allowlist still wants a real-fleet pass once F1 finishes and the prod CP can be restarted. |

**Remaining in Phase 9:** F1 stress-matrix variants
(burst running, 72 h / density pre-staged). F1 / F2 / F6 done;
slow-leak investigation closed (NOT a leak — commit `3cfffbf`).
F3/F4/F5/F7/F8(single-source) all have
local test coverage or a fleet-validated harness.

**Active workstreams (parallel to F1 #6 running 24 h in background):**
- F2 — rolling 20 % network partition harness via `iptables` between regions
- F6 — rolling upgrade harness using cp-spare-02 as the v2 CP
- F8 multi-source — 2-IP simultaneous storm (cp-spare-01 + cp-spare-02 → cp-01) to verify per-IP isolation
- F1 stress matrix — 72 h soak, 5–10 RPS variant, multi-agent-per-VPS density variant
- Phase 10 — cross-compile `mipsel-unknown-linux-musl` + run via `qemu-mipsel-static` for binary-size + functional smoke
- Observability — Prometheus/Grafana on cp-spare-01 collecting RSS samplers + audit metrics
- WAL-incremental backup — litestream-style replication CP → cp-spare-02 (sub-second RPO target)
- Security audit r7 — manual round against post-5-fix code
- **CP slow-leak investigation** (sixth real-fleet finding from F1 #5 finalize)
  — CP RSS grew 195→207 MB over 10 h idle; harness fix v2 confirmed
  +301 % growth from warm baseline to late window. Need heap profiler.

### Phase 10 — Cross-architecture validation (MIPS / network gear)

README claims "works on network equipment". Validated on aarch64 via Pi
4; not yet validated on MIPS / OpenWrt-class targets, which are the
bottom of the "weak hardware" curve and exercise different rustc
compilation paths (Tier-3 targets).

- [ ] Cross-build for `mipsel-unknown-linux-musl` and `mips64el-...` —
      both are Tier-3, need `-Z build-std` on nightly OR pre-built
      `cross` Docker images.
- [ ] Static binary size budget check — aim < 10 MiB for OpenWrt
      package install via opkg.
- [ ] Run a single agent on a real MikroTik / GL.iNet device, exercise
      `firewall.rule` (iptables) and `file` providers.
- [ ] Document the cross-compile recipe in `docs/en/runbook.md`.

**Trigger:** physical access to one MIPS device. Cost: $30–80 single
device, half-day cross-build setup, day for the bring-up.

---

## Trigger-bound backlog

Items that have a real cause-effect "do this when X happens" — kept here
so they don't get lost, but not actively scheduled.

| Trigger                                     | Item |
|---------------------------------------------|------|
| ~~Real-fleet trial gets near 2^31 drift rows~~ | ~~Promote audit_events.drift_id from INTEGER to BIGINT~~ **Done** — the column was already BIGINT; comment synced to reality (commit `1650a58`). |
| Operator complains about restart for capability allowlist edits | Add an inotify watcher on `capabilities_file` to `iac-agent`. Currently documented as "requires restart" by design |
| Operator wants WASM module hot-swap         | Add SHA-256-based change detection on the module path, recompile when it changes. Currently load-once-at-startup |
| Rate-limit config changes more than once per quarter | Make `RateLimiter` hot-reloadable across SIGHUP. Currently documented in `server.rs` as not hot-reloadable because `Instant` buckets lose meaning across a swap |
| Operator running on RHEL with firewalld     | Add nftables-native firewall provider (current `firewall.rule` shells out to `iptables`; `iptables-nft` shim works but isn't first-class) |
| ~~First operator complaint about list-style CLI gaps~~ | ~~Add admin-CLI wrappers for `iac agents list`, `iac operations list --status failed`, `iac audit tail --follow`.~~ **Done** — wrappers landed proactively rather than reactively (no specific operator complaint, but the runbook flow against curl+jq was unwieldy enough that pre-emption made sense). Adds `iac agents list`, `iac ops list --status <s> --limit N`, and `iac audit --follow`. Server-side: new `GET /v1/operations` endpoint + audit `since_id` cursor for the polling loop. See "Decisions log" entry on the API-as-contract policy revision. |

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
- **LegacyAdmin token is bootstrap-permanent.** Originally slated for removal once user-auth landed (Phase 7e); design moved to "keep, gate behind config (`admin_token = null` after bootstrap)" because a fresh control-plane has no users yet and `iac users create` requires Admin.
