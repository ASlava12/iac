# IaC Tool — Working Tasks

> Living roadmap. Updated as work progresses. Source of truth for "what's
> next" across sessions. Completed phases live in
> [TASKS_ARCHIVE.md](TASKS_ARCHIVE.md).

## Status (2026-05-09)

Static-clean across six audit rounds (7dh.1–12), three architectural
deduplication waves (7di.1–6), a bare-metal trial on Pi 4 (8.7),
**five F1 real-fleet fixes** (commits `227f65e`, `aebbfb9`,
`9ace0b6`, `eb2b14d`, `7cccd3b`; see archive 9-F1-fix-1 through
9-F1-fix-5), **Phase 10 cross-compile end-to-end** (commit
`f3f0a21`; mipsel-musl iac-agent at 7.0 MiB stripped — fits OpenWrt
flash budget), **Phase 9 observability stack** (Prometheus + Grafana
on cp-spare-01 scraping all 10 VPS), **Phase 11 prep**
(Litestream WAL replication PoC), **F8 multi-source-IP follow-up
PASS** (commit `93f5936`). 1117/1117 workspace tests green,
`cargo clippy --workspace --all-targets` clean.

F1 attempt #5 PASSed by application criteria; #6 in flight (gap-#6
emerging as expected — `journal_size_limit` ceiling under
sustained scaling). Once #6 finalizes (~13 h to go), the planned
fix #6 is config-only: `journal_size_limit` 256 → 1024 MiB +
`retention.interval_secs` 300 → 60. Then F1 #7 for clean sign-off.

**All 8 Phase 9 scenarios** now have harnesses or local coverage —
F1/F2/F6 ready to run, F3/F4/F5 covered by local tests, F7 PASS
(commit `a4c3c9d`), F8 PASS + multi-IP follow-up PASS. F2 and F6
gated on F1 #7 PASS to avoid mixing soak fail with structural
test. F1 stress matrix (72h, burst, density) pre-staged in
`fleet-f1-stress-matrix.sh` for post-F1-#7 deeper validation.

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
| F1 | 24 h soak: 7 agents × 1 RPS                 | RSS not climbing > 5 % over 24 h; 0 unaccounted restarts; audit chain verifies clean | Single-host loops can't catch slow-leak per-FD-table memory accounting. **Attempts 1–4 each surfaced a real production gap** (WAL unbounded, observations unbounded on CP, WAL TRUNCATE blocking + agent observations unbounded, per-row INSERT saturated SQLite) — all five fixes landed (`227f65e`, `aebbfb9`, `9ace0b6`, `eb2b14d`, `7cccd3b`). **Attempt #5 PASSED** by all application criteria (0.062 % errors, audit ok, 0 restarts). Attempt #6 in flight 2026-05-08T19:21Z with finalize-harness fix (`9ace0b6`-style cold-start-aware RSS) for clean verdict. |
| F2 | Network partition (rolling 20 % per cycle)  | recovery time < 5 min after restore; no split-brain; replay-protection still rejects re-played envelopes | Real WAN delay + DNS reconvergence look nothing like docker bridge `disconnect` |
| ~~F3~~ | ~~Cold reboot of an agent under apply~~ | ~~partial-state reconciles to desired on next observe~~ | **Done locally — see archive 7dh.13.** Real-fleet IPMI/SIGKILL semantics still want validation, but the agent-level reconvergence contract is now pinned by 3 integration tests (`tests/cold_reboot.rs`). |
| ~~F4~~ | ~~Disk-full / inode-full on an agent~~  | ~~graceful degradation; agent reboots clean; no identity-file corruption~~ | **Done locally — see archive 7dh.13.** Atomic-write contract on `identity.json` pinned by 4 unit tests in `remote::tests`. Real disk-full / overlayfs behaviour still wants a VM trial. |
| ~~F5~~ | ~~Time-skew attack (agent clock 25 h in past)~~ | ~~replay-protection holds (Phase 7cq.2 / 7dh.12)~~ | **Done locally — see archive 7dh.13.** Symmetric-window age check pinned by 13 deterministic unit tests in `remote::tests`. |
| F6 | Rolling upgrade agent v1 ↔ controlplane v2  | wire-protocol compatibility; in-flight ops complete; no agent re-registration storm | Needs two binary versions deployed sequentially across distinct hosts |
| ~~F7~~ | ~~Backup/restore of controlplane DB~~   | ~~RPO/RTO measured; audit-chain integrity preserved across restore~~ | **Done — see archive 9-F7.** Hot `VACUUM INTO` snapshot of the live CP DB (no service restart, F1 untouched), restore on a separate VPS, full integrity check + post-restore write. RPO 45.6 s (snapshot time on a 947 MB live DB), RTO 1.6 s (cold-start of restored CP to first 200 on `/v1/health`). audit-tip match + `/v1/audit/verify` ok=true. |
| ~~F8~~ | ~~DDoS on `/v1/agents/register`~~       | ~~rate-limit holds; legitimate agents not starved~~ | **Done — see archive 9-F8.** Empirical storm proved the gap (250 req / 10 s from one IP, 0 × 429); per-IP register cap (default 20/min) + axum `ConnectInfo` plumbing land in this fix. Re-storm at 30 s × 50 against the fixed binary returned 20 × 200 / 880 × 429 as expected. Multi-source-IP / `X-Forwarded-For` allowlist still wants a real-fleet pass once F1 finishes and the prod CP can be restarted. |

**Remaining:** F2, F6, plus F8 multi-source-IP follow-up (~3 items).
F1 attempt #5 PASSED by application criteria; #6 is the
ceremony-clean sign-off. F3/F4/F5/F7/F8(single-source) all have
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
| Real-fleet trial gets near 2^31 drift rows  | Promote `audit_events.drift_id` from INTEGER to BIGINT in the Postgres migration (existing comment in `migrations-postgres/20260429000004_audit.sql` flags the risk) |
| Operator complains about restart for capability allowlist edits | Add an inotify watcher on `capabilities_file` to `iac-agent`. Currently documented as "requires restart" by design |
| Operator wants WASM module hot-swap         | Add SHA-256-based change detection on the module path, recompile when it changes. Currently load-once-at-startup |
| Rate-limit config changes more than once per quarter | Make `RateLimiter` hot-reloadable across SIGHUP. Currently documented in `server.rs` as not hot-reloadable because `Instant` buckets lose meaning across a swap |
| Operator running on RHEL with firewalld     | Add nftables-native firewall provider (current `firewall.rule` shells out to `iptables`; `iptables-nft` shim works but isn't first-class) |
| First operator complaint about list-style CLI gaps | Add admin-CLI wrappers for `iac agents list`, `iac operations list --status failed`, `iac audit tail --follow`. Current runbook routes operators through `curl + jq` against the API by design — explicit "API is the contract, CLI is the ergonomics layer" |

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
- **API is the contract, CLI is the ergonomics layer.** Read-side admin tooling (list operations, list agents, tail audit) lives behind `curl + jq` against documented endpoints, not a thicker CLI. Add wrappers only after a concrete operator complaint.
- **LegacyAdmin token is bootstrap-permanent.** Originally slated for removal once user-auth landed (Phase 7e); design moved to "keep, gate behind config (`admin_token = null` after bootstrap)" because a fresh control-plane has no users yet and `iac users create` requires Admin.
