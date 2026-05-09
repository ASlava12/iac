# Operations runbook

Field guide for running this IaC tool in anger: incident triage,
rollback procedures, and the on-call playbook for the most common
failure modes. Pair with [`reference.md`](reference.md) (config
schema and feature surface) and [`architecture.md`](architecture.md)
(why things are wired the way they are).

This runbook covers v0 of the tool. As the tool evolves, runbook
items should age out as the underlying problem is fixed at the
code level — flag stale entries during incident reviews.

---

## Table of contents

1. [On-call essentials](#on-call-essentials)
2. [Incident severity levels](#incident-severity-levels)
3. [Triage decision tree](#triage-decision-tree)
4. [Rollback procedures](#rollback-procedures)
5. [Common failure modes](#common-failure-modes)
6. [Diagnostic commands](#diagnostic-commands)
7. [When to page humans](#when-to-page-humans)
8. [Post-incident](#post-incident)

---

## On-call essentials

**Before your first shift:**

- You can `ssh` to the control-plane host and read `/var/lib/iac-controlplane/`.
- Your account has an admin token in the control-plane's RBAC tables (see [reference.md#RBAC](reference.md#rbac)).
- You have read access to the agent fleet's host inventory.
- Your laptop has a working `iac` CLI, pinned to the same version the fleet runs.
- You know where the audit-chain anchor is published (out-of-band log: syslog, S3, signed-witness service — whatever your org chose).

**During a shift, keep open:**

- The Prometheus dashboard for the control-plane (the `iac_*` metrics).
- The audit feed. The CLI doesn't ship a follow-style tail today; either
  poll the kind you care about with `watch -n 5 'iac audit --server <url>
  --kind drift.detected --limit 20'`, or stream from the API directly:
  `curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit?limit=50&kind=drift.detected" | jq`.
- The on-call channel for paging signals.

**Rules of thumb:**

- **Slow down before destructive actions.** Every rollback path is
  recoverable; an over-eager `iac apply --force` is not. When in
  doubt, page a second pair of eyes.
- **Audit-log first, action second.** Before `iac apply`, read recent
  audit events for the resources you're about to touch. Other people
  may already be in flight.
- **Maintenance windows exist for a reason.** If you're outside one,
  consider whether the change can wait until you're inside.

---

## Incident severity levels

| Sev | Definition                                              | Response time | Examples |
|-----|---------------------------------------------------------|--------------|----------|
| 1   | Production-affecting; observed user-visible breakage    | Immediate    | Cert expired, mass agent disconnect, control-plane HTTP 5xx |
| 2   | Production at-risk; redundancy compromised              | < 30 min     | Single-AZ control-plane down, signing-key rotation stuck |
| 3   | Degraded but not user-visible                           | Same business day | Drift accumulating on N hosts, audit-chain probe lagging |
| 4   | Operator hygiene                                        | Best-effort  | Stale capability allowlist, log retention nearing cap |

Sev 1 and 2 require an incident commander, even if it's a one-person
team. Document timestamps, decisions, and queries you ran — your
post-incident review depends on it.

---

## Triage decision tree

When the page lands and you don't know which dimension is broken,
work this list top-to-bottom. Each step rules out a class of issue
in under 60 seconds.

1. **Is the control-plane reachable?**
   `curl -sS https://control-plane.example/v1/health` — expect HTTP
   200 with `{"status":"ok"}`. Not 200 → control-plane is the fault
   domain; jump to [Control-plane down](#control-plane-down).

2. **Are agents reporting in?**
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents" \
     | jq '.[] | {name, status, last_heartbeat_at}'
   ```
   Agents whose `last_heartbeat_at` is older than 2× their observe
   interval are silent. > 5% silent → fleet connectivity issue; jump
   to [Agent fleet partition](#agent-fleet-partition).

3. **Is drift accumulating?**
   `iac drift --server $URL list` — a sudden jump in open drift events
   suggests an applied change either failed or is being reverted by
   something on the host. Jump to [Drift surge](#drift-surge).

4. **Did a recent operation fail?**
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations?status=failed&limit=50" | jq
   ```
   A failed apply may have left the world half-changed. Jump to
   [Failed apply](#failed-apply-half-applied-state).

5. **Audit-chain integrity probe?**
   `curl -sS -H "Authorization: Bearer $TOKEN" $URL/v1/audit/verify` —
   `{"ok": false}` means a row's hash doesn't match. **This is a
   sev 1.** Stop triaging other paths and follow
   [Audit-chain mismatch](#audit-chain-mismatch).

If none of the above — open the audit feed, scan the last 30
minutes for anything that looks like an out-of-band action you
weren't expecting. If still nothing, escalate.

---

## Rollback procedures

### Roll back a single resource

The agent stores a checkpoint per applied step. To restore the
pre-apply state of one resource:

```sh
# 1. Find the operation that last touched the resource.
#    The local `iac operations` lists what THIS host applied (state-
#    dir backed); the server-side history needs the API:
curl -sS -H "Authorization: Bearer $TOKEN" \
     "$URL/v1/audit?kind=operation.succeeded&limit=20" \
   | jq '.[] | select(.payload.resource_ids[]?=="file/prod/nginx-conf") | .operation_id'

# 2. Roll it back. The CLI walks the checkpoint and re-applies the
#    prior state. Idempotent — running it twice is a no-op.
iac rollback <op-id> --server "$URL"
```

The rollback emits a fresh audit event with `kind=operation.rolled_back`.
Verify in the audit feed before declaring done.

### Roll back a whole apply

If an apply failed mid-way (some steps succeeded, some failed) the
operation is in `partially_applied` state. The control-plane
auto-rolls successful steps back when the operation transitions to
`failed`, but you can force it manually:

```sh
iac rollback --operation <op-id> --include-succeeded
```

This walks every step that was reported `succeeded` and runs the
provider's `rollback` for each. Steps without a recorded checkpoint
are skipped with a warning.

### Roll back to a known-good git commit

When the manifests in git went bad and you want to fast-revert the
fleet, do it the same way you originally rolled forward — by
re-submitting from the known-good ref:

```sh
# Apply manifests at <good-sha>. The resolved SHA is recorded as
# `source_commit` in the audit log automatically; --canary-pct
# gates the rollout if you're not confident.
iac apply --git-repo https://git.example.com/infra.git \
          --git-ref <good-sha> \
          --git-path manifests/ \
          --server "$URL" \
          --environment prod \
          --canary-pct 25 --yes
```

Agents pick up the new desired state on their next observe; drift
auto-resolves as the world converges back. **This is not the same
as a per-resource rollback** — it relies on the new manifest
declaring what you want. If a resource is removed from git between
the bad and the good ref, the agent will tear it down (see
manifest deletion semantics in [reference.md#GitOps](reference.md#gitops)).

### Restore from a backup

For control-plane state corruption — see
[reference.md#Backups](reference.md#backups). The backup tarball
includes the SQLite DB or Postgres dump plus the signing-key
material. Restore is offline: stop the control-plane, swap the
state-dir, restart.

For SQLite deployments, two complementary recovery paths are
validated:

1. **Hot snapshot via `VACUUM INTO`** (Phase 9-F7,
   `trial/scenarios/fleet-f7-backup-restore.sh`). RPO ≈ snapshot
   wall-time (~45 s on a 947 MB DB), RTO ≈ 1.6 s. No service
   restart on the source. **Always use `VACUUM INTO`, not `.backup`**
   — `.backup` retries on every page-level SQLITE_BUSY and stalls
   forever against a busy writer; `VACUUM INTO` is a single
   transactional snapshot that completes in disk-write time.

2. **Continuous WAL replication via Litestream** (Phase 11 prep,
   `trial/scenarios/setup-litestream-replication.sh`). Sub-second
   RPO (default 1 s), RTO ≈ 30 s for a typical fleet DB. Zero
   impact on source — Litestream tails the WAL via its shadow-WAL
   mechanism without locking against writers. Replicates SFTP to
   `cp-spare-02:/var/lib/iac-replica/`.

**Forensics caveat (lesson from F1 attempt #1).** If the CP died
from disk-full, do **NOT** remove the WAL file before checkpointing.
The main DB has un-checkpointed frames sitting in the WAL; deleting
the WAL leaves the main DB malformed and `.dump` will fail. Correct
recovery sequence:

```sh
systemctl stop iac-controlplane
# WAL still has uncommitted frames — checkpoint FIRST.
sqlite3 /var/lib/iac-controlplane/server.db 'PRAGMA wal_checkpoint(TRUNCATE);'
# only NOW is it safe to move things around.
```

---

## Common failure modes

### Control-plane down

**Symptom:** `/v1/health` returns 5xx or connection-refused. Agents
keep observing locally but can't post results until the control-plane
is back; the local audit log on each agent fills the gap.

**Quick check:**
```sh
ssh control-plane.example
sudo systemctl status iac-controlplane
sudo journalctl -u iac-controlplane -n 200 --no-pager
```

**Common causes:**

- **Disk full.** `/var/lib/iac-controlplane/server.db` grew past
  the partition. `df -h /var/lib/iac-controlplane` confirms.
  Treatment: tighten retention in `server.toml` (`[retention]
  audit_days = ...`) and SIGHUP the controlplane — the prune
  worker runs each cycle and trims the audit / drift / per-resource
  caps automatically. There is no admin-CLI `prune` command. Disk
  full *also* takes audit appends with it — agents will buffer
  locally.
- **Postgres connection storm.** Connection pool exhausted; the
  agent fleet ramped up faster than `max_connections`. Treatment:
  raise `max_connections` on the DB or lower per-agent observe
  parallelism.
- **TLS cert expired.** `openssl s_client -connect control-plane:443
  -servername control-plane.example` shows expired cert. Renew via
  the agent's own ACME provider (we eat our own dog food) — see
  cert path in `server.toml`.
- **Migration failure on restart.** `journalctl` shows a SQL error
  during `_iac_migrations` apply. Treatment: roll forward only —
  fix the underlying migration, deploy a new binary; never edit a
  shipped migration.

**Recovery path:**

1. Restore DB from latest backup if disk corruption.
2. Restart the control-plane.
3. Watch `iac_agent_seen_total` start ticking up.
4. Once ≥ 95% of expected agents are reporting, the fleet has reconverged.
5. Verify audit-chain integrity *before* serving any new operations
   (corrupted tail can hide tampering): `GET /v1/audit/verify`.

### Agent fleet partition

**Symptom:** Many agents have `last_seen` older than their observe
interval but each individual host responds to TCP probes.

**Common causes:**

- A network-side firewall change blocking the control-plane port.
- DNS for the control-plane hostname changed and agents cached the
  old resolution.
- mTLS cert rotation that didn't propagate to all agents.

**Quick check from one agent:**
```sh
ssh affected-agent
journalctl -u iac-agent -n 100 --no-pager
sudo -u iac-agent /usr/local/bin/iac-agent status     # local snapshot
```

**Recovery:** the fix is almost always at the network/credential
boundary, not the agent itself. Agents auto-reconnect with
exponential backoff; you don't need to restart them once the
underlying issue is fixed.

### Drift surge

**Symptom:** Open drift count jumped sharply in the last observe cycle.

**Most likely causes (in order):**

1. **Someone hand-edited config on the hosts.** Compare a sample
   manifest with the actual on-disk state.
2. **A package upgrade reset a config file.** Common on Debian/Ubuntu
   when `dpkg` prompts and an unattended-upgrade chose `keep-default`.
3. **A cron / scheduled task is rewriting state.** Look for cron
   entries managed *outside* IaC.
4. **Genuine policy drift** — the spec changed in git; agents are
   honestly catching up. Cross-reference with the recent operation
   audit via `iac audit --server $URL --kind operation.succeeded
   --limit 30`.

**Treatment:** decide whether the world is right or the spec is
right. If the world is right, accept the drift via `iac drift
--server $URL accept <id> --reason "<text>"` (records reason +
actor in the audit log). If the spec is right, apply it.

### Failed apply (half-applied state)

**Symptom:** the GET `/v1/operations` endpoint returns rows with
status `failed`. (`iac operations` is the local-state-dir lister
only — server-side history needs the API or the audit feed.)

**Steps:**

```sh
# What happened?
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations/<op-id>" | jq

# Which assignments are stuck?
curl -sS -H "Authorization: Bearer $TOKEN" \
     "$URL/v1/operations/<op-id>/desired-state" \
   | jq '.items[] | select(.status != "succeeded") | {resource_id, status, message}'

# Roll back. With --server the controlplane builds a new operation
# that re-applies each affected resource's prior desired-state.
iac rollback <op-id> --server "$URL" --reason "<incident-id>"

# Investigate the underlying failure (logs, audit, the resource itself).
# Fix the root cause, then re-apply.
iac apply --server "$URL" --environment <env> manifests/
```

If a step is marked `Failed` but its `rollback` checkpoint is
missing (rare — usually means the failure happened *before*
`pre_apply` recorded one), you have to roll back manually by
applying the prior spec from git.

### Audit-chain mismatch

**Symptom:** `GET /v1/audit/verify` returns `{"ok":false,
"broken_id":N}`.

**This is a sev 1.** It means either:

- Database corruption (rare, caught by SQLite/PG integrity checks).
- Someone with DB write access edited an audit row out-of-band.
  *That's a security incident.*
- A bug in the audit chain implementation. Bug-shaped: you can't
  rule it out, but treat as the security case until proven otherwise.

**Steps:**

1. **Stop accepting new operations.** Maintenance windows are config-
   driven (`maintenance_windows` / `recurring_maintenance_windows` in
   `server.toml`); add an entry covering `now → now+2h` and SIGHUP the
   controlplane to gate non-admin submissions until you're done. There's
   no admin-CLI shortcut for this today; edit the config file.
2. **Fetch the broken row** and the row immediately before it:
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" \
        "$URL/v1/audit?limit=1000" \
     | jq '.[] | select(.id == BROKEN_ID or .id == BROKEN_ID-1)'
   ```
   (The `/v1/audit` endpoint filters by `kind`/`actor`/`operation_id`/
   `agent_id`/`limit` only — there is no server-side `since` filter; do
   the time-window narrow client-side with `jq` if you need it.)
3. **Compare against the out-of-band trust anchor** (your syslog /
   S3 / signed-witness feed of `chain-tip`, fed from
   `GET /v1/audit/chain-tip`). Whichever row's `prev_hash` agrees
   with the anchor is authentic; the other is forged.
4. **Rotate every credential** that gave the attacker DB write
   access: admin tokens, DB passwords, control-plane signing key
   (`POST /v1/admin/signing-keys/rotate`).
5. Document the IRC for post-incident review.

### Capacity exhaustion under sustained load

**Symptom:** sustained 1+ hour 5xx rate with `database is locked` /
`disk is full` / 4-6 s INSERT latency. The SQLite write path is
saturating.

**Background — F1 trial findings.** Phase 9 fleet validation
surfaced six distinct capacity ceilings on a 7-agent fleet running
1 RPS submit-burst. All six are addressed in defaults; this section
exists for operators on bigger fleets where the same patterns
re-emerge at higher scale.

| Symptom | Mechanism | Default that bounds it |
|---|---|---|
| `disk is full` after several hours | SQLite WAL grows unbounded (autocheckpoint pages back but doesn't truncate) | `journal_size_limit = 256 MiB` per-connection PRAGMA + periodic `wal_checkpoint(TRUNCATE)` task |
| 4-7 s INSERT latency under load | Per-row INSERTs queue WAL frame allocation | Multi-row batched INSERTs (chunk = 100) in `record_observations` |
| `observations` table 1 M+ rows | No per-resource cap; all observations kept until age-pruned | `observation_max_per_resource = 50` + 5-min retention interval |
| 30 s freezes every minute | `wal_checkpoint(TRUNCATE)` blocking on contention | PASSIVE most ticks, TRUNCATE every 10th tick (so on default 60 s cadence, TRUNCATE every 10 min) |
| Agent local DB unbounded | `record_observation` INSERTs without cap | `AGENT_OBSERVATION_HISTORY_CAP = 10` per `resource_id`, inline DELETE after each INSERT |
| Agent stuck in 413 retry-loop | Push body > CP `max_body_bytes`, agent retries the same oversized batch | Adaptive chunked push (chunk = 500 obs, halve on 413, drop singleton) |

**Tuning beyond defaults.** If the fleet outgrows defaults
(symptom: WAL hits cap + 5xx rate climbs over hours despite no
config changes), the tunables are in
[`crates/iac-controlplane/src/config.rs`](../../crates/iac-controlplane/src/config.rs):

- `[retention] observation_max_per_resource` — lower to shrink
  steady-state DB. 10–20 acceptable for most observability needs.
- `[retention] interval_secs` — lower to keep working set small.
  60 s aggressive but fine on SSD-class storage.
- `wal_checkpoint_interval_secs` — lower to reclaim WAL faster.
- TODO post-Phase 11: `journal_size_limit` is hard-coded; promote
  to config when first operator hits the 256 MiB ceiling on a
  larger fleet.

**Live triage.** If you have the
[Phase 9 observability stack](../../trial/observability/README.md)
deployed (Prometheus + Grafana on cp-spare-01), watch the **RSS by
host** panel for the CP — sustained linear growth past 200 MB on
a small fleet is the early signal. The disk-free panel catches
the WAL-unbounded class before it becomes service-impacting.

Without Grafana, poll directly:
```sh
ssh root@<cp> "ls -lh /var/lib/iac-controlplane/server.db*; df -h /"
journalctl -u iac-controlplane --since '5 minutes ago' \
    | grep -c 'database is locked'  # > 50/min ≈ saturation imminent
```

---

## Diagnostic commands

Pair with `iac --help`. The control-plane CLI today is intentionally
narrow (apply / plan / rollback / drift / audit / users / approve /
reject / login / logout / version); read-side fleet inspection goes
through `curl` + `jq` against the API. This is on purpose — the
server is the source of truth and the API is the contract; a thicker
admin CLI would be a v2 ergonomics pass on top of these primitives.
`$URL` is the controlplane base URL, `$TOKEN` an admin or operator
bearer.

```sh
# Recent operations on the server.
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations?limit=20" | jq

# Drift queue.
iac drift --server "$URL" list                     # all open
iac drift --server "$URL" list --agent-id <id>    # narrow to one agent

# Audit feed (filter is exact-match per field; no glob, no `since`).
iac audit --server "$URL" --kind operation.submitted --limit 50
iac audit --server "$URL" --actor admin --limit 50
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit/chain-tip" | jq
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit/verify" | jq

# Agent inventory.
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents" \
  | jq '.[] | {name, environment, status, last_heartbeat_at, open_drifts}'
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents/<id>" | jq

# Local agent status (run on the agent host).
iac-agent --config /etc/iac/agent.toml status

# Force a re-observe locally (no apply, no server interaction).
iac-agent --config /etc/iac/agent.toml observe
```

For the control-plane host:

```sh
# Storage health.
sqlite3 /var/lib/iac-controlplane/server.db "PRAGMA integrity_check;"
# Or for Postgres:
psql -c "VACUUM (ANALYZE, VERBOSE) audit_events;"

# Latest log lines.
journalctl -u iac-controlplane -n 200 --no-pager

# Prometheus-shaped metrics, dumped to stdout.
curl -sS http://localhost:9090/metrics | grep -E '^iac_'
```

---

## When to page humans

| Page if…                                          | Sev |
|--------------------------------------------------|-----|
| Audit-chain verify returns `ok:false`            | 1   |
| Control-plane down for > 5 min                   | 1   |
| Mass agent disconnect (> 50% of fleet)           | 1   |
| Cert expiry < 24h on a production-facing service | 1   |
| Failed apply that touched > 10 hosts             | 2   |
| Signing-key rotation hung                        | 2   |
| Sustained drift surge (> 10× baseline)           | 2   |
| Backup job failed twice in a row                 | 3   |

For sev 1, page **two** people: the on-call primary AND a senior
engineer familiar with the control-plane. Sev 2 pages primary
only. Sev 3 and 4 file a ticket; no page.

---

## Post-incident

Write the after-action report within 24h while details are fresh.
Include:

- **Timeline.** Page time, time-to-detection, time-to-mitigation,
  time-to-resolution. UTC throughout.
- **Detection.** Who/what noticed; could a metric have caught it
  earlier?
- **Root cause.** *Not* the proximate trigger — the underlying
  reason. Five-whys or your team's preferred framing.
- **Contributing factors.** Latent issues that turned a small
  problem into a big one (e.g. a stale runbook, a missing alert).
- **Action items.** Each owned by a named person, with a deadline.
  File them as tickets immediately, don't let them rot in the
  document.

Update *this runbook* if the incident exposed a triage path or
diagnostic command that wasn't here. Future-you will thank present-you.
