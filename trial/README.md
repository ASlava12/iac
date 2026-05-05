# Phase 8 — Trial harness

Local docker-compose harness for fleet-shape regression testing.
N agents + 1 control-plane + Prometheus, all on one host. The
[`iac-trial`](../crates/iac-trial) binary drives synthetic
workloads and reports pass/fail.

> **Not a production deployment.** Containers share the host
> kernel, so per-container `systemd.unit` / `package` providers
> are still single-globally. Use this to exercise the
> control-plane, agent registration, audit chain, plugin
> runtime stability, network chaos. For real systemd / apt
> / yum behaviour, run a few agents on Vagrant VMs alongside.

## Quick start

```sh
# 1. Build images (one-time, cached after).
docker compose -f trial/compose/docker-compose.yml build

# 2. Run the baseline scenario: 50 agents, 1000 ops at 50 RPS.
trial/scenarios/baseline-50.sh

# 3. Inspect.
docker compose -f trial/compose/docker-compose.yml ps
open http://localhost:9090/graph                   # Prometheus
curl -s -H 'Authorization: Bearer trial-admin-token' \
     http://localhost:8443/v1/agents | jq '. | length'
```

## Layout

```
trial/
├── compose/
│   ├── docker-compose.yml        # control-plane + agent (replicable) + Prometheus
│   ├── server.toml               # control-plane config (mounted RO)
│   └── prometheus.yml            # scrape config
├── docker/
│   ├── Dockerfile.controlplane   # multi-stage rust:1.95 → debian:slim
│   ├── Dockerfile.agent          # ditto
│   └── entrypoint-agent.sh       # generates per-replica agent.toml
├── chaos/
│   ├── slow-network.sh           # tc/netem inside agent containers
│   └── partition.sh              # docker network disconnect
├── scenarios/
│   ├── baseline-50.sh            # 50 agents × 1000 ops @ 50 RPS
│   └── longevity.sh              # 30 agents × 1 RPS for N seconds
└── README.md (this file)
```

## Scaling agents

```sh
docker compose -f trial/compose/docker-compose.yml up -d --scale agent=100
```

Each replica gets a hostname like `trial-agent-1`, `trial-agent-2`, …
which the entrypoint script reads as the agent's name.

Resource limits are set per-container (256 MiB RAM, 0.5 CPU).
On a 64 GiB host you can comfortably run 200+ agents without
swapping.

## Workload generator

[`crates/iac-trial`](../crates/iac-trial) builds to a single
`iac-trial` binary with three subcommands:

| Subcommand     | Purpose                                                  |
|----------------|----------------------------------------------------------|
| `wait-fleet`   | Block until N agents have registered. Gates scenario starts. |
| `submit-burst` | Fire N submissions at target RPS, report latency histogram. |
| `longevity`    | Long low-rate workload — soak / overnight runs.          |

Pass thresholds for `submit-burst` and `longevity`:
- < 1 % submission failures
- < 5 % submissions in the slowest bucket (≥ 2.5 s)

Tune in `crates/iac-trial/src/main.rs::Stats::passed`.

## Chaos

```sh
# Inject 100 ms ± 30 ms latency + 5 % packet loss on every agent
trial/chaos/slow-network.sh apply 100ms 30ms 5%

# … run a scenario …
trial/scenarios/baseline-50.sh

# Clear
trial/chaos/slow-network.sh clear

# Detach 5 random agents from the trial network
trial/chaos/partition.sh apply 5
# … wait for replay-protection / recovery to engage …
trial/chaos/partition.sh restore
```

Pin chaos to specific replicas:

```sh
IAC_CHAOS_AGENTS="trial-agent-1 trial-agent-7" \
    trial/chaos/slow-network.sh apply 250ms
```

## Metrics & inspection

Prometheus scrapes `/v1/metrics` on the control-plane every 5 s.
Useful queries:

```promql
# How many agents have a heartbeat in the last 30 s?
iac_agent_heartbeats_total

# Operation throughput (1-minute average)
rate(iac_operations_submitted_total[1m])

# Audit-chain growth — should track operation rate
rate(iac_audit_events_total[1m])

# Rate-limited rejects — should be 0 in normal trials
rate(iac_rate_limit_rejected_total[1m])
```

Per-agent state: hit `/v1/agents` directly with the trial admin
token (`trial-admin-token`). Every agent logs to stdout — view
with `docker compose -f trial/compose/docker-compose.yml logs agent`.

## What the trial validates

Mapped to the readiness checklist:

| Inv. | Run with                                     |
|------|----------------------------------------------|
| Throughput (control-plane holds N agents)    | `baseline-50.sh`, scale to 100/200 |
| Longevity (no leaks, agent stays up)         | `longevity.sh DURATION_SECS=86400` |
| Slow / lossy network behaviour               | `slow-network.sh apply` + scenario |
| Partition recovery                           | `partition.sh apply 10` mid-scenario |
| Audit chain under burst                      | post-run: `curl /v1/audit/verify` |
| Rate-limit + retry interaction               | scale agents > rate cap → expect 429 |

## What it doesn't validate

- **Real `systemd.unit` / `package` providers** — containers
  share the host kernel + dpkg. Run a few agents on Vagrant
  VMs alongside to cover those.
- **Real disk-failure modes** — overlay FS doesn't behave like
  a real ext4 with bad sectors. Use cloud / VM trials for that.
- **Real network jitter at scale** — a 64 GiB host can still
  inject realistic loss/delay through netem; cross-DC latency
  needs real distributed deployment.

## Adding scenarios

1. Drop a script in `trial/scenarios/`. Convention: it must
   exit non-zero on failure so CI catches regressions.
2. Use `iac-trial wait-fleet` to gate any workload after the
   stack comes up — agents take ~5–10 s to register on a cold
   start.
3. Always teardown via `docker compose down -v` in a `trap`.
