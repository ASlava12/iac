# Phase 9 fleet observability

Real-time monitoring stack on `cp-spare-01` (104.128.140.48):

| Component | Port | URL |
|-----------|------|-----|
| Prometheus | 9090 | http://104.128.140.48:9090 |
| Grafana    | 3000 | http://104.128.140.48:3000 |
| node_exporter (each host) | 9100 | http://*:9100/metrics |

Grafana login: `admin` / `iac-grafana-2026` (or anonymous Viewer).

## What it shows

Pre-provisioned dashboard "iac fleet" with:
- RSS by host (MB) — ловит memory leaks across all 10 VPS
- CPU by host (%) — saturation early warning
- Disk free (GB) — disk-full predictor (lessons-learned from F1 #1 / #2)
- Network RX/TX (MB/s) — observation push throughput

The dashboard exists to make F1-style soaks debuggable at runtime
without ssh-ing into each VPS to tail logs. F1 #1-#5 surfaced six
production gaps; #6 is currently emerging on F1 #6 in flight (WAL
saturation under sustained scaling). Pre-Observability we caught
this only via post-hoc CSV analysis; with Prometheus + Grafana the
deterioration trend would be visible at h+1.

## Setup recipe (recreate from scratch)

On cp-spare-01:
```bash
./trial/observability/setup-monitoring-host.sh
```

On every other host (cp-01, cp-spare-02, all 7 agents):
```bash
./trial/observability/install-node-exporter.sh
```

Both scripts are idempotent — re-running upgrades to the latest
binary, leaves systemd units intact.

## Caveats

- No alerting rules wired up — operators watch the dashboard.
  Phase 11+ if needed: alertmanager + PagerDuty/Slack hook.
- No long-term storage — Prometheus default 15-day retention is
  enough for fleet trial work; production would need Thanos or
  remote_write to a managed TSDB.
- iac-controlplane's `/v1/metrics` endpoint exposes JSON, not
  Prometheus exposition format. Future work: emit text/plain
  Prometheus on `/v1/metrics?format=prometheus` or wire a sidecar
  json_exporter. Today we get system-level metrics via
  node_exporter; app-level metrics still require curl + jq.
