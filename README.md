# iac

A single-binary, agent-based IaC control plane. Written in Rust. Built to run
the same on a Raspberry Pi and a datacenter rack — the SQLite single-file
backend keeps homelab deployments lean; the Postgres backend scales the
same wire format to thousands of agents.

## What it does

You write desired-state manifests (YAML). You submit them to a control plane.
Per-host agents pull their share of the work, apply it, and report back. The
control plane keeps an audit trail, gates risky operations through approval +
canary rollouts, and lets you roll back fleet-wide changes with one command.

```yaml
# manifests/web.yaml
apiVersion: iac.example/v1
kind: file
metadata:
  name: nginx-config
  environment: prod
spec:
  path: /etc/nginx/sites-available/web
  mode: "0644"
  content: |
    server { listen 80; root /var/www/html; }
```

```bash
# Single-host smoke test
iac apply manifests/

# Or fleet-wide via the control plane
iac apply manifests/ --server https://iac.example.com --environment prod \
                     --canary-pct 25 --yes
```

## Providers

Built-in resource kinds: `file`, `systemd.unit`, `package`, `docker.container`,
`docker.compose`, `dns.record`, `acme.certificate`, `nginx.vhost`, `cron.job`,
`firewall.rule` (iptables), `monitoring.check` (HTTP/TCP probe),
`sysctl.setting`. Composite kinds: `service` (docker + nginx + monitoring).
Dynamic-plugin runtimes for operator-defined kinds: shellout (per-method shell
script), external-process (long-running NDJSON-RPC daemon), WASM (sandboxed
module). See [docs/en/reference.md](docs/en/reference.md) for the field
reference.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ASlava12/iac/master/install.sh | sh
```

The installer detects host OS + CPU architecture, downloads the matching
release tarball, verifies the SHA-256 checksum, and drops binaries into
`~/.iac/bin/`. Pin a version with `... | sh -s -- --version v0.0.4`; install
system-wide with `... | sudo sh -s -- --prefix /usr/local`.

Prebuilt binaries are published for: Linux x86_64 / aarch64, macOS aarch64,
FreeBSD x86_64, and Windows x86_64 / aarch64 (Windows users: grab the `.zip`
from the [releases page](https://github.com/ASlava12/iac/releases)).
Build from source on anything else: `cargo install --path crates/iac-cli`.

## Status

Pre-production. Functionally complete; static-audit-clean across six rounds
(see TASKS.md). Wire format stable in v1. SQLite backend exercised on a
Raspberry Pi 4 trial (10 agents, 1000 ops at 50 RPS, 0 errors after the
Phase 8.7 SQLite-busy fix). Phase 9 fleet validation (10 VPS, two regions)
is closed: F1 soak (baseline / burst / density / 72h), F2, F6, F7 and F8 all
PASS on the real fleet. A security-remediation pass is in progress on top of
that. See [TASKS.md](TASKS.md) for the phased roadmap and what's been shipped.

## Documentation

* [docs/en/tutorial.md](docs/en/tutorial.md) — install, first apply,
  set up the control plane (RU: [docs/ru/tutorial.md](docs/ru/tutorial.md)).
* [docs/en/reference.md](docs/en/reference.md) — production reference:
  RBAC, canary, GitOps, rollback, observability (RU:
  [docs/ru/reference.md](docs/ru/reference.md)).
* [docs/en/runbook.md](docs/en/runbook.md) — on-call playbook for the most
  common failure modes (RU: [docs/ru/runbook.md](docs/ru/runbook.md)).
* [docs/en/architecture.md](docs/en/architecture.md) — how the pieces fit
  together (RU: [docs/ru/architecture.md](docs/ru/architecture.md)).

## License

MIT or Apache-2.0.
