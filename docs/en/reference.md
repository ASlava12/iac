# Reference

Production reference for running iac. Assumes you've read
[tutorial.md](tutorial.md).

## Architecture in one paragraph

The control plane (`iac-controlplane`) is one process backed by
SQLite or Postgres. It accepts desired-state submissions from
operators (`iac` CLI), routes them to per-environment agents
(`iac-agent`), keeps an audit log, and gates risky changes through
RBAC + approval + canary. The agent is a long-running daemon on each
managed host that pulls assignments, applies them through the
provider catalog, and reports back. All wire traffic is over HTTP[S];
the agent verifies an Ed25519 signature on every assignment so a
hostile network can't inject work.

```
   operator                control plane             agents
  ┌────────┐    submit    ┌──────────────┐  pull   ┌────────┐
  │ iac    │─────────────▶│ controlplane │◀────────│ iac-   │
  │ (CLI)  │   approve     │ (one process) │ result │ agent  │
  └────────┘    rollback   │  + SQLite/PG │─────────└────────┘
                          └──────────────┘            (per host)
```

## Server config (`server.toml`)

Loaded by `iac-controlplane --config <path>`. Reload soft fields with
`SIGHUP` (Phase 7bx) — policies, modules, retention, maintenance
windows, retry-after format reload atomically. Hard fields (`bind`,
`database_url`, `tls`, `rate_limit`, `webhooks`) require a restart.

```toml
bind          = "0.0.0.0:8443"
database_url  = "sqlite:///var/lib/iac/server/server.db?mode=rwc"
state_dir     = "/var/lib/iac/server"
admin_token   = "<long random string — used by `iac login`>"
max_body_bytes = 8388608   # 8 MiB; bump for large manifest sets

# Agent token TTL — None (omit) means tokens never expire (legacy).
# Recommended for production: 86400 (24h) with auto-rotation enabled.
agent_token_ttl_secs = 86400

# TLS. Drop the block to run on plain HTTP (dev/internal only).
[tls]
cert_file       = "/etc/iac/tls/server.crt"
key_file        = "/etc/iac/tls/server.key"
client_ca_file  = "/etc/iac/tls/ca.crt"   # optional: enables mTLS
require_client_cert = false               # set true to reject anon

# Retention — how long to keep terminal operations + audit events.
[retention]
operations_terminal_days = 90
audit_events_days        = 365

# Per-environment + per-policy + per-agent rate limits.
[rate_limit]
operations_per_minute       = 30   # per environment
agent_requests_per_minute   = 600  # per agent (heartbeat/observ./drift)

# Webhook delivery for ops events. Multiple sinks supported.
[[webhooks.sinks]]
name        = "slack-prod"
url         = "https://hooks.slack.example.com/..."
events      = ["operation.failed", "drift.detected"]

# Secret resolvers — operators reference encrypted/external secrets in
# manifests as `${secret://<scheme>/<path>[#field]}`. The `env` scheme is
# always available (reads server-process env vars). Vault and SOPS are
# opt-in.

# HashiCorp Vault — KV v2 lookup over HTTPS. The token must travel over
# TLS (plain http:// is rejected; use VaultResolver::new_allow_insecure
# in tests if you must).
[secrets.vault]
addr      = "https://vault.internal:8200"
token_env = "VAULT_TOKEN"   # preferred — token loaded from process env at startup
# token   = "..."           # inline token (avoid in production)

# Mozilla SOPS — decrypt age/PGP-encrypted files in a sandboxed dir.
# Operators put `*.enc.yaml` (etc.) under `base_dir`; references are
# resolved against it and refused if they escape via `..` or symlinks.
# Without `#field`, returns the entire decrypted file (TLS certs,
# SSH keys, .env blobs round-trip cleanly with internal newlines).
[secrets.sops]
base_dir = "/var/lib/iac/secrets"
# binary = "/usr/local/bin/sops"   # optional; defaults to $IAC_SOPS_BIN or "sops"

# Postgres example (replace SQLite for >100-agent fleets):
# database_url = "postgres://iac:secret@db.internal/iac?sslmode=require"
```

### Secret reference syntax

```yaml
# Anywhere a string spec field appears:
spec:
  env_var:    "${secret://env/DATABASE_PASSWORD}"
  vault_kv:   "${secret://vault/secret/data/myapp/db#password}"
  sops_field: "${secret://sops/postgres.enc.yaml#password}"
  sops_file:  "${secret://sops/tls/server.key.enc}"   # whole-file decrypt
  composed:   "postgres://app:${secret://sops/db.enc.yaml#password}@db/app"
```

References are resolved at the control plane *before* the assignment
envelope is signed, so the agent only ever sees plaintext through the
same signed-envelope path that protects every other secret backend.
Manifest files themselves never contain plaintext.

The full schema is in [crates/iac-controlplane/src/config.rs](../crates/iac-controlplane/src/config.rs).

## Agent config (`agent.toml`)

```toml
server_url    = "https://iac.example.com:8443"
state_dir     = "/var/lib/iac/agent"
environment   = "prod"
agent_name    = "vm-web-01"
observe_interval_secs = 30   # how often to push observations + drift

# Optional capabilities allowlist. Without this, the agent applies
# any kind it has a provider for. With it, the agent rejects
# assignments containing kinds NOT in this list — the safety
# rail for "this host should never run docker."
capabilities_file = "/etc/iac/agent.capabilities.yaml"

# Optional TLS / mTLS configuration. Mirror the server's [tls] block.
[tls]
ca_file          = "/etc/iac/tls/ca.crt"
client_cert_file = "/etc/iac/tls/agent.crt"
client_key_file  = "/etc/iac/tls/agent.key"
```

`capabilities.yaml`:

```yaml
# Optional. Default: `allow` — kinds without an explicit rules block
# are unrestricted. Set to `deny` for strict mode (kinds without a
# block are rejected outright).
default_kind_policy: allow

# Per-kind sections. Each block has `allow` (and `deny` for path-based
# kinds). Globs use the `globset` flavour (`*`, `**`, `?`, `[…]`).
# Resources are matched against the per-resource identifier the
# provider returns from `capability_keys` (see the per-provider
# sections below).
files:                    # governs `file` resources
  allow:
    - "/etc/nginx/**"
    - "/var/lib/myapp/*.json"
  deny:
    - "/etc/nginx/secrets/*"
nginx_vhost:              # governs `nginx.vhost` resources
  allow: ["/etc/nginx/sites-available/*"]
systemd:                  # governs `systemd.unit` (allow-only)
  allow: ["nginx", "myapp-*"]
docker:                   # governs `docker.container` (allow-only)
  allow: ["web-*"]
packages:                 # governs `package` (allow-only)
  allow: ["nginx", "ca-certificates"]
cron:                     # governs `cron.job` (allow-only)
  allow: ["backup-*"]
```

Kinds without a per-section block (`acme.certificate`, `dns.record`,
`monitoring.check`, `sysctl.setting`, `docker.compose`,
`firewall.rule`, plus any operator-defined plugin kinds) fall through
to `default_kind_policy`.

## Provider catalog reference

Each provider follows the same lifecycle: observe → diff → apply →
rollback. `state: present` is the default; `state: absent` deletes
where supported.

Per-provider sections below cover: **spec** (full schema),
**capability allowlist** (the [`capabilities.yaml`](#agent-config-agenttoml)
section governing this kind, and the per-resource identifier the
provider returns to be matched against the section's globs),
**pitfalls**, **manifest sample**. Kinds whose entry says
*"no per-kind section — falls through to `default_kind_policy`"*
do not have a dedicated block in `capabilities.yaml`; their access
is controlled solely by the top-level default.

### `file`

```yaml
kind: file
spec:
  path: /etc/foo.conf       # absolute path required
  mode: "0644"              # octal string
  content: "..."            # OR content_from: <path>
  owner: root               # optional, defaults to current uid
  group: root
  state: present            # present|absent
```

* **Allowlist:** section `files:` (path globs); identifier = `spec.path`
* **Pitfalls:** `mode` must be a quoted string (octal). The agent must
  have write permission to the parent directory; for `/etc/*` that
  usually means agent runs as root or via `sudo`. Atomic writes use
  `<path>.iac.tmp` then rename — make sure the FS supports rename
  on the target dir (most do; some FUSE mounts don't).
* **Sample:**

  ```yaml
  apiVersion: iac.example/v1
  kind: file
  metadata:
    name: nginx-default
    environment: prod
  spec:
    path: /etc/nginx/sites-available/default
    mode: "0644"
    owner: root
    content: |
      server { listen 80; root /var/www/html; }
  ```

### `systemd.unit`

```yaml
kind: systemd.unit
spec:
  name: nginx              # service name without .service suffix
  state: present           # present|absent
  enabled: true            # systemctl enable / disable
  active: true             # systemctl start / stop
  unit_file: |             # OR unit_file_from: <path>
    [Unit]
    Description=...
    [Service]
    ExecStart=/usr/sbin/nginx -g 'daemon off;'
```

* **Allowlist:** section `systemd:` (name globs, allow-only); identifier = unit name (e.g. `nginx`)
* **Pitfalls:** `enabled` and `active` are independent — `enabled:
  true` without `active: true` configures auto-start at boot but
  doesn't start the service now. Reload triggers (`systemctl
  daemon-reload`) fire only when `unit_file` content changes; not on
  `enabled`/`active` toggles. `name` must not include `.service`.
* **Sample:** see `service` composite — it wraps `file` + `systemd.unit`.

### `package`

```yaml
kind: package
spec:
  name: nginx
  state: present           # present|absent|latest
```

* **Allowlist:** section `packages:` (name globs, allow-only); identifier = `spec.name`
* **Pitfalls:** Backend autodetect (apt → dnf → pacman) reads
  `/etc/os-release`; on bespoke distros the agent may pick the wrong
  backend. State `latest` runs an upgrade on every apply — use it
  sparingly to avoid surprise upgrades during canary rollouts. No
  version pinning yet (Phase 8 backlog).

### `docker.container`

```yaml
kind: docker.container
spec:
  name: web
  image: nginx:1.27
  ports: ["80:80"]                     # ["host:container", ...]
  env:
    NGINX_HOST: "example.com"
  volumes: ["/var/www:/usr/share/nginx/html:ro"]
  restart: unless-stopped              # docker --restart=
  state: present
```

* **Allowlist:** section `docker:` (name globs, allow-only); identifier = `spec.name`
* **Pitfalls:** Image tag changes trigger a recreate, not a rolling
  update — accept downtime or front it with a load balancer. Drift
  detection compares image, env, and port mappings via `docker
  inspect`; volume drift is detected by source path, not contents
  (use `file` for the contents). For multi-container stacks use
  `docker.compose` instead.

### `docker.compose`

```yaml
kind: docker.compose
spec:
  project: web-stack       # docker-compose project name
  state: present           # present|absent
  source: |                # inline compose YAML
    services:
      app:
        image: nginx:1.27
        ports: ["8080:80"]
  env_file: /etc/iac/web.env  # optional, --env-file
  workdir: /var/lib/iac/compose  # optional override
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** Project name is restricted to `[a-z0-9_-]+` (mirrors
  docker's own validation). The full source is hashed (sha256) for
  drift detection — a whitespace-only change re-applies the stack.
  We materialise the compose file at `<workdir>/<project>/docker-compose.yml`;
  operators can `cd` there for ad-hoc `docker compose ps` debugging.
  Per-service health checks belong inside the compose YAML (Docker
  natively manages them); we don't surface them as IaC drift.
* **Sample:**

  ```yaml
  apiVersion: iac.example/v1
  kind: docker.compose
  metadata: { name: web-stack, environment: prod }
  spec:
    project: web-stack
    source: |
      services:
        web: { image: nginx:1.27, ports: ["80:80"] }
        cache: { image: redis:7, restart: unless-stopped }
  ```

### `nginx.vhost`

```yaml
kind: nginx.vhost
spec:
  name: example
  server_name: example.com
  upstream: 127.0.0.1:8080
  state: present
```

* **Allowlist:** section `nginx_vhost:` (path globs); identifier = `spec.config_path`
* **Pitfalls:** Rendered into `/etc/nginx/sites-available/<name>` and
  symlinked to `sites-enabled/`. Service reload (`nginx -s reload`) is
  only triggered when the rendered content changes. To customise the
  template (TLS, custom headers) use `file` + `systemd.unit`
  directly — the vhost provider intentionally doesn't expose every
  knob.

### `cron.job`

```yaml
kind: cron.job
spec:
  name: backup
  schedule: "0 3 * * *"    # 5-field crontab
  command: "/usr/local/bin/backup.sh"
  user: root
  state: present
```

* **Allowlist:** section `cron:` (name globs, allow-only); identifier = `spec.name`
* **Pitfalls:** Writes to `/etc/cron.d/iac-<name>` with a tag header
  so a hand-edit (or another tool's edit) is safe. Schedule uses the
  classic 5-field syntax (no `@yearly` / seconds). Command runs
  through `/bin/sh -c` — quote env-var expansions carefully.

### `firewall.rule` (iptables)

```yaml
kind: firewall.rule
spec:
  name: allow-https        # used as the iptables comment tag
  chain: INPUT
  action: ACCEPT
  protocol: tcp
  destination_port: 443
  state: present
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** Uses iptables `-m comment --comment "iac:<name>"` for
  identity — comments are how we find our rules on next observe.
  Survives `iptables -F` because we re-apply on observe; doesn't
  survive a kernel reboot unless you persist via your distro's tooling
  (`iptables-persistent` on Debian, `firewalld` permanent rules on
  RHEL — IaC doesn't manage that today). nftables backend is on the
  Phase 8 roadmap.

### `monitoring.check`

```yaml
kind: monitoring.check
spec:
  type: http               # http|tcp
  target: http://localhost:8080/healthz
  expected_status: 200     # http only
  timeout_secs: 5
  retries: 5               # Phase 7cj: retry on failure
  retry_interval_secs: 2
  state: present
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** `apply` actively runs the probe (it's a verification
  step, not just a config record). Pure `std::net` HTTP/1.0 — no
  HTTPS support in v1; for TLS targets place a local non-TLS
  liveness endpoint behind your TLS terminator. Failure after
  retries cancels the baseline rollout (canary gating). Set
  `retries`/`retry_interval_secs` based on how long the upstream
  takes to warm up — too aggressive triggers false-negative
  rollbacks during app startup.

### `sysctl.setting`

```yaml
kind: sysctl.setting
spec:
  key: net.ipv4.tcp_keepalive_time
  value: "120"
  state: present
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** Writes to `/etc/sysctl.d/iac-<name>.conf` then runs
  `sysctl -p <file>`. Some keys (e.g. `net.bridge.*`) require the
  matching kernel module to be loaded first — IaC won't load it
  for you. Quote the value as a string even when numeric (YAML's
  type coercion bites on values like `0644`).

### `dns.record`

```yaml
kind: dns.record
spec:
  zone: example.com
  name: app                # relative to zone, FQDN, or '@' for apex
  type: A                  # A|AAAA|CNAME|TXT|MX
  value: "1.2.3.4"
  ttl: 300                 # seconds, ≥30
  state: present
  provider: cloudflare     # only backend in Phase 7cx
  cloudflare:
    api_token: "${secret://env/CF_API_TOKEN}"
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** Identity for upserts is `(zone, name, type)`. Multiple
  records with identical name+type (round-robin A, multiple TXT) are
  not modelled — declare them under separate manifests with distinct
  `metadata.name` if your backend de-duplicates server-side.
  Type-specific value validation is enforced client-side: `A` rejects
  non-IPv4, `CNAME` requires a hostname shape. `ttl < 30` is rejected
  upfront — most providers reject anyway.
* **Sample:**

  ```yaml
  apiVersion: iac.example/v1
  kind: dns.record
  metadata: { name: app-a, environment: prod }
  spec:
    zone: example.com
    name: app
    type: A
    value: "203.0.113.10"
    ttl: 300
    provider: cloudflare
    cloudflare: { api_token: "${secret://env/CF_API_TOKEN}" }
  ```

### `acme.certificate`

```yaml
kind: acme.certificate
spec:
  domains: ["example.com", "www.example.com"]
  email: ops@example.com
  cert_dir: /etc/iac/certs/example.com
  state: present
  renew_window_days: 30                # 1..=89
  staging: false                       # use Let's Encrypt staging
  challenge: http-01                   # http-01 | dns-01-cloudflare
  webroot: /var/www/html               # required for http-01
  cloudflare_api_token: "${secret://env/CF_API_TOKEN}"  # for dns-01-cloudflare
```

* **Allowlist:** no per-kind section — falls through to `default_kind_policy`
* **Pitfalls:** First domain is the CN; the rest are SANs. Wildcards
  (`*.example.com`) require `challenge: dns-01-cloudflare` — HTTP-01
  can't validate a literal `*` hostname. Cert/key files land at
  `<cert_dir>/<primary>.crt` and `<cert_dir>/<primary>.key`; chain
  with `nginx.vhost` (or your TLS terminator) by referencing those
  paths. Auto-renew triggers when expiry is within `renew_window_days`.
  Staging mode is the right first move when wiring a new zone — the
  ACME prod rate-limits are unforgiving.
* **Sample:**

  ```yaml
  apiVersion: iac.example/v1
  kind: acme.certificate
  metadata: { name: example-com-cert, environment: prod }
  spec:
    domains: ["example.com", "www.example.com"]
    email: ops@example.com
    cert_dir: /etc/iac/certs/example.com
    challenge: dns-01-cloudflare
    cloudflare_api_token: "${secret://env/CF_API_TOKEN}"
  ```

### Composites

`kind: service` expands server-side into `docker.container` + optional
`nginx.vhost` + optional `monitoring.check`. Keeps manifests concise:

```yaml
kind: service
spec:
  name: web
  image: nginx:1.27
  ports: ["80:80"]
  domain: example.com
  health_path: /healthz
```

Operators can also declare custom composites under `[[modules]]` in
`server.toml` (Phase 7bv): a TOML template + `{{ var }}` scalar
substitution. See `crates/iac-controlplane/src/modules.rs` for the
template surface.

## Custom providers

Agents add new resource kinds without rebuilding the binary. Two
extension points cover most operator needs — pick the simpler one
that fits.

### Plugin trust model

> **Plugins run with the agent's full UID-level privileges.**
> A malicious or buggy plugin can read the agent's identity file
> (`<state_dir>/identity.json` — your control-plane credentials),
> rewrite the agent's database, exfiltrate any resource that ever
> passed through `observe`, and exec arbitrary binaries.
> **Treat plugin binaries the same way you treat the agent binary
> itself.** Use the same provenance, sign-off, and pinning machinery.

What the runtime *does* enforce:

* **WASM plugins** run inside wasmtime with hard CPU (fuel) and
  memory caps and no I/O imports unless the operator opts in
  via `[wasi]`. The sandbox boundary is real — a WASM plugin
  cannot escape it without a wasmtime CVE.
* **External-process plugins** are subject to call timeouts,
  NDJSON line caps (16 MiB), and a restart cool-off after
  consecutive crashes. Within those limits the plugin still
  runs as the agent's UID and inherits the agent's filesystem
  access.
* **Shellout plugins** get per-command timeouts and zombie
  reaping. Same UID-level trust as external-process.

What the runtime does **not** do (operator's responsibility):

* **Plugin binary integrity.** Use `module_sha256` /
  `binary_sha256` config fields to pin SHA-256 of the plugin
  artifact. Without a pin, an attacker who can write to the
  plugin's path on the agent host can swap the binary and the
  agent will load whatever's there. Pin hashes via your config-
  management of choice (Ansible, Chef, Salt, GitOps).
* **OS-level isolation.** The agent does not spawn plugins
  under separate UIDs / namespaces / cgroups. If you need
  per-plugin isolation, run the agent inside a systemd user
  service with its own UID, or wrap the whole agent in a
  container. This is platform integration work, not something
  the agent does for you.
* **Plugin egress control.** The runtime can restrict WASI
  network/filesystem capabilities, but external-process and
  shellout plugins inherit the agent's network. If a plugin
  must NOT reach the public internet, that's a network-policy
  / firewall job at the OS / cluster level.

### Recommended hygiene checklist

1. **Pin every plugin binary's SHA-256** in `agent.toml`. Update
   pins through your normal config-change-management flow.
2. **Run the agent under a dedicated UID** (not root) if the
   resources it manages don't require root. Most providers
   work fine as a non-privileged user with sudo for specific
   commands.
3. **Use WASM component plugins** (with `[wasi]` opt-in) for
   anything you don't fully control — community plugins, vendor-
   shipped extensions, anything you didn't write yourself. The
   sandbox is a real boundary; the other runtimes aren't.
4. **Audit `agent.toml`** the same way you audit the agent
   binary — it controls what code the agent will load and run.

### Shell-out providers (`[[shellout_providers]]`)

Wrap an existing CLI in three small shell scripts. Right tool when
the underlying operation is already exposed as a one-shot command
(`iptables`, `ufw`, a vendor's REST CLI, an in-house Python tool).

```toml
# agent.toml
[[shellout_providers]]
kind = "ufw.rule"                              # required, unique
observe = "/usr/local/bin/iac-ufw observe"     # required
apply   = "/usr/local/bin/iac-ufw apply"       # required
verify  = "/usr/local/bin/iac-ufw verify"      # optional; falls back to re-observe
rollback = "/usr/local/bin/iac-ufw rollback"   # optional; falls back to re-apply prior spec
capability_keys = ["{{ name }}"]               # `{{ field }}` pulls top-level scalars from spec
env = ["UFW_DEBUG=1"]                          # additive — inherited env preserved
timeout_secs = 30                              # 1..=600
```

**Wire protocol** (stdin → stdout, one JSON object each):

* `observe` ← `{ kind, metadata, spec }` → `{ present: bool, spec? }`
* `apply` ← `{ kind, metadata, spec, phase: "create"|"update"|"delete" }` → `{ status: "ok"|"failed", message? }`
* `verify` ← same as observe → same as observe (used to assert post-apply state)
* `rollback` ← `{ kind, metadata, checkpoint }` → empty body, exit 0 = success

The agent automatically derives `diff` by comparing `spec` byte-for-byte
against `observed.spec` (with `state: absent` triggering Delete) — your
script never sees a diff request. Capability keys come from rendering
the templates above against top-level scalar fields of the resource's
`spec`.

Tradeoff: per-call spawn cost (~1–5 ms on a slow CPU) and limited
diff granularity (top-level only). For chatty upstreams or
structured field comparison, use external-process providers.

### External-process plugin providers (`[[external_providers]]`)

A long-running plugin binary speaks NDJSON-RPC over stdin/stdout.
Right tool when the upstream needs persistent state — connection
pools, auth tokens, caches — that would be expensive to rebuild on
every call (Kubernetes API, AWS SDK, gRPC services).

```toml
# agent.toml
[[external_providers]]
kind = "k8s.deployment"
binary = "/usr/local/bin/iac-k8s-plugin"      # required, absolute path
args = ["--cluster", "prod"]                   # optional, prepended to argv
env = ["KUBECONFIG=/etc/iac/kc"]               # optional
restart_on_crash = true                        # default true
handshake_timeout_secs = 5                     # 1..=60
call_timeout_secs = 60                         # 1..=3600
```

**Lifecycle:**

1. Agent spawns the binary with stdin/stdout piped.
2. Plugin emits one JSON line on stdout — the **hello message**:
   ```json
   {"hello":{"protocol_version":1,"kind":"k8s.deployment","capability_keys":["{{ name }}"],"methods":["observe","apply","diff","verify"]}}
   ```
   `kind` must match the agent's config (defence in depth — catches
   binary/config drift). `methods` enumerates which optional methods
   the plugin opts into; the agent supplies fallbacks for the rest.
3. Agent then drives a request/response loop on the plugin's stdin/stdout:
   * Request: `{"id":<u64>, "method":"<name>", "params":{...}}`
   * Response: `{"id":<u64>, "result":{...}}` or `{"id":<u64>, "error":"..."}`

**Required methods:** `observe`, `apply` (same params as the
shellout protocol). The agent always falls back for `diff`,
`verify`, `rollback`, `pre_apply` unless the plugin explicitly
lists them in `hello.methods`.

**Crash recovery:** if `restart_on_crash` is true (default), the
agent transparently respawns the binary on the next call after a
transport error. Plugins should keep durable state on disk (not
in-memory) since the runtime can restart them at any boundary.

**Trust model:** the plugin runs as the agent's UID with full
filesystem access. Operators ship plugins they trust, just like
the agent binary itself. Pin binary hashes via your distribution
mechanism if you need integrity.

### Sandboxed WASM plugin providers (`[[wasm_providers]]`)

A `.wasm` module loaded into a wasmtime sandbox. Right tool for
less-trusted code (community marketplace, third-party vendors,
plugins from a partner who shouldn't have host filesystem access)
and for reproducible cross-platform delivery (one `.wasm`, identical
on linux/macos/windows).

```toml
# agent.toml
[[wasm_providers]]
kind = "ufw.rule"
module = "/usr/local/share/iac/plugins/ufw.wasm"  # absolute path
max_memory_bytes = 16777216                       # 16 MiB, default 16 MiB; range 64 KiB..=1 GiB
fuel_per_call = 100_000_000                       # ~100M instructions, default 100M
```

**ABI v1.** A WASM plugin must export:

* `memory: memory` — its linear memory.
* `iac_alloc(size: i32) -> i32` — allocate scratch space; host stages the JSON envelope here.
* `iac_dealloc(ptr: i32, size: i32)` — release a buffer.
* `iac_kind() -> i64` — packed `(ptr<<32) | len` of the module's kind. Validated against config.
* `iac_observe(ptr: i32, len: i32) -> i64` — required.
* `iac_apply(ptr: i32, len: i32) -> i64` — required.

Optional, opted into by exporting `iac_methods() -> i64` returning a JSON-array string of method names: `iac_diff`, `iac_verify`, `iac_rollback`, `iac_pre_apply`, `iac_capability_keys`. Anything not opted into uses the host's fallback (same behaviour as shellout / external-process).

**Sandbox model.**

* No WASI. The plugin sees no filesystem, environment, or network.
* `max_memory_bytes` caps `memory.grow` — exceeding it traps the guest.
* `fuel_per_call` decrements roughly once per instruction; runaway loops trap before they melt the host.
* The host imports exactly one helper: `iac.log(ptr, len)` — pipe operator-visible diagnostics through the agent's `tracing` pipeline.

**Each top-level method call gets a fresh `Store`** with full fuel budget — a previous call's overrun can't poison the next one. Plugins that need persistent state must store it outside the module (e.g. in a host-managed file the agent owns).

**Writing a plugin in Rust.** Build with `cargo build --release --target wasm32-unknown-unknown`; export the ABI via `#[no_mangle] pub extern "C" fn iac_observe(...) -> i64 { ... }`. A minimal scratchpad allocator is fine — see [`crates/iac-providers/src/wasm/runtime.rs`](crates/iac-providers/src/wasm/runtime.rs) tests for an end-to-end WAT example.

#### Component-model variant (`runtime = "component"`)

The `core` ABI above is fine for hand-written plugins, but managing
ptr/len pairs and JSON envelopes manually gets tedious fast. Phase
7dd adds a typed alternative: switch `runtime = "component"` and
your plugin works against a strongly-typed WIT interface instead.

```toml
[[wasm_providers]]
kind = "ufw.rule"
module = "/usr/local/share/iac/plugins/ufw.component.wasm"
runtime = "component"                       # opt in
max_memory_bytes = 16777216
fuel_per_call = 100_000_000
```

**WIT interface** (canonical source: [`crates/iac-providers/wit/plugin.wit`](crates/iac-providers/wit/plugin.wit)):

```wit
package iac:plugin@0.1.0;

interface provider {
    record metadata { name: string, environment: string,
                      labels: list<tuple<string, string>>,
                      annotations: list<tuple<string, string>> }
    record observed { present: bool, spec-json: string }
    record apply-outcome { ok: bool, message: string }
    enum phase { create, update, delete }

    kind: func() -> string;
    methods: func() -> list<string>;
    observe: func(metadata: metadata, spec-json: string) -> result<observed, string>;
    apply: func(metadata: metadata, spec-json: string, phase: phase) -> apply-outcome;
    capability-keys: func(metadata: metadata, spec-json: string) -> list<string>;
}

world plugin { export provider; }
```

**Author surface (Rust).** Drop in [`wit-bindgen`](https://crates.io/crates/wit-bindgen) and write:

```rust
wit_bindgen::generate!({ world: "plugin", path: "wit/plugin.wit", generate_all });

use exports::iac::plugin::provider::{
    ApplyOutcome, DiffKind, DiffResult, Guest, Metadata, Observed, Phase, VerifyOutcome,
};

struct MyPlugin;
impl Guest for MyPlugin {
    fn kind() -> String { "ufw.rule".into() }
    fn methods() -> Vec<String> { vec![] }  // or ["diff", "verify", "pre-apply", "rollback"]
    fn observe(m: Metadata, spec: String) -> Result<Observed, String> { /* ... */ }
    fn diff(m: Metadata, spec: String, observed: Observed) -> DiffResult { /* ... */ }
    fn pre_apply(m: Metadata, spec: String) -> Result<String, String> { /* checkpoint JSON */ }
    fn apply(m: Metadata, spec: String, phase: Phase) -> ApplyOutcome { /* ... */ }
    fn verify(m: Metadata, spec: String) -> VerifyOutcome { /* ... */ }
    fn rollback(m: Metadata, checkpoint: String) -> Result<(), String> { /* restore */ }
    fn capability_keys(m: Metadata, _: String) -> Vec<String> { vec![m.name] }
}
export!(MyPlugin);
```

Build with [`cargo-component`](https://github.com/bytecodealliance/cargo-component) (recommended) or `cargo build --target wasm32-unknown-unknown` followed by `wasm-tools component new`. Either way you ship a single `.component.wasm` artifact.

**Optional methods.** All trait methods are mandatory at the *Rust* level (the `Guest` impl must implement every signature wit-bindgen generates) but only the methods you list in `methods()` are *called* by the host. Recognised opt-in names: `"diff"`, `"verify"`, `"pre-apply"`, `"rollback"`. Each non-listed method gets a host fallback:

| Method      | Host fallback when not opted in |
|-------------|---------------------------------|
| `diff`      | spec-equality byte compare      |
| `verify`    | re-observe + diff               |
| `pre-apply` | snapshot prior observed state   |
| `rollback`  | re-apply prior observed spec    |

**Why opt in?** The host's spec-equality diff is fine for record-shaped resources but loses precision when observed state is *derived* (a checksum vs. literal content, a normalised representation vs. the user's input). Plugins that own that nuance return structured `DiffResult` values directly — the host wraps them verbatim, no JSON round-trip on the wire.

**Typed pre-apply / rollback.** When opted in, `pre-apply` returns a JSON-encoded *checkpoint string* the host stores opaquely. The host doesn't peek inside; on rollback it hands the same string back to the plugin's `rollback`. This keeps the checkpoint shape entirely in the plugin's hands — operators don't have to design a host-shaped schema for plugin state. WIT signature:

```wit
pre-apply: func(metadata: metadata, spec-json: string) -> result<string, string>;
rollback: func(metadata: metadata, checkpoint-json: string) -> result<_, string>;
```

The bytes round-trip verbatim. Plugins that need richer rollback semantics (multi-step, idempotent retries) own that logic — the host is just the byte-pipe.

**Same sandbox, same lifecycle.** Fuel limits, memory caps. By default no I/O — identical to the core variant. Component plugins can opt into capability-driven I/O via the `[wasi]` block (next section).

**Reference fixture.** [`crates/iac-providers/tests/fixtures/test-plugin/`](crates/iac-providers/tests/fixtures/test-plugin/) is a complete working component plugin in ~50 lines of Rust — copy it as a starting point.

#### WASI preview2 capabilities

Component-model plugins (and only component-model — the core ABI doesn't carry preview2 imports) can opt into capability-driven I/O. The default is no WASI surface at all; everything below is opt-in.

```toml
[[wasm_providers]]
kind = "policy.engine"
module = "/srv/iac/policy.component.wasm"
runtime = "component"

[wasm_providers.wasi]
env = ["LOG_LEVEL=info"]
inherit_stdout = false       # default false — drop guest stdout
inherit_stderr = false
allow_network = false        # default false — no sockets / dns

[[wasm_providers.wasi.preopens]]
host = "/var/lib/iac/policy/state"
guest = "/state"
writable = true              # default false — read-only

[[wasm_providers.wasi.preopens]]
host = "/etc/iac/policy.d"
guest = "/policies"
# writable defaults to false → read-only mount
```

**Capability semantics.**

* **Preopens.** Each entry maps a host directory to a guest path. The plugin sees `/state` (or whatever guest path) as a root and can `std::fs::read_dir`, `read_to_string`, etc. underneath. *No* host paths are accessible — the plugin can't `..` its way out, can't open arbitrary files, can't even see other preopens unless they're declared.
* **Read-only by default.** `writable = true` is required for any write. The pattern `read /etc/iac/<plugin>/config + write /var/lib/iac/<plugin>/state` is what we recommend.
* **Env.** Listed explicitly; the plugin does NOT inherit the agent's environment. Pass only what the plugin needs.
* **Stdio.** Off by default. Plugin output goes nowhere. The agent's `tracing` pipeline (via `iac.log` or wit-bindgen-generated logging) is the structured path.
* **Network.** Off by default. When opted in, the plugin sees a wasi-sockets surface. **Plugins that genuinely need outbound network are usually better served by external-process providers** — but for vendor-shipped components that need it, this is the knob.

**Build target.** Plugins that use WASI must target `wasm32-wasip2`:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

The output is already a component (no `wasm-tools component new` step needed). Plugins that don't use WASI can still target `wasm32-unknown-unknown` and componentise post-build via `cargo-component` or `wasm-tools`.

**Fail-closed.** If a plugin's component imports `wasi:filesystem` but the operator forgot the `[wasi]` block (or set `preopens = []`), instantiation fails at agent startup with a clear "missing import" error. Operators get a loud signal, not silent malfunction.

**Reference fixture.** [`crates/iac-providers/tests/fixtures/wasi-plugin/`](crates/iac-providers/tests/fixtures/wasi-plugin/) reads a host-preopened file via `std::fs` and reflects the contents back through `observe`. Starting point for plugins that need filesystem state.

### When to pick which

| Need                                            | shellout | external-process | wasm |
|-------------------------------------------------|:-------:|:----------------:|:----:|
| Wrap an existing CLI                            | ✅      |                  |      |
| Per-resource latency dominated by spawn cost    |         | ✅               | ✅   |
| Persistent in-memory state across calls         |         | ✅               |      |
| Custom diff / structured field-by-field         |         | ✅               | ✅   |
| Untrusted / third-party plugin code             |         |                  | ✅   |
| Hard CPU + memory limits on the plugin          |         |                  | ✅   |
| Cross-platform single artifact                  |         |                  | ✅   |
| Author lacks experience with read/write loops   | ✅      |                  |      |
| Adding 12 trivial kinds quickly                 | ✅      |                  |      |

All three extension points override built-ins when their `kind`
collides — the agent logs the override and uses the dynamic one.
Duplicate kinds *across* the three sources are rejected at config
load time.

## RBAC

Three identity classes share one bearer-token auth:

* **`LegacyAdmin`** — the static `admin_token` from `server.toml`.
  Equivalent to `Admin` role. Useful for bootstrap; rotate
  out via real users in production.
* **`User`** — created via `iac users create`, stored hashed
  (Argon2id) in the DB. Roles attached on creation.
* **`Agent`** — programmatic identity, registered via
  `POST /v1/agents/register`. Cannot do operator-level actions.

Roles form an inclusion lattice: `Viewer < Operator < Approver < Admin`.

```bash
iac users create --server <url> --user alice --role operator
iac users create --server <url> --user bob   --role approver
iac users create --server <url> --user root  --role admin
```

`Operator` can submit ops, `Approver` can also approve gated ops,
`Admin` can also rotate signing keys, manage users, and edit policies.

## Policies + approval gates

Policies match operations by environment/kind/resource count and can
require approval, set per-policy rate limits, and restrict approvers:

```toml
[[policies]]
name = "prod-requires-approval"
match.environment = "prod"
match.resource_count_min = 1
requires_approval = true
approvers = ["bob", "charlie"]

[[policies]]
name = "prod-rate-limit"
match.environment = "prod"
rate_limit_per_minute = 5
```

A `requires_approval` operation lands in `pending_approval` status.
Approvers see it via `iac plan --server <url> --operation <id>`,
review the planned diff, then `iac approve <op-id> --server <url>`.

## Canary rollouts

```bash
iac apply manifests/ --server <url> --environment prod \
                     --canary-pct 25 --yes
```

Within each layer (Phase 7by dependsOn), 25% of agents go in batch 0
(canary), the rest in batch 1 (baseline). Canary dispatches
immediately; baseline waits in `pending_canary`. Any failure in
canary cancels both the rest of canary AND all baseline. Compose
with `monitoring.check` in the canary resource list for active
health gating:

```yaml
- kind: file
  metadata: { name: app-config, dependsOn: [] }
- kind: docker.container
  metadata: { name: app, dependsOn: [file/prod/app-config] }
- kind: monitoring.check
  metadata: { name: app-health, dependsOn: [docker.container/prod/app] }
  spec:
    type: http
    target: http://localhost:8080/health
    retries: 5
    retry_interval_secs: 2
```

If `monitoring.check` fails after retries, the assignment fails →
canary fails → baseline cancelled.

## GitOps

```bash
# CI gate on every PR
iac plan --git-repo $REPO --git-ref $PR_SHA \
         --git-path manifests/ --server $URL

# After merge
iac apply --git-repo $REPO --git-ref main \
          --git-path manifests/ --server $URL \
          --canary-pct 25 --yes
```

The CLI clones (`git fetch --depth=1`), resolves the ref to a 40-char
SHA via `git rev-parse FETCH_HEAD`, checks it out detached, and
records the SHA as `source_commit`. Per-repo cache under
`$XDG_CACHE_HOME/iac-cli/git/` so reruns are fast. Auth comes from
the system git config (`~/.gitconfig`, `GIT_SSH_COMMAND`, GitHub
Actions' `GITHUB_TOKEN`).

## Rollback

```bash
iac rollback <operation-id> --server <url> \
             --reason "incident-1234" \
             --canary-pct 50
```

Builds a new operation with each resource's most-recent-prior
successful spec. Goes through the normal pipeline (policy + approval
+ canary). Resources without a prior state (first-applied in the
rolled-back op) come back as `orphaned` — operator deletes those
manually.

## Observability

### Prometheus metrics

`GET /metrics` (no auth). Exports operation counters, agent fleet
size, drift counts, rate-limit rejections, signing-key info, etc.
Standard Prometheus exposition format.

### Audit log

```bash
iac audit --server <url> --kind operation.submitted --limit 50
iac audit --server <url> --actor admin --limit 100
iac audit --server <url> --operation-id <id>
iac audit --server <url> --agent-id <id>
```

Filters are exact-match per field — there is no server-side
time-window narrow. Pull a recent batch with `--limit`, then narrow
client-side with `jq` if you need a `since`-style filter; the
endpoint returns rows newest-first.

Every state-changing call appends a row. Events:
`operation.{submitted,approved,rejected,failed,succeeded,partially_applied,
rollback_initiated}`,
`agent.{registered,token_rotated,heartbeat_lost}`, `drift.{detected,
accepted,reverted}`, `signing.key_{rotated,retired}`,
`maintenance.window_{entered,exited}`, etc.

## SSH push (agent-less targets)

For hosts where you can't run a long-running `iac-agent` daemon —
embedded network gear, vendor appliances, contractor environments
where security policy bans daemons — declare them as `[[ssh_targets]]`
in `server.toml`. The control plane treats them as virtual agents
(routing, canary, rollback all work the same), but instead of
waiting for them to poll, a push worker SSHes to each one as
assignments arrive.

```toml
[[ssh_targets]]
name           = "edge-router-01"
environment    = "edge"
host           = "10.0.0.1"
user           = "admin"
identity_file  = "/etc/iac/ssh/edge.key"   # SSH key auth only
remote_iac_path = "/usr/local/bin/iac"     # must be pre-installed
capabilities   = ["file", "sysctl.setting"] # allowlist; empty = any
connect_timeout_secs = 10
```

Prerequisites on each target:
1. SSH key in `~admin/.ssh/authorized_keys` (the `identity_file`'s
   public counterpart).
2. The `iac` binary at `remote_iac_path`. On Ubuntu:
   `curl -L https://example.com/iac-aarch64 > /usr/local/bin/iac && chmod +x ...`
3. The user has whatever privileges the assignment needs (root for
   `file` writing to `/etc`, etc). `sudo` is not auto-invoked.

Operator-side use is identical to a pull-mode agent — same `iac
apply` with `hostSelector.name: edge-router-01`. The SSH worker
pool dispatches transparently.

Audit log entries: `ssh.push_succeeded`, `ssh.push_partial`,
`ssh.push_failed`. Actor is `ssh-push:<target_name>`.

Trade-offs vs pull-mode agents:
* No NAT traversal — the control plane must reach the target.
* Credentials in the control plane (SSH key) — wider blast radius
  if it's compromised.
* No agent-side capability enforcement — only the server-side
  `capabilities = [...]` allowlist applies.

Use pull-mode for the bulk of fleet; reserve SSH push for hosts
where you have no choice.

## Direct CLI SSH apply (Phase 7cl)

For one-off operator-driven deploys without a server — the
ad-hoc Ansible-style mode. `iac apply` opens an SSH connection,
pipes the assignment payload to a remote `iac apply
--assignment-stdin` invocation, and parses the result locally.
No control plane needed; no `[[ssh_targets]]` config; no agent
daemon on the target.

```bash
# Single target:
iac apply manifest.yaml --ssh admin@host.example \
                        --ssh-key ~/.ssh/iac-admin

# Multi-host fan-out via inventory:
iac apply manifests/ --inventory hosts.yaml \
                     --group webservers \
                     --ssh-key ~/.ssh/iac-admin
```

Prerequisites on the target:
- SSH key auth (the public key in `~admin/.ssh/authorized_keys`).
- The `iac` binary at `--ssh-remote-iac` (default
  `/usr/local/bin/iac`). Pass `--auto-bootstrap` to scp the local
  binary up if it's missing AND the target architecture matches.

Trade-offs vs SSH push (server-driven):
* No audit log on the control plane — the local `iac` writes a
  per-invocation NDJSON line to `<state_dir>/run-history.jsonl`
  instead. Read it back via `iac history`.
* No RBAC / approval / canary gating — operator is the trust root.
* No retries — one connection, one apply.

Use this for break-glass fixes and small one-shot changes. For
anything that wants an audit trail, route through the control plane
(pull-mode agent or SSH push).

## Maintenance windows

Pause non-emergency apply during change-freeze periods:

```toml
[[maintenance_windows]]
start    = "2026-12-24T00:00:00Z"
end      = "2027-01-02T00:00:00Z"
reason   = "holiday freeze"

[[recurring_maintenance_windows]]
days     = ["Sat", "Sun"]
start_time = "00:00"
end_time   = "23:59"
timezone   = "America/New_York"
reason     = "weekend freeze"
```

Submit during a window → 503 with `Retry-After`. Override with
`X-IAC-Maintenance-Bypass: yes` (admin only).

## Drift workflows

```bash
iac drift --server <url> list                          # show open drifts
iac drift --server <url> accept <drift-id> --reason X  # accept as known
iac drift --server <url> ignore <drift-id> --until 1h  # silence for N {s|m|h|d}
iac drift --server <url> revert <drift-id> --reason X  # re-apply prior state
iac drift --server <url> accept-bulk --agent-id <id> --reason X
iac drift --server <url> ignore-bulk --agent-id <id> --until 24h --reason X
```

Agents push drift on every observe cycle. Drift not in the latest
push auto-closes (assumed converged externally).

## Server signing key rotation

```bash
# Rotate (active key changes; old stays in verification set)
curl -X POST https://iac.example.com:8443/v1/admin/signing-keys/rotate \
     -H "Authorization: Bearer $ADMIN_TOKEN"

# Wait until all agents have re-fetched the bundle (Phase 7cf
# multi-key verification), then retire the old key.
curl -X POST https://iac.example.com:8443/v1/admin/signing-keys/<old-id>/retire \
     -H "Authorization: Bearer $ADMIN_TOKEN"
```

Agent-side bundle refresh happens on every reconnect; with continuous
agents you can retire safely after one full poll cycle.

## Performance + capacity

Stress harness in [crates/iac-controlplane/tests/stress.rs](../crates/iac-controlplane/tests/stress.rs).
Run with:

```bash
IAC_STRESS=1 IAC_ASSIGNMENT_LEASE_SECS=5 \
  cargo test -p iac-controlplane --test stress -- --nocapture
```

Observed envelope (developer laptop, single-process SQLite):

| Fleet     | Ops × Resources | Submit p99 | Drain time |
|-----------|-----------------|-----------:|-----------:|
| 3 agents  | 5 × 2           | 150 ms     | 2 s        |
| 10 agents | 20 × 3          | 263 ms     | 24 s       |
| 30 agents | 15 × 5          | 447 ms     | 40 s       |

SQLite ceiling: ~100 agents or ~5 ops/sec sustained. For larger
fleets, switch `database_url` to Postgres — wire format identical.

## Postgres deployment

```toml
database_url = "postgres://iac:secret@db.internal:5432/iac?sslmode=require"
```

Run migrations: the server applies them automatically on first
connect (`migrations-postgres/`). Make sure the DB user has
`CREATE TABLE` initially; can be dropped to read/write after the
first successful start.

## Backups

* SQLite: `sqlite3 server.db .dump > backup.sql`. The `state_dir`
  also holds signing keys (`signing-keys/`) — back up the entire
  state_dir.
* Postgres: standard `pg_dump`. State dir signing keys still need
  separate backup.

Restore = restore the DB + state_dir on a fresh server install.
Agents reconnect automatically; no re-registration required.

## Troubleshooting

* **Agent stuck "fetched" assignments after a crash** — Phase 7cj
  added a 60s lease. Wait one minute; the next GET re-claims them.
  Override with `IAC_ASSIGNMENT_LEASE_SECS` for shorter recovery.
* **"server signing bundle has no overlap with pinned keys"** —
  Phase 7cf safety rail. Means the server's signing key set
  fully rotated past what the agent has pinned. Inspect the agent's
  `state_dir/identity.json`, clear `server_pubkeys`, restart agent
  to re-pin (TOFU).
* **Operation stuck in `pending_canary`** — canary batch hasn't
  completed. `iac plan --server <url> --operation <id>` shows
  per-assignment status. If a canary agent is dead, mark the
  assignment failed via DB intervention or wait for the lease to
  recycle and let another agent pick it up if the resource isn't
  hostSelector-pinned.
* **`iac plan --git-repo` fails with auth** — git CLI uses your
  shell environment. Set `GIT_SSH_COMMAND` or
  `GH_TOKEN`/`GITHUB_TOKEN` per your remote. We deliberately don't
  reinvent credential helpers.

## Where to look in the code

* `crates/iac-core/src/protocol.rs` — wire format (single source of
  truth for what server and agent see).
* `crates/iac-controlplane/src/store.rs` — server-side state machine
  (operations, assignments, audit, layers, canary).
* `crates/iac-controlplane/src/api/` — HTTP handlers.
* `crates/iac-agent/src/{agent,remote}.rs` — agent loop + control
  plane client.
* `crates/iac-providers/src/<kind>/` — per-provider lifecycle.
* `crates/iac-controlplane/tests/` — every feature has an e2e test;
  read these as the canonical example for any flow.
