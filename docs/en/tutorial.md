# Getting started

This guide walks a new operator from "I have a host" to "I can apply
desired state, observe drift, and roll back if needed." It covers
local single-host use first (no control plane), then fleet mode.

## Install

### From source (recommended for now)

```bash
git clone https://github.com/<your-fork>/iac
cd iac
cargo build --release --workspace
sudo install -m 0755 target/release/iac /usr/local/bin/
sudo install -m 0755 target/release/iac-agent /usr/local/bin/
sudo install -m 0755 target/release/iac-controlplane /usr/local/bin/
```

The build needs Rust 1.95+. On Debian/Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install -y build-essential libsqlite3-dev pkg-config
```

`iac` is the operator-facing CLI. `iac-agent` is the per-host daemon.
`iac-controlplane` is the central server.

### Verify

```bash
iac --version
```

## Hello, file

The shortest possible end-to-end run uses local mode — no control plane,
no agent, just `iac apply` against the local host. Save this as
`hello.yaml`:

```yaml
apiVersion: iac.example/v1
kind: file
metadata:
  name: hello
  environment: smoke
spec:
  path: /tmp/iac-hello.txt
  mode: "0644"
  content: "hello from iac\n"
```

Plan first to see what would change:

```bash
iac plan hello.yaml
```

Apply:

```bash
iac apply hello.yaml --yes
cat /tmp/iac-hello.txt
# hello from iac
```

Re-running `iac plan` is a no-op now — `iac` knows the file is converged.

## Observing drift

Manually break the state to see drift detection at work:

```bash
echo "tampered" > /tmp/iac-hello.txt
iac plan hello.yaml
```

The plan output will show the file as drifted. `iac apply` re-converges it.

## Rolling back locally

Every successful apply is recorded under `$IAC_STATE_DIR/operations/`
(default `~/.iac/state/operations/`). To roll back the most recent apply:

```bash
iac operations          # list recent op ids
iac rollback <op-id>    # re-applies the previous desired state
```

## Going fleet-wide

Local mode is great for a single host, but the real value is fleet
orchestration. The control plane is one binary, the agent is another.

### Start the control plane

On a control machine (can be the same host while you're learning):

```bash
mkdir -p /var/lib/iac/server
cat >/etc/iac/server.toml <<'EOF'
bind = "0.0.0.0:8443"
database_url = "sqlite:///var/lib/iac/server/server.db?mode=rwc"
state_dir = "/var/lib/iac/server"
admin_token = "change-me-something-long"
[tls]
mode      = "server"
cert_file = "/etc/iac/tls/server.crt"
key_file  = "/etc/iac/tls/server.key"
# For mTLS, set mode = "mutual" and add:
# client_ca_file = "/etc/iac/tls/clients-ca.pem"
EOF

iac-controlplane --config /etc/iac/server.toml
```

For a quick test you can run it on plain HTTP (set `mode = "none"` in
`[tls]` or drop the block entirely, and use `bind = "127.0.0.1:8080"`).

### Register an agent

On a target host:

```bash
mkdir -p /var/lib/iac/agent
cat >/etc/iac/agent.toml <<'EOF'
server_url   = "https://iac.example.com:8443"
state_dir    = "/var/lib/iac/agent"
environment  = "prod"
agent_name   = "vm-web-01"
EOF

iac-agent --config /etc/iac/agent.toml
```

The first run registers the agent and pins the server's signing key (TOFU).
Subsequent runs reuse the persisted identity in `state_dir/identity.json`.

### Submit from the operator side

```bash
# Real users: `iac login` calls POST /v1/auth/login with the password
# you set when you ran `iac users create`. Token is cached in
# ~/.iac/credentials.json (mode 0600).
iac login --server https://iac.example.com:8443 --user admin

# Bootstrap shortcut: skip `iac login` entirely and pass the static
# admin_token from server.toml via the IAC_ADMIN_TOKEN env var. Useful
# until you provision your first real User; not for day-2 operators.
# IAC_ADMIN_TOKEN=... iac apply ...

iac apply manifests/ --server https://iac.example.com:8443 \
                     --environment prod --yes
```

To gate the rollout, add `--canary-pct 25`:

```bash
iac apply manifests/ --server https://iac.example.com:8443 \
                     --environment prod --canary-pct 25 --yes
```

The control plane will dispatch the change to 25% of the agents first, wait
for them to report success, and only then send to the rest. Any failure
in the canary cancels the baseline batch.

### SSH push (instead of an agent on the target)

If you can't run a long-running agent on a target — embedded network
gear, vendor appliance, security policy banning daemons — declare the
host as an `[[ssh_targets]]` block in `server.toml`:

```toml
[[ssh_targets]]
name = "edge-router-01"
environment = "edge"
host = "10.0.0.1"
user = "admin"
identity_file = "/etc/iac/ssh/edge.key"
# Required under the default host_key_policy = "strict". For a dev
# spike you can swap in host_key_policy = "accept_new" instead.
known_hosts_file = "/etc/iac/ssh/known_hosts"
```

The control plane SSHes to such targets when they need a change.
Routing (`hostSelector.name`), canary, rollback, and the audit log
all work transparently. Reload server config with SIGHUP after
adding a target. See [reference.md#ssh-push-agent-less-targets](reference.md#ssh-push-agent-less-targets)
for the full schema, prerequisites, and trade-offs against pull-mode
agents.

For one-off operator-driven SSH apply *without* the control plane —
the Ansible-style break-glass mode — use `iac apply --ssh
user@host` directly. Documented in
[reference.md#direct-cli-ssh-apply-phase-7cl](reference.md#direct-cli-ssh-apply-phase-7cl).

### GitOps

`iac apply` and `iac plan` both accept `--git-repo URL --git-ref REF` to
load manifests from a Git revision instead of a local path. The resolved
SHA is recorded as `source_commit` in the audit log:

```bash
# CI gate (exits 0 if no changes, 2 if changes pending, non-zero on errors)
iac plan --git-repo https://git.example.com/infra.git \
         --git-ref main --git-path manifests/ \
         --server https://iac.example.com:8443

# Merge gate (after PR approval)
iac apply --git-repo https://git.example.com/infra.git \
          --git-ref main --git-path manifests/ \
          --server https://iac.example.com:8443 \
          --canary-pct 25 --yes
```

### Server-side rollback

When an apply turns out to have been a bad idea, roll back the *operation*
(not just the file):

```bash
iac rollback <operation-id> --server https://iac.example.com:8443 \
                            --reason "incident-1234" --canary-pct 50
```

The server walks back one step per resource (most recent prior successful
state) and dispatches it as a fresh operation. Resources that had no prior
state (first-applied in the rolled-back op) are listed as `orphaned` —
operator must delete those manually since the right delete semantic is
provider-specific.

## Next steps

* Read [reference.md](reference.md) for the full provider catalog, config
  schema, RBAC setup, audit log queries, drift workflows, maintenance
  windows, and TLS/mTLS configuration.
* [runbook.md](runbook.md) for the on-call playbook (triage decision
  tree, rollback procedures, common failure modes).
* [architecture.md](architecture.md) for how the pieces fit together
  internally — control plane, agent, dispatcher, signing, layered apply.
* Look at `examples/` for richer manifest patterns (services, monitoring
  checks, dependency graphs).
* Check `crates/iac-controlplane/tests/stress.rs` for the simulated-fleet
  stress harness — useful for benchmarking your own deployment.
