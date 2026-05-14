#!/bin/bash
# Phase 9 fleet bootstrap — ship release binaries, drop config +
# systemd units, start services. Idempotent: re-runs upgrade
# binaries in place without losing state-dir contents.
#
# Run from the iac repo root after `cargo build --release`:
#   ./trial/fleet/bootstrap.sh
#
# Env knobs:
#   RESET_AGENT_STATE=1
#       Wipe each agent's persistent state (agent.db / identity.json)
#       before restart. Use after the CP DB has been recreated from
#       scratch — without it, the agents come up with credentials the
#       new CP doesn't recognise and 401 on every heartbeat. Default
#       is unset (preserves state across upgrades).
#   RESET_CP_STATE=1
#       Same idea on the controlplane side: wipe `server.db*` before
#       restart. Use deliberately — this drops every agent / op /
#       audit row.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

REPO_ROOT="$(cd "$FLEET_DIR/../.." && pwd)"
TARGET_DIR="$REPO_ROOT/target/release"

# Sanity: every binary the fleet needs must exist.
for bin in iac-controlplane iac-agent; do
    if [ ! -x "$TARGET_DIR/$bin" ]; then
        echo "missing $TARGET_DIR/$bin — run 'cargo build --release -p iac-controlplane -p iac-agent -p iac-trial'" >&2
        exit 1
    fi
done
if [ ! -x "$TARGET_DIR/iac-trial" ]; then
    echo "missing $TARGET_DIR/iac-trial (workload generator)" >&2
    exit 1
fi

# Render server.toml from the template, substituting the admin token.
SERVER_TOML="$(mktemp)"
trap 'rm -f "$SERVER_TOML"' EXIT
sed -e "s|__CP_PORT__|$CP_PORT|g" \
    -e "s|__ADMIN_TOKEN__|$ADMIN_TOKEN|g" \
    "$FLEET_DIR/server.toml.tmpl" > "$SERVER_TOML"

# ---- Step 1: controlplane ---------------------------------------

echo
echo "=== bootstrapping controlplane on $CP_IP ==="
say "$CP_IP" "stopping any existing service"
ssh_to "$CP_IP" 'systemctl stop iac-controlplane 2>/dev/null || true'

if [ "${RESET_CP_STATE:-0}" = "1" ]; then
    say "$CP_IP" "RESET_CP_STATE=1 — wiping server.db*"
    ssh_to "$CP_IP" 'rm -f /var/lib/iac-controlplane/server.db /var/lib/iac-controlplane/server.db-wal /var/lib/iac-controlplane/server.db-shm'
fi

say "$CP_IP" "installing binary + config + unit"
ssh_to "$CP_IP" '
    set -eu
    mkdir -p /etc/iac /var/lib/iac-controlplane
    chmod 0755 /var/lib/iac-controlplane
'
scp_to "$TARGET_DIR/iac-controlplane" "$CP_IP" /usr/local/bin/iac-controlplane
# iac-trial runs from the CP (operator launches via fleet-f1-soak.sh, etc.).
# Without this scp the CP keeps whatever binary was placed there manually
# during initial provisioning, so iac-trial fixes never reach the workload
# generator. F1 #10 fix-9 silently no-op'd because of this. Always re-deploy.
scp_to "$TARGET_DIR/iac-trial"        "$CP_IP" /usr/local/bin/iac-trial
scp_to "$SERVER_TOML"                  "$CP_IP" /etc/iac/server.toml
scp_to "$FLEET_DIR/iac-controlplane.service" "$CP_IP" /etc/systemd/system/iac-controlplane.service
ssh_to "$CP_IP" '
    set -eu
    chmod 0755 /usr/local/bin/iac-controlplane /usr/local/bin/iac-trial
    chmod 0600 /etc/iac/server.toml
    systemctl daemon-reload
    systemctl enable iac-controlplane >/dev/null 2>&1
    systemctl start iac-controlplane
'
say "$CP_IP" "started; waiting for /v1/health"
sleep 2
i=0
while [ $i -lt 30 ]; do
    if ssh_to "$CP_IP" "curl -fsS -o /dev/null http://127.0.0.1:$CP_PORT/v1/health"; then
        say "$CP_IP" "/v1/health OK"
        break
    fi
    i=$((i+1))
    sleep 1
done
if [ $i -eq 30 ]; then
    say "$CP_IP" "FAILED to come up; tailing journal"
    ssh_to "$CP_IP" 'journalctl -u iac-controlplane -n 30 --no-pager'
    exit 1
fi

# ---- Step 2: agents (parallel) ----------------------------------

echo
echo "=== bootstrapping agents (parallel) ==="

bootstrap_agent() {
    name="$1"
    ip="$2"
    region="$3"

    say "$ip" "($name, region=$region) installing"
    ssh_to "$ip" 'systemctl stop iac-agent 2>/dev/null || true' || true
    if [ "${RESET_AGENT_STATE:-0}" = "1" ]; then
        say "$ip" "($name) RESET_AGENT_STATE=1 — wiping agent.db + identity.json"
        ssh_to "$ip" 'rm -f /var/lib/iac-agent/agent.db /var/lib/iac-agent/agent.db-wal /var/lib/iac-agent/agent.db-shm /var/lib/iac-agent/identity.json'
    fi
    ssh_to "$ip" '
        set -eu
        mkdir -p /etc/iac /var/lib/iac-agent /var/lib/iac-agent/manifests.d
        chmod 0755 /var/lib/iac-agent
    '

    # Render agent.toml for this host.
    agent_toml="$(mktemp)"
    sed -e "s|__AGENT_NAME__|$name|g" \
        -e "s|__SERVER_URL__|$SERVER_URL|g" \
        "$FLEET_DIR/agent.toml.tmpl" > "$agent_toml"

    scp_to "$TARGET_DIR/iac-agent" "$ip" /usr/local/bin/iac-agent
    scp_to "$agent_toml"            "$ip" /etc/iac/agent.toml
    scp_to "$FLEET_DIR/iac-agent.service" "$ip" /etc/systemd/system/iac-agent.service
    rm -f "$agent_toml"

    ssh_to "$ip" '
        set -eu
        chmod 0755 /usr/local/bin/iac-agent
        chmod 0600 /etc/iac/agent.toml
        systemctl daemon-reload
        systemctl enable iac-agent >/dev/null 2>&1
        systemctl start iac-agent
    '
    say "$ip" "($name) started"
}

# Parallel fan-out. Background each, then wait. Using process
# substitution `< <(...)` instead of a `|` pipe so the loop stays in
# the main shell — `&` jobs spawned inside a pipeline-subshell
# escape the parent's wait list and the script returns before the
# installs finish.
agent_entries=()
while IFS=$'\t' read -r name ip region; do
    agent_entries+=("$name|$ip|$region")
done < <(inventory_hosts agent)

for entry in "${agent_entries[@]}"; do
    IFS='|' read -r name ip region <<< "$entry"
    bootstrap_agent "$name" "$ip" "$region" &
done
wait

# ---- Step 3: registration verification --------------------------

echo
echo "=== verifying registration ==="
sleep 5  # let agents do their first connect_remote
expected=$(inventory_hosts agent | wc -l)

i=0
while [ $i -lt 60 ]; do
    actual=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length' 2>/dev/null || echo 0")
    say "$CP_IP" "registered: $actual / $expected"
    if [ "$actual" -ge "$expected" ]; then
        break
    fi
    i=$((i+1))
    sleep 2
done

if [ "$actual" -lt "$expected" ]; then
    echo "FAIL: only $actual / $expected agents registered after 120s"
    echo "checking each agent's journal:"
    inventory_hosts agent | while IFS="$(printf '\t')" read -r name ip region; do
        echo "--- $name ($ip) ---"
        ssh_to "$ip" 'journalctl -u iac-agent -n 10 --no-pager' || true
    done
    exit 1
fi

echo
echo "=== bootstrap complete ==="
echo "controlplane:  $SERVER_URL"
echo "admin token:   $ADMIN_TOKEN"
echo "agents:        $actual registered"
