#!/bin/bash
# Phase 9-F1-stress-density runner. Invoked by
# `fleet-f1-stress-matrix.sh density`. Bootstraps N agents per VPS
# via the systemd template unit `iac-agent@.service` (+ per-instance
# state dirs and config files) and launches an iac-trial longevity
# soak targeting all DENSITY×7 agent names.
#
# Env knobs:
#   DENSITY=N             # agents per VPS (default 3)
#   DURATION_SECS=86400   # 24h baseline shape
#   RPS=1.0               # proportional to baseline; total rate
#                         # scales with the bigger agent count
#
# Lifecycle pieces:
#   - Refuses to start if F1 baseline trial.pid is alive (would
#     break per-resource caps; density wants a clean fleet).
#   - Installs iac-agent@.service + agent-density.toml.tmpl on each
#     VPS, renders one agent-{slot}.toml per density slot, starts
#     all instances.
#   - Sets fleet-wide target list `agent-01-1,agent-01-2,...,
#     agent-07-{DENSITY}` and runs iac-trial longevity. Same
#     finalize pipeline (fleet-f1-finalize.sh) when the soak ends —
#     the per-host RSS sampler picks up every iac-agent process
#     because it greps on the binary name.
#
# Operator note: rolling back to the 7-agent baseline is
# `RESET_AGENT_STATE=1 ./trial/fleet/bootstrap.sh` (drops the
# density configs + restores the single iac-agent service).

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

DENSITY="${DENSITY:-3}"
DURATION_SECS="${DURATION_SECS:-86400}"
RPS="${RPS:-1.0}"
F1_DIR=/var/lib/iac-trial/f1

# Refuse if a baseline F1 is in flight.
if ssh_to "$CP_IP" "[ -f $F1_DIR/trial.pid ] && kill -0 \$(cat $F1_DIR/trial.pid) 2>/dev/null"; then
    echo "FAIL: F1 baseline in flight on $CP_IP. Finalize it first." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLEET_DIR="$REPO_ROOT/fleet"
TMPL="$FLEET_DIR/agent-density.toml.tmpl"
SERVICE="$FLEET_DIR/iac-agent@.service"
[ -f "$TMPL" ] || { echo "missing $TMPL" >&2; exit 1; }
[ -f "$SERVICE" ] || { echo "missing $SERVICE" >&2; exit 1; }

SERVER_URL="http://$CP_IP:$CP_PORT"

# ---- install density configs + template on each VPS ----------------

echo "=== installing density harness (D=$DENSITY) on each VPS ==="
agent_entries=()
all_target_names=()
while IFS=$'\t' read -r name ip _; do
    agent_entries+=("$name|$ip")
done < <(inventory_hosts agent)

for entry in "${agent_entries[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    say "$ip" "($name) provisioning $DENSITY density slots"
    # Push the template unit; reload daemon once at the end.
    scp_to "$SERVICE" "$ip" /etc/systemd/system/iac-agent@.service
    # Per-slot config + state dir + start unit.
    for i in $(seq 1 "$DENSITY"); do
        slot_name="${name}-${i}"
        rendered=$(sed \
            -e "s|__AGENT_NAME__|$slot_name|" \
            -e "s|__SERVER_URL__|$SERVER_URL|" \
            -e "s|__INSTANCE__|$i|" \
            "$TMPL")
        # Heredoc-friendly: write rendered toml to a remote temp file,
        # then `install` it into /etc/iac/. (scp doesn't take stdin.)
        ssh_to "$ip" "mkdir -p /etc/iac /var/lib/iac-agent-$i/manifests.d && cat > /etc/iac/agent-${i}.toml <<'EOF'
$rendered
EOF"
        all_target_names+=("$slot_name")
    done
    ssh_to "$ip" "systemctl daemon-reload"
    for i in $(seq 1 "$DENSITY"); do
        ssh_to "$ip" "systemctl enable --now iac-agent@${i} >/dev/null 2>&1"
    done
done

# ---- wait for all instances to register ----------------------------

expected=$((DENSITY * ${#agent_entries[@]}))
echo
echo "=== waiting for $expected agents to register ==="
deadline=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    fleet_size=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length'" 2>/dev/null || echo 0)
    if [ "$fleet_size" -ge "$expected" ]; then
        say "$CP_IP" "fleet ready: $fleet_size / $expected agents"
        break
    fi
    sleep 3
done
if [ "$fleet_size" -lt "$expected" ]; then
    echo "FAIL: only $fleet_size / $expected agents registered within 120 s" >&2
    exit 1
fi

# ---- launch the soak via iac-trial ---------------------------------

# `$F1_DIR` is on the CP, not local — the local mkdir was a thinko
# from the first draft. The ssh_to block below does the real
# remote mkdir as part of the same heredoc that writes
# started_at / trial.pid.
targets_csv=$(IFS=,; echo "${all_target_names[*]}")
say "$CP_IP" "starting density soak: D=$DENSITY target_count=${#all_target_names[@]} duration=${DURATION_SECS}s rps=$RPS"

# Mirror fleet-f1-soak.sh: nohup iac-trial, write trial.pid + started_at.
ssh_to "$CP_IP" "
    set -eu
    mkdir -p $F1_DIR
    date +%s > $F1_DIR/started_at
    echo $DURATION_SECS > $F1_DIR/duration_secs
    nohup /usr/local/bin/iac-trial \
        --server-url $SERVER_URL \
        --admin-token '$ADMIN_TOKEN' \
        --environment fleet \
        --targets '$targets_csv' \
        longevity --duration-secs $DURATION_SECS --rps $RPS \
        > $F1_DIR/trial.log 2>&1 &
    echo \$! > $F1_DIR/trial.pid
"

pid=$(ssh_to "$CP_IP" "cat $F1_DIR/trial.pid")
echo
echo "=== F1 density soak running ==="
echo "  PID on $CP_IP:  $pid"
echo "  density:        $DENSITY × $(echo "${#agent_entries[@]}") = $expected agents"
echo "  expected end:   $(date -u -d "+$DURATION_SECS seconds" +%FT%TZ)"
echo "  status:         ./trial/scenarios/fleet-f1-status.sh"
echo "  finalize:       ./trial/scenarios/fleet-f1-finalize.sh"
echo
echo "Operator can disconnect now — the run survives via nohup."
