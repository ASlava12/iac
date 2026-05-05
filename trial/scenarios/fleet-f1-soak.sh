#!/bin/bash
# Phase 9 F1 — 24-hour soak: 7 agents × 1 RPS round-robin.
#
# Pass criteria (checked by `fleet-f1-finalize.sh`):
#   * RSS not climbing > 5 % over the run on cp + every agent
#   * 0 unaccounted systemd restarts on cp + every agent
#   * GET /v1/audit/verify returns ok at the end
#   * iac-trial longevity exits 0 (its built-in pass thresholds)
#
# Strategy: start the workload generator AND the per-host RSS samplers
# under `nohup` so they survive the operator's SSH session ending.
# State saved on the CP under `/var/lib/iac-trial/f1/` so a fresh
# operator session can re-attach without re-running the whole thing.
#
# Usage:
#   ./trial/scenarios/fleet-f1-soak.sh            # 24h
#   DURATION_SECS=600 ./fleet-f1-soak.sh          # 10-min smoke
#   RPS=2 ./fleet-f1-soak.sh                      # higher rate

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

DURATION_SECS="${DURATION_SECS:-86400}"  # 24h default
RPS="${RPS:-1.0}"
F1_DIR=/var/lib/iac-trial/f1
SAMPLE_INTERVAL=300  # RSS sample every 5 min

# ---- preflight ------------------------------------------------------

echo "=== preflight ==="
fleet_size=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length'")
expected=$(inventory_hosts agent | wc -l)
if [ "$fleet_size" != "$expected" ]; then
    echo "FAIL: $fleet_size of $expected agents registered; run bootstrap.sh first" >&2
    exit 1
fi
say "$CP_IP" "fleet ready: $fleet_size / $expected agents healthy"

# Refuse to start a second F1 when one is already running — the
# RSS-sampler PIDs would collide and the soak result would be
# unreliable. Operator can `fleet-f1-finalize.sh` to close out the
# previous run first.
if ssh_to "$CP_IP" "[ -f $F1_DIR/trial.pid ] && kill -0 \$(cat $F1_DIR/trial.pid) 2>/dev/null"; then
    echo "FAIL: F1 already running on $CP_IP. Use fleet-f1-finalize.sh to close it out." >&2
    exit 1
fi

# ---- per-host RSS sampler ------------------------------------------

# Each VPS gets a tiny background process: every $SAMPLE_INTERVAL
# seconds, write `unix_ts,rss_kb,vsz_kb,cpu_pct` to /var/log/iac-trial-f1-rss.csv.
# `pgrep` finds the right binary regardless of restarts (a restart
# would change the PID); on the CP we sample iac-controlplane, on
# agents we sample iac-agent.
start_sampler() {
    ip="$1"
    binary="$2"
    say "$ip" "starting RSS sampler ($binary)"
    # Ship the sampler as a real file (versus a nested heredoc inside
    # ssh "...", which the prior version mangled with the layered
    # quote escaping — RSS / VSZ / %CPU columns came out empty).
    scp_to "$FLEET_DIR/sampler.sh" "$ip" /usr/local/bin/iac-trial-f1-sampler.sh
    ssh_to "$ip" "
        set -eu
        mkdir -p $F1_DIR
        chmod +x /usr/local/bin/iac-trial-f1-sampler.sh
        rm -f /var/log/iac-trial-f1-stop /var/log/iac-trial-f1-rss.csv
        nohup /usr/local/bin/iac-trial-f1-sampler.sh $binary $SAMPLE_INTERVAL \
            > /var/log/iac-trial-f1-sampler.log 2>&1 &
        echo \$! > $F1_DIR/sampler.pid
    "
}

ssh_to "$CP_IP" "mkdir -p $F1_DIR"
start_sampler "$CP_IP" "iac-controlplane"
sampler_entries=()
while IFS=$'\t' read -r name ip _; do
    sampler_entries+=("$name|$ip")
done < <(inventory_hosts agent)
for entry in "${sampler_entries[@]}"; do
    IFS='|' read -r _ ip <<< "$entry"
    start_sampler "$ip" "iac-agent" &
done
wait
echo "samplers up on cp + 7 agents"

# ---- record audit-chain tip BEFORE so we can verify growth + integrity ----

ssh_to "$CP_IP" "
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F1_DIR/chain-tip-start.json
"
say "$CP_IP" "saved audit chain-tip at start"

# ---- record systemd restart counters BEFORE ------------------------

record_systemd_state() {
    ip="$1"
    unit="$2"
    when="$3"
    ssh_to "$ip" "systemctl show $unit --property=NRestarts,ActiveEnterTimestamp,MainPID 2>/dev/null > $F1_DIR/systemd-${unit}-${when}.txt"
}
record_systemd_state "$CP_IP" iac-controlplane start
for ip in $(inventory_hosts agent | cut -f2); do
    record_systemd_state "$ip" iac-agent start &
done
wait
echo "systemd state captured at start"

# ---- launch iac-trial longevity (detached) -------------------------

TARGETS=$(inventory_hosts agent | cut -f1 | paste -sd,)
say "$CP_IP" "starting iac-trial longevity duration=${DURATION_SECS}s rps=${RPS} targets=${TARGETS}"
ssh_to "$CP_IP" "
    set -eu
    mkdir -p $F1_DIR
    nohup /usr/local/bin/iac-trial \
        --server-url http://127.0.0.1:$CP_PORT \
        --admin-token '$ADMIN_TOKEN' \
        --environment fleet \
        --targets '$TARGETS' \
        longevity --duration-secs $DURATION_SECS --rps $RPS \
        > $F1_DIR/trial.log 2>&1 &
    echo \$! > $F1_DIR/trial.pid
    echo \$(date +%s) > $F1_DIR/started_at
    echo $((DURATION_SECS)) > $F1_DIR/duration_secs
"
sleep 2
trial_pid=$(ssh_to "$CP_IP" "cat $F1_DIR/trial.pid")
if ssh_to "$CP_IP" "kill -0 $trial_pid 2>/dev/null"; then
    say "$CP_IP" "iac-trial running PID=$trial_pid"
else
    say "$CP_IP" "FAIL: iac-trial didn't stay up; tail of trial.log:"
    ssh_to "$CP_IP" "tail -20 $F1_DIR/trial.log"
    exit 1
fi

# ---- print resume info ---------------------------------------------

DEADLINE=$(date -u -d @$(($(date +%s) + DURATION_SECS)) +"%Y-%m-%dT%H:%M:%SZ")
echo
echo "=== F1 soak running ==="
echo "  PID on $CP_IP: $trial_pid"
echo "  log:           ssh ... 'tail -f $F1_DIR/trial.log'"
echo "  status:        ./trial/scenarios/fleet-f1-status.sh"
echo "  finalize:      ./trial/scenarios/fleet-f1-finalize.sh"
echo "  expected end:  $DEADLINE (${DURATION_SECS}s)"
echo
echo "Operator can disconnect now — the run survives via nohup."
