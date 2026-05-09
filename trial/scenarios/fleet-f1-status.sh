#!/bin/bash
# Phase 9 F1 — read-only status check on a running soak. Doesn't
# touch fleet state; safe to run from any operator session.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"
. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib-capacity.sh"

F1_DIR=/var/lib/iac-trial/f1
cap_fail=0
trend_fail=0

echo "=== iac-trial process on $CP_IP ==="
trial_pid=$(ssh_to "$CP_IP" "cat $F1_DIR/trial.pid 2>/dev/null || true")
if [ -z "$trial_pid" ]; then
    echo "  no PID file — F1 not running here, or already finalized"
    exit 0
fi
if ssh_to "$CP_IP" "kill -0 $trial_pid 2>/dev/null"; then
    started=$(ssh_to "$CP_IP" "cat $F1_DIR/started_at")
    duration=$(ssh_to "$CP_IP" "cat $F1_DIR/duration_secs")
    now=$(date +%s)
    elapsed=$((now - started))
    remaining=$((duration - elapsed))
    pct=$((elapsed * 100 / duration))
    printf "  RUNNING  pid=%s  elapsed=%ss / %ss (%d%%)  remaining=%ss\n" \
        "$trial_pid" "$elapsed" "$duration" "$pct" "$remaining"
else
    echo "  STOPPED  pid=$trial_pid no longer exists; tail of trial.log:"
    ssh_to "$CP_IP" "tail -10 $F1_DIR/trial.log" | sed 's/^/    /'
fi

echo
echo "=== submission progress ==="
submitted=$(ssh_to "$CP_IP" "grep -c 'longevity progress' $F1_DIR/trial.log 2>/dev/null || echo 0")
last_prog=$(ssh_to "$CP_IP" "grep 'longevity progress' $F1_DIR/trial.log 2>/dev/null | tail -1 || true")
echo "  progress lines: $submitted"
[ -n "$last_prog" ] && echo "  last:           $last_prog"
# Phase 9-F1-fix-6 (operational): auto-compute failure rate. iac-trial
# logs `submitted=N failures=M`; we extract the latest N+M and show
# the %. Threshold 1 % matches iac-trial's own pass criterion.
if [ -n "$last_prog" ]; then
    # iac-trial logs in ANSI-coloured format — strip escape codes
    # before extracting numeric fields.
    last_clean=$(printf '%s' "$last_prog" | sed 's/\x1b\[[0-9;]*m//g')
    nsub=$(printf '%s' "$last_clean" | grep -oE 'submitted=[0-9]+' | cut -d= -f2)
    nfail=$(printf '%s' "$last_clean" | grep -oE 'failures=[0-9]+' | cut -d= -f2)
    if [ -n "$nsub" ] && [ -n "$nfail" ] && [ "$nsub" -gt 0 ]; then
        pct=$(awk -v s="$nsub" -v f="$nfail" 'BEGIN { printf "%.2f", f*100/s }')
        flag="✓"
        awk -v p="$pct" 'BEGIN { exit (p < 1.0 ? 0 : 1) }' || flag="✗"
        printf "  %s failure rate:  %d / %d = %s%% (threshold < 1.00%%)\n" "$flag" "$nfail" "$nsub" "$pct"
    fi
fi

echo
echo "=== fleet health ==="
ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents 2>/dev/null" | \
    jq -r 'sort_by(.name) | .[] | "  \(.name): status=\(.status) managed=\(.managed) drifts=\(.open_drifts)"' \
    || echo "  (cp unreachable?)"

echo
echo "=== capacity health (Phase 9 fix-1..5 ceilings) ==="
capacity_health_report

echo
echo "=== failure-rate trend ==="
failure_trend_report "$F1_DIR/trial.log" remote

echo
echo "=== audit chain growth ==="
chain=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip 2>/dev/null" || true)
if [ -n "$chain" ]; then
    last_id=$(echo "$chain" | jq -r '.last_id')
    start_id=$(ssh_to "$CP_IP" "jq -r '.last_id' $F1_DIR/chain-tip-start.json 2>/dev/null" || echo "")
    if [ -n "$start_id" ] && [ "$start_id" != "?" ]; then
        delta=$((last_id - start_id))
        echo "  start last_id=$start_id  current=$last_id  delta=$delta audit rows since soak began"
    else
        echo "  current last_id=$last_id  (no start snapshot — fresh run?)"
    fi
else
    echo "  (chain-tip query failed)"
fi

echo
echo "=== RSS sampler status ==="
echo "  cp:"
ssh_to "$CP_IP" "wc -l /var/log/iac-trial-f1-rss.csv 2>/dev/null | awk '{print \"    \" \$1 \" samples / \" \$2}'" || true
echo "  agents (1 sample row each from /var/log/iac-trial-f1-rss.csv):"
agent_entries=()
while IFS=$'\t' read -r name ip _; do
    agent_entries+=("$name|$ip")
done < <(inventory_hosts agent)
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    sample=$(ssh_to "$ip" "tail -1 /var/log/iac-trial-f1-rss.csv 2>/dev/null" 2>/dev/null || echo "(unreachable)")
    printf "    %-10s %s\n" "$name" "$sample"
done
