#!/bin/bash
# Phase 9 F1 — read-only status check on a running soak. Doesn't
# touch fleet state; safe to run from any operator session.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

F1_DIR=/var/lib/iac-trial/f1

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

echo
echo "=== fleet health ==="
ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents 2>/dev/null" | \
    jq -r 'sort_by(.name) | .[] | "  \(.name): status=\(.status) managed=\(.managed) drifts=\(.open_drifts)"' \
    || echo "  (cp unreachable?)"

echo
echo "=== capacity health (Phase 9 fix-1..5 ceilings) ==="
# Phase 9-F1-fix-6 (operational): show the same scaling ceilings the
# CP code defaults bound, with red/yellow/green flags. Operators
# spot WAL saturation / disk pressure before failure rate climbs.
cap_data=$(ssh_to "$CP_IP" "
    db_kb=\$(stat -c%s /var/lib/iac-controlplane/server.db 2>/dev/null || echo 0)
    wal_kb=\$(stat -c%s /var/lib/iac-controlplane/server.db-wal 2>/dev/null || echo 0)
    df_avail=\$(df -k / | awk 'NR==2 {print \$4}')
    df_total=\$(df -k / | awk 'NR==2 {print \$2}')
    busy_5m=\$(journalctl -u iac-controlplane --since '5 minutes ago' --no-pager 2>/dev/null | grep -c 'database is locked' || echo 0)
    slow_5m=\$(journalctl -u iac-controlplane --since '5 minutes ago' --no-pager 2>/dev/null | grep -c 'slow statement' || echo 0)
    echo \"\$db_kb \$wal_kb \$df_avail \$df_total \$busy_5m \$slow_5m\"
" 2>/dev/null || echo "0 0 0 0 0 0")
read -r db wal avail total busy slow <<< "$cap_data"
db_mb=$((db / 1024 / 1024))
wal_mb=$((wal / 1024 / 1024))
avail_gb=$((avail / 1024 / 1024))
disk_pct=$((100 - (avail * 100 / total)))

flag_wal="✓"
[ "$wal_mb" -ge 200 ] && flag_wal="!"   # near 256 MiB cap
[ "$wal_mb" -ge 240 ] && flag_wal="✗"   # at cap, throttling

flag_disk="✓"
[ "$disk_pct" -ge 75 ] && flag_disk="!"
[ "$disk_pct" -ge 90 ] && flag_disk="✗"

flag_busy="✓"
[ "$busy" -ge 100 ] && flag_busy="!"    # > 20/min — under load
[ "$busy" -ge 500 ] && flag_busy="✗"    # > 100/min — saturated

printf "  %s server.db:    %d MiB\n" "✓" "$db_mb"
printf "  %s WAL:          %d MiB  (cap 256 MiB; > 200 = warning, > 240 = saturation)\n" "$flag_wal" "$wal_mb"
printf "  %s Disk used:    %d%% (%d GiB free)\n" "$flag_disk" "$disk_pct" "$avail_gb"
printf "  %s 'busy' last 5 min:  %d  (>100 warn, >500 saturation)\n" "$flag_busy" "$busy"
printf "  %s slow stmts last 5m: %d\n" "✓" "$slow"

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
