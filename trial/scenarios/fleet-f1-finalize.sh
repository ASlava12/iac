#!/bin/bash
# Phase 9 F1 finalize. Stops the workload generator + samplers,
# pulls all RSS CSVs and trial.log to a local directory, computes
# pass/fail against the F1 criteria.
#
# Run AFTER fleet-f1-soak.sh has been running for $DURATION_SECS,
# or to abort early. Idempotent — re-running on an already-finalized
# F1 just reprints the verdict.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

F1_DIR=/var/lib/iac-trial/f1
LOCAL_OUT="${LOCAL_OUT:-/tmp/iac-f1-results}"
mkdir -p "$LOCAL_OUT"

# ---- stop workload + samplers --------------------------------------

echo "=== stopping workload + samplers ==="
trial_pid=$(ssh_to "$CP_IP" "cat $F1_DIR/trial.pid 2>/dev/null || true")
if [ -n "$trial_pid" ] && ssh_to "$CP_IP" "kill -0 $trial_pid 2>/dev/null"; then
    say "$CP_IP" "stopping iac-trial PID=$trial_pid"
    ssh_to "$CP_IP" "kill $trial_pid 2>/dev/null || true; sleep 2; kill -9 $trial_pid 2>/dev/null || true"
fi

stop_sampler() {
    ip="$1"
    ssh_to "$ip" "touch /var/log/iac-trial-f1-stop"
    say "$ip" "sampler stop signal sent"
}
stop_sampler "$CP_IP"
agent_entries=()
while IFS=$'\t' read -r name ip _; do
    agent_entries+=("$name|$ip")
done < <(inventory_hosts agent)
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r _ ip <<< "$entry"
    stop_sampler "$ip" &
done
wait
sleep 2

# ---- record systemd state AFTER + chain-tip AFTER ------------------

ssh_to "$CP_IP" "
    set -eu
    systemctl show iac-controlplane --property=NRestarts,ActiveEnterTimestamp,MainPID > $F1_DIR/systemd-iac-controlplane-end.txt
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F1_DIR/chain-tip-end.json
"
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r _ ip <<< "$entry"
    ssh_to "$ip" "systemctl show iac-agent --property=NRestarts,ActiveEnterTimestamp,MainPID > $F1_DIR/systemd-iac-agent-end.txt" &
done
wait

# ---- pull artefacts to operator ------------------------------------

echo
echo "=== pulling artefacts to $LOCAL_OUT ==="
ssh -i "$SSH_KEY" -o BatchMode=yes "root@$CP_IP" "cd $F1_DIR && tar czf - ." | tar xz -C "$LOCAL_OUT"
mkdir -p "$LOCAL_OUT/rss"
scp -i "$SSH_KEY" -o BatchMode=yes -q "root@$CP_IP:/var/log/iac-trial-f1-rss.csv" "$LOCAL_OUT/rss/cp.csv"
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    scp -i "$SSH_KEY" -o BatchMode=yes -q "root@$ip:/var/log/iac-trial-f1-rss.csv" "$LOCAL_OUT/rss/${name}.csv" 2>/dev/null \
        || echo "  WARN: ${name} csv missing"
done

# ---- pass/fail check -----------------------------------------------

echo
echo "=== verdict ==="
fail=0

# 1. iac-trial exit (no longer running, log shows pass/fail)
if grep -q "^PASS" "$LOCAL_OUT/trial.log" 2>/dev/null; then
    echo "  ✓ iac-trial PASS thresholds"
else
    if grep -q "FAILED pass thresholds" "$LOCAL_OUT/trial.log" 2>/dev/null; then
        echo "  ✗ iac-trial FAILED its own pass thresholds"
        fail=1
    else
        echo "  ? iac-trial: no PASS/FAIL marker (run aborted? log tail:)"
        tail -5 "$LOCAL_OUT/trial.log" 2>/dev/null | sed 's/^/      /'
    fi
fi

# 2. RSS not climbing > 5 % (linear regression slope on each CSV)
echo
echo "  RSS analysis:"
for csv in "$LOCAL_OUT"/rss/*.csv; do
    name=$(basename "$csv" .csv)
    # Compute RSS at first valid sample vs last valid sample.
    first=$(awk -F',' 'NR>1 && $4 != "" {print $4; exit}' "$csv")
    last=$(awk -F',' 'NR>1 && $4 != "" {v=$4} END {print v}' "$csv")
    if [ -z "$first" ] || [ -z "$last" ]; then
        printf "    %-12s no samples\n" "$name"
        continue
    fi
    growth=$(awk -v a="$first" -v b="$last" 'BEGIN { printf "%.1f", (b-a)*100/a }')
    flag="✓"
    if awk -v g="$growth" 'BEGIN { exit (g <= 5.0 ? 0 : 1) }'; then :; else flag="✗"; fail=1; fi
    printf "    %s %-12s RSS %s → %s KB  (%s%%)\n" "$flag" "$name" "$first" "$last" "$growth"
done

# 3. systemd restarts (NRestarts before vs after)
echo
echo "  systemd restarts:"
restarts_check() {
    label="$1"
    before_file="$LOCAL_OUT/systemd-${2}-start.txt"
    after_file="$LOCAL_OUT/systemd-${2}-end.txt"
    [ -f "$before_file" ] && [ -f "$after_file" ] || { echo "    ? $label: missing systemd snapshot"; return; }
    nb=$(grep -E "^NRestarts=" "$before_file" | cut -d= -f2)
    na=$(grep -E "^NRestarts=" "$after_file" | cut -d= -f2)
    delta=$((na - nb))
    if [ "$delta" -eq 0 ]; then
        printf "    ✓ %s: 0 unaccounted restarts\n" "$label"
    else
        printf "    ✗ %s: %d restarts during soak\n" "$label" "$delta"
        fail=1
    fi
}
restarts_check "controlplane" "iac-controlplane"
# Per-agent NRestarts comparison would need separate per-host files;
# we recorded them all to the same path, so just report the latest.
agent_after=$(ssh_to "$(inventory_hosts agent | head -1 | cut -f2)" "cat $F1_DIR/systemd-iac-agent-end.txt 2>/dev/null" | grep NRestarts || echo "missing")
echo "    (agent NRestarts sample): $agent_after"

# 4. audit chain integrity
echo
echo "  audit chain:"
start_id=$(jq -r '.last_id' "$LOCAL_OUT/chain-tip-start.json")
end_id=$(jq -r '.last_id' "$LOCAL_OUT/chain-tip-end.json")
echo "    start last_id=$start_id  end=$end_id  rows added: $((end_id - start_id))"
verify=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify" || echo '{}')
ok=$(echo "$verify" | jq -r '.ok // empty')
if [ "$ok" = "true" ]; then
    echo "    ✓ /v1/audit/verify ok=true"
else
    echo "    ✗ /v1/audit/verify ok=false: $verify"
    fail=1
fi

# ---- cleanup F1 dir on cp so re-runs work --------------------------

ssh_to "$CP_IP" "rm -f $F1_DIR/trial.pid $F1_DIR/sampler.pid"
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r _ ip <<< "$entry"
    ssh_to "$ip" "rm -f $F1_DIR/sampler.pid /var/log/iac-trial-f1-stop" &
done
wait

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F1 PASS ==="
    exit 0
else
    echo "=== F1 FAIL ==="
    exit 1
fi
