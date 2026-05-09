#!/bin/bash
# Phase 9 F2 — rolling network partition.
#
# Pass criteria:
#   * recovery time < 5 min after partition is lifted (agent
#     reconnects, heartbeat goes through, observations resume);
#   * no split-brain — when an agent comes back, CP doesn't have
#     contradictory state about it;
#   * replay-protection still rejects re-played envelopes captured
#     during the outage (Phase 7cq.2 / 7dh.12 contract).
#
# Strategy: rolling partition. Pick one agent at a time, block its
# inbound/outbound to the controlplane via `iptables` for N minutes,
# then unblock. Repeat for each of the 7 agents. Per-cycle:
#   1. snapshot CP-side state for that agent (managed count,
#      last_seen, audit-tip) — call it A0
#   2. partition agent X (DROP iptables rule, both directions)
#   3. wait `OUTAGE_SECS` (default 180 s = 3 min)
#   4. capture an envelope mid-outage by tailing the agent's
#      assignments table — we'll replay it post-outage to test
#      replay protection
#   5. unblock the agent (delete iptables rule)
#   6. start a wall-clock timer; poll CP `/v1/agents` every 5 s
#      until that agent is healthy again — record `recovery_secs`
#   7. attempt to replay the captured envelope — expect rejection
#   8. snapshot again — call it A1; verify (managed >= A0,
#      last_seen advanced, audit chain still verifies)
#
# Constraints:
#   * F1 must NOT be running — F2 partitions agents that F1 also
#     uses, and the disruption breaks F1's "0 unaccounted restarts"
#     and "< 1 % errors" criteria. Refuse to start if F1 trial.pid
#     exists and is alive.
#   * Run from the operator host. The iptables rules go in via SSH.
#
# Usage:
#   ./trial/scenarios/fleet-f2-network-partition.sh
#   OUTAGE_SECS=60 RECOVERY_TIMEOUT=300 ./trial/scenarios/fleet-f2-network-partition.sh

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"
. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib-capacity.sh"

cap_fail=0
OUTAGE_SECS="${OUTAGE_SECS:-180}"            # 3-min partition per cycle
RECOVERY_TIMEOUT="${RECOVERY_TIMEOUT:-300}"  # 5-min recovery threshold
RESULTS_DIR=/tmp/iac-f2-results
F2_DIR=/var/lib/iac-trial/f2
mkdir -p "$RESULTS_DIR"

# ---- preflight -----------------------------------------------------

echo "=== preflight ==="
# Refuse if F1 is in flight.
if ssh_to "$CP_IP" "[ -f /var/lib/iac-trial/f1/trial.pid ] && kill -0 \$(cat /var/lib/iac-trial/f1/trial.pid) 2>/dev/null"; then
    echo "FAIL: F1 in flight on $CP_IP. Finalize it first." >&2
    exit 1
fi

# Verify all 7 agents healthy on CP.
fleet_size=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length'")
expected=$(inventory_hosts agent | wc -l)
if [ "$fleet_size" -lt "$expected" ]; then
    echo "FAIL: only $fleet_size of $expected agents registered" >&2
    exit 1
fi
say "$CP_IP" "fleet ready: $fleet_size / $expected agents"

# Capture audit-chain start tip for the integrity check at the end.
ssh_to "$CP_IP" "
    set -eu
    mkdir -p $F2_DIR
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F2_DIR/chain-tip-start.json
"
chain_start=$(ssh_to "$CP_IP" "jq -r '.last_id' $F2_DIR/chain-tip-start.json")
say "$CP_IP" "audit chain start tip: $chain_start"

# ---- per-cycle helpers ---------------------------------------------

# Block: drop both directions of CP↔agent traffic on the agent side.
# Add OUTPUT to drop responses too — agent thinks CP is unreachable AND
# CP can't push assignments (relevant once the SSH-push path is on).
partition_agent() {
    local ip="$1"
    ssh_to "$ip" "
        iptables -A OUTPUT -d $CP_IP -j DROP
        iptables -A INPUT -s $CP_IP -j DROP
    " 2>/dev/null
}

unpartition_agent() {
    local ip="$1"
    # Use -D twice to flush both rules. Idempotent — harmless if
    # rules don't exist.
    ssh_to "$ip" "
        iptables -D OUTPUT -d $CP_IP -j DROP 2>/dev/null || true
        iptables -D INPUT -s $CP_IP -j DROP 2>/dev/null || true
    " 2>/dev/null
}

# Snapshot one agent's CP-side view: managed_count, last_seen_unix,
# total agents-table count.
agent_snapshot() {
    local name="$1"
    curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$CP_IP:$CP_PORT/v1/agents" \
        | jq -r --arg n "$name" '.[] | select(.name==$n) | "\(.managed) \(.last_seen_unix // 0) \(.status)"'
}

# Capture one assignment envelope from an agent's local pending queue.
# Returns the envelope JSON (or empty if no pending assignments).
# We use it as the replay-protection probe target: stash it now,
# replay it later, expect "already processed" rejection.
capture_envelope() {
    local ip="$1"
    # The agent's assignments live in agent.db (rusqlite-managed).
    # Easiest extraction: shell out to sqlite3 on the agent.
    ssh_to "$ip" "sqlite3 /var/lib/iac-agent/agent.db 'SELECT envelope_json FROM assignments LIMIT 1' 2>/dev/null || echo ''"
}

# ---- main loop ----------------------------------------------------

echo
echo "=== rolling partition: 1 agent at a time, ${OUTAGE_SECS}s outage each ==="

cycle=0
fails=0
agent_entries=()
while IFS=$'\t' read -r name ip _; do
    agent_entries+=("$name|$ip")
done < <(inventory_hosts agent)

LOG="$RESULTS_DIR/cycles.csv"
echo 'cycle,name,ip,recovery_secs,A0_managed,A1_managed,replay_rejected,split_brain' > "$LOG"

# Trap: ALWAYS unpartition every agent on exit, even on Ctrl-C / error.
# Otherwise we leave the fleet partially partitioned and break F1 / F6
# / future runs.
trap 'echo; echo "[trap] unpartitioning all agents"; for entry in "${agent_entries[@]}"; do IFS="|" read -r _ ip <<< "$entry"; unpartition_agent "$ip" || true; done' EXIT INT TERM

for entry in "${agent_entries[@]}"; do
    cycle=$((cycle + 1))
    IFS='|' read -r name ip <<< "$entry"
    echo
    echo "--- cycle $cycle/7: $name ($ip) ---"

    # A0
    a0=$(agent_snapshot "$name")
    a0_managed=$(echo "$a0" | awk '{print $1}')
    a0_last=$(echo "$a0" | awk '{print $2}')
    say "$ip" "A0: managed=$a0_managed last_seen=$a0_last status=$(echo "$a0" | awk '{print $3}')"

    # Partition.
    partition_agent "$ip"
    say "$ip" "partitioned (iptables DROP both directions to/from $CP_IP)"
    partition_started=$(date +%s)

    # During outage, capture an envelope to replay later. Wait a
    # beat for any in-flight one to land on the agent first.
    sleep 5
    captured=$(capture_envelope "$ip")
    if [ -z "$captured" ]; then
        say "$ip" "no envelope captured (no pending assignments) — replay test will skip"
    else
        say "$ip" "envelope captured for replay test ($(echo "$captured" | wc -c) bytes)"
    fi

    # Wait the rest of the outage window.
    elapsed=$(($(date +%s) - partition_started))
    remaining=$((OUTAGE_SECS - elapsed))
    [ $remaining -gt 0 ] && sleep $remaining

    # Restore.
    unpartition_agent "$ip"
    restore_started=$(date +%s)
    say "$ip" "unpartitioned; polling for recovery (timeout ${RECOVERY_TIMEOUT}s)"

    # Poll CP every 5 s for agent to be healthy with last_seen newer
    # than A0.
    recovery_secs=0
    while [ $recovery_secs -lt "$RECOVERY_TIMEOUT" ]; do
        a1=$(agent_snapshot "$name")
        a1_status=$(echo "$a1" | awk '{print $3}')
        a1_last=$(echo "$a1" | awk '{print $2}')
        if [ "$a1_status" = "healthy" ] && [ "$a1_last" -gt "$a0_last" ]; then
            break
        fi
        sleep 5
        recovery_secs=$(($(date +%s) - restore_started))
    done
    a1_managed=$(echo "$a1" | awk '{print $1}')

    if [ "$recovery_secs" -ge "$RECOVERY_TIMEOUT" ]; then
        say "$ip" "✗ RECOVERY FAILED — agent not healthy after ${recovery_secs}s"
        fails=$((fails + 1))
        replay_rejected=skipped
        split=unknown
    else
        say "$ip" "✓ recovered after ${recovery_secs}s"

        # Replay test (if we captured an envelope).
        if [ -n "$captured" ]; then
            assignment_id=$(echo "$captured" | jq -r '.assignment_id // empty')
            agent_id=$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
                "http://$CP_IP:$CP_PORT/v1/agents" | jq -r --arg n "$name" '.[] | select(.name==$n) | .id')
            # Re-inject envelope to the agent's assignments table.
            # The agent's replay-protection should reject it on the
            # next observe cycle (Phase 7cq.2 contract).
            ssh_to "$ip" "sqlite3 /var/lib/iac-agent/agent.db \"DELETE FROM processed_assignments WHERE assignment_id='$assignment_id'\" 2>/dev/null || true"
            # Wait for one observe cycle so the agent encounters the
            # re-injected envelope.
            sleep 30
            # Check the agent's log for "replay rejected" on this id.
            if ssh_to "$ip" "journalctl -u iac-agent --since '60 seconds ago' --no-pager 2>/dev/null | grep -q 'replay rejected.*$assignment_id'"; then
                replay_rejected=yes
            else
                replay_rejected=no
                fails=$((fails + 1))
                say "$ip" "✗ replay-protection FAILED — re-injected envelope $assignment_id was not rejected"
            fi
        else
            replay_rejected=skipped
        fi

        # Split-brain check: managed should be >= A0 (resources
        # didn't disappear from CP's view).
        if [ "$a1_managed" -ge "$a0_managed" ]; then
            split=no
        else
            split=yes
            fails=$((fails + 1))
            say "$ip" "✗ SPLIT-BRAIN — managed dropped from $a0_managed to $a1_managed"
        fi
    fi

    echo "$cycle,$name,$ip,$recovery_secs,$a0_managed,$a1_managed,$replay_rejected,$split" >> "$LOG"
done

# ---- final integrity check ----------------------------------------

echo
echo "=== final audit-chain integrity ==="
ssh_to "$CP_IP" "
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F2_DIR/chain-tip-end.json
"
chain_end=$(ssh_to "$CP_IP" "jq -r '.last_id' $F2_DIR/chain-tip-end.json")
delta=$((chain_end - chain_start))
verify=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify | jq -r '.ok // false'")
echo "  chain delta: $delta rows added across F2"
echo "  /v1/audit/verify ok=$verify"

# ---- capacity-health (Phase 9 ceilings) ----------------------------
#
# F2 stresses the network path, but the CP's SQLite store is also
# under load throughout (audit_events for every partition / restore
# cycle). If F2 surfaces a NEW capacity gap on top of partition
# resilience — e.g. WAL saturation under partition-recovery write
# bursts — flag it here.
echo
capacity_health_report
[ "$cap_fail" = "1" ] && fails=$((fails + 1))

# ---- verdict ------------------------------------------------------

echo
echo "=== F2 verdict ==="
echo "  cycles run:        $cycle"
echo "  failures:          $fails"
echo "  recovery times:"
awk -F, 'NR>1 {printf "    %-10s %ss\n", $2, $4}' "$LOG"
echo "  audit verify:      $verify"
if [ "$fails" -eq 0 ] && [ "$verify" = "true" ]; then
    echo "  overall:           PASS"
else
    echo "  overall:           FAIL"
    exit 1
fi
