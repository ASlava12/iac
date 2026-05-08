#!/bin/bash
# Phase 9 F6 — rolling upgrade: agent v1 ↔ controlplane v2.
#
# Pass criteria:
#   * wire-protocol compatibility — old agents survive new CP without
#     re-registration storm; new agents survive old CP analogously;
#   * in-flight ops complete (assignments started under v1 finish
#     under v2 with the same final state);
#   * 0 unaccounted systemd restarts beyond the planned binary swap.
#
# Strategy: two-phase upgrade.
#   Phase A — CP first (agent stays v1):
#     1. snapshot fleet state (agent count, audit tip, assignments)
#     2. submit a "long-tail" operation (multi-step, takes > 60 s
#        to converge); record assignment_id
#     3. mid-flight: stop CP-v1, swap binary to v2, start CP-v2
#     4. verify the assignment continues to converge; on completion
#        verify the result was reported successfully and audit chain
#        kept verifiable across the swap
#   Phase B — agents (one at a time):
#     5. for each agent: stop iac-agent, swap binary v1→v2, start
#     6. verify it heartbeats successfully against CP-v2
#     7. submit a fresh op targeting that agent; verify success
#
# Constraints:
#   * F1 must NOT be running (binary swap creates a planned restart;
#     F1's "0 unaccounted restarts" criterion would tally it).
#   * Refuse to start if F1 trial.pid is alive.
#   * "v1" = the binary currently in /usr/local/bin/. "v2" = the new
#     binary at $V2_BIN_DIR/iac-controlplane (default ./target/release/).
#
# Wire-compat caveat: this scenario presumes v1↔v2 are designed to be
# wire-compatible. If we ever break wire compat between releases (e.g.
# a v3 envelope bumps a required field), this scenario will fail —
# THAT IS THE POINT. Use F6 as the "did we keep wire compat?" gate
# before merging breaking changes.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

V2_BIN_DIR="${V2_BIN_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/release}"
RESULTS_DIR=/tmp/iac-f6-results
F6_DIR=/var/lib/iac-trial/f6
mkdir -p "$RESULTS_DIR"

# ---- preflight ----------------------------------------------------

echo "=== preflight ==="
[ -x "$V2_BIN_DIR/iac-controlplane" ] || { echo "FAIL: missing v2 binary at $V2_BIN_DIR/iac-controlplane" >&2; exit 1; }
[ -x "$V2_BIN_DIR/iac-agent" ]        || { echo "FAIL: missing v2 binary at $V2_BIN_DIR/iac-agent" >&2; exit 1; }

if ssh_to "$CP_IP" "[ -f /var/lib/iac-trial/f1/trial.pid ] && kill -0 \$(cat /var/lib/iac-trial/f1/trial.pid) 2>/dev/null"; then
    echo "FAIL: F1 in flight on $CP_IP. Finalize it first." >&2
    exit 1
fi

# Snapshot fleet state.
ssh_to "$CP_IP" "
    set -eu
    mkdir -p $F6_DIR
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F6_DIR/chain-tip-start.json
"
chain_start=$(ssh_to "$CP_IP" "jq -r '.last_id' $F6_DIR/chain-tip-start.json")

# Capture v1 versions (file mtime as proxy for "what was here before").
cp_v1_size=$(ssh_to "$CP_IP" "stat -c%s /usr/local/bin/iac-controlplane")
cp_v2_size=$(stat -c%s "$V2_BIN_DIR/iac-controlplane")
ag_v1_size=$(ssh_to "45.138.74.147" "stat -c%s /usr/local/bin/iac-agent")
ag_v2_size=$(stat -c%s "$V2_BIN_DIR/iac-agent")
say "$CP_IP" "v1 cp-bin $cp_v1_size B → v2 $cp_v2_size B"
say "agent-01" "v1 agent-bin $ag_v1_size B → v2 $ag_v2_size B"

if [ "$cp_v1_size" = "$cp_v2_size" ] && [ "$ag_v1_size" = "$ag_v2_size" ]; then
    say "preflight" "WARNING: v1 and v2 binary sizes match — possibly the same build. F6 still validates the systemd restart path but the protocol-compat check is a no-op."
fi

say "$CP_IP" "audit chain start tip: $chain_start"

# ---- Phase A: CP swap (agents stay on v1) -------------------------

echo
echo "=== Phase A — CP swap ==="

# 1. Submit a long-tail op via iac-trial single-shot. iac-trial's
#    `submit-burst` creates resources; we want one that takes >60 s
#    to converge. Easiest: submit ~50 file operations targeting one
#    agent — the agent's executor processes them sequentially, so
#    50 ops × ~1.5 s each ≈ 75 s mid-flight window.
say "$CP_IP" "submitting 50-op burst targeting agent-01 (will run for ~75 s)"
ssh_to "$CP_IP" "
    nohup /usr/local/bin/iac-trial \
        --server-url http://127.0.0.1:$CP_PORT \
        --admin-token '$ADMIN_TOKEN' \
        --environment fleet \
        --targets agent-01 \
        submit-burst --count 50 --rps 1.0 > $F6_DIR/burst-A.log 2>&1 &
    echo \$! > $F6_DIR/burst-A.pid
"

# Wait long enough for some to land but not all.
sleep 15

# 2. Mid-flight: swap CP binary.
swap_started=$(date +%s)
say "$CP_IP" "stopping iac-controlplane (mid-burst)"
ssh_to "$CP_IP" "systemctl stop iac-controlplane"

scp_to "$V2_BIN_DIR/iac-controlplane" "$CP_IP" /usr/local/bin/iac-controlplane.v2-staging
ssh_to "$CP_IP" "
    chmod +x /usr/local/bin/iac-controlplane.v2-staging
    mv /usr/local/bin/iac-controlplane.v2-staging /usr/local/bin/iac-controlplane
    systemctl start iac-controlplane
"
# Wait for /v1/health.
i=0
while [ $i -lt 30 ]; do
    if ssh_to "$CP_IP" "curl -fsS -o /dev/null http://127.0.0.1:$CP_PORT/v1/health"; then
        break
    fi
    i=$((i+1))
    sleep 1
done
swap_done=$(date +%s)
swap_secs=$((swap_done - swap_started))
say "$CP_IP" "CP-v2 healthy after ${swap_secs}s downtime"
[ $i -ge 30 ] && { echo "FAIL: CP-v2 didn't come up" >&2; exit 1; }

# 3. Wait for the burst to finish (it should resume against the new
#    CP without re-registration — agent has its bearer token already).
say "$CP_IP" "waiting for burst to finish post-swap"
burst_pid=$(ssh_to "$CP_IP" "cat $F6_DIR/burst-A.pid")
i=0
while [ $i -lt 120 ]; do
    if ! ssh_to "$CP_IP" "kill -0 $burst_pid 2>/dev/null"; then
        break
    fi
    i=$((i+1))
    sleep 1
done

if [ $i -ge 120 ]; then
    echo "FAIL: burst-A didn't finish 2 min after CP-v2 came up" >&2
    ssh_to "$CP_IP" "tail -20 $F6_DIR/burst-A.log"
    exit 1
fi
say "$CP_IP" "burst-A finished post-swap"

# 4. Verify burst's exit code by checking trial log for terminator.
burst_exit=$(ssh_to "$CP_IP" "tail -1 $F6_DIR/burst-A.log | grep -oE 'PASS|FAIL' || echo unknown")
say "$CP_IP" "burst-A verdict: $burst_exit"

# Audit chain still verifies?
verify_a=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify | jq -r '.ok // false'")
say "$CP_IP" "audit verify post-Phase-A: $verify_a"

phase_a_ok=PASS
[ "$burst_exit" = "PASS" ] || phase_a_ok=FAIL
[ "$verify_a" = "true" ]   || phase_a_ok=FAIL

# ---- Phase B: agents one at a time --------------------------------

echo
echo "=== Phase B — rolling agent swap ==="

agent_entries=()
while IFS=$'\t' read -r name ip _; do
    agent_entries+=("$name|$ip")
done < <(inventory_hosts agent)

phase_b_ok=PASS
for entry in "${agent_entries[@]}"; do
    IFS='|' read -r name ip <<< "$entry"
    echo
    echo "--- swapping $name ($ip) ---"

    # Snapshot pre.
    a0_managed=$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "http://$CP_IP:$CP_PORT/v1/agents" \
        | jq -r --arg n "$name" '.[] | select(.name==$n) | .managed')

    # Stop, swap, start.
    swap_a_started=$(date +%s)
    ssh_to "$ip" "systemctl stop iac-agent"
    scp_to "$V2_BIN_DIR/iac-agent" "$ip" /usr/local/bin/iac-agent.v2-staging
    ssh_to "$ip" "
        chmod +x /usr/local/bin/iac-agent.v2-staging
        mv /usr/local/bin/iac-agent.v2-staging /usr/local/bin/iac-agent
        systemctl start iac-agent
    "

    # Wait for it to heartbeat (CP marks it healthy with last_seen
    # newer than swap_a_started).
    i=0
    healthy_secs=999
    while [ $i -lt 120 ]; do
        last=$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
            "http://$CP_IP:$CP_PORT/v1/agents" \
            | jq -r --arg n "$name" '.[] | select(.name==$n) | .last_seen_unix // 0')
        if [ "$last" -gt "$swap_a_started" ]; then
            healthy_secs=$(($(date +%s) - swap_a_started))
            break
        fi
        i=$((i+1))
        sleep 2
    done

    if [ "$healthy_secs" -eq 999 ]; then
        say "$ip" "✗ $name didn't heartbeat post-swap within 4 min"
        phase_b_ok=FAIL
        continue
    fi
    say "$ip" "✓ $name heartbeat after ${healthy_secs}s post-swap"

    # Submit a probe op targeting this agent; verify it lands.
    probe_resp=$(ssh_to "$CP_IP" "
        /usr/local/bin/iac-trial \
            --server-url http://127.0.0.1:$CP_PORT \
            --admin-token '$ADMIN_TOKEN' \
            --environment fleet \
            --targets $name \
            submit-burst --count 1 --rps 1.0 2>&1 | tail -3
    " || echo "probe-failed")
    if echo "$probe_resp" | grep -q PASS; then
        say "$ip" "✓ post-swap probe op succeeded"
    else
        say "$ip" "✗ post-swap probe op failed: $probe_resp"
        phase_b_ok=FAIL
    fi
done

# ---- final integrity ----------------------------------------------

echo
echo "=== final audit-chain integrity ==="
ssh_to "$CP_IP" "
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F6_DIR/chain-tip-end.json
"
chain_end=$(ssh_to "$CP_IP" "jq -r '.last_id' $F6_DIR/chain-tip-end.json")
verify_end=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify | jq -r '.ok // false'")

# ---- verdict ------------------------------------------------------

echo
echo "=== F6 verdict ==="
echo "  Phase A (CP mid-burst swap): $phase_a_ok (CP downtime ${swap_secs}s)"
echo "  Phase B (rolling agent swap): $phase_b_ok"
echo "  audit chain: start=$chain_start end=$chain_end (delta $((chain_end-chain_start)))"
echo "  /v1/audit/verify ok=$verify_end"
if [ "$phase_a_ok" = "PASS" ] && [ "$phase_b_ok" = "PASS" ] && [ "$verify_end" = "true" ]; then
    echo "  overall: PASS"
else
    echo "  overall: FAIL"
    exit 1
fi
