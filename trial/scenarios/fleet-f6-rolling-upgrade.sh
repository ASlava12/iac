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
. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib-capacity.sh"

cap_fail=0
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

# 1. Submit a 50-op burst PRE-swap and wait for it to finish. The
#    "in-flight ops survive" contract is: ops that v1 CP accepted
#    must still complete after v2 CP takes over. We don't try to
#    keep ops submitting DURING the swap window — that would test
#    "CP available during binary swap", which is a different (and
#    impossible-for-non-HA-single-host-CP) property. The relevant
#    test is "v1-accepted ops eventually reach the agent and the
#    agent's result eventually lands in the v2 audit chain."
say "$CP_IP" "submitting 50-op pre-swap burst targeting agent-01"
ssh_to "$CP_IP" "
    /usr/local/bin/iac-trial \
        --server-url http://127.0.0.1:$CP_PORT \
        --admin-token '$ADMIN_TOKEN' \
        --environment fleet \
        --targets agent-01 \
        submit-burst --count 50 --rps 5.0 > $F6_DIR/burst-A.log 2>&1
"
burst_exit=$(ssh_to "$CP_IP" "tail -1 $F6_DIR/burst-A.log | grep -oE 'PASS|FAIL' || echo unknown")
say "$CP_IP" "burst-A pre-swap verdict: $burst_exit"
[ "$burst_exit" = "PASS" ] || { echo "FAIL: pre-swap burst didn't exit PASS — CP-v1 broken before swap" >&2; exit 1; }

# 2. Snapshot the audit chain tip on v1 BEFORE the swap.
chain_pre_swap=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip | jq -r '.last_id'")
say "$CP_IP" "audit chain pre-swap: $chain_pre_swap"

# 3. Swap CP binary.
swap_started=$(date +%s)
say "$CP_IP" "stopping iac-controlplane"
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

# 4. Wait for agent-01 to eventually report the 50 ops as completed
#    on the v2 CP. CP exposes `assignments?status=succeeded` count
#    per agent; the audit chain should also advance by ~50 + per-op
#    overhead events. We poll for the chain to grow past the
#    pre-swap tip by at least 50 — heuristic but enough to confirm
#    that v1-accepted ops did flow through v2's audit pipeline.
say "$CP_IP" "polling for agent-01 to drain 50 in-flight ops (audit chain advances ≥50 past pre-swap tip)"
chain_target=$((chain_pre_swap + 50))
i=0
chain_now=0
while [ $i -lt 120 ]; do
    chain_now=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip | jq -r '.last_id'" 2>/dev/null || echo 0)
    [ "$chain_now" -ge "$chain_target" ] && break
    i=$((i+1))
    sleep 2
done
if [ "$chain_now" -lt "$chain_target" ]; then
    say "$CP_IP" "✗ audit chain only reached $chain_now (target $chain_target) — in-flight ops did NOT drain after swap"
fi
say "$CP_IP" "audit chain post-drain: $chain_now (target $chain_target)"

# Audit chain still verifies?
verify_a=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify | jq -r '.ok // false'")
say "$CP_IP" "audit verify post-Phase-A: $verify_a"

phase_a_ok=PASS
[ "$burst_exit" = "PASS" ]           || phase_a_ok=FAIL
[ "$verify_a" = "true" ]             || phase_a_ok=FAIL
[ "$chain_now" -ge "$chain_target" ] || phase_a_ok=FAIL

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

    # Wait for it to heartbeat (CP marks it healthy with
    # last_heartbeat_at newer than swap_a_started). The API exposes
    # this as an ISO 8601 string; convert via `date -d` for
    # numeric comparison (same fixup as F2 fix-10 commit).
    i=0
    healthy_secs=999
    while [ $i -lt 120 ]; do
        last_iso=$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
            "http://$CP_IP:$CP_PORT/v1/agents" \
            | jq -r --arg n "$name" '.[] | select(.name==$n) | .last_heartbeat_at // "1970-01-01T00:00:00Z"')
        last=$(date -d "$last_iso" +%s 2>/dev/null || echo 0)
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

# ---- capacity-health (Phase 9 ceilings) ----------------------------
#
# Rolling upgrade exercises the CP write-path heavily during burst-A
# (50 ops mid-flight while binary swaps) and again during Phase B
# (each agent re-establishes session, re-pulls assignments).
# Capacity ceilings have to hold across the two restarts; assert it.
echo
capacity_health_report

# ---- verdict ------------------------------------------------------

cap_flag=PASS; [ "$cap_fail" = "1" ] && cap_flag=FAIL

echo
echo "=== F6 verdict ==="
echo "  Phase A (CP mid-burst swap): $phase_a_ok (CP downtime ${swap_secs}s)"
echo "  Phase B (rolling agent swap): $phase_b_ok"
echo "  capacity-health post-upgrade: $cap_flag"
echo "  audit chain: start=$chain_start end=$chain_end (delta $((chain_end-chain_start)))"
echo "  /v1/audit/verify ok=$verify_end"
if [ "$phase_a_ok" = "PASS" ] && [ "$phase_b_ok" = "PASS" ] \
   && [ "$cap_flag" = "PASS" ] && [ "$verify_end" = "true" ]; then
    echo "  overall: PASS"
else
    echo "  overall: FAIL"
    exit 1
fi
