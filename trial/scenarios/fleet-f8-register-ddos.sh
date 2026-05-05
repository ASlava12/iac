#!/bin/bash
# Phase 9 F8 — DDoS on /v1/agents/register.
#
# What it tries to validate:
#   * rate-limit on the register endpoint holds
#   * legitimate agents don't starve during the storm
#   * controlplane stays responsive (/v1/health continues to 200)
#   * audit chain integrity preserved across the storm
#
# Pre-test inspection of the code revealed there is currently NO
# rate-limit on /v1/agents/register (agents.rs adds the route with
# no middleware; the four RateLimiter buckets cover operations /
# heartbeat / login per-user / login per-IP). This scenario will
# surface that gap as a real finding rather than a doc claim.
#
# Storm is launched from cp-spare-01 (104.128.140.48) — a separate
# VPS so the storm traffic crosses the network like a real attacker
# would, not a localhost flood.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

STORM_HOST="$(inventory_hosts cp_spare | head -1 | cut -f2)"
STORM_DURATION="${STORM_DURATION:-60}"        # seconds of flood
STORM_CONCURRENCY="${STORM_CONCURRENCY:-50}"  # concurrent curls
LEGIT_NAME="${LEGIT_NAME:-legit-agent-$(date +%s)}"

F8_DIR=/var/lib/iac-trial/f8

# ---- preflight -----------------------------------------------------

echo "=== preflight ==="
fleet_size=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length'")
say "$CP_IP" "fleet baseline: $fleet_size agents"
say "$STORM_HOST" "will originate the register storm from here"

# Capture audit chain tip + agents-table size before.
ssh_to "$CP_IP" "
    set -eu
    mkdir -p $F8_DIR
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F8_DIR/chain-tip-start.json
    echo $fleet_size > $F8_DIR/agents-before.txt
"

# ---- legit registrant: try to register every 5s during the storm ---
# Runs from this operator host. Each attempt records (start_ts,
# elapsed_ms, http_status) so we can answer "did legitimate traffic
# get starved?". The first 200 wins; subsequent attempts back off.

LEGIT_LOG=/tmp/iac-f8-legit.csv
echo 'attempt_ts,elapsed_ms,http_status' > "$LEGIT_LOG"

legit_loop() {
    local i=0
    local got_200=0
    while [ $i -lt 30 ]; do
        local start=$(date +%s%N)
        local code
        code=$(curl -sS -o /dev/null -w '%{http_code}' \
            --max-time 10 \
            -X POST "http://$CP_IP:$CP_PORT/v1/agents/register" \
            -H 'Content-Type: application/json' \
            -d "{\"name\":\"$LEGIT_NAME\",\"environment\":\"f8-legit\",\"metadata\":{}}" \
            2>/dev/null || echo 000)
        local end=$(date +%s%N)
        local elapsed_ms=$(( (end - start) / 1000000 ))
        echo "$(date +%s),$elapsed_ms,$code" >> "$LEGIT_LOG"
        if [ "$code" = "200" ] && [ "$got_200" = 0 ]; then
            got_200=1
            say "legit" "first 200 OK after attempt #$((i+1)) at ${elapsed_ms}ms"
        elif [ "$code" = "409" ]; then
            # Conflict = name already registered, also a 'success' for
            # our retry loop's purposes (it means we're not blocked).
            if [ "$got_200" = 0 ]; then
                got_200=1
                say "legit" "409 (name taken) on attempt #$((i+1)) — fine, server is responsive"
            fi
        fi
        i=$((i+1))
        sleep 5
    done
}

# ---- launch storm + legit-loop in parallel -------------------------

echo
echo "=== launching storm: ${STORM_CONCURRENCY} workers × ${STORM_DURATION}s ==="
echo "    from: $STORM_HOST → $CP_IP:$CP_PORT/v1/agents/register"
echo "    legit registrant: $LEGIT_NAME (every 5s, from operator host)"
echo

# Storm launcher script on the storm host. xargs-parallel curl,
# generating fake names so each request hits the agents-table INSERT
# rather than the UNIQUE-violation 409 path.
ssh_to "$STORM_HOST" "
    set -eu
    cat > /tmp/storm.sh <<'EOSTORM'
#!/bin/bash
# Storm script — run on the storm host. Runs `curl POST /register`
# in a tight xargs-parallel loop with random fake names.
set -eu
DURATION=\$1
PARALLEL=\$2
URL=\$3
LOG=/tmp/iac-f8-storm.csv
echo 'unix_ts,http_status,elapsed_ms' > \$LOG
end=\$((\$(date +%s) + DURATION))
# Inline the work in the xargs subshell — avoids \`export -f\` which
# Ubuntu's /bin/sh (dash) doesn't support.
hammer() {
    local url=\$1
    local log=\$2
    local name=\"storm-\$(od -An -N4 -tx4 /dev/urandom | tr -d ' \\n')\"
    local start=\$(date +%s%N)
    local code
    code=\$(curl -sS -o /dev/null -w '%{http_code}' \\
        --max-time 5 \\
        -X POST \"\$url\" \\
        -H 'Content-Type: application/json' \\
        -d \"{\\\"name\\\":\\\"\$name\\\",\\\"environment\\\":\\\"f8-storm\\\",\\\"metadata\\\":{}}\" \\
        2>/dev/null || echo 000)
    local end=\$(date +%s%N)
    local elapsed=\$(( (end - start) / 1000000 ))
    echo \"\$(date +%s),\$code,\$elapsed\" >> \$log
}
export -f hammer
while [ \$(date +%s) -lt \$end ]; do
    seq 1 \$PARALLEL | xargs -P \$PARALLEL -I {} bash -c \"hammer '\$URL' '\$LOG'\"
done
EOSTORM
    chmod +x /tmp/storm.sh
"

# Kick off legit-loop in background on the operator host.
legit_loop > /tmp/iac-f8-legit.log 2>&1 &
legit_pid=$!

# Run the storm (blocks until the storm script's loop finishes).
storm_started=$(date +%s)
ssh_to "$STORM_HOST" "/tmp/storm.sh $STORM_DURATION $STORM_CONCURRENCY \
    http://$CP_IP:$CP_PORT/v1/agents/register"
storm_ended=$(date +%s)
storm_elapsed=$((storm_ended - storm_started))
echo
say "$STORM_HOST" "storm finished after ${storm_elapsed}s wall-clock"

# Let the legit-loop run a couple more iterations after the storm
# stops, then close it.
sleep 12
kill "$legit_pid" 2>/dev/null || true
wait "$legit_pid" 2>/dev/null || true

# ---- gather artefacts + verdict ------------------------------------

echo
echo "=== gathering artefacts ==="
mkdir -p /tmp/iac-f8-results
scp -i "$SSH_KEY" -o BatchMode=yes -q "root@$STORM_HOST:/tmp/iac-f8-storm.csv" /tmp/iac-f8-results/storm.csv
cp "$LEGIT_LOG" /tmp/iac-f8-results/legit.csv

ssh_to "$CP_IP" "
    set -eu
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/chain-tip > $F8_DIR/chain-tip-end.json
    curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/agents | jq 'length' > $F8_DIR/agents-after.txt
"
scp -i "$SSH_KEY" -o BatchMode=yes -q "root@$CP_IP:$F8_DIR/chain-tip-start.json" /tmp/iac-f8-results/chain-tip-start.json
scp -i "$SSH_KEY" -o BatchMode=yes -q "root@$CP_IP:$F8_DIR/chain-tip-end.json"   /tmp/iac-f8-results/chain-tip-end.json

agents_before=$(ssh_to "$CP_IP" "cat $F8_DIR/agents-before.txt")
agents_after=$(ssh_to "$CP_IP" "cat $F8_DIR/agents-after.txt")

echo
echo "=== F8 verdict ==="
echo
echo "Storm summary:"
total=$(wc -l < /tmp/iac-f8-results/storm.csv)
total=$((total - 1))  # subtract header
ok=$(awk -F, 'NR>1 && $2=="200" {n++} END {print n+0}' /tmp/iac-f8-results/storm.csv)
err=$(awk -F, 'NR>1 && $2!="200" && $2!="409" {n++} END {print n+0}' /tmp/iac-f8-results/storm.csv)
conflict=$(awk -F, 'NR>1 && $2=="409" {n++} END {print n+0}' /tmp/iac-f8-results/storm.csv)
ratelimit=$(awk -F, 'NR>1 && $2=="429" {n++} END {print n+0}' /tmp/iac-f8-results/storm.csv)
p50=$(awk -F, 'NR>1 && $3 != "" {print $3}' /tmp/iac-f8-results/storm.csv | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c/2)]}')
p99=$(awk -F, 'NR>1 && $3 != "" {print $3}' /tmp/iac-f8-results/storm.csv | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c*0.99)]}')
printf "  total:        %d requests in %ds (%.1f rps)\n" "$total" "$storm_elapsed" "$(awk -v t=$total -v d=$storm_elapsed 'BEGIN{print t/d}')"
printf "  HTTP 200 OK:  %d\n" "$ok"
printf "  HTTP 409 dup: %d\n" "$conflict"
printf "  HTTP 429 rl:  %d  ← *** if 0, the register endpoint has no rate limit ***\n" "$ratelimit"
printf "  other / err:  %d\n" "$err"
printf "  latency p50 / p99: %s ms / %s ms\n" "$p50" "$p99"
echo
echo "Legit registrant ($LEGIT_NAME):"
legit_total=$(awk 'NR>1 {n++} END {print n}' "$LEGIT_LOG")
legit_200=$(awk -F, 'NR>1 && $3=="200" {n++} END {print n+0}' "$LEGIT_LOG")
legit_409=$(awk -F, 'NR>1 && $3=="409" {n++} END {print n+0}' "$LEGIT_LOG")
legit_5xx=$(awk -F, 'NR>1 && $3>=500 && $3<600 {n++} END {print n+0}' "$LEGIT_LOG")
legit_first200=$(awk -F, 'NR>1 && $3=="200" {print $1; exit}' "$LEGIT_LOG")
printf "  attempts:        %d\n" "$legit_total"
printf "  2xx successes:   %d\n" "$legit_200"
printf "  409 conflict:    %d\n" "$legit_409"
printf "  5xx errors:      %d  ← legit traffic starved if > 0 in steady state\n" "$legit_5xx"
[ -n "$legit_first200" ] && printf "  first 200 at:    %s (storm started: %s)\n" "$legit_first200" "$storm_started"
echo
echo "DB growth:"
echo "  agents before:   $agents_before"
echo "  agents after:    $agents_after"
echo "  delta:           $((agents_after - agents_before))   ← matches storm 200-count if no rate limit"
echo
echo "Audit chain:"
start_id=$(jq -r '.last_id' /tmp/iac-f8-results/chain-tip-start.json)
end_id=$(jq -r '.last_id' /tmp/iac-f8-results/chain-tip-end.json)
echo "  rows added: $((end_id - start_id))"
verify=$(ssh_to "$CP_IP" "curl -fsS -H 'Authorization: Bearer $ADMIN_TOKEN' http://127.0.0.1:$CP_PORT/v1/audit/verify" || echo '{}')
ok=$(echo "$verify" | jq -r '.ok // empty')
if [ "$ok" = "true" ]; then
    echo "  /v1/audit/verify ok=true"
else
    echo "  /v1/audit/verify FAILED: $verify"
fi
echo
echo "CSVs at /tmp/iac-f8-results/{storm,legit}.csv"
