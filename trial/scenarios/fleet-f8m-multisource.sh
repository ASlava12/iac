#!/bin/bash
# Phase 9 F8 follow-up — multi-source-IP storm.
#
# Originally F8 (commit 9da4475) validated single-source-IP cap on
# /v1/agents/register: per-IP=20 worked, 880/900 storm requests
# returned 429. This follow-up validates the per-IP isolation
# property: when two distinct IPs storm simultaneously, each gets
# its own 20/min budget independently — neither shares a counter,
# neither blocks the other.
#
# Why important: production CPs sit behind load balancers / NAT'd
# operator networks. The per-IP cap must isolate per-source — a
# misbehaving IP must NOT lock out a quiet legitimate one.
#
# Setup:
#   * Test CP on cp-spare-02:8446 (fresh DB; doesn't touch prod CP
#     so safe to run during F1)
#   * Source 1: storm helper running on cp-spare-01
#   * Source 2: storm helper running on operator host (this machine)
#   * 30 s storm × 25 parallel each = ~50 parallel total
#   * Expect: each source ~20 × 200 + ~880 × 429 (cap=20/min/IP)
#
# Pass:
#   * Each source independently sees ~20 admitted (matches single-
#     source ratio from F8 single-IP run)
#   * Total admitted ≈ 2 × per-source = 40 (vs 20 in single-source)
#     — proves per-IP isolation
#   * No source blocked the other

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

REPLICA_HOST="$(inventory_hosts cp_spare | sed -n '2p' | cut -f2)"
STORM1_HOST="$(inventory_hosts cp_spare | head -1 | cut -f2)"
TEST_PORT=8446
TEST_TOKEN=f8m-test-token
URL="http://$REPLICA_HOST:$TEST_PORT/v1/agents/register"
RESULTS=/tmp/iac-f8m-results
mkdir -p "$RESULTS"

# ---- preflight: stage test CP on replica host ----------------------

echo "[1/4] preflight: launch fresh CP on $REPLICA_HOST:$TEST_PORT"
LOCAL_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/release/iac-controlplane"
[ -x "$LOCAL_BIN" ] || { echo "FAIL: $LOCAL_BIN not built" >&2; exit 1; }
scp_to "$LOCAL_BIN" "$REPLICA_HOST" /usr/local/bin/iac-cp-f8m
ssh_to "$REPLICA_HOST" "
    set -eu
    mkdir -p /var/lib/iac-cp-f8m
    cat > /etc/iac-cp-f8m.toml <<EOF
bind          = '0.0.0.0:$TEST_PORT'
state_dir     = '/var/lib/iac-cp-f8m'
database_url  = 'sqlite:///var/lib/iac-cp-f8m/server.db?mode=rwc'
max_body_bytes = 4194304
admin_token   = '$TEST_TOKEN'
[rate_limit]
operations_per_minute = 100000
register_per_minute_per_ip = 20
[retention]
audit_days = 7
[tls]
mode = 'none'
EOF
    chmod +x /usr/local/bin/iac-cp-f8m
    nohup /usr/local/bin/iac-cp-f8m --config /etc/iac-cp-f8m.toml > /var/log/iac-cp-f8m.log 2>&1 &
    echo \$! > /tmp/iac-cp-f8m.pid
"
sleep 3
code=$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://$REPLICA_HOST:$TEST_PORT/v1/health")
[ "$code" = "200" ] || { echo "FAIL: test CP not healthy ($code)" >&2; exit 1; }
say "$REPLICA_HOST" "test CP up at $URL"

# ---- ship storm helper to source 1 + run both sources in parallel --

echo "[2/4] shipping storm helper to source-1 ($STORM1_HOST)"
scp_to "$(dirname "${BASH_SOURCE[0]}")/storm-helper.sh" "$STORM1_HOST" /tmp/storm-helper.sh
ssh_to "$STORM1_HOST" "chmod +x /tmp/storm-helper.sh"

echo "[3/4] launching dual storm: 30 s × 25 parallel each"
# Source 1 in background — capture CSV via ssh stdout.
ssh_to "$STORM1_HOST" "/tmp/storm-helper.sh 30 25 '$URL' source1" > "$RESULTS/source1.csv" 2>&1 &
S1_PID=$!
# Source 2 (this host) in background.
"$(dirname "${BASH_SOURCE[0]}")/storm-helper.sh" 30 25 "$URL" source2 > "$RESULTS/source2.csv" 2>&1 &
S2_PID=$!

wait $S1_PID $S2_PID
say "both sources" "storms complete"

# ---- analyse ------------------------------------------------------

echo "[4/4] verdict"
analyse() {
    local f=$1 label=$2
    local total=$(($(wc -l < "$f") - 1))
    local ok=$(awk -F, 'NR>1 && $2=="200" {n++} END {print n+0}' "$f")
    local rl=$(awk -F, 'NR>1 && $2=="429" {n++} END {print n+0}' "$f")
    local err=$(awk -F, 'NR>1 && $2!="200" && $2!="429" {n++} END {print n+0}' "$f")
    printf "  %s: total=%d  200=%d  429=%d  err=%d\n" "$label" "$total" "$ok" "$rl" "$err"
}
analyse "$RESULTS/source1.csv" "source-1"
analyse "$RESULTS/source2.csv" "source-2"

s1_ok=$(awk -F, 'NR>1 && $2=="200" {n++} END {print n+0}' "$RESULTS/source1.csv")
s2_ok=$(awk -F, 'NR>1 && $2=="200" {n++} END {print n+0}' "$RESULTS/source2.csv")
total_ok=$((s1_ok + s2_ok))

echo
echo "  per-IP cap: 20/min"
echo "  source-1 admitted: $s1_ok"
echo "  source-2 admitted: $s2_ok"
echo "  total admitted:    $total_ok"

# Pass criteria: each source admitted ~20 (within 5-30 tolerance for
# clock skew / retention pass), total > single-source baseline of 20.
flag1=PASS; [ "$s1_ok" -ge 5 ] && [ "$s1_ok" -le 30 ] || flag1=FAIL
flag2=PASS; [ "$s2_ok" -ge 5 ] && [ "$s2_ok" -le 30 ] || flag2=FAIL
flag_iso=PASS; [ "$total_ok" -ge 30 ] || flag_iso=FAIL  # > single-source baseline

echo "  source-1 in band (5-30):    $flag1"
echo "  source-2 in band (5-30):    $flag2"
echo "  isolation (total > 30):     $flag_iso"

# ---- teardown -----------------------------------------------------

ssh_to "$REPLICA_HOST" "
    kill \$(cat /tmp/iac-cp-f8m.pid) 2>/dev/null || true
    sleep 1
    rm -rf /var/lib/iac-cp-f8m /etc/iac-cp-f8m.toml /usr/local/bin/iac-cp-f8m /var/log/iac-cp-f8m.log /tmp/iac-cp-f8m.pid
"
ssh_to "$STORM1_HOST" "rm -f /tmp/storm-helper.sh"

if [ "$flag1" = "PASS" ] && [ "$flag2" = "PASS" ] && [ "$flag_iso" = "PASS" ]; then
    echo
    echo "F8 multi-IP: PASS"
else
    echo
    echo "F8 multi-IP: FAIL"
    exit 1
fi
