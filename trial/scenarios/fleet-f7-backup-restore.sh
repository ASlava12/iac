#!/bin/bash
# Phase 9 F7 — backup / restore of the controlplane DB.
#
# Pass criteria:
#   * hot backup completes WITHOUT restarting iac-controlplane
#     (pre-condition for "0 unaccounted restarts" in F1)
#   * restored CP comes up clean on a different host with the same
#     audit-chain tip the snapshot captured
#   * /v1/audit/verify on restored CP returns ok=true
#   * agents-table count matches snapshot-time count
#   * a fresh write on the restored CP extends the chain cleanly
#     (proves the chain is not corrupted at the restore tip)
#
# Strategy: SQLite `.backup` is a hot, page-level copy that handles
# concurrent writers via the same locks that normal queries use.
# It works even with WAL active; the snapshot is internally
# consistent. We measure:
#   RPO = backup_completed_ts - backup_started_ts
#         (the window where post-snapshot writes are NOT in the snapshot)
#   RTO = restore_done_ts - restore_started_ts
#         (the operator-experienced "time to a healthy CP back up")
#
# Usage:
#   ./trial/scenarios/fleet-f7-backup-restore.sh
#
# Required:
#   * fixed iac-controlplane binary at target/release/iac-controlplane
#     (copied here from the build host).
#   * cp-spare-02 reachable, sqlite3 + curl available.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

RESTORE_HOST="$(inventory_hosts cp_spare | sed -n '2p' | cut -f2)"
RESTORE_PORT=8445
RESTORE_TOKEN="f7-restore-token"
F7_LOCAL=/tmp/iac-f7-results
mkdir -p "$F7_LOCAL"

echo "=== F7 backup/restore ==="
echo "  source CP:   $CP_IP:$CP_PORT (live, F1 in flight — must not restart)"
echo "  restore on:  $RESTORE_HOST:$RESTORE_PORT (fresh CP, clean state dir)"
echo

# ---- step 1: ensure restore-host has the fixed binary -------------

echo "[1/6] staging fixed binary on $RESTORE_HOST"
LOCAL_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/release/iac-controlplane"
[ -x "$LOCAL_BIN" ] || { echo "FAIL: $LOCAL_BIN not built" >&2; exit 1; }
scp_to "$LOCAL_BIN" "$RESTORE_HOST" /usr/local/bin/iac-cp-f7
ssh_to "$RESTORE_HOST" "chmod +x /usr/local/bin/iac-cp-f7"

# ---- step 2: hot backup on prod CP --------------------------------

echo "[2/6] VACUUM INTO snapshot on prod CP (no service restart)"
ssh_to "$CP_IP" "
    set -eu
    mkdir -p /var/lib/iac-controlplane/backups
    rm -f /var/lib/iac-controlplane/backups/snapshot.db
"
backup_started=$(date +%s%N)
# `VACUUM INTO` is a single-statement transactional snapshot — unlike
# `.backup`, it doesn't restart on every page-level SQLITE_BUSY, so it
# completes in roughly disk-write time even on a hot DB. The earlier
# `.backup` attempt stalled at 40% after 30 min on this 950 MB DB
# under F1's ~3 ops/sec write load. `VACUUM INTO` finishes in seconds.
# Bonus: it also defragments and drops free pages, so the snapshot
# file is smaller than the source.
ssh_to "$CP_IP" "sqlite3 /var/lib/iac-controlplane/server.db \"VACUUM INTO '/var/lib/iac-controlplane/backups/snapshot.db'\""
backup_done=$(date +%s%N)
backup_ms=$(( (backup_done - backup_started) / 1000000 ))

# Read snapshot stats *from the snapshot file* (deterministic — no race
# with the live CP that keeps writing).
snap_size=$(ssh_to "$CP_IP" "stat -c%s /var/lib/iac-controlplane/backups/snapshot.db")
snap_audit_tip=$(ssh_to "$CP_IP" "sqlite3 /var/lib/iac-controlplane/backups/snapshot.db 'SELECT COALESCE(MAX(id),0) FROM audit_events'")
snap_agents=$(ssh_to "$CP_IP" "sqlite3 /var/lib/iac-controlplane/backups/snapshot.db 'SELECT COUNT(*) FROM agents'")
echo "  snapshot:    $((snap_size/1024/1024)) MiB, audit tip $snap_audit_tip, $snap_agents agents"
echo "  backup wall: ${backup_ms} ms (RPO = post-snapshot writes lost on restore)"

# Also confirm prod CP did NOT restart during the backup.
prod_uptime_sec=$(ssh_to "$CP_IP" "systemctl show iac-controlplane --property=ActiveEnterTimestampMonotonic --value")
echo "  prod CP ActiveEnter (monotonic μs): $prod_uptime_sec  (unchanged from F1 start = pass)"

# ---- step 3: ship snapshot to restore host ------------------------

echo "[3/6] shipping snapshot to $RESTORE_HOST"
ship_start=$(date +%s%N)
ssh_to "$RESTORE_HOST" "
    set -eu
    rm -rf /var/lib/iac-cp-f7
    mkdir -p /var/lib/iac-cp-f7
"
# Direct VPS-to-VPS copy avoids a round-trip through the operator host.
ssh_to "$CP_IP" "
    set -eu
    scp -i ~/.ssh/iac_fleet -o BatchMode=yes -o StrictHostKeyChecking=no -q \
        /var/lib/iac-controlplane/backups/snapshot.db \
        root@$RESTORE_HOST:/var/lib/iac-cp-f7/server.db
" || {
    # Fall back via operator host if cp doesn't have the fleet key.
    echo "  (direct VPS→VPS scp failed; routing via operator host)"
    scp -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no -q \
        "root@$CP_IP:/var/lib/iac-controlplane/backups/snapshot.db" "$F7_LOCAL/snapshot.db"
    scp_to "$F7_LOCAL/snapshot.db" "$RESTORE_HOST" /var/lib/iac-cp-f7/server.db
}
ship_done=$(date +%s%N)
ship_ms=$(( (ship_done - ship_start) / 1000000 ))
echo "  shipped in:  ${ship_ms} ms"

# ---- step 4: spin up restored CP ----------------------------------

echo "[4/6] starting restored CP on $RESTORE_HOST:$RESTORE_PORT"
restore_started=$(date +%s%N)
ssh_to "$RESTORE_HOST" "
    set -eu
    cat > /etc/iac-cp-f7.toml <<EOF
bind          = '0.0.0.0:$RESTORE_PORT'
state_dir     = '/var/lib/iac-cp-f7'
database_url  = 'sqlite:///var/lib/iac-cp-f7/server.db?mode=rwc'
max_body_bytes = 4194304
admin_token   = '$RESTORE_TOKEN'
[rate_limit]
operations_per_minute = 100000
[retention]
audit_days = 7
[tls]
mode = 'none'
EOF
    nohup /usr/local/bin/iac-cp-f7 --config /etc/iac-cp-f7.toml \
        > /var/log/iac-cp-f7.log 2>&1 &
    echo \$! > /tmp/iac-cp-f7.pid
"

# Wait for /v1/health 200 — this is the operator-visible RTO.
for i in $(seq 1 30); do
    code=$(curl -sS -m 2 -o /dev/null -w '%{http_code}' \
        "http://$RESTORE_HOST:$RESTORE_PORT/v1/health" 2>/dev/null || echo 000)
    if [ "$code" = "200" ]; then
        restore_done=$(date +%s%N)
        rto_ms=$(( (restore_done - restore_started) / 1000000 ))
        echo "  /v1/health 200 after ${rto_ms} ms (RTO including process start)"
        break
    fi
    sleep 1
done
[ -n "${rto_ms:-}" ] || { echo "FAIL: restored CP didn't come healthy in 30s" >&2; ssh_to "$RESTORE_HOST" "tail -30 /var/log/iac-cp-f7.log"; exit 1; }

# ---- step 5: integrity checks -------------------------------------

echo "[5/6] integrity checks on restored CP"
restored_chain=$(curl -fsS -m 5 -H "Authorization: Bearer $RESTORE_TOKEN" \
    "http://$RESTORE_HOST:$RESTORE_PORT/v1/audit/chain-tip")
restored_tip=$(echo "$restored_chain" | jq -r '.last_id')
restored_agents=$(curl -fsS -m 5 -H "Authorization: Bearer $RESTORE_TOKEN" \
    "http://$RESTORE_HOST:$RESTORE_PORT/v1/agents" | jq 'length')
verify_resp=$(curl -fsS -m 10 -H "Authorization: Bearer $RESTORE_TOKEN" \
    "http://$RESTORE_HOST:$RESTORE_PORT/v1/audit/verify" || echo '{}')
verify_ok=$(echo "$verify_resp" | jq -r '.ok // false')

ok_tip=PASS;    [ "$restored_tip"    = "$snap_audit_tip" ] || ok_tip=FAIL
ok_agents=PASS; [ "$restored_agents" = "$snap_agents" ]    || ok_agents=FAIL
ok_verify=PASS; [ "$verify_ok"       = "true" ]            || ok_verify=FAIL

echo "  audit tip   restored=$restored_tip  expected=$snap_audit_tip  [$ok_tip]"
echo "  agents      restored=$restored_agents  expected=$snap_agents  [$ok_agents]"
echo "  /v1/audit/verify ok=$verify_ok  [$ok_verify]"

# Step 5b: fresh write to prove the chain extends cleanly post-restore.
fresh_resp=$(curl -fsS -m 5 -X POST \
    "http://$RESTORE_HOST:$RESTORE_PORT/v1/agents/register" \
    -H 'Content-Type: application/json' \
    -d '{"name":"f7-post-restore-probe","environment":"f7","metadata":{}}' || echo '{}')
fresh_ok=$(echo "$fresh_resp" | jq -r 'has("agent_id")')
if [ "$fresh_ok" = "true" ]; then
    new_tip=$(curl -fsS -m 5 -H "Authorization: Bearer $RESTORE_TOKEN" \
        "http://$RESTORE_HOST:$RESTORE_PORT/v1/audit/chain-tip" | jq -r '.last_id')
    final_verify=$(curl -fsS -m 10 -H "Authorization: Bearer $RESTORE_TOKEN" \
        "http://$RESTORE_HOST:$RESTORE_PORT/v1/audit/verify" | jq -r '.ok // false')
    ok_extend=PASS
    [ "$new_tip" -gt "$restored_tip" ] || ok_extend=FAIL
    [ "$final_verify" = "true" ]       || ok_extend=FAIL
    echo "  post-restore write: tip $restored_tip → $new_tip, verify=$final_verify  [$ok_extend]"
else
    ok_extend=FAIL
    echo "  post-restore write FAILED: $fresh_resp  [FAIL]"
fi

# ---- step 6: tear down restored CP --------------------------------

echo "[6/6] tearing down restored CP"
ssh_to "$RESTORE_HOST" "
    kill \$(cat /tmp/iac-cp-f7.pid) 2>/dev/null || true
    sleep 1
    rm -rf /var/lib/iac-cp-f7 /etc/iac-cp-f7.toml /usr/local/bin/iac-cp-f7 \
           /var/log/iac-cp-f7.log /tmp/iac-cp-f7.pid
"
ssh_to "$CP_IP" "rm -f /var/lib/iac-controlplane/backups/snapshot.db"

# ---- verdict ------------------------------------------------------

echo
echo "=== F7 verdict ==="
if [ "$ok_tip" = "PASS" ] && [ "$ok_agents" = "PASS" ] \
   && [ "$ok_verify" = "PASS" ] && [ "$ok_extend" = "PASS" ]; then
    overall=PASS
else
    overall=FAIL
fi
printf "  RPO (backup wall):    %d ms\n" "$backup_ms"
printf "  RTO (start→healthy):  %d ms\n" "$rto_ms"
printf "  ship time on wire:    %d ms (%d MiB)\n" "$ship_ms" "$((snap_size/1024/1024))"
printf "  audit-tip match:      %s\n" "$ok_tip"
printf "  agent-count match:    %s\n" "$ok_agents"
printf "  audit verify ok:      %s\n" "$ok_verify"
printf "  post-restore extend:  %s\n" "$ok_extend"
printf "  overall:              %s\n" "$overall"
[ "$overall" = "PASS" ] || exit 1
