#!/bin/bash
# Phase 9-F1-fix-6: shared capacity-health + failure-trend helpers,
# sourced by fleet-f1-{status,finalize}.sh and any other harness that
# wants to assert the F1 capacity ceilings held.
#
# Functions:
#   capacity_health_report  — print 5-flag status of CP capacity
#                             ceilings (db/wal/disk/busy/slow). Sets
#                             $cap_fail to 1 if any breaks the ceiling.
#   failure_trend_report    — print per-hour failure-rate trend +
#                             slope detection. Sets $trend_fail to 1
#                             if the rate is climbing through the
#                             1 % threshold.
#
# Both depend on the parent script having sourced fleet/lib.sh first
# (provides $CP_IP, $CP_PORT, $ADMIN_TOKEN, $ssh_to). Both are safe
# to call in any order; failure modes are independent.

# ---- capacity-health -----------------------------------------------

# Caps — tuned from Phase 9-F1-fix-1..5 defaults. Keep in sync with
# crates/iac-controlplane/src/{config.rs,store.rs,retention.rs}.
: "${CAPHEALTH_DB_MIB_CAP:=5120}"      # 5 GiB — fleet outgrew SQLite
: "${CAPHEALTH_WAL_MIB_CAP:=1024}"     # journal_size_limit (fix #6: 256→1024)
: "${CAPHEALTH_DISK_PCT_CAP:=80}"      # disk-full pre-warning
: "${CAPHEALTH_BUSY_5M_CAP:=50}"       # ~10/min — saturation
: "${CAPHEALTH_SLOW_5M_CAP:=100}"      # SQLite write-path blocked

capacity_health_report() {
    local title="${1:-capacity-health (Phase 9-F1-fix ceilings)}"
    echo "  $title:"

    local cap
    # `grep -c` already prints "0" on no-match (with exit 1); using
    # `|| echo 0` doubles the output and breaks the single-line
    # `read -r` below. Use `|| true` to suppress the exit code only.
    cap=$(ssh_to "$CP_IP" "
        db=\$(stat -c%s /var/lib/iac-controlplane/server.db 2>/dev/null || echo 0)
        wal=\$(stat -c%s /var/lib/iac-controlplane/server.db-wal 2>/dev/null || echo 0)
        df_avail=\$(df -k / | awk 'NR==2 {print \$4}')
        df_total=\$(df -k / | awk 'NR==2 {print \$2}')
        busy=\$(journalctl -u iac-controlplane --since '5 minutes ago' --no-pager 2>/dev/null | grep -c 'database is locked' || true)
        slow=\$(journalctl -u iac-controlplane --since '5 minutes ago' --no-pager 2>/dev/null | grep -c 'slow statement' || true)
        echo \"\$db \$wal \$df_avail \$df_total \$busy \$slow\"
    " 2>/dev/null || echo "0 0 0 0 0 0")
    local db_b wal_b avail_kb total_kb busy slow
    read -r db_b wal_b avail_kb total_kb busy slow <<< "$cap"

    local db_mb=$((db_b / 1024 / 1024))
    local wal_mb=$((wal_b / 1024 / 1024))
    local disk_pct=0
    [ "$total_kb" -gt 0 ] && disk_pct=$((100 - (avail_kb * 100 / total_kb)))

    local f_db="✓" f_wal="✓" f_disk="✓" f_busy="✓" f_slow="✓"
    [ "$db_mb"    -gt "$CAPHEALTH_DB_MIB_CAP"   ] && { f_db="✗";   cap_fail=1; }
    [ "$wal_mb"   -gt "$CAPHEALTH_WAL_MIB_CAP"  ] && { f_wal="✗";  cap_fail=1; }
    [ "$disk_pct" -gt "$CAPHEALTH_DISK_PCT_CAP" ] && { f_disk="✗"; cap_fail=1; }
    [ "$busy"     -gt "$CAPHEALTH_BUSY_5M_CAP"  ] && { f_busy="✗"; cap_fail=1; }
    [ "$slow"     -gt "$CAPHEALTH_SLOW_5M_CAP"  ] && { f_slow="✗"; cap_fail=1; }

    printf "    %s server.db:    %d MiB  (cap %d MiB)\n" "$f_db"   "$db_mb"    "$CAPHEALTH_DB_MIB_CAP"
    printf "    %s WAL:          %d MiB  (cap %d MiB)\n" "$f_wal"  "$wal_mb"   "$CAPHEALTH_WAL_MIB_CAP"
    printf "    %s Disk used:    %d %%   (cap %d%%)\n"   "$f_disk" "$disk_pct" "$CAPHEALTH_DISK_PCT_CAP"
    printf "    %s busy/5min:    %d      (cap %d)\n"     "$f_busy" "$busy"     "$CAPHEALTH_BUSY_5M_CAP"
    printf "    %s slow/5min:    %d      (cap %d)\n"     "$f_slow" "$slow"     "$CAPHEALTH_SLOW_5M_CAP"

    if [ "$f_wal" = "✗" ] || [ "$f_busy" = "✗" ]; then
        echo "    NOTE: WAL or busy-rate ceiling exceeded — likely a NEW gap"
        echo "          (or load pattern outgrew the corresponding default)."
        echo "          See docs/en/runbook.md \"Capacity exhaustion\" for tuning."
    fi
}

# ---- failure-rate trend / slope detection --------------------------

# iac-trial logs `longevity progress submitted=N failures=M` ~every
# 100 ops. We bucket the timestamps into 1-hour windows and compute
# the per-window failure delta. Rising slope = deterioration.
#
# Args:
#   $1 = path to trial.log (defaults to /var/lib/iac-trial/f1/trial.log
#        on $CP_IP if remote; for local files pass directly).
#   $2 = source mode: "remote" (default) or "local".

failure_trend_report() {
    local log_path="${1:-/var/lib/iac-trial/f1/trial.log}"
    local mode="${2:-remote}"
    echo "  failure-rate trend (per-hour deltas):"

    local lines
    if [ "$mode" = "local" ]; then
        lines=$(grep 'longevity progress' "$log_path" 2>/dev/null || true)
    else
        lines=$(ssh_to "$CP_IP" "grep 'longevity progress' $log_path 2>/dev/null || true")
    fi

    if [ -z "$lines" ]; then
        echo "    (no progress lines yet — < 100 ops submitted)"
        return
    fi

    # Strip ANSI escapes; extract iso8601 timestamp + submitted + failures.
    # Bucket by hour (HH from "T<HH>:..."). Track per-bucket max
    # cumulative submitted/failures, then compute delta vs prior bucket.
    local trend
    trend=$(printf '%s\n' "$lines" \
        | sed 's/\x1b\[[0-9;]*m//g' \
        | awk '
            match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}/) {
                bucket = substr($0, RSTART, RLENGTH)
                match($0, /submitted=[0-9]+/);  s = substr($0, RSTART+10, RLENGTH-10) + 0
                match($0, /failures=[0-9]+/);   f = substr($0, RSTART+9,  RLENGTH-9)  + 0
                if (!(bucket in firstS) || s > maxS[bucket]) maxS[bucket] = s
                if (!(bucket in firstS) || f > maxF[bucket]) maxF[bucket] = f
                if (!(bucket in firstS)) { firstS[bucket] = s; firstF[bucket] = f; ord[++n] = bucket }
            }
            END {
                # Print buckets in arrival order with delta vs previous.
                prev_s = 0; prev_f = 0
                for (i=1; i<=n; i++) {
                    b = ord[i]
                    ds = maxS[b] - prev_s
                    df = maxF[b] - prev_f
                    pct = ds > 0 ? df*100/ds : 0
                    printf "%s %d %d %.2f\n", b, ds, df, pct
                    prev_s = maxS[b]; prev_f = maxF[b]
                }
            }')

    if [ -z "$trend" ]; then
        echo "    (no parsable progress lines)"
        return
    fi

    # Pretty-print per-hour deltas with ✓/! flags.
    printf "    %-15s %10s %10s %10s\n" "hour" "Δsub" "Δfail" "rate%"
    local last_pct=0 first_pct=-1
    while IFS=' ' read -r bucket ds df pct; do
        local flag="✓"
        awk -v p="$pct" 'BEGIN { exit (p < 1.0 ? 0 : 1) }' || flag="!"
        printf "    %s  %-2s %10s %10s %10s\n" "$bucket" "$flag" "$ds" "$df" "${pct}%"
        last_pct=$pct
        [ "$first_pct" = "-1" ] && first_pct=$pct
    done <<< "$trend"

    # Slope detection. Two complementary triggers:
    #  1. last-hour rate > 2× the first non-zero hour AND last-hour
    #     ≥ 0.5 % absolute (catches "we started clean and the pattern
    #     emerged" — F1 #6's shape). The 0.5 % floor stops the
    #     detector from firing on noise: F1 #9 saw 0.03 % → 0.24 %
    #     in early hours which is an 8× ratio but utterly under SLA;
    #     without the floor the harness reports false-positive
    #     "deteriorating" on healthy runs. F1 #6-#8's actual
    #     deterioration crossed 0.5 % within an hour of starting, so
    #     the floor doesn't mask real bad runs.
    #  2. last-hour rate sustained ≥ 1 % over multiple hours (catches
    #     "we entered the danger zone and stayed there" even if the
    #     rate is steady, not growing).
    # Either flips trend_fail; the report distinguishes them so the
    # operator can see WHY it tripped.
    local first_nonzero
    first_nonzero=$(printf '%s\n' "$trend" \
        | awk '$4+0 > 0 { print $4; exit }')
    if [ -n "$first_nonzero" ] \
       && awk -v f="$first_nonzero" -v l="$last_pct" 'BEGIN { exit (f > 0 && l > 2*f && l >= 0.5 ? 0 : 1) }'; then
        echo "    ✗ slope: last-hour rate ${last_pct}% > 2× first-non-zero ${first_nonzero}% — deteriorating"
        trend_fail=1
    fi
    # Count hours where rate ≥ 1 %.
    local hot_hours
    hot_hours=$(printf '%s\n' "$trend" | awk '$4+0 >= 1.0 { n++ } END { print n+0 }')
    if [ "$hot_hours" -ge 3 ]; then
        echo "    ✗ rate sustained ≥ 1 % across $hot_hours hours — failure budget breached"
        trend_fail=1
    fi
    if [ "$trend_fail" != "1" ] && awk -v l="$last_pct" 'BEGIN { exit (l >= 1.0 ? 0 : 1) }'; then
        echo "    ! last-hour rate ${last_pct}% above 1 % threshold (slope not yet flagged)"
    elif [ "$trend_fail" != "1" ]; then
        echo "    ✓ rate steady ≤ 1 % over time"
    fi
}
