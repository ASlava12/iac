#!/bin/sh
# F1 RSS sampler — runs as a nohup daemon on cp + every agent.
# Polls the iac binary's RSS / VSZ / %CPU at $SAMPLE_INTERVAL_SECS
# and appends to /var/log/iac-trial-f1-rss.csv.
#
# Two args (positional):
#   $1 = systemd unit to track (e.g. `iac-controlplane` or `iac-agent`)
#   $2 = sample interval in seconds
# Stops when /var/log/iac-trial-f1-stop exists.
#
# Why systemctl-MainPID instead of `pgrep`: Linux truncates the
# `comm` field to 15 chars, so `pgrep -x iac-controlplane` (16
# chars) finds nothing. Using `systemctl show -p MainPID` is
# unambiguous, also handles restart correctly (MainPID updates).

set -eu
UNIT="${1:-iac-agent}"
INTERVAL="${2:-300}"
LOG=/var/log/iac-trial-f1-rss.csv
STOP=/var/log/iac-trial-f1-stop

[ -f "$LOG" ] || echo 'unix_ts,unit,pid,rss_kb,vsz_kb,cpu_pct' > "$LOG"

while [ ! -f "$STOP" ]; do
    PID=$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null || echo 0)
    TS=$(date +%s)
    if [ "$PID" != "0" ] && [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        STATS=$(ps -p "$PID" -o rss=,vsz=,pcpu= 2>/dev/null | awk '{print $1","$2","$3}')
        printf '%s,%s,%s,%s\n' "$TS" "$UNIT" "$PID" "$STATS" >> "$LOG"
    else
        printf '%s,%s,,,,\n' "$TS" "$UNIT" >> "$LOG"
    fi
    sleep "$INTERVAL"
done
