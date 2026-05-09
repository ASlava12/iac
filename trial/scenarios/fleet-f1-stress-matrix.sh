#!/bin/bash
# Phase 9 F1 stress matrix — pre-defined long-form variants of the
# baseline F1 soak. Each variant exercises one axis at extreme:
#
#   72h    — 3× the baseline duration. Catches slow leaks that
#            evade 24h (e.g. a 0.1 MB/h growth that aggregates to
#            7 MB at 24h is invisible — at 72h it's 22 MB and the
#            absolute-cap finalize check trips).
#   burst  — 5–10× the baseline submit rate. Catches latency
#            knees: F1 baseline is 1 RPS; production fleets push
#            10–50 RPS sustained. With fixes 1–6 in place this
#            should stay under SLA at 5 RPS; if not, that's the
#            next gap.
#   density — multiple iac-agent processes per VPS, simulating a
#            larger fleet without renting more hardware. Stub for
#            now (needs systemd template unit + per-instance state
#            dirs); use whichever variant matters first.
#
# Usage:
#   ./trial/scenarios/fleet-f1-stress-matrix.sh 72h
#   ./trial/scenarios/fleet-f1-stress-matrix.sh burst
#   ./trial/scenarios/fleet-f1-stress-matrix.sh density   # stub
#
# Pre-condition: F1 baseline has PASSed cleanly at least once. The
# stress matrix is for *post*-F1-#7-PASS deeper validation; running
# it before clean baseline obscures what's variant-induced vs
# already-broken.

set -eu

VARIANT="${1:-}"
[ -n "$VARIANT" ] || { echo "usage: $0 {72h|burst|density}" >&2; exit 1; }

SOAK="$(dirname "${BASH_SOURCE[0]}")/fleet-f1-soak.sh"
[ -x "$SOAK" ] || { echo "$SOAK missing" >&2; exit 1; }

case "$VARIANT" in
    72h)
        echo "=== F1 stress: 72-hour duration ==="
        echo "Doctrine: 3× baseline. Catches slow leaks invisible at 24h."
        echo "Capacity-health caps need to hold for 3× duration; failure-trend"
        echo "slope detection (≥3 hours @ ≥1 %) treats this exactly the same."
        echo "Estimated wall: 72h. Runs under nohup; safe to disconnect."
        echo
        DURATION_SECS=259200 RPS=1.0 exec "$SOAK"
        ;;
    burst)
        echo "=== F1 stress: 5 RPS burst ==="
        echo "Doctrine: 5× baseline submit rate, 24h duration."
        echo "Catches latency-knee patterns: with fix #4 (batched INSERTs)"
        echo "and fix #6 (planned), should stay under 1 % failures."
        echo "If failure trend climbs > 1 % within first 2 hours, abort."
        echo
        DURATION_SECS=86400 RPS=5.0 exec "$SOAK"
        ;;
    density)
        echo "=== F1 stress: agent density (STUB) ==="
        echo
        echo "Not yet implemented. Plan:"
        echo "  1. systemd template unit iac-agent@.service on each VPS"
        echo "     (lets us spawn iac-agent@1, iac-agent@2, … with"
        echo "      isolated state_dir / config)."
        echo "  2. agent.toml.tmpl with ${INSTANCE} substitution for"
        echo "     state_dir / db_path / agent_name."
        echo "  3. fleet-bootstrap with DENSITY=N — install N agents/VPS."
        echo "  4. iac-trial --targets resolves to all N×7 = 7N names."
        echo
        echo "Skipped for now: at 7 agents the 5 fix defaults haven't"
        echo "fully bedded in. Density variant is more useful AFTER"
        echo "F1 #7 demonstrates clean PASS at the 7-agent baseline."
        exit 1
        ;;
    *)
        echo "Unknown variant: $VARIANT (try 72h, burst, density)" >&2
        exit 1
        ;;
esac
