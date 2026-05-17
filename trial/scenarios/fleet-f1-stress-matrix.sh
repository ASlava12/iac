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
        # Phase 9-F1-stress-density: multi-iac-agent-per-VPS via the
        # systemd template unit `iac-agent@.service` + per-instance
        # state dirs. F1 baseline PASSed at 7 agents (commit 483ff87);
        # density variant lets us probe the agent-count axis without
        # renting more VPS.
        #
        # Defaults:
        #   DENSITY=3        — 3 agents per VPS → 7×3 = 21 total
        #   DURATION_SECS    — 86400 (24h F1-baseline shape)
        #   RPS              — 1.0 (proportional to baseline; total
        #                      submit rate scales with agent count)
        #
        # Refuses to start if F1 baseline (agent count 7) is already
        # active — the density variant assumes a clean fleet.
        DENSITY="${DENSITY:-3}"
        if ! [[ "$DENSITY" =~ ^[0-9]+$ ]] || [ "$DENSITY" -lt 1 ] || [ "$DENSITY" -gt 20 ]; then
            echo "DENSITY must be an integer in [1, 20]; got: $DENSITY" >&2
            exit 1
        fi
        DENSITY_SCRIPT="$(dirname "${BASH_SOURCE[0]}")/fleet-f1-stress-density.sh"
        [ -x "$DENSITY_SCRIPT" ] || { echo "$DENSITY_SCRIPT missing" >&2; exit 1; }
        echo "=== F1 stress: agent density ==="
        echo "Doctrine: $DENSITY agents per VPS × 7 VPS = $((DENSITY * 7)) total agents."
        echo "Same F1 PASS thresholds (RSS < 5 % growth, 0 unaccounted"
        echo "restarts, audit chain verifies, < 1 % errors). Probes the"
        echo "agent-count axis — useful for sizing decisions ('can 1 CP"
        echo "really hold 50 agents?') without spinning up more VPS."
        echo
        exec "$DENSITY_SCRIPT"
        ;;
    *)
        echo "Unknown variant: $VARIANT (try 72h, burst, density)" >&2
        exit 1
        ;;
esac
