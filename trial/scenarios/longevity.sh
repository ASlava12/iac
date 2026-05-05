#!/bin/sh
# Phase 8: longevity scenario.
#
# 30-agent fleet, low constant submit rate for 30 minutes (default;
# override via DURATION_SECS). Pass criteria same as
# submit-burst: < 1% errors, < 5% slow ops.
#
# Doubles as a "leave it running overnight" smoke test — set
# DURATION_SECS=86400 for 24h.

set -eu

cd "$(dirname "$0")/../.."

COMPOSE="docker compose -f trial/compose/docker-compose.yml"
TRIAL_BIN="${TRIAL_BIN:-./target/release/iac-trial}"
DURATION_SECS="${DURATION_SECS:-1800}"

if [ ! -x "$TRIAL_BIN" ]; then
    cargo build --release -p iac-trial
fi
# Phase 7dh.10 (audit): see baseline-50.sh — guard against build silently
# putting the binary somewhere else.
if [ ! -x "$TRIAL_BIN" ]; then
    echo "iac-trial binary not found at $TRIAL_BIN after build" >&2
    exit 1
fi

cleanup() {
    echo "--- tearing down ---"
    # Phase 7dh.10 (audit): bound `compose down` so a wedged container
    # can't pin the cleanup forever (this script is meant to run for
    # hours; a stuck teardown is doubly painful here).
    timeout 60s $COMPOSE down -v --remove-orphans || true
}
trap cleanup EXIT

$COMPOSE build
$COMPOSE up -d --scale agent=30
"$TRIAL_BIN" wait-fleet --expected 30 --timeout-secs 180

echo "--- longevity: $DURATION_SECS seconds @ 1 RPS ---"
"$TRIAL_BIN" longevity --duration-secs "$DURATION_SECS" --rps 1.0

echo "--- longevity: PASS ---"
