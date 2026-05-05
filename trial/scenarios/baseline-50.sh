#!/bin/sh
# Phase 8: baseline trial scenario.
#
# 50-agent fleet, register them, fire 1000 ops at 50 RPS,
# tear down. Pass criteria: < 1% errors, < 5% slow ops (≥ 2.5 s).
# Exits non-zero on failure — wire into CI for regression
# detection.
#
# Run from repo root:
#   trial/scenarios/baseline-50.sh

set -eu

cd "$(dirname "$0")/../.."

COMPOSE="docker compose -f trial/compose/docker-compose.yml"
TRIAL_BIN="${TRIAL_BIN:-./target/release/iac-trial}"

if [ ! -x "$TRIAL_BIN" ]; then
    echo "building iac-trial release binary..."
    cargo build --release -p iac-trial
fi
# Phase 7dh.10 (audit): a successful `cargo build` doesn't guarantee the
# binary lives where we expect (custom `target-dir`, workspace re-layout,
# build script that emits to a different artefact path). Verify post-build
# so we fail loud here instead of mid-scenario when "$TRIAL_BIN" can't run.
if [ ! -x "$TRIAL_BIN" ]; then
    echo "iac-trial binary not found at $TRIAL_BIN after build" >&2
    exit 1
fi

cleanup() {
    echo "--- tearing down ---"
    # Phase 7dh.10 (audit): bound `compose down`. Without a timeout a
    # wedged agent container (e.g. ignoring SIGTERM) hangs the trap
    # forever, blocks CI, and prevents the next run from starting.
    timeout 60s $COMPOSE down -v --remove-orphans || true
}
trap cleanup EXIT

echo "--- building images (cached if unchanged) ---"
$COMPOSE build

echo "--- starting stack with 50 agents ---"
$COMPOSE up -d --scale agent=50

echo "--- waiting for fleet to register ---"
"$TRIAL_BIN" wait-fleet --expected 50 --timeout-secs 180

echo "--- submit-burst: 1000 ops @ 50 RPS, 16 concurrent ---"
"$TRIAL_BIN" submit-burst --count 1000 --rps 50 --concurrency 16

echo "--- baseline-50: PASS ---"
