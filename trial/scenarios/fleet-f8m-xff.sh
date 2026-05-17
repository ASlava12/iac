#!/bin/bash
# Phase 9-F8 follow-up: X-Forwarded-For trusted-proxy harness.
#
# Validates that when the CP is behind a reverse proxy listed in
# `trusted_proxies`, the per-IP rate-limit bucket keys by the
# `X-Forwarded-For` header instead of the socket peer's IP. Without
# this, a single proxy fronting many real clients would squash them
# all into one bucket and the per-IP cap would be useless.
#
# Spins up an ephemeral CP on 127.0.0.1 with trusted_proxies =
# ["127.0.0.1"] and register_per_minute_per_ip = 5 — no real fleet
# disruption, deterministic timings, fully reproducible locally.
#
# Pass criteria:
#   - 5 requests with X-Forwarded-For: 1.1.1.1 succeed (200).
#   - 6th request with the same header returns 429.
#   - 5 requests with X-Forwarded-For: 2.2.2.2 succeed (separate
#     bucket; proves the limiter is keying by the header, not by
#     socket IP — which is 127.0.0.1 for both).
#   - 1 request WITHOUT the header goes to the bucket for the
#     socket IP (127.0.0.1). It's a 4th distinct bucket — still
#     OK since this is the harness's only direct-from-trusted-IP
#     request in this run.
#
# Usage:
#   ./trial/scenarios/fleet-f8m-xff.sh
#
# Exits 0 on PASS, non-zero on FAIL.

set -eu

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CP_BIN="$REPO_ROOT/target/release/iac-controlplane"
[ -x "$CP_BIN" ] || { echo "missing $CP_BIN; build with cargo build --release -p iac-controlplane" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'set +e; [ -n "${CP_PID:-}" ] && kill "$CP_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

PORT=18443
CFG="$WORK/server.toml"
cat > "$CFG" <<EOF
bind          = "127.0.0.1:$PORT"
state_dir     = "$WORK/state"
database_url  = "sqlite://$WORK/state/server.db?mode=rwc"
admin_token   = "f8-xff-test-token"

[rate_limit]
register_per_minute_per_ip = 5

[[trusted_proxies]]
# Inline-table TOML syntax for std::net::IpAddr would be cleaner; the
# Vec<IpAddr> deserialiser accepts the standard array-of-string form
# (see Config::trusted_proxies serde decl), so use that here.
EOF
# trusted_proxies as a TOML array of strings — serde_json IP-deserialise
# accepts that shape.
cat > "$CFG" <<EOF
bind            = "127.0.0.1:$PORT"
state_dir       = "$WORK/state"
database_url    = "sqlite://$WORK/state/server.db?mode=rwc"
admin_token     = "f8-xff-test-token"
trusted_proxies = ["127.0.0.1"]

[rate_limit]
register_per_minute_per_ip = 5
EOF

mkdir -p "$WORK/state"
echo "=== starting ephemeral CP on 127.0.0.1:$PORT ==="
"$CP_BIN" --config "$CFG" > "$WORK/cp.log" 2>&1 &
CP_PID=$!

# Wait for /v1/health.
i=0
while [ $i -lt 30 ]; do
    if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/v1/health" 2>/dev/null; then
        echo "  /v1/health OK after ${i}s"
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ $i -ge 30 ]; then
    echo "FAIL: CP didn't come up within 30 s" >&2
    cat "$WORK/cp.log" >&2
    exit 1
fi

# Helper: register N times with a given X-F-F header. Returns
# `<200-count> <429-count>` on stdout.
register_burst() {
    local xff="$1"; local n="$2"
    local ok=0 over=0 other=0
    for i in $(seq 1 "$n"); do
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            -X POST "http://127.0.0.1:$PORT/v1/agents/register" \
            -H "Content-Type: application/json" \
            ${xff:+-H "X-Forwarded-For: $xff"} \
            -d "{\"name\":\"xff-test-${xff:-bare}-$i\",\"environment\":\"f8-xff\",\"metadata\":{}}")
        case "$code" in
            200) ok=$((ok + 1));;
            429) over=$((over + 1));;
              *) other=$((other + 1));;
        esac
    done
    echo "$ok $over $other"
}

fail=0

# Cycle 1 — IP 1.1.1.1 hits its cap on the 6th call.
echo
echo "=== cycle 1/3: X-Forwarded-For: 1.1.1.1 (cap=5, sending 6) ==="
read -r ok over other < <(register_burst "1.1.1.1" 6)
echo "  200=$ok  429=$over  other=$other"
if [ "$ok" -eq 5 ] && [ "$over" -eq 1 ] && [ "$other" -eq 0 ]; then
    echo "  ✓ correct shape (5 admitted, 1 rejected at cap)"
else
    echo "  ✗ expected 200=5 429=1 other=0"
    fail=1
fi

# Cycle 2 — different X-F-F goes to a fresh bucket.
echo
echo "=== cycle 2/3: X-Forwarded-For: 2.2.2.2 (separate bucket; cap=5, sending 5) ==="
read -r ok over other < <(register_burst "2.2.2.2" 5)
echo "  200=$ok  429=$over  other=$other"
if [ "$ok" -eq 5 ] && [ "$over" -eq 0 ] && [ "$other" -eq 0 ]; then
    echo "  ✓ separate bucket; all admitted"
else
    echo "  ✗ expected 200=5 429=0 other=0 (separate-bucket proof)"
    fail=1
fi

# Cycle 3 — bare request (no X-F-F): keys by socket IP (127.0.0.1),
# which is the trusted-proxy entry itself. That's a third distinct
# bucket and should admit cleanly.
echo
echo "=== cycle 3/3: no X-Forwarded-For (keys by socket IP) ==="
read -r ok over other < <(register_burst "" 1)
echo "  200=$ok  429=$over  other=$other"
if [ "$ok" -eq 1 ] && [ "$over" -eq 0 ] && [ "$other" -eq 0 ]; then
    echo "  ✓ socket-IP bucket admits"
else
    echo "  ✗ expected 200=1 429=0 other=0"
    fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F8 X-F-F PASS ==="
    exit 0
else
    echo "=== F8 X-F-F FAIL ==="
    echo "CP log tail:"
    tail -20 "$WORK/cp.log" >&2
    exit 1
fi
