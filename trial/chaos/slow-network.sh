#!/bin/sh
# Phase 8: inject network latency on a fraction of trial agents.
#
# tc/netem inside each container's network namespace. We `docker
# exec` so the chaos runs from the host without needing the
# orchestrator to know about specific replicas.
#
# Usage:
#   trial/chaos/slow-network.sh apply  100ms 30ms 5%
#   trial/chaos/slow-network.sh clear
#
# Args (apply):
#   $2 = base latency (e.g. `100ms`)
#   $3 = jitter        (e.g. `30ms`, optional)
#   $4 = loss          (e.g. `5%`, optional — sustained packet drop)
#
# By default applies to every agent. Pin to specific replicas
# with `IAC_CHAOS_AGENTS="trial-agent-1 trial-agent-7"`.
#
# Phase 7dh.10 (audit fixes C2/C5):
#   * Args are validated with strict regex before being interpolated
#     into the inner `sh -c` — prevents command injection if this
#     script is ever wrapped in automation that takes external input.
#   * The inner shell uses `set -e` so a `tc` failure aborts the
#     command instead of silently being absorbed.
#   * `--fail-fast` (env: IAC_CHAOS_FAIL_FAST=1) aborts the loop on
#     the first agent failure; default is best-effort across the
#     fleet.

set -eu

PROJECT="${COMPOSE_PROJECT_NAME:-trial}"
ACTION="${1:?usage: $0 apply|clear LATENCY [JITTER] [LOSS]}"
FAIL_FAST="${IAC_CHAOS_FAIL_FAST:-0}"

agents() {
    if [ -n "${IAC_CHAOS_AGENTS:-}" ]; then
        echo "$IAC_CHAOS_AGENTS" | tr ' ' '\n'
    else
        docker ps --filter "label=com.docker.compose.project=$PROJECT" \
                  --filter "label=com.docker.compose.service=agent" \
                  --format '{{.Names}}'
    fi
}

# tc/netem accepts:
#   * latency / jitter — `<integer><unit>` where unit ∈ {ns,us,ms,s}
#   * loss — `<integer>%` or `<float>%`
# Anything else is a config typo or an injection attempt; reject upfront.
validate_time_arg() {
    case "$1" in
        ''|*[!0-9.musnsec%]*)
            echo "invalid time arg: $1 (expected e.g. 100ms, 30ms, 1.5s)" >&2
            exit 2
            ;;
    esac
    case "$1" in
        *[0-9]ns|*[0-9]us|*[0-9]ms|*[0-9]s) ;;
        *)
            echo "invalid time arg: $1 (must end in ns/us/ms/s)" >&2
            exit 2
            ;;
    esac
}

validate_loss_arg() {
    case "$1" in
        ''|*[!0-9.%]*|*%*%*)
            echo "invalid loss arg: $1 (expected e.g. 5% or 0.5%)" >&2
            exit 2
            ;;
        *%) ;;
        *)
            echo "invalid loss arg: $1 (must end in %)" >&2
            exit 2
            ;;
    esac
}

run_on_agent() {
    container="$1"
    inner_cmd="$2"
    if docker exec "$container" sh -c "set -e; $inner_cmd" 2>&1; then
        echo "  $container: ok"
        return 0
    fi
    rc=$?
    echo "  $container: FAILED (rc=$rc)" >&2
    if [ "$FAIL_FAST" = "1" ]; then
        exit "$rc"
    fi
    return 0
}

case "$ACTION" in
    apply)
        LATENCY="${2:-100ms}"
        JITTER="${3:-}"
        LOSS="${4:-}"
        validate_time_arg "$LATENCY"
        [ -n "$JITTER" ] && validate_time_arg "$JITTER"
        [ -n "$LOSS" ] && validate_loss_arg "$LOSS"
        # Build SPEC from validated args. Each arg is whitelisted to
        # `[0-9.musns%]` shapes above so even after interpolation no
        # shell-active character can sneak in.
        SPEC="delay $LATENCY"
        [ -n "$JITTER" ] && SPEC="$SPEC $JITTER"
        [ -n "$LOSS" ] && SPEC="$SPEC loss $LOSS"
        echo "applying netem: $SPEC"
        for c in $(agents); do
            run_on_agent "$c" "tc qdisc replace dev eth0 root netem $SPEC"
        done
        ;;
    clear)
        echo "clearing netem"
        for c in $(agents); do
            run_on_agent "$c" "tc qdisc del dev eth0 root 2>/dev/null || true"
        done
        ;;
    *)
        echo "usage: $0 apply LATENCY [JITTER] [LOSS] | clear" >&2
        exit 1
        ;;
esac
