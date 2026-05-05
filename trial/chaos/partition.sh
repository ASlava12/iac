#!/bin/sh
# Phase 8: simulate control-plane partition by detaching a
# fraction of agents from the trial network.
#
# Usage:
#   trial/chaos/partition.sh apply 5      # detach 5 random agents
#   trial/chaos/partition.sh restore      # re-attach everyone
#
# `apply` records the detached agents into /tmp/iac-chaos-partition
# so `restore` knows what to re-attach. Idempotent: applying twice
# without `restore` between is a no-op for already-detached agents.

set -eu

PROJECT="${COMPOSE_PROJECT_NAME:-trial}"
ACTION="${1:?usage: $0 apply N | restore}"
STATE_FILE=/tmp/iac-chaos-partition

network() {
    docker network ls --filter "name=${PROJECT}_iac-trial" --format '{{.Name}}' | head -1
}

case "$ACTION" in
    apply)
        # Phase 7dh.10 (audit fix C2): N must be a positive integer.
        # We pass it to `head -n` and `shuf | head` later; an
        # operator typo (`apply 5; rm -rf /`) gets caught here.
        N="${2:-1}"
        case "$N" in
            ''|*[!0-9]*|0)
                echo "invalid N: $N (expected positive integer)" >&2
                exit 2
                ;;
        esac
        NET="$(network)"
        if [ -z "$NET" ]; then
            echo "no trial network found (looked for ${PROJECT}_iac-trial)" >&2
            exit 1
        fi
        : > "$STATE_FILE"
        AGENTS=$(docker ps --filter "label=com.docker.compose.project=$PROJECT" \
                            --filter "label=com.docker.compose.service=agent" \
                            --format '{{.Names}}' | shuf | head -n "$N")
        for c in $AGENTS; do
            # Phase 7dh.10 (audit fix C6): capture stderr so we can
            # tell apart "already disconnected" (idempotent skip)
            # from real errors (network gone, permission denied,
            # docker daemon offline). Pre-7dh.10 we swallowed both
            # and logged a single ambiguous message.
            err=$(docker network disconnect "$NET" "$c" 2>&1) && rc=0 || rc=$?
            if [ "$rc" = 0 ]; then
                echo "detached: $c"
                echo "$c" >> "$STATE_FILE"
            elif echo "$err" | grep -q "is not connected"; then
                echo "skip (already disconnected): $c"
            else
                echo "ERROR detaching $c: $err" >&2
                exit "$rc"
            fi
        done
        ;;
    restore)
        if [ ! -s "$STATE_FILE" ]; then
            echo "no partition state recorded; nothing to do"
            exit 0
        fi
        NET="$(network)"
        while IFS= read -r c; do
            [ -z "$c" ] && continue
            err=$(docker network connect "$NET" "$c" 2>&1) && rc=0 || rc=$?
            if [ "$rc" = 0 ]; then
                echo "re-attached: $c"
            elif echo "$err" | grep -qE "already exists|is already"; then
                echo "skip (already connected): $c"
            else
                echo "ERROR re-attaching $c: $err" >&2
                # Don't exit on restore errors — keep trying
                # the rest of the file so as many agents as
                # possible come back.
            fi
        done < "$STATE_FILE"
        rm -f "$STATE_FILE"
        ;;
    *)
        echo "usage: $0 apply N | restore" >&2
        exit 1
        ;;
esac
