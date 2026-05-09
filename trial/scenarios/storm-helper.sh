#!/bin/bash
# F8 storm helper. Posts to /v1/agents/register in tight xargs-parallel
# loop. Self-contained: takes URL + duration + concurrency + label as
# args, emits CSV (`unix_ts,http_status,elapsed_ms`) to stdout.
#
# Designed to be scp-shipped to a storm host and run via ssh, avoiding
# the nested-heredoc escaping that bit the inline version. Bash, NOT
# sh — `export -f` is bash-specific.

set -eu
DURATION=${1:?usage: $0 DURATION_SECS PARALLEL URL LABEL}
PARALLEL=${2:?}
URL=${3:?}
LABEL=${4:-anon}

hammer() {
    local url=$1 label=$2
    local name="storm-${label}-$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')"
    local start=$(date +%s%N)
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        -X POST "$url" \
        -H 'Content-Type: application/json' \
        -d "{\"name\":\"$name\",\"environment\":\"f8m\",\"metadata\":{}}" \
        2>/dev/null || echo 000)
    local end=$(date +%s%N)
    printf '%s,%s,%s\n' "$(date +%s)" "$code" "$(( (end - start) / 1000000 ))"
}
export -f hammer

echo 'unix_ts,http_status,elapsed_ms'
end=$(($(date +%s) + DURATION))
while [ $(date +%s) -lt $end ]; do
    seq 1 $PARALLEL | xargs -P $PARALLEL -I {} bash -c "hammer '$URL' '$LABEL'"
done
