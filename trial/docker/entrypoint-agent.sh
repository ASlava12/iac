#!/bin/sh
# Phase 8: agent container entrypoint.
#
# Generates a minimal agent.toml from environment variables on each
# start, then execs the agent. This is what makes `--scale agent=N`
# work — every replica gets a fresh hostname-derived agent name and
# the same control-plane URL.
#
# Environment variables:
#   IAC_CONTROLPLANE_URL    required — server URL the agent registers with
#   IAC_AGENT_NAME          optional — override the auto-generated name
#   IAC_ENVIRONMENT         default "trial"
#   IAC_OBSERVE_INTERVAL    default 10 (seconds)
#   IAC_RUST_LOG            default "info" — passed to RUST_LOG

set -eu

# Fall back to the container hostname if no explicit name was set.
# Compose gives each replica a hostname like `trial-agent-1`,
# `trial-agent-2`, etc., which is exactly what we want for fleet
# observability.
NAME="${IAC_AGENT_NAME:-$(hostname)}"
SERVER_URL="${IAC_CONTROLPLANE_URL:?IAC_CONTROLPLANE_URL must be set}"
ENV="${IAC_ENVIRONMENT:-trial}"
OBSERVE="${IAC_OBSERVE_INTERVAL:-10}"

cat > /etc/iac-agent/agent.toml <<EOF
state_dir = "/var/lib/iac-agent"
manifests_dir = "/var/lib/iac-agent/manifests.d"
observe_interval_secs = $OBSERVE
environment = "$ENV"
actor = "trial-agent"
server_url = "$SERVER_URL"
agent_name = "$NAME"
EOF

export RUST_LOG="${IAC_RUST_LOG:-info}"

exec iac-agent --config /etc/iac-agent/agent.toml
