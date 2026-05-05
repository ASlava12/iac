#!/bin/bash
# Shared shell helpers for the Phase 9 fleet harness. Sourced by
# bootstrap.sh and the per-scenario scripts.
#
# Reads inventory.toml from the same dir. The TOML is small + flat;
# `awk` parses it without pulling in a runtime dep.
#
# Bash-specific because we use `${BASH_SOURCE[0]}` to find our own
# directory when sourced (POSIX `$0` evaluates to the parent shell
# under `. lib.sh`).

set -eu

FLEET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="$FLEET_DIR/inventory.toml"
SSH_KEY="$HOME/.ssh/iac_fleet"

# `inventory_get_field <field-name>` — single-value extractor for
# `[fleet]` block. Used for `ssh_user`, `controlplane_port`, etc.
inventory_get_field() {
    awk -v key="$1" '
        BEGIN {in_fleet=0}
        /^\[fleet\]/ {in_fleet=1; next}
        /^\[/ {in_fleet=0}
        in_fleet && $1 == key {
            sub(/^[^=]*=[ \t]*/, "")
            gsub(/"/, "")
            sub(/[ \t]*$/, "")
            print
            exit
        }
    ' "$INVENTORY"
}

# `inventory_hosts <role>` — emit `name<TAB>ip<TAB>region` for every
# host whose role matches the argument. Use `_all_` to list every
# host regardless of role.
inventory_hosts() {
    awk -v want="$1" '
        BEGIN {n=""; ip=""; role=""; region=""}
        /^\[\[hosts\]\]/ {
            if (n != "") emit()
            n=""; ip=""; role=""; region=""
            next
        }
        /^\[/ {
            if (n != "") emit()
            n=""; ip=""; role=""; region=""
        }
        $1 == "name"   {n      = strip($0)}
        $1 == "ip"     {ip     = strip($0)}
        $1 == "role"   {role   = strip($0)}
        $1 == "region" {region = strip($0)}
        END {if (n != "") emit()}
        function strip(line) {
            sub(/^[^=]*=[ \t]*/, "", line)
            gsub(/"/, "", line)
            sub(/[ \t\r]*$/, "", line)
            return line
        }
        function emit() {
            if (want == "_all_" || role == want) {
                printf "%s\t%s\t%s\n", n, ip, region
            }
        }
    ' "$INVENTORY"
}

CP_IP="$(inventory_hosts controlplane | head -1 | cut -f2)"
CP_PORT="$(inventory_get_field controlplane_port)"
ADMIN_TOKEN="$(inventory_get_field admin_token)"
SERVER_URL="http://$CP_IP:$CP_PORT"

# `ssh_to <ip> <command...>` — run the command on the VPS. We accept
# new host keys on first contact (TOFU); subsequent runs verify
# against the known_hosts entry. BatchMode + ConnectTimeout so a
# silent host doesn't hang the harness.
ssh_to() {
    ip="$1"
    shift
    ssh -i "$SSH_KEY" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$HOME/.ssh/known_hosts" \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        "root@$ip" "$@"
}

scp_to() {
    src="$1"
    ip="$2"
    dst="$3"
    scp -i "$SSH_KEY" \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$HOME/.ssh/known_hosts" \
        -o ConnectTimeout=10 \
        -q \
        "$src" "root@$ip:$dst"
}

# Pretty per-host status line. Use it from xargs / parallel loops so
# the output makes sense even when runs interleave.
say() {
    printf "[%s] %s\n" "$1" "$2"
}
