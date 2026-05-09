#!/bin/bash
# Phase 11 prep: continuous WAL-based replication of the controlplane
# DB to cp-spare-02. Sub-second RPO vs F7's `VACUUM INTO` snapshot
# (45.6 s on a 947 MB DB) and zero impact on the source — Litestream
# tails the SQLite WAL via shadow-WAL mechanism, no locks against
# writers.
#
# Architecture:
#
#   cp-01 (104.128.140.54)              cp-spare-02 (104.128.140.49)
#   ─────────────────────                ─────────────────────────
#   iac-controlplane                     /var/lib/iac-replica/cp/
#       ↓                                       ↑
#   server.db    ──── litestream ──── replicate via SFTP
#   server.db-wal     replicate
#                     (cp-01 reads WAL frames as iac-controlplane writes
#                      them, ships compressed to spare-02 every ~1s)
#
# Recovery: on cp-spare-02 (or wherever):
#   litestream restore -config /etc/litestream.yml /path/to/restored.db
#
# Pass criteria for the F7 follow-up:
#   * RPO < 5 s (last write before disaster recoverable)
#   * RTO < 30 s (litestream restore + start CP on replica DB)
#   * No measurable impact on source CP write latency
#
# Usage:
#   ./trial/scenarios/setup-litestream-replication.sh
#
# This script is conservative — it does NOT touch the running CP
# beyond installing litestream binary and starting the replicate
# service. The CP itself is unaware of replication; if litestream
# fails, CP keeps working.

set -eu

. "$(dirname "${BASH_SOURCE[0]}")/../fleet/lib.sh"

REPLICA_HOST="$(inventory_hosts cp_spare | sed -n '2p' | cut -f2)"

echo "=== Phase 11 prep: WAL replication cp-01 → $REPLICA_HOST ==="

# 1. Replica host: install litestream + create receive directory.
echo "[1/5] preparing replica host $REPLICA_HOST"
ssh_to "$REPLICA_HOST" 'set -e
[ -x /usr/bin/litestream ] || {
    cd /tmp
    wget -q https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.deb -O litestream.deb
    dpkg -i litestream.deb
}
mkdir -p /var/lib/iac-replica/cp
chmod 0700 /var/lib/iac-replica
'

# 2. Generate ssh keypair on cp-01 so it can SFTP to spare-02.
echo "[2/5] preparing source-side SSH key"
ssh_to "$CP_IP" 'set -e
if [ ! -f /root/.ssh/replication_key ]; then
    ssh-keygen -q -t ed25519 -N "" -C "iac-replication" -f /root/.ssh/replication_key
fi
cat /root/.ssh/replication_key.pub
' > /tmp/replication.pub
ssh_to "$REPLICA_HOST" "mkdir -p /root/.ssh && chmod 0700 /root/.ssh && touch /root/.ssh/authorized_keys && grep -q iac-replication /root/.ssh/authorized_keys || cat >> /root/.ssh/authorized_keys" < /tmp/replication.pub
rm -f /tmp/replication.pub

# 3. Source host: install litestream + drop config + systemd unit.
echo "[3/5] installing litestream on source $CP_IP"
ssh_to "$CP_IP" 'set -e
[ -x /usr/bin/litestream ] || {
    cd /tmp
    wget -q https://github.com/benbjohnson/litestream/releases/download/v0.3.13/litestream-v0.3.13-linux-amd64.deb -O litestream.deb
    dpkg -i litestream.deb
}
'
ssh_to "$CP_IP" "cat > /etc/litestream.yml" <<EOF
# Phase 11: replicate iac-controlplane SQLite to cp-spare-02 over
# SFTP. Litestream tails the WAL — zero locking against the source
# CP. Sync every 1 s gives sub-second RPO for the steady state.
dbs:
  - path: /var/lib/iac-controlplane/server.db
    replicas:
      - type: sftp
        host: ${REPLICA_HOST}:22
        user: root
        path: /var/lib/iac-replica/cp
        key-path: /root/.ssh/replication_key
        sync-interval: 1s
        snapshot-interval: 1h
        retention: 168h     # keep 7 days of generations
EOF

ssh_to "$CP_IP" 'cat > /etc/systemd/system/litestream.service <<EOF
[Unit]
Description=Litestream WAL replicator
After=network-online.target iac-controlplane.service
[Service]
Type=simple
ExecStart=/usr/bin/litestream replicate -config /etc/litestream.yml
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now litestream
sleep 3
systemctl is-active litestream
'

# 4. Verify replica is receiving generations.
echo "[4/5] verifying replication"
sleep 5
ssh_to "$REPLICA_HOST" 'find /var/lib/iac-replica/cp -type f 2>/dev/null | head -5; du -sh /var/lib/iac-replica/cp 2>/dev/null'

# 5. Print restore recipe.
echo
echo "[5/5] OK. Restore recipe (run on $REPLICA_HOST or any host
       with litestream binary + the SFTP key + this config):

   litestream restore -config /etc/litestream.yml \\
       -o /var/lib/iac-controlplane/server.db.recovered \\
       /var/lib/iac-controlplane/server.db

  …then point a fresh iac-controlplane at the recovered DB. The
  recovery state matches the source within sync-interval (1 s by
  default).
"
