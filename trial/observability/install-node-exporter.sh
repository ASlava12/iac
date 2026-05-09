#!/bin/bash
# Phase 9 observability — install node_exporter on each fleet host.
#
# Idempotent. Pulls the binary from upstream releases, drops the
# systemd unit, starts. Safe to re-run for upgrades.
#
# Usage (from operator):
#   for ip in <each-host>; do
#       scp -i ~/.ssh/iac_fleet trial/observability/install-node-exporter.sh root@$ip:/tmp/
#       ssh -i ~/.ssh/iac_fleet root@$ip bash /tmp/install-node-exporter.sh
#   done

set -eu

NE_VER=1.9.0
cd /tmp

if [ ! -x /usr/local/bin/node_exporter ] \
   || ! /usr/local/bin/node_exporter --version 2>&1 | grep -q "version $NE_VER"; then
    wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NE_VER}/node_exporter-${NE_VER}.linux-amd64.tar.gz" -O node_exporter.tar.gz
    tar -xzf node_exporter.tar.gz
    cp "node_exporter-${NE_VER}.linux-amd64/node_exporter" /usr/local/bin/
    chmod +x /usr/local/bin/node_exporter
fi

cat > /etc/systemd/system/node-exporter.service <<EOF
[Unit]
Description=Prometheus Node Exporter
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/node_exporter
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now node-exporter
sleep 1
systemctl is-active node-exporter
echo "node_exporter on $(hostname -s) :9100 ready"
