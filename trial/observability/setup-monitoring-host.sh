#!/bin/bash
# Phase 9 observability host setup — idempotent.
#
# Runs on cp-spare-01: installs Prometheus + Grafana + node_exporter
# from upstream static binaries (apt repos for these are inconsistent
# across Ubuntu 24.04 mirrors), wires systemd units, drops the
# auto-provisioned datasource + dashboard.
#
# Usage (from operator):
#   scp -i ~/.ssh/iac_fleet trial/observability/setup-monitoring-host.sh root@<spare-01>:/tmp/
#   ssh -i ~/.ssh/iac_fleet root@<spare-01> bash /tmp/setup-monitoring-host.sh
#
# Result:
#   * Prometheus on :9090 scraping all 10 fleet VPS at :9100
#   * Grafana on :3000 with the "iac fleet" dashboard auto-loaded
#   * node_exporter on :9100 (this host scrapes itself too)

set -eu

PROM_VER=2.55.1
NE_VER=1.9.0
GRAFANA_VER=11.4.0

cd /tmp

echo "== prometheus $PROM_VER =="
[ -d /opt/prometheus ] || {
    wget -q "https://github.com/prometheus/prometheus/releases/download/v${PROM_VER}/prometheus-${PROM_VER}.linux-amd64.tar.gz" -O prometheus.tar.gz
    tar -xzf prometheus.tar.gz
    mv "prometheus-${PROM_VER}.linux-amd64" /opt/prometheus
}

echo "== node_exporter $NE_VER =="
[ -x /usr/local/bin/node_exporter ] || {
    wget -q "https://github.com/prometheus/node_exporter/releases/download/v${NE_VER}/node_exporter-${NE_VER}.linux-amd64.tar.gz" -O node_exporter.tar.gz
    tar -xzf node_exporter.tar.gz
    cp "node_exporter-${NE_VER}.linux-amd64/node_exporter" /usr/local/bin/
}

echo "== grafana $GRAFANA_VER =="
[ -d /opt/grafana ] || {
    wget -q "https://dl.grafana.com/oss/release/grafana-${GRAFANA_VER}.linux-amd64.tar.gz" -O grafana.tar.gz
    tar -xzf grafana.tar.gz
    mv "grafana-v${GRAFANA_VER}" /opt/grafana
}

echo "== systemd units =="
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

mkdir -p /var/lib/prometheus
cat > /etc/systemd/system/prometheus.service <<EOF
[Unit]
Description=Prometheus
After=network-online.target
[Service]
Type=simple
ExecStart=/opt/prometheus/prometheus --config.file=/etc/prometheus.yml --storage.tsdb.path=/var/lib/prometheus --web.listen-address=0.0.0.0:9090
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/prometheus.yml <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
scrape_configs:
  - job_name: node
    static_configs:
      - targets:
          - "104.128.140.54:9100"
          - "104.128.140.48:9100"
          - "104.128.140.49:9100"
          - "45.138.74.147:9100"
          - "185.106.93.142:9100"
          - "185.106.93.170:9100"
          - "185.106.93.191:9100"
          - "185.217.197.85:9100"
          - "185.217.197.215:9100"
          - "185.217.197.159:9100"
EOF

mkdir -p /var/lib/grafana
cat > /etc/systemd/system/grafana.service <<EOF
[Unit]
Description=Grafana
After=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/grafana
ExecStart=/opt/grafana/bin/grafana server --homepath=/opt/grafana --config=/etc/grafana.ini
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/grafana.ini <<EOF
[server]
http_port = 3000
http_addr = 0.0.0.0
[paths]
data = /var/lib/grafana
[security]
admin_user = admin
admin_password = iac-grafana-2026
[auth.anonymous]
enabled = true
org_role = Viewer
EOF

# Auto-provision datasource + fleet dashboard.
mkdir -p /opt/grafana/conf/provisioning/datasources \
         /opt/grafana/conf/provisioning/dashboards \
         /var/lib/grafana/dashboards

cat > /opt/grafana/conf/provisioning/datasources/prom.yaml <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://localhost:9090
    isDefault: true
    access: proxy
EOF

cat > /opt/grafana/conf/provisioning/dashboards/fleet.yaml <<EOF
apiVersion: 1
providers:
  - name: fleet
    folder: ""
    type: file
    options:
      path: /var/lib/grafana/dashboards
EOF

cat > /var/lib/grafana/dashboards/fleet.json <<'DASH'
{
  "title": "iac fleet",
  "schemaVersion": 38,
  "version": 1,
  "refresh": "30s",
  "time": {"from": "now-3h", "to": "now"},
  "panels": [
    {"id":1,"title":"RSS by host (MB)","type":"timeseries","gridPos":{"x":0,"y":0,"w":24,"h":10},"targets":[{"expr":"process_resident_memory_bytes{instance=~\".*:9100\"} / 1024 / 1024","legendFormat":"{{instance}}"}],"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}},
    {"id":2,"title":"CPU by host (%)","type":"timeseries","gridPos":{"x":0,"y":10,"w":12,"h":8},"targets":[{"expr":"100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)","legendFormat":"{{instance}}"}],"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}},
    {"id":3,"title":"Disk free (GB)","type":"timeseries","gridPos":{"x":12,"y":10,"w":12,"h":8},"targets":[{"expr":"node_filesystem_avail_bytes{mountpoint=\"/\"} / 1024 / 1024 / 1024","legendFormat":"{{instance}}"}],"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}},
    {"id":4,"title":"Network RX (MB/s)","type":"timeseries","gridPos":{"x":0,"y":18,"w":12,"h":8},"targets":[{"expr":"sum by (instance) (rate(node_network_receive_bytes_total{device!~\"lo|veth.*\"}[1m])) / 1024 / 1024"}],"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}},
    {"id":5,"title":"Network TX (MB/s)","type":"timeseries","gridPos":{"x":12,"y":18,"w":12,"h":8},"targets":[{"expr":"sum by (instance) (rate(node_network_transmit_bytes_total{device!~\"lo|veth.*\"}[1m])) / 1024 / 1024"}],"datasource":{"type":"prometheus","uid":"PBFA97CFB590B2093"}}
  ]
}
DASH
chown -R nobody:nogroup /var/lib/grafana

systemctl daemon-reload
systemctl enable --now node-exporter prometheus grafana
sleep 3
echo
echo "== status =="
systemctl is-active node-exporter prometheus grafana
ss -ltn | grep -E "9090|3000|9100" || true

echo
echo "Prometheus: http://$(hostname -I | awk '{print $1}'):9090"
echo "Grafana:    http://$(hostname -I | awk '{print $1}'):3000"
echo "  login:    admin / iac-grafana-2026"
