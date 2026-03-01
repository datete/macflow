#!/usr/bin/env bash
set -euo pipefail

echo "[panel] installing python3 pip packages..."
opkg list-installed | grep -q python3-pip || opkg install python3-pip 2>/dev/null || true

pip3 install fastapi uvicorn requests pydantic 2>/dev/null || {
    echo "[panel] pip install failed, trying opkg fallback..."
    opkg install python3-requests 2>/dev/null || true
}

echo "[panel] deploying backend + web..."
mkdir -p /opt/macflow/web /opt/macflow/data

cp -r /tmp/macflow/core /opt/macflow/
cp -r /tmp/macflow/config /opt/macflow/
cp -r /tmp/macflow/scripts /opt/macflow/

echo "[panel] creating procd service..."
cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common

START=98
STOP=11
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 18080
    procd_set_param env PYTHONPATH=/opt/macflow/backend
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/macflowd.pid
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd

echo "[panel] done"
