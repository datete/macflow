#!/usr/bin/env bash
set -euo pipefail

echo "[panel] deploying macflowd (Go) + web..."
mkdir -p /opt/macflow/data /opt/macflow/web

# 拷贝 Go 二进制
if [ -f /tmp/macflow/macflowd ]; then
    cp -f /tmp/macflow/macflowd /opt/macflow/macflowd
    chmod +x /opt/macflow/macflowd
elif [ -x /opt/macflow/macflowd ]; then
    echo "[panel] using existing binary"
else
    echo "[panel] WARNING: No Go binary found, checking for Python fallback..."
    if [ -d /tmp/macflow/backend ]; then
        echo "[panel] installing Python backend (legacy)..."
        opkg list-installed | grep -q python3-pip || opkg install python3-pip 2>/dev/null || true
        pip3 install fastapi uvicorn requests pydantic 2>/dev/null || true
        mkdir -p /opt/macflow/backend
        cp -rf /tmp/macflow/backend/. /opt/macflow/backend/
    else
        echo "[panel] ERROR: No backend found" >&2
        exit 1
    fi
fi

# 拷贝静态资源
[ -d /tmp/macflow/web ] && cp -rf /tmp/macflow/web/. /opt/macflow/web/
[ -d /tmp/macflow/core ] && cp -r /tmp/macflow/core /opt/macflow/
[ -d /tmp/macflow/config ] && cp -r /tmp/macflow/config /opt/macflow/
[ -d /tmp/macflow/scripts ] && cp -r /tmp/macflow/scripts /opt/macflow/

echo "[panel] creating procd service..."
cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common

START=98
STOP=11
USE_PROCD=1

start_service() {
    procd_open_instance
    if [ -x /opt/macflow/macflowd ]; then
        procd_set_param command /opt/macflow/macflowd
        procd_set_param env MACFLOW_PORT=18080 MACFLOW_DATA_DIR=/opt/macflow/data MACFLOW_WEB_DIR=/opt/macflow/web
    else
        procd_set_param command /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 18080
        procd_set_param env PYTHONPATH=/opt/macflow/backend
    fi
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/macflowd.pid
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd

echo "[panel] done"
