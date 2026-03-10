#!/bin/bash
# 重启 macflowd (Go 版)
# 兼容 Python 旧版回退

kill $(pgrep -f "/opt/macflow/macflowd") 2>/dev/null || true
kill $(pgrep -f "uvicorn main:app") 2>/dev/null || true
kill $(pgrep -f "backend/main.py") 2>/dev/null || true
sleep 1

if [ -x /opt/macflow/macflowd ]; then
    # Go 版
    cd /opt/macflow
    MACFLOW_DATA_DIR=/opt/macflow/data \
    MACFLOW_WEB_DIR=/opt/macflow/web \
    nohup /opt/macflow/macflowd > /var/log/macflow.log 2>&1 &
    sleep 1
    netstat -tlnp | grep 18080
    echo "MACFlow (Go) restarted PID=$!"
elif [ -f /opt/macflow/backend/main.py ]; then
    # Python 旧版回退
    cd /opt/macflow
    nohup python3 backend/main.py > /var/log/macflow.log 2>&1 &
    sleep 2
    netstat -tlnp | grep 18080
    echo "MACFlow (Python) restarted PID=$!"
else
    echo "ERROR: No macflowd binary or Python backend found"
    exit 1
fi
