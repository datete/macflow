#!/bin/sh
set -e

mkdir -p /opt/macflow/data /opt/macflow/web

# 从 staging 区拷贝文件 (如果有)
[ -d /tmp/macflow/web ] && cp -rf /tmp/macflow/web/. /opt/macflow/web/
[ -d /tmp/macflow/core ] && cp -rf /tmp/macflow/core/. /opt/macflow/core/
[ -d /tmp/macflow/config ] && cp -rf /tmp/macflow/config/. /opt/macflow/config/

# 停掉已有进程
kill $(pgrep -f "/opt/macflow/macflowd") 2>/dev/null || true
kill $(pgrep -f "uvicorn main:app") 2>/dev/null || true
kill $(pgrep -f "backend/main.py") 2>/dev/null || true
sleep 1

# 创建 procd 服务
cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common
START=98
STOP=11
USE_PROCD=1
start_service() {
    procd_open_instance macflowd
    procd_set_param command /opt/macflow/macflowd
    procd_set_param env MACFLOW_PORT=18080 MACFLOW_DATA_DIR=/opt/macflow/data MACFLOW_WEB_DIR=/opt/macflow/web
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd

# 启动
if [ -x /opt/macflow/macflowd ]; then
    MACFLOW_PORT=18080 \
    MACFLOW_DATA_DIR=/opt/macflow/data \
    MACFLOW_WEB_DIR=/opt/macflow/web \
    /opt/macflow/macflowd &
    PANEL_PID=$!
    sleep 2
elif [ -f /opt/macflow/backend/main.py ]; then
    cd /opt/macflow/backend
    /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 18080 &
    PANEL_PID=$!
    sleep 4
else
    echo "PANEL_FAIL - no binary or Python backend found"
    exit 1
fi

if wget -qO- http://127.0.0.1:18080/api/status 2>/dev/null; then
    echo ""
    echo "PANEL_OK pid=$PANEL_PID"
else
    echo "PANEL_FAIL - checking logs"
    kill $PANEL_PID 2>/dev/null || true
fi
