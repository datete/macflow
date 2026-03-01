#!/bin/sh
set -e

mkdir -p /opt/macflow/backend /opt/macflow/web /opt/macflow/data
cp -f /tmp/macflow/backend/main.py /opt/macflow/backend/
cp -f /tmp/macflow/web/index.html /opt/macflow/web/

cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common
START=98
STOP=11
USE_PROCD=1
start_service() {
    procd_open_instance macflowd
    procd_set_param command /usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 18080
    procd_set_param env HOME=/root PYTHONPATH=/opt/macflow/backend
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd

kill $(pgrep -f "uvicorn main:app") 2>/dev/null || true
sleep 1

cd /opt/macflow/backend
/usr/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 18080 &
PANEL_PID=$!
sleep 4

if wget -qO- http://127.0.0.1:18080/api/status 2>/dev/null; then
    echo ""
    echo "PANEL_OK pid=$PANEL_PID"
else
    echo "PANEL_FAIL - checking logs"
    kill $PANEL_PID 2>/dev/null || true
fi
