#!/usr/bin/env bash
# Go 版 macflowd 一键部署到 iStoreOS VM
# 用法:
#   QEMU VM:    ./vm/deploy-go.sh              (默认 localhost:2222)
#   Hyper-V VM: ./vm/deploy-go.sh 192.168.100.1
#   指定端口:    SSH_PORT=22 ./vm/deploy-go.sh 192.168.100.1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

HOST="${1:-localhost}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_USER="${SSH_USER:-root}"
BINARY="${PROJECT_DIR}/backend-go/macflowd-linux-amd64"
REMOTE_DIR="/opt/macflow"

# 如果给了非 localhost 地址，默认用 22 端口 (Hyper-V 场景)
if [[ "$HOST" != "localhost" && "$HOST" != "127.0.0.1" && "$SSH_PORT" == "2222" ]]; then
    SSH_PORT=22
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
SSH_CMD="ssh ${SSH_OPTS} -p ${SSH_PORT} ${SSH_USER}@${HOST}"
SCP_CMD="scp ${SSH_OPTS} -P ${SSH_PORT}"

echo "======================================"
echo "  MACFlow Go 部署"
echo "  目标: ${SSH_USER}@${HOST}:${SSH_PORT}"
echo "======================================"

# 1. 检查二进制文件
if [[ ! -f "$BINARY" ]]; then
    echo "[错误] 未找到二进制文件: $BINARY"
    echo "  请先编译: cd backend-go && GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o macflowd-linux-amd64 ./cmd/macflowd/"
    exit 1
fi

echo "[1/5] 检查 VM 连接..."
${SSH_CMD} "echo ok" >/dev/null 2>&1 || {
    echo "[错误] 无法连接 ${SSH_USER}@${HOST}:${SSH_PORT}"
    echo "  QEMU: 确认 VM 在运行 (./vm/run-istoreos.sh)"
    echo "  Hyper-V: 确认 VM 启动且网络通 (ping ${HOST})"
    exit 1
}

echo "[2/5] 停止旧服务..."
${SSH_CMD} <<'STOP_EOF'
# 停止 procd 服务
/etc/init.d/macflowd stop 2>/dev/null || true
# 杀掉所有旧进程 (Python 和 Go)
kill $(pgrep -f "uvicorn main:app") 2>/dev/null || true
kill $(pgrep -f "macflowd") 2>/dev/null || true
sleep 1
STOP_EOF

echo "[3/5] 上传 Go 二进制 + 静态资源..."
${SSH_CMD} "mkdir -p ${REMOTE_DIR}/data"
${SCP_CMD} "${BINARY}" "${SSH_USER}@${HOST}:${REMOTE_DIR}/macflowd"
${SSH_CMD} "chmod +x ${REMOTE_DIR}/macflowd"

# 上传 web 前端
if [[ -d "${PROJECT_DIR}/web" ]]; then
    ${SCP_CMD} -r "${PROJECT_DIR}/web" "${SSH_USER}@${HOST}:${REMOTE_DIR}/"
fi

# 上传 core 规则引擎 (nft 模板等)
if [[ -d "${PROJECT_DIR}/core" ]]; then
    ${SCP_CMD} -r "${PROJECT_DIR}/core" "${SSH_USER}@${HOST}:${REMOTE_DIR}/"
fi

# 上传默认配置
if [[ -d "${PROJECT_DIR}/config" ]]; then
    ${SCP_CMD} -r "${PROJECT_DIR}/config" "${SSH_USER}@${HOST}:${REMOTE_DIR}/"
fi

echo "[4/5] 创建 procd 服务..."
${SSH_CMD} <<'SERVICE_EOF'
cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common

START=98
STOP=11
USE_PROCD=1

start_service() {
    procd_open_instance macflowd
    procd_set_param command /opt/macflow/macflowd
    procd_set_param env \
        MACFLOW_PORT=18080 \
        MACFLOW_DATA_DIR=/opt/macflow/data \
        MACFLOW_WEB_DIR=/opt/macflow/web
    procd_set_param respawn 5 30 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/macflowd.pid
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd
/etc/init.d/macflowd enable
SERVICE_EOF

echo "[5/5] 启动服务并验证..."
${SSH_CMD} <<'START_EOF'
/etc/init.d/macflowd start
sleep 2

# 验证进程
if pgrep -f "/opt/macflow/macflowd" > /dev/null; then
    PID=$(pgrep -f "/opt/macflow/macflowd")
    MEM=$(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null || echo "?")
    echo ""
    echo "✅ macflowd (Go) 启动成功"
    echo "   PID:  $PID"
    echo "   内存: ${MEM} kB"
else
    echo "❌ macflowd 启动失败"
    echo "日志:"
    logread -e macflowd | tail -20
    exit 1
fi

# 验证 API
if wget -qO- http://127.0.0.1:18080/api/status 2>/dev/null; then
    echo ""
    echo "✅ API 正常 (port 18080)"
else
    echo "⚠️  API 端口未响应，检查日志:"
    logread -e macflowd | tail -10
fi
START_EOF

echo ""
echo "======================================"
echo "  部署完成!"
echo "  API:   http://${HOST}:18080"
echo "  面板:  http://${HOST}:18080/"
echo "======================================"
