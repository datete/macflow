# MACFlow Go 版一键部署到 Hyper-V iStoreOS VM
# 用法: powershell -ExecutionPolicy Bypass -File .\vm\deploy-go.ps1
#       powershell -File .\vm\deploy-go.ps1 -Host 192.168.100.1

param(
    [string]$VMHost = "192.168.100.1",
    [int]$Port = 22,
    [string]$User = "root"
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Binary = Join-Path $ProjectDir "backend-go\macflowd-linux-amd64"

Write-Host "======================================"
Write-Host "  MACFlow Go 部署 (Hyper-V)"
Write-Host "  目标: ${User}@${VMHost}:${Port}"
Write-Host "======================================"

# 检查二进制
if (-not (Test-Path $Binary)) {
    Write-Host "[错误] 未找到: $Binary" -ForegroundColor Red
    Write-Host "  请先编译:"
    Write-Host '  cd backend-go; $env:GOOS="linux"; $env:GOARCH="amd64"; go build -ldflags="-s -w" -o macflowd-linux-amd64 ./cmd/macflowd/'
    exit 1
}

$size = [math]::Round((Get-Item $Binary).Length / 1MB, 1)
Write-Host "[info] 二进制大小: ${size} MB"

# 检查 ssh/scp 可用
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Host "[错误] 未找到 ssh 命令, 请安装 OpenSSH" -ForegroundColor Red
    exit 1
}

$sshOpts = @("-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=NUL", "-o", "ConnectTimeout=5")

Write-Host "[1/5] 检查 VM 连接..."
$result = ssh @sshOpts -p $Port "${User}@${VMHost}" "echo ok" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[错误] 无法连接 VM" -ForegroundColor Red
    Write-Host "  确认 VM 已启动: Get-VM -Name 'iStoreOS-Dev' | Start-VM"
    Write-Host "  确认网络通: ping $VMHost"
    exit 1
}

Write-Host "[2/5] 停止旧服务..."
ssh @sshOpts -p $Port "${User}@${VMHost}" @"
/etc/init.d/macflowd stop 2>/dev/null || true
kill `$(pgrep -f 'uvicorn main:app') 2>/dev/null || true
kill `$(pgrep -f macflowd) 2>/dev/null || true
sleep 1
"@

Write-Host "[3/5] 上传 Go 二进制..."
ssh @sshOpts -p $Port "${User}@${VMHost}" "mkdir -p /opt/macflow/data"
scp @sshOpts -P $Port $Binary "${User}@${VMHost}:/opt/macflow/macflowd"
ssh @sshOpts -p $Port "${User}@${VMHost}" "chmod +x /opt/macflow/macflowd"

# 上传 web 和 core
$webDir = Join-Path $ProjectDir "web"
$coreDir = Join-Path $ProjectDir "core"
$configDir = Join-Path $ProjectDir "config"

if (Test-Path $webDir) {
    Write-Host "     上传 web/..."
    scp @sshOpts -r -P $Port $webDir "${User}@${VMHost}:/opt/macflow/"
}
if (Test-Path $coreDir) {
    Write-Host "     上传 core/..."
    scp @sshOpts -r -P $Port $coreDir "${User}@${VMHost}:/opt/macflow/"
}
if (Test-Path $configDir) {
    Write-Host "     上传 config/..."
    scp @sshOpts -r -P $Port $configDir "${User}@${VMHost}:/opt/macflow/"
}

Write-Host "[4/5] 创建 procd 服务..."
ssh @sshOpts -p $Port "${User}@${VMHost}" @"
cat > /etc/init.d/macflowd <<'INITEOF'
#!/bin/sh /etc/rc.common
START=98
STOP=11
USE_PROCD=1
start_service() {
    procd_open_instance macflowd
    procd_set_param command /opt/macflow/macflowd
    procd_set_param env MACFLOW_PORT=18080 MACFLOW_DATA_DIR=/opt/macflow/data MACFLOW_WEB_DIR=/opt/macflow/web
    procd_set_param respawn 5 30 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param pidfile /var/run/macflowd.pid
    procd_close_instance
}
INITEOF
chmod +x /etc/init.d/macflowd
/etc/init.d/macflowd enable
"@

Write-Host "[5/5] 启动并验证..."
ssh @sshOpts -p $Port "${User}@${VMHost}" @"
/etc/init.d/macflowd start
sleep 2
if pgrep -f '/opt/macflow/macflowd' > /dev/null; then
    PID=`$(pgrep -f '/opt/macflow/macflowd')
    echo 'macflowd (Go) started OK, PID='`$PID
else
    echo 'FAIL: macflowd not running'
    logread -e macflowd | tail -20
    exit 1
fi
wget -qO- http://127.0.0.1:18080/api/status 2>/dev/null && echo '' && echo 'API OK' || echo 'API not responding yet'
"@

Write-Host ""
Write-Host "======================================"
Write-Host "  部署完成!" -ForegroundColor Green
Write-Host "  API:  http://${VMHost}:18080"
Write-Host "  面板: http://${VMHost}:18080/"
Write-Host "======================================"
