# Run as Administrator
# Sets up Windows port proxy to forward localhost -> WSL2 IP -> QEMU VM

$wslIp = (wsl -d Ubuntu -- bash -c "ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'") -replace '\s',''
Write-Host "WSL2 IP: $wslIp"

$ports = @(8080, 18080, 2222)
foreach ($port in $ports) {
    netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null
    netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$wslIp
    Write-Host "  forwarding 0.0.0.0:$port -> ${wslIp}:$port"
}

Write-Host ""
Write-Host "Port proxy configured. Access:"
Write-Host "  LuCI:  http://localhost:8080"
Write-Host "  API:   http://localhost:18080"
Write-Host "  SSH:   ssh -p 2222 root@localhost"
