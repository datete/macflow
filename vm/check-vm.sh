#!/usr/bin/env bash
set -euo pipefail

echo "=== SSH test ==="
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p 2222 root@localhost '
echo VM_ALIVE
netstat -tlnp 2>/dev/null | grep -E ":80 |:22 |:18080 "
echo ---
ip addr show eth0
echo CHECK_DONE
' 2>&1 || echo "SSH_FAILED"
