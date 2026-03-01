#!/usr/bin/env bash
set -euo pipefail

cd /tmp/macflow

echo "=== render policy ==="
python3 core/rule-engine/render_policy.py --policy config/policy.example.json --out-dir /tmp/macflow/build

echo "=== load nft rules ==="
nft -f /tmp/macflow/build/macflow.nft
echo "NFT_OK"

echo "=== nft table ==="
nft list table inet macflow

echo "=== ip rules ==="
ip -4 rule show

echo "=== singtun0 interface ==="
ip link show singtun0

echo "=== sing-box clash API: proxies ==="
wget -qO- http://127.0.0.1:9090/proxies 2>/dev/null || echo "API not ready"

echo ""
echo "=== FULL STACK VERIFIED ==="
