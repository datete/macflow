#!/usr/bin/env bash
set -euo pipefail

cd /tmp/macflow

echo "=== render policy ==="
python3 core/rule-engine/render_policy.py \
    --policy config/policy.example.json \
    --out-dir /tmp/macflow/build

echo "=== generated nft rules ==="
cat /tmp/macflow/build/macflow.nft

echo "=== validate nft ==="
nft -c -f /tmp/macflow/build/macflow.nft
echo "NFT_VALIDATE_OK"

echo "=== apply nft ==="
nft -f /tmp/macflow/build/macflow.nft
echo "NFT_APPLY_OK"

echo "=== apply ip rules ==="
bash /tmp/macflow/build/iprules.sh
echo "IPRULE_OK"

echo "=== verify nft table ==="
nft list table inet macflow

echo "=== verify ip rules ==="
ip -4 rule show

echo "=== ALL DONE ==="
