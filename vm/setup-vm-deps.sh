#!/usr/bin/env bash
set -euo pipefail

echo "[deps] updating opkg..."
opkg update > /dev/null 2>&1 || true

echo "[deps] installing python3 modules..."
opkg install python3 python3-urllib python3-email python3-codecs python3-logging 2>/dev/null || true

echo "[deps] verify imports..."
python3 -c "import pathlib, json, sys, argparse; print('python3 modules ok')"

echo "[deps] check nft..."
nft --version

echo "[deps] done"
