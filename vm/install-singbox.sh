#!/usr/bin/env bash
set -euo pipefail

echo "[singbox] check if already installed..."
if command -v sing-box >/dev/null 2>&1; then
    echo "[singbox] already installed: $(sing-box version)"
    exit 0
fi

echo "[singbox] installing via opkg..."
opkg update > /dev/null 2>&1 || true
opkg install sing-box 2>/dev/null && {
    echo "[singbox] installed via opkg: $(sing-box version)"
    exit 0
}

echo "[singbox] opkg failed, downloading binary directly..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  SB_ARCH="amd64" ;;
    aarch64) SB_ARCH="arm64" ;;
    *)       echo "unsupported arch: $ARCH"; exit 1 ;;
esac

SB_VERSION="1.11.0"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${SB_ARCH}.tar.gz"
TMP_DIR="/tmp/singbox-install"
mkdir -p "$TMP_DIR"

echo "[singbox] downloading v${SB_VERSION} for ${SB_ARCH}..."
wget -q -O "$TMP_DIR/sing-box.tar.gz" "$SB_URL"
tar -xzf "$TMP_DIR/sing-box.tar.gz" -C "$TMP_DIR"
cp "$TMP_DIR/sing-box-${SB_VERSION}-linux-${SB_ARCH}/sing-box" /usr/bin/sing-box
chmod +x /usr/bin/sing-box
rm -rf "$TMP_DIR"

echo "[singbox] installed: $(sing-box version)"
