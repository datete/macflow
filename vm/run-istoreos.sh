#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="${SCRIPT_DIR}/istoreos-work.qcow2"
SRC="${SCRIPT_DIR}/istoreos.img"
OVMF="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="${SCRIPT_DIR}/ovmf_vars.fd"
SSH_FWD_PORT=2222
WEB_FWD_PORT=8080
API_FWD_PORT=18080

if [[ ! -f "${IMG}" ]]; then
    echo "[run] creating working copy (qcow2, 4G) ..."
    qemu-img convert -f raw -O qcow2 "${SRC}" "${IMG}"
    qemu-img resize "${IMG}" 4G
fi

if [[ ! -f "${OVMF_VARS}" ]]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd "${OVMF_VARS}"
fi

echo "[run] starting iStoreOS VM ..."
echo "  SSH:  localhost:${SSH_FWD_PORT} -> VM:22"
echo "  Web:  localhost:${WEB_FWD_PORT} -> VM:80  (iStoreOS LuCI)"
echo "  API:  localhost:${API_FWD_PORT} -> VM:18080 (macflowd)"
echo ""
echo "  Connect: ssh -p ${SSH_FWD_PORT} root@localhost"
echo "  LuCI:    http://localhost:${WEB_FWD_PORT}"
echo "  Press Ctrl-A X to quit QEMU"
echo ""

exec qemu-system-x86_64 \
    -enable-kvm \
    -m 1024 \
    -smp 2 \
    -drive if=pflash,format=raw,readonly=on,file="${OVMF}" \
    -drive if=pflash,format=raw,file="${OVMF_VARS}" \
    -drive file="${IMG}",format=qcow2,if=virtio \
    -netdev user,id=wan,hostfwd=tcp:0.0.0.0:${SSH_FWD_PORT}-:22,hostfwd=tcp:0.0.0.0:${WEB_FWD_PORT}-:80,hostfwd=tcp:0.0.0.0:${API_FWD_PORT}-:18080 \
    -device virtio-net-pci,netdev=wan \
    -netdev user,id=lan \
    -device virtio-net-pci,netdev=lan \
    -monitor tcp:0.0.0.0:4444,server,nowait \
    -serial telnet:0.0.0.0:4445,server,nowait \
    -daemonize
