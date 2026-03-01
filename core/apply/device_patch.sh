#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  device_patch.sh --action <upsert|delete> --mac <mac> [--mark <hex_or_int>] [--namespace <ns>]

Examples:
  device_patch.sh --action upsert --mac 02:AA:BB:CC:DD:10 --mark 0x100 --namespace ns-router
  device_patch.sh --action delete --mac 02:AA:BB:CC:DD:10 --namespace ns-router

Notes:
  - Performs element-level updates only, no full table reload.
  - Keeps non-target devices untouched.
EOF
}

ACTION=""
MAC=""
MARK=""
NS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      ACTION="$2"
      shift 2
      ;;
    --mac)
      MAC="$2"
      shift 2
      ;;
    --mark)
      MARK="$2"
      shift 2
      ;;
    --namespace)
      NS="$2"
      shift 2
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${ACTION}" || -z "${MAC}" ]]; then
  usage
  exit 1
fi

run_cmd() {
  if [[ -n "${NS}" ]]; then
    ip netns exec "${NS}" "$@"
  else
    "$@"
  fi
}

case "${ACTION}" in
  upsert)
    if [[ -z "${MARK}" ]]; then
      echo "[device_patch] --mark is required for upsert" >&2
      exit 1
    fi
    run_cmd nft add element inet macflow managed_macs "{ ${MAC} }" 2>/dev/null || true
    run_cmd nft add element inet macflow mac_to_mark "{ ${MAC} : ${MARK} }" 2>/dev/null || \
      run_cmd nft replace element inet macflow mac_to_mark "{ ${MAC} : ${MARK} }"
    echo "[device_patch] upsert ok mac=${MAC} mark=${MARK}"
    ;;
  delete)
    run_cmd nft delete element inet macflow managed_macs "{ ${MAC} }" 2>/dev/null || true
    run_cmd nft delete element inet macflow mac_to_mark "{ ${MAC} }" 2>/dev/null || true
    echo "[device_patch] delete ok mac=${MAC}"
    ;;
  *)
    echo "[device_patch] invalid action: ${ACTION}" >&2
    usage
    exit 1
    ;;
esac
