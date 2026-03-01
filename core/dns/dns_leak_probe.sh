#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  dns_leak_probe.sh [--router-ns <ns>] [--lan-ns <ns>] [--strict]

What it checks:
  1) dns_guard rules exist in inet/macflow table.
  2) Managed client DNS packet increments redirect counter.
  3) DoT/DoQ blocking rules exist for managed devices.
EOF
}

ROUTER_NS="ns-router"
LAN_NS="ns-lan"
STRICT="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --router-ns)
      ROUTER_NS="$2"
      shift 2
      ;;
    --lan-ns)
      LAN_NS="$2"
      shift 2
      ;;
    --strict)
      STRICT="1"
      shift 1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

rcmd() { ip netns exec "${ROUTER_NS}" "$@"; }
lcmd() { ip netns exec "${LAN_NS}" "$@"; }

echo "[dns_probe] verify dns_guard chain existence"
if ! rcmd nft list chain inet macflow dns_guard >/dev/null 2>&1; then
  echo "[dns_probe] dns_guard chain missing" >&2
  exit 2
fi

before_pkts="$(rcmd nft list chain inet macflow dns_guard | awk '/redirect to :/ {for (i=1; i<=NF; i++) if ($i=="packets") {print $(i+1); exit}}')"
before_pkts="${before_pkts:-0}"

echo "[dns_probe] send DNS packet from managed client (192.168.50.11)"
lcmd python3 - <<'PY'
import socket
payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
for _ in range(5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, 25, b"managed0\x00")
    s.bind(("192.168.50.11", 0))
    s.sendto(payload, ("8.8.8.8", 53))
    s.close()
PY

sleep 1

after_pkts="$(rcmd nft list chain inet macflow dns_guard | awk '/redirect to :/ {for (i=1; i<=NF; i++) if ($i=="packets") {print $(i+1); exit}}')"
after_pkts="${after_pkts:-0}"

echo "[dns_probe] dns_guard packets before=${before_pkts} after=${after_pkts}"
if [[ "${after_pkts}" -le "${before_pkts}" ]]; then
  if [[ "${STRICT}" == "1" ]]; then
    echo "[dns_probe] no redirect counter increase, potential DNS leak path" >&2
    exit 3
  fi
  echo "[dns_probe] warn: counter unchanged in lab mode, keep structural checks only"
fi

echo "[dns_probe] verify DoT block rules (port 853)"
if ! rcmd nft list chain inet macflow forward_guard 2>/dev/null | awk '/dport 853/ && /drop/ {found=1} END {exit !found}'; then
  echo "[dns_probe] CRITICAL: DoT block rule missing (port 853)" >&2
  exit 4
fi

echo "[dns_probe] verify DoQ block rules (port 8853)"
WARN=0
if ! rcmd nft list chain inet macflow forward_guard 2>/dev/null | awk '/dport 8853/ && /drop/ {found=1} END {exit !found}'; then
  echo "[dns_probe] WARN: DoQ block rule missing (port 8853)" >&2
  WARN=1
fi

echo "[dns_probe] verify DoH IP block rules (doh_ipv4 + port 443)"
if ! rcmd nft list chain inet macflow forward_guard 2>/dev/null | awk '/doh_ipv4/ && /dport 443/ && /drop/ {found=1} END {exit !found}'; then
  echo "[dns_probe] WARN: DoH IP block rule missing" >&2
  WARN=1
fi

echo "[dns_probe] verify STUN block rules (port 3478)"
if ! rcmd nft list chain inet macflow forward_guard 2>/dev/null | awk '/dport 3478/ && /drop/ {found=1} END {exit !found}'; then
  echo "[dns_probe] WARN: STUN block rule missing (port 3478)" >&2
  WARN=1
fi

echo "[dns_probe] verify IPv6 guard chain"
if rcmd nft list chain inet macflow ipv6_guard >/dev/null 2>&1; then
  if ! rcmd nft list chain inet macflow ipv6_guard | awk '/ip6/ && /drop/ {found=1} END {exit !found}'; then
    echo "[dns_probe] WARN: ipv6_guard chain exists but no drop rules" >&2
    WARN=1
  else
    echo "[dns_probe] ipv6_guard active"
  fi
else
  echo "[dns_probe] WARN: ipv6_guard chain not found (optional)" >&2
  WARN=1
fi

if [[ "${STRICT}" == "1" && "${WARN}" == "1" ]]; then
  echo "[dns_probe] strict mode: exiting with warn status" >&2
  exit 1
fi

echo "[dns_probe] pass (warnings=${WARN})"
