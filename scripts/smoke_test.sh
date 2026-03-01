#!/usr/bin/env bash
set -euo pipefail

ROUTER_NS="ns-router"
LAN_NS="ns-lan"

echo "[smoke] checking namespaces"
ip netns exec "${ROUTER_NS}" true
ip netns exec "${LAN_NS}" true

echo "[smoke] basic reachability"
ip netns exec "${LAN_NS}" ping -c 1 -I managed0 192.168.50.1 >/dev/null
ip netns exec "${LAN_NS}" ping -c 1 -I normal0 192.168.50.1 >/dev/null

echo "[smoke] trigger sample traffic from managed and unmanaged interfaces"
ip netns exec "${LAN_NS}" ping -c 1 -I managed0 10.0.1.2 >/dev/null || true
ip netns exec "${LAN_NS}" ping -c 1 -I normal0 10.0.1.2 >/dev/null || true

echo "[smoke] print router marks and policy rules"
ip netns exec "${ROUTER_NS}" nft list table inet macflow || true
ip netns exec "${ROUTER_NS}" ip -4 rule show || true

echo "[smoke] run dns leak probe (strict)"
bash core/dns/dns_leak_probe.sh --router-ns "${ROUTER_NS}" --lan-ns "${LAN_NS}" --strict
DNS_RC=$?
if [ "${DNS_RC}" -ne 0 ]; then
  echo "[smoke] WARN: dns leak probe returned ${DNS_RC}" >&2
fi

echo "[smoke] verify dns_guard redirect counters"
ip netns exec "${ROUTER_NS}" nft list chain inet macflow dns_guard 2>/dev/null | grep -q "redirect" \
  && echo "[smoke] dns_guard redirect rules present" \
  || echo "[smoke] WARN: dns_guard redirect rules not found" >&2

echo "[smoke] verify forward_guard DoH/DoT/DoQ/STUN block"
FG_OUT="$(ip netns exec "${ROUTER_NS}" nft list chain inet macflow forward_guard 2>/dev/null || echo '')"
echo "${FG_OUT}" | grep -q "dport 853" && echo "[smoke] DoT block (853) OK" || echo "[smoke] WARN: DoT block missing" >&2
echo "${FG_OUT}" | grep -q "dport 8853" && echo "[smoke] DoQ block (8853) OK" || echo "[smoke] WARN: DoQ block missing" >&2
echo "${FG_OUT}" | grep -q "doh_ipv4" && echo "[smoke] DoH IP block OK" || echo "[smoke] WARN: DoH IP block missing" >&2
echo "${FG_OUT}" | grep -q "dport 3478" && echo "[smoke] STUN block (3478) OK" || echo "[smoke] WARN: STUN block missing" >&2

echo "[smoke] verify ipv6_guard"
ip netns exec "${ROUTER_NS}" nft list chain inet macflow ipv6_guard 2>/dev/null | grep -q "drop" \
  && echo "[smoke] ipv6_guard active" \
  || echo "[smoke] WARN: ipv6_guard not active" >&2

echo "[smoke] check egress IP consistency (if API available)"
EGRESS="$(curl -sf http://127.0.0.1:18080/api/egress/router 2>/dev/null || echo '')"
if [ -n "${EGRESS}" ]; then
  echo "[smoke] egress API response: ${EGRESS}" | head -c 200
  echo ""
else
  echo "[smoke] INFO: egress API not reachable (expected in netns-only mode)"
fi

echo "[smoke] done (dns_probe_rc=${DNS_RC})"
