#!/bin/sh
PASS=0
WARN=0
FAIL=0

ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
warn() { echo "[WARN] $1"; WARN=$((WARN+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== SYSTEM ==="
cat /etc/openwrt_release 2>/dev/null || warn "openwrt_release not found"

echo ""
echo "=== SING-BOX ==="
sing-box version 2>&1 | head -1
if pgrep -f sing-box >/dev/null 2>&1; then ok "sing-box running"; else fail "sing-box not running"; fi

echo ""
echo "=== TUN ==="
if ip link show singtun0 2>/dev/null | grep -q "UP"; then ok "singtun0 UP"; else fail "singtun0 down or missing"; fi

echo ""
echo "=== NFTABLES ==="
if nft list table inet macflow >/dev/null 2>&1; then ok "macflow table loaded"; else fail "macflow table missing"; fi
if nft list set inet macflow unresolved_marks >/dev/null 2>&1; then ok "unresolved_marks set present"; else warn "unresolved_marks set missing"; fi
if nft list chain inet macflow forward_guard 2>/dev/null | grep -q "unresolved_marks.*drop"; then ok "unresolved device forward drop active"; else warn "unresolved device forward drop missing"; fi
CR="$(nft list chain inet macflow captive_redirect 2>/dev/null || echo '')"
if [ -n "${CR}" ]; then
  if echo "${CR}" | grep -q "unresolved_macs.*dport 80.*redirect to :18080"; then ok "unresolved device captive redirect active"; else warn "unresolved device captive redirect missing"; fi
fi

echo ""
echo "=== DNS GUARD (dns_guard chain) ==="
DG="$(nft list chain inet macflow dns_guard 2>/dev/null || echo '')"
if echo "${DG}" | grep -q "udp dport 53.*redirect"; then ok "DNS UDP53 redirect"; else fail "DNS UDP53 redirect missing"; fi
if echo "${DG}" | grep -q "tcp dport 53.*redirect"; then ok "DNS TCP53 redirect"; else fail "DNS TCP53 redirect missing"; fi
DNS_PORT="$(echo "${DG}" | awk '/redirect to :/{for(i=1;i<=NF;i++) if ($i=="to") {gsub(":","",$(i+1)); print $(i+1); exit}}')"
if [ -n "${DNS_PORT}" ]; then
  if command -v ss >/dev/null 2>&1; then
    if ss -lunt 2>/dev/null | grep -qE "[.:]${DNS_PORT}[[:space:]]"; then ok "DNS redirect port ${DNS_PORT} listening"; else fail "DNS redirect port ${DNS_PORT} not listening"; fi
  else
    ok "ss command missing, skip DNS listener check"
  fi
else
  ok "cannot parse DNS redirect port"
fi

echo ""
echo "=== LEAK GUARD (forward_guard chain) ==="
FG="$(nft list chain inet macflow forward_guard 2>/dev/null || echo '')"
if echo "${FG}" | grep -q "dport 853.*drop"; then ok "DoT block (853)"; else warn "DoT block missing"; fi
if echo "${FG}" | grep -q "dport 8853.*drop"; then ok "DoQ block (8853)"; else warn "DoQ block missing"; fi
if echo "${FG}" | grep -q "dport 784.*drop"; then ok "DNSCrypt block (784)"; else warn "DNSCrypt block missing"; fi
if echo "${FG}" | grep -q "doh_ipv4.*dport 443.*drop"; then ok "DoH IP block (443)"; else warn "DoH IP block missing"; fi
if echo "${FG}" | grep -q "doh_ipv6.*dport 443.*drop"; then ok "DoH IPv6 block (443)"; else warn "DoH IPv6 block missing"; fi
if echo "${FG}" | grep -q "dport 3478.*drop"; then ok "STUN block (3478)"; else warn "STUN block missing"; fi
if echo "${FG}" | grep -q "dport 5349.*drop"; then ok "STUN-TLS block (5349)"; else warn "STUN-TLS block missing"; fi

echo ""
echo "=== IPv6 GUARD ==="
IG="$(nft list chain inet macflow ipv6_guard 2>/dev/null || echo '')"
if echo "${IG}" | grep -q "ip6.*drop"; then ok "ipv6_guard active"; else warn "ipv6_guard not active"; fi

echo ""
echo "=== POLICY ROUTING ==="
ip -4 rule show | grep fwmark || warn "no fwmark ip rules found"

echo ""
echo "=== ROUTE TABLES ==="
echo "table 100:"; ip -4 route show table 100 2>/dev/null || echo "(empty)"
echo "table 200:"; ip -4 route show table 200 2>/dev/null || echo "(empty)"

echo ""
echo "=== WEB PANEL (structured health) ==="
HEALTH="$(wget -qO- http://127.0.0.1:18080/api/health 2>/dev/null || echo '')"
if [ -n "${HEALTH}" ]; then
  echo "${HEALTH}" | head -c 500
  echo ""
  if echo "${HEALTH}" | grep -q '"overall_status"'; then ok "health API structured"; else warn "health API legacy format"; fi
  if echo "${HEALTH}" | grep -q '"ok"'; then ok "health reports ok checks"; fi
  if echo "${HEALTH}" | grep -q '"critical"'; then fail "health reports critical checks"; fi
else
  warn "web panel API not reachable"
fi

echo ""
echo "=== EGRESS IP ==="
EGRESS="$(wget -qO- http://127.0.0.1:18080/api/egress/router 2>/dev/null || echo '')"
if [ -n "${EGRESS}" ]; then
  echo "${EGRESS}" | head -c 300
  echo ""
  if echo "${EGRESS}" | grep -q '"consistent":true'; then ok "egress IP consistent"; else warn "egress IP inconsistent or partial"; fi
else
  warn "egress API not reachable"
fi

echo ""
echo "=== CLASH API ==="
wget -qO- http://127.0.0.1:9090/ 2>/dev/null && echo "" || warn "clash API not reachable"

echo ""
echo "==============================="
echo "PASS=${PASS}  WARN=${WARN}  FAIL=${FAIL}"
if [ "${FAIL}" -gt 0 ]; then
  echo "STATUS: CRITICAL"
  exit 2
elif [ "${WARN}" -gt 0 ]; then
  echo "STATUS: WARNING"
  exit 1
else
  echo "STATUS: ALL SYSTEMS GO"
  exit 0
fi
