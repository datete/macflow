#!/bin/bash
# MACFlow stability tests: restarts, node switching, rapid apply
set -euo pipefail
API="http://127.0.0.1:18080"
PASS=0; FAIL=0
ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
  echo "== Cleanup =="
  for tag in stab-node-a stab-node-b stab-node-c; do
    curl -s -X DELETE "$API/api/nodes/$tag" >/dev/null 2>&1 || true
  done
  curl -s -X DELETE "$API/api/devices/AA:BB:CC:0B:01:01" >/dev/null 2>&1 || true
  service sing-box start >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "========================================="
echo "  MACFlow Stability Test"
echo "========================================="

echo ""
echo "== Setup =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"stab-node-a","server":"10.0.1.1","server_port":8388,"method":"aes-256-gcm","password":"pa"}'
echo ""
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"stab-node-b","server":"10.0.1.2","server_port":8389,"method":"aes-256-gcm","password":"pb"}'
echo ""
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"stab-dev","mac":"AA:BB:CC:0B:01:01","node_tag":"stab-node-a","managed":true}'
echo ""
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":true}'
echo ""
curl -s -X POST "$API/api/apply" >/dev/null 2>&1

# ─────────────────────────────────────────────
echo ""
echo "== TEST 1: Restart sing-box - nftables/ip rules survive =="
NFT_BEFORE=$(nft list table inet macflow 2>/dev/null | md5sum | cut -d' ' -f1)

service sing-box restart
sleep 3

NFT_AFTER=$(nft list table inet macflow 2>/dev/null | md5sum | cut -d' ' -f1)
if [ "$NFT_BEFORE" = "$NFT_AFTER" ]; then
  ok "sing-box restart: nftables unchanged"
else
  fail "sing-box restart: nftables changed unexpectedly"
fi

pgrep -f sing-box >/dev/null 2>&1 && ok "sing-box restart: process recovered" || fail "sing-box restart: process not recovered"

# ─────────────────────────────────────────────
echo ""
echo "== TEST 2: Restart backend - state.json survives =="
STATE_BEFORE=$(cat /opt/macflow/data/state.json 2>/dev/null | md5sum | cut -d' ' -f1 || echo "none")

BACKEND_PID=$(pgrep -f "python3.*main.py" | head -1 || echo "")
if [ -n "$BACKEND_PID" ]; then
  kill "$BACKEND_PID" 2>/dev/null || true
  sleep 1
  cd /opt/macflow && python3 backend/main.py >/dev/null 2>&1 &
  sleep 3
fi

STATE_AFTER=$(cat /opt/macflow/data/state.json 2>/dev/null | md5sum | cut -d' ' -f1 || echo "none")
if [ "$STATE_BEFORE" = "$STATE_AFTER" ]; then
  ok "backend restart: state.json preserved"
else
  fail "backend restart: state.json changed"
fi

HEALTH=$(curl -s "$API/api/status" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q '"version"'; then
  ok "backend restart: API responsive"
else
  fail "backend restart: API not responsive"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 3: Rapid consecutive apply (5x) =="
for i in 1 2 3 4 5; do
  R=$(curl -s -X POST "$API/api/apply" 2>/dev/null)
  echo "  apply $i: $(echo "$R" | grep -o '"ok":[a-z]*')"
done

NFT_CHECK=$(nft list table inet macflow 2>/dev/null || echo "error")
if echo "$NFT_CHECK" | grep -q "mac_to_mark"; then
  ok "rapid apply: nftables consistent after 5x apply"
else
  fail "rapid apply: nftables broken after 5x apply"
fi

RULES_COUNT=$(ip -4 rule show | grep -c "fwmark" || echo "0")
echo "  ip rule count with fwmark: $RULES_COUNT"
if [ "$RULES_COUNT" -gt 0 ] && [ "$RULES_COUNT" -lt 50 ]; then
  ok "rapid apply: ip rules not duplicated ($RULES_COUNT rules)"
else
  fail "rapid apply: ip rules count abnormal ($RULES_COUNT)"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 4: Add new node then apply - existing device unaffected =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"stab-node-c","server":"10.0.1.3","server_port":8390,"method":"aes-256-gcm","password":"pc"}'
echo ""

curl -s -X POST "$API/api/apply" >/dev/null 2>&1

DEV_STATUS=$(curl -s "$API/api/devices" 2>/dev/null)
if echo "$DEV_STATUS" | grep -q '"node_tag":"stab-node-a"'; then
  ok "add node + apply: existing device still bound to stab-node-a"
else
  fail "add node + apply: existing device binding changed"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 5: Delete bound node - device node_tag cleared =="
curl -s -X DELETE "$API/api/nodes/stab-node-a" >/dev/null 2>&1

DEV_AFTER=$(curl -s "$API/api/devices" 2>/dev/null)
if echo "$DEV_AFTER" | grep -q '"node_tag":null'; then
  ok "delete bound node: device node_tag cleared to null"
else
  fail "delete bound node: device node_tag not cleared"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 6: Switch device node A->B - no disruption =="
curl -s -X PUT "$API/api/devices/AA:BB:CC:0B:01:01/node" \
  -H "Content-Type: application/json" \
  -d '{"node_tag":"stab-node-b"}'
echo ""

curl -s -X POST "$API/api/apply" >/dev/null 2>&1

SB_CFG=$(cat /etc/sing-box/config.json 2>/dev/null || echo "{}")
ROUTE_CHECK=$(echo "$SB_CFG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
rules=d.get('route',{}).get('rules',[])
for r in rules:
    if 'source_ip_cidr' in r and r.get('outbound')=='stab-node-b':
        print('found')
        break
else:
    print('not_found')" 2>/dev/null || echo "error")

NFT_MAC=$(nft list map inet macflow mac_to_mark 2>/dev/null || echo "")
echo "$NFT_MAC" | grep -qi "AA:BB:CC:0B:01:01" && ok "switch node: device still in nftables" || fail "switch node: device missing from nftables"

pgrep -f sing-box >/dev/null 2>&1 && ok "switch node: sing-box still running" || fail "switch node: sing-box crashed"

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL STABILITY TESTS PASSED" || echo "  STATUS: SOME TESTS FAILED"
exit "$FAIL"
