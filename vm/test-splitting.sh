#!/bin/bash
# MACFlow per-device splitting verification
set -euo pipefail
API="http://127.0.0.1:18080"
PASS=0; FAIL=0
ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
  echo "== Cleanup =="
  curl -s -X DELETE "$API/api/nodes/split-node-hk" >/dev/null 2>&1 || true
  curl -s -X DELETE "$API/api/nodes/split-node-us" >/dev/null 2>&1 || true
  curl -s -X DELETE "$API/api/devices/AA:BB:CC:01:01:01" >/dev/null 2>&1 || true
  curl -s -X DELETE "$API/api/devices/AA:BB:CC:02:02:02" >/dev/null 2>&1 || true
  curl -s -X DELETE "$API/api/devices/AA:BB:CC:03:03:03" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "========================================="
echo "  MACFlow Splitting Test"
echo "========================================="

echo ""
echo "== 1. Add two proxy nodes =="
R1=$(curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"split-node-hk","server":"10.0.0.1","server_port":8388,"method":"aes-256-gcm","password":"pass1"}')
echo "$R1"
echo "$R1" | grep -q '"ok":true' && ok "node split-node-hk added" || fail "node split-node-hk add failed"

R2=$(curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"split-node-us","server":"10.0.0.2","server_port":8389,"method":"aes-256-gcm","password":"pass2"}')
echo "$R2"
echo "$R2" | grep -q '"ok":true' && ok "node split-node-us added" || fail "node split-node-us add failed"

echo ""
echo "== 2. Add three devices (HK, US, direct) =="
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"dev-hk","mac":"AA:BB:CC:01:01:01","node_tag":"split-node-hk","managed":true}'
echo ""

curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"dev-us","mac":"AA:BB:CC:02:02:02","node_tag":"split-node-us","managed":true}'
echo ""

curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"dev-direct","mac":"AA:BB:CC:03:03:03","node_tag":"direct","managed":true}'
echo ""

echo ""
echo "== 3. Enable service =="
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}'
echo ""

echo ""
echo "== 4. Apply =="
APPLY=$(curl -s -X POST "$API/api/apply")
echo "$APPLY"
echo "$APPLY" | grep -q '"ok":true' && ok "apply succeeded" || fail "apply failed"

echo ""
echo "== 4.5 Verify invalid node egress does NOT fallback to local =="
EGR_HK=$(curl -s "$API/api/egress/node/split-node-hk" 2>/dev/null || echo "")
echo "$EGR_HK"
echo "$EGR_HK" | grep -q '"detected_ip":null' && ok "invalid node egress: no detected IP" || fail "invalid node egress unexpectedly has IP"
echo "$EGR_HK" | grep -q '"proxied":false' && ok "invalid node egress: proxied=false" || fail "invalid node egress proxied state unexpected"

echo ""
echo "== 5. Verify nftables mac_to_mark =="
NFT_OUT=$(nft list map inet macflow mac_to_mark 2>/dev/null || echo "")
echo "$NFT_OUT"
echo "$NFT_OUT" | grep -qi "AA:BB:CC:01:01:01" && ok "dev-hk in mac_to_mark" || fail "dev-hk missing from mac_to_mark"
echo "$NFT_OUT" | grep -qi "AA:BB:CC:02:02:02" && ok "dev-us in mac_to_mark" || fail "dev-us missing from mac_to_mark"
echo "$NFT_OUT" | grep -qi "AA:BB:CC:03:03:03" && ok "dev-direct in mac_to_mark" || fail "dev-direct missing from mac_to_mark"

MARK_HK=$(echo "$NFT_OUT" | grep -i "AA:BB:CC:01:01:01" | grep -oE '0x[0-9a-f]+' | head -1)
MARK_US=$(echo "$NFT_OUT" | grep -i "AA:BB:CC:02:02:02" | grep -oE '0x[0-9a-f]+' | head -1)
if [ -n "$MARK_HK" ] && [ -n "$MARK_US" ] && [ "$MARK_HK" != "$MARK_US" ]; then
  ok "devices have different marks (HK=$MARK_HK US=$MARK_US)"
else
  fail "device marks not unique (HK=$MARK_HK US=$MARK_US)"
fi

echo ""
echo "== 6. Verify sing-box config has per-device route rules =="
SB_CFG=$(cat /etc/sing-box/config.json 2>/dev/null || echo "{}")
HAS_RULES=$(echo "$SB_CFG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
rules=d.get('route',{}).get('rules',[])
src_rules=[r for r in rules if 'source_ip_cidr' in r]
print(f'device_rules={len(src_rules)}')
for r in src_rules:
    print(f'  {r[\"source_ip_cidr\"]} -> {r.get(\"outbound\",\"?\")}')" 2>/dev/null || echo "parse_error")
echo "$HAS_RULES"

OB_TAGS=$(echo "$SB_CFG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
tags=[o['tag'] for o in d.get('outbounds',[])]
print(' '.join(tags))" 2>/dev/null || echo "")
echo "outbound tags: $OB_TAGS"
echo "$OB_TAGS" | grep -q "split-node-hk" && ok "split-node-hk in outbounds" || fail "split-node-hk missing from outbounds"
echo "$OB_TAGS" | grep -q "split-node-us" && ok "split-node-us in outbounds" || fail "split-node-us missing from outbounds"

FINAL=$(echo "$SB_CFG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('route',{}).get('final','none'))" 2>/dev/null || echo "none")
echo "route.final: $FINAL"
[ "$FINAL" = "proxy-select" ] && ok "default fallback is proxy-select" || fail "route.final != proxy-select"

echo ""
echo "== 7. Verify ip rules =="
IP_RULES=$(ip -4 rule show 2>/dev/null || echo "")
echo "$IP_RULES" | head -15
echo "$IP_RULES" | grep -q "fwmark" && ok "fwmark ip rules exist" || fail "no fwmark ip rules"

echo ""
echo "== 8. Verify sing-box running =="
pgrep -f sing-box >/dev/null 2>&1 && ok "sing-box running" || fail "sing-box not running"

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL SPLITTING TESTS PASSED" || echo "  STATUS: SOME TESTS FAILED"
exit "$FAIL"
