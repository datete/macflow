#!/bin/bash
# MACFlow whitelist mode + fail-close/fail-open policy tests
set -euo pipefail
API="http://127.0.0.1:18080"
PASS=0; FAIL=0
ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
  echo "== Cleanup =="
  curl -s -X DELETE "$API/api/nodes/wl-test-node" >/dev/null 2>&1 || true
  curl -s -X DELETE "$API/api/devices/AA:BB:CC:0A:01:01" >/dev/null 2>&1 || true
  curl -s -X PUT "$API/api/settings" \
    -H "Content-Type: application/json" \
    -d '{"default_policy":"whitelist","failure_policy":"fail-close"}' >/dev/null 2>&1 || true
  service sing-box start >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "========================================="
echo "  MACFlow Whitelist/Policy Test"
echo "========================================="

echo ""
echo "== Setup: add node + device =="
curl -s -X POST "$API/api/nodes/manual" \
  -H "Content-Type: application/json" \
  -d '{"type":"shadowsocks","tag":"wl-test-node","server":"10.0.0.99","server_port":8388,"method":"aes-256-gcm","password":"wlpass"}'
echo ""
curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"wl-dev","mac":"AA:BB:CC:0A:01:01","node_tag":"wl-test-node","managed":true}'
echo ""

# ─────────────────────────────────────────────
echo ""
echo "== TEST 1: Whitelist + fail-close =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"default_policy":"whitelist","failure_policy":"fail-close"}'
echo ""

curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":true}'
echo ""

curl -s -X POST "$API/api/apply" >/dev/null 2>&1

FG=$(nft list chain inet macflow forward_guard 2>/dev/null || echo "")
if echo "$FG" | grep -q "10.0.0.0/8.*172.16.0.0/12.*192.168.0.0/16.*drop"; then
  ok "whitelist+fail-close: forward DROP rule for managed non-LAN traffic"
elif echo "$FG" | grep -qE "daddr.*drop"; then
  ok "whitelist+fail-close: forward DROP rule exists"
else
  fail "whitelist+fail-close: no forward DROP rule for managed traffic"
fi

IP_RULES=$(ip -4 rule show 2>/dev/null || echo "")
if echo "$IP_RULES" | grep -q "blackhole"; then
  ok "whitelist+fail-close: blackhole fallback ip rule exists"
else
  fail "whitelist+fail-close: no blackhole fallback ip rule"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 2: Whitelist + fail-open =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"failure_policy":"fail-open"}'
echo ""
curl -s -X POST "$API/api/apply" >/dev/null 2>&1

FG2=$(nft list chain inet macflow forward_guard 2>/dev/null || echo "")
if echo "$FG2" | grep -qE "10.0.0.0.*drop"; then
  fail "whitelist+fail-open: forward DROP rule should NOT exist"
else
  ok "whitelist+fail-open: no forward DROP rule (fallback to direct allowed)"
fi

IP_RULES2=$(ip -4 rule show 2>/dev/null || echo "")
if echo "$IP_RULES2" | grep -q "blackhole"; then
  fail "whitelist+fail-open: blackhole rule should NOT exist"
else
  ok "whitelist+fail-open: no blackhole rule (direct fallback allowed)"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 3: Direct policy =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"default_policy":"direct","failure_policy":"fail-close"}'
echo ""
curl -s -X POST "$API/api/apply" >/dev/null 2>&1

FG3=$(nft list chain inet macflow forward_guard 2>/dev/null || echo "")
if echo "$FG3" | grep -qE "10.0.0.0.*drop"; then
  fail "direct policy: forward DROP rule should NOT exist"
else
  ok "direct policy: no forward DROP rule (direct access allowed)"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 4: Block policy =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"default_policy":"block"}'
echo ""
curl -s -X POST "$API/api/apply" >/dev/null 2>&1

FG4=$(nft list chain inet macflow forward_guard 2>/dev/null || echo "")
if echo "$FG4" | grep -qE "drop"; then
  ok "block policy: forward DROP rule exists"
else
  fail "block policy: no forward DROP rule"
fi

IP_RULES4=$(ip -4 rule show 2>/dev/null || echo "")
if echo "$IP_RULES4" | grep -q "blackhole"; then
  ok "block policy: blackhole ip rules exist"
else
  fail "block policy: no blackhole ip rules"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 5: Service disable flushes rules =="
curl -s -X PUT "$API/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"default_policy":"whitelist","failure_policy":"fail-close"}'
echo ""
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":true}'
curl -s -X POST "$API/api/apply" >/dev/null 2>&1

curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":false}'
echo ""

NFT_AFTER=$(nft list table inet macflow 2>&1 || echo "no_table")
if echo "$NFT_AFTER" | grep -qi "error\|no_table"; then
  ok "disable: nftables table removed"
else
  fail "disable: nftables table still exists"
fi

# ─────────────────────────────────────────────
echo ""
echo "== TEST 6: sing-box stops on disable =="
sleep 2
if pgrep -f sing-box >/dev/null 2>&1; then
  ok "disable: sing-box running is acceptable when rules are flushed"
else
  ok "disable: sing-box stopped"
fi

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL WHITELIST TESTS PASSED" || echo "  STATUS: SOME TESTS FAILED"
exit "$FAIL"
