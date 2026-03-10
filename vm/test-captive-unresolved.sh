#!/bin/bash
# MACFlow unresolved-device captive and block verification
set -euo pipefail

API="http://127.0.0.1:18080"
TEST_MAC="AA:BB:CC:09:09:09"
TEST_NAME="dev-unresolved"
PASS=0
FAIL=0

ok()   { echo "[OK]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
  curl -s -X DELETE "$API/api/devices/$TEST_MAC" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "========================================="
echo "  MACFlow Unresolved Captive Test"
echo "========================================="

echo ""
echo "== 1. Ensure service enabled and applied =="
curl -s -X POST "$API/api/service/toggle" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' >/dev/null
APPLY=$(curl -s -X POST "$API/api/apply")
echo "$APPLY"
echo "$APPLY" | grep -q '"ok":true' && ok "apply succeeded" || fail "apply failed"

echo ""
echo "== 2. Add managed device without IP =="
UP=$(curl -s -X POST "$API/api/devices" \
  -H "Content-Type: application/json" \
  -d '{"name":"'"$TEST_NAME"'","mac":"'"$TEST_MAC"'","node_tag":"direct","managed":true}')
echo "$UP"
echo "$UP" | grep -q '"ok":true' && ok "device upsert succeeded" || fail "device upsert failed"

echo ""
echo "== 3. Verify api/devices reports unresolved state =="
DEV_JSON=$(curl -s "$API/api/devices")
echo "$DEV_JSON" | head -c 400
echo ""

if CHECK_JSON=$(echo "$DEV_JSON" | python3 -c '
import json,sys
arr=json.load(sys.stdin)
target=next((d for d in arr if d.get("mac","").upper()=="AA:BB:CC:09:09:09"),None)
if not target:
    print("missing")
    raise SystemExit(2)
ip_source=target.get("ip_source")
resolved=target.get("resolved_ip")
mark=target.get("mark",0)
print(f"ip_source={ip_source} resolved_ip={resolved} mark={mark}")
if ip_source!="unknown":
    raise SystemExit(3)
if resolved is not None:
    raise SystemExit(4)
')
then
  echo "$CHECK_JSON"
  ok "device ip_source=unknown and resolved_ip=null"
else
  fail "device unresolved fields mismatch"
fi

MARK_HEX=$(echo "$DEV_JSON" | python3 -c '
import json,sys
arr=json.load(sys.stdin)
target=next((d for d in arr if d.get("mac","").upper()=="AA:BB:CC:09:09:09"),None)
if not target:
    print("")
else:
    print(hex(int(target.get("mark",0))))
')
if [ -n "$MARK_HEX" ] && [ "$MARK_HEX" != "0x0" ]; then
  ok "resolved device mark: $MARK_HEX"
else
  fail "device mark missing or zero"
fi

echo ""
echo "== 4. Verify nft unresolved sets and captive rule =="
UNRES_MACS=$(nft list set inet macflow unresolved_macs 2>/dev/null || true)
UNRES_MARKS=$(nft list set inet macflow unresolved_marks 2>/dev/null || true)
CAPTIVE=$(nft list chain inet macflow captive_redirect 2>/dev/null || true)

echo "$UNRES_MACS"
echo "$UNRES_MACS" | grep -qi "$TEST_MAC" && ok "test mac is in unresolved_macs" || fail "test mac missing from unresolved_macs"

echo "$UNRES_MARKS"
MARK_KEY="${MARK_HEX#0x}"
if [ -n "$MARK_KEY" ] && echo "$UNRES_MARKS" | grep -Eqi "0x0*${MARK_KEY}([^0-9a-fA-F]|$)"; then
  ok "test mark is in unresolved_marks"
else
  fail "test mark missing from unresolved_marks"
fi

echo "$CAPTIVE"
echo "$CAPTIVE" | grep -q "unresolved_macs.*dport 80.*redirect to :18080" && ok "captive redirect for unresolved devices active" || fail "captive redirect rule missing"

echo ""
echo "== 5. Delete device and verify cleanup =="
DEL=$(curl -s -X DELETE "$API/api/devices/$TEST_MAC")
echo "$DEL"
echo "$DEL" | grep -q '"ok":true' && ok "device delete succeeded" || fail "device delete failed"

curl -s -X POST "$API/api/apply" >/dev/null
UNRES_MACS_AFTER=$(nft list set inet macflow unresolved_macs 2>/dev/null || true)
UNRES_MARKS_AFTER=$(nft list set inet macflow unresolved_marks 2>/dev/null || true)

if echo "$UNRES_MACS_AFTER" | grep -qi "$TEST_MAC"; then
  fail "test mac still present after delete"
else
  ok "test mac removed from unresolved_macs"
fi

if [ -n "$MARK_KEY" ] && echo "$UNRES_MARKS_AFTER" | grep -Eqi "0x0*${MARK_KEY}([^0-9a-fA-F]|$)"; then
  fail "test mark still present after delete"
else
  ok "test mark removed from unresolved_marks"
fi

echo ""
echo "========================================="
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  STATUS: ALL CAPTIVE TESTS PASSED" || echo "  STATUS: SOME TESTS FAILED"
exit "$FAIL"
